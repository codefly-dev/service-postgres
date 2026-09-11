package bootstrap

import (
	"context"
	"crypto/rand"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/codefly-dev/service-postgres/libs/go/controlplane"
	"github.com/codefly-dev/service-postgres/libs/go/schemaplan"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/lib/pq"
)

// Options accepts a passwordless TCP endpoint supplied by an authenticated
// proxy/tunnel. Cloud authentication and the executable's immutable packaging
// remain deployment-owner responsibilities. This runner never obtains tokens.
type Options struct {
	Directory         string
	Binding           Binding
	Connection        string
	MigrateExecutable string
	Timeout           time.Duration
	LockTimeout       time.Duration
	StatementTimeout  time.Duration
}

type Result struct {
	PlanSHA256        string   `json:"plan-sha256"`
	PlanDigest        string   `json:"plan-digest"`
	CompletedLineages []string `json:"completed-lineages"`
	SkippedExtensions []string `json:"skipped-extensions"`
	AccessCommitted   bool     `json:"access-committed"`
}

// Run serializes every lineage and access reconciliation with the same lock
// used by the service runtime and password bootstrap. Migrations are not one
// transaction with grants: failed/dirty lineages stop access reconciliation and
// require the existing dirty-migration runbook. Safe reruns use existing ledgers.
// Errors deliberately omit SQL, connection strings and subprocess output.
func Run(ctx context.Context, o Options) (result Result, err error) {
	if ctx == nil || o.Timeout < time.Second || o.Timeout > time.Hour || o.LockTimeout < time.Millisecond || o.LockTimeout > o.Timeout || o.StatementTimeout < time.Millisecond || o.StatementTimeout > o.Timeout {
		return result, errors.New("invalid managed bootstrap time budgets")
	}
	if !filepath.IsAbs(o.MigrateExecutable) {
		return result, errors.New("absolute migrate executable path is required")
	}
	info, e := os.Stat(o.MigrateExecutable)
	if e != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0111 == 0 {
		return result, errors.New("migrate executable is unavailable")
	}
	p, staged, e := snapshot(o.Directory, o.Binding)
	if e != nil {
		return result, e
	}
	defer os.RemoveAll(staged)
	dsn, e := connection(o, p)
	if e != nil {
		return result, e
	}
	cfg, e := pgx.ParseConfig(dsn)
	if e != nil {
		return result, errors.New("invalid managed connection")
	}
	// pgx can otherwise discover a local .pgpass even though the URL is clean.
	cfg.Password = ""
	cfg.RuntimeParams = map[string]string{"lock_timeout": fmt.Sprint(o.LockTimeout.Milliseconds()), "statement_timeout": fmt.Sprint(o.StatementTimeout.Milliseconds()), "search_path": "public"}
	ctx, cancel := context.WithTimeout(ctx, o.Timeout)
	defer cancel()
	db := stdlib.OpenDB(*cfg)
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(0)
	defer db.Close()
	conn, e := db.Conn(ctx)
	if e != nil {
		return result, errors.New("managed database connection failed")
	}
	defer conn.Close()
	var database, owner string
	if e = conn.QueryRowContext(ctx, "SELECT current_database(),current_user").Scan(&database, &owner); e != nil || database != p.Database || owner != o.Binding.OwnerRole {
		return result, errors.New("connected database or migration owner does not match binding")
	}
	if e = preflight(ctx, conn, p, o.Binding); e != nil {
		return result, e
	}
	if _, e = conn.ExecContext(ctx, `SELECT pg_advisory_lock(hashtext('codefly-runtime-access:' || current_database()))`); e != nil {
		return result, errors.New("managed bootstrap lock unavailable")
	}
	// This connection is never returned to an idle pool, including on failure;
	// closing it releases the session lock even when cancellation prevents unlock.
	result.PlanDigest = p.Digest
	result.PlanSHA256 = o.Binding.PlanSHA256
	for _, extension := range p.Extensions {
		if _, e = conn.ExecContext(ctx, "CREATE EXTENSION IF NOT EXISTS "+pq.QuoteIdentifier(extension.Name)); e != nil {
			if extension.Required {
				return result, errors.New("required extension failed")
			}
			result.SkippedExtensions = append(result.SkippedExtensions, extension.Name)
		}
	}
	for _, l := range p.Lineages {
		if e = ctx.Err(); e != nil {
			return result, errors.New("managed bootstrap deadline or cancellation")
		}
		u, _ := url.Parse(dsn)
		q := u.Query()
		q.Set("x-migrations-table", l.Ledger)
		application := fmt.Sprintf("codefly-bootstrap-%x", randomIdentity())
		q.Set("application_name", application)
		u.RawQuery = q.Encode()
		command := exec.CommandContext(ctx, o.MigrateExecutable, "-path", filepath.Join(staged, l.Stage), "-database", u.String(), "up")
		// No inherited PG service/password settings, cloud credentials or unrelated
		// secrets. The DSN is passwordless, including in the child process arguments.
		command.Env = []string{"PGPASSFILE=/dev/null"}
		command.WaitDelay = time.Second
		runErr := command.Run()
		// Killing a client does not prove its server-side statement has stopped.
		// Drain this child's uniquely named owner sessions before releasing the
		// shared control-plane lock, including after deadline cancellation.
		if e = drainChild(conn, application); e != nil {
			return result, e
		}
		if runErr != nil {
			return result, errors.New("migration lineage failed; inspect its ledger using docs/dirty-migrations.md")
		}
		result.CompletedLineages = append(result.CompletedLineages, l.Label)
	}
	tx, e := conn.BeginTx(ctx, nil)
	if e != nil {
		return result, errors.New("cannot begin runtime access reconciliation")
	}
	defer tx.Rollback()
	// Recheck under lock after migrations before the canonical engine can alter
	// group attributes. A preexisting LOGIN role is not a managed group.
	if e = preflight(ctx, tx, p, o.Binding); e != nil {
		return result, e
	}
	a := controlplane.RuntimeAccess{Database: p.Database, OwnerRole: o.Binding.OwnerRole, ReadOnlyRole: p.Access.ReadOnlyRole, ReadWriteRole: p.Access.ReadWriteRole, Schemas: p.Access.Schemas, ReadWriteRoles: p.Access.ReadWriteRoles, ReconcileReadWriteRoleMemberships: true, AuthMode: controlplane.AuthModeExternalIdentity, ReadOnlyPrincipals: o.Binding.ReadOnlyPrincipals, ReadWritePrincipals: o.Binding.ReadWritePrincipals}
	if e = controlplane.ReconcileRuntimeAccess(ctx, tx, a); e != nil {
		return result, errors.New("runtime access reconciliation failed")
	}
	if e = tx.Commit(); e != nil {
		return result, errors.New("runtime access commit failed; verify database state before retry")
	}
	result.AccessCommitted = true
	return result, nil
}

type querier interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

func preflight(ctx context.Context, db querier, p schemaplan.Plan, b Binding) error {
	for _, group := range []string{p.Access.ReadOnlyRole, p.Access.ReadWriteRole} {
		var login bool
		e := db.QueryRowContext(ctx, "SELECT (rolcanlogin OR rolsuper OR rolcreatedb OR rolcreaterole OR rolreplication OR rolbypassrls) FROM pg_roles WHERE rolname=$1", group).Scan(&login)
		if e != nil && !errors.Is(e, sql.ErrNoRows) {
			return errors.New("cannot verify managed group")
		}
		if login {
			return errors.New("managed group binding names a login or elevated role")
		}
	}
	for _, principals := range [][]string{b.ReadOnlyPrincipals, b.ReadWritePrincipals} {
		for _, principal := range principals {
			var login bool
			if e := db.QueryRowContext(ctx, "SELECT rolcanlogin FROM pg_roles WHERE rolname=$1", principal).Scan(&login); e != nil || !login {
				return errors.New("external principal must be an existing login role")
			}
		}
	}
	return nil
}

func connection(o Options, p schemaplan.Plan) (string, error) {
	invalid := errors.New("managed connection requires an explicit passwordless postgres TCP URL matching the plan and owner")
	u, e := url.Parse(o.Connection)
	if e != nil || u == nil || u.Scheme != "postgres" || u.User == nil || u.User.Username() != o.Binding.OwnerRole || u.Hostname() == "" || u.Path != "/"+p.Database || u.Fragment != "" {
		return "", invalid
	}
	if _, password := u.User.Password(); password {
		return "", invalid
	}
	q, e := url.ParseQuery(u.RawQuery)
	if e != nil {
		return "", invalid
	}
	for key, values := range q {
		switch key {
		case "sslmode", "sslrootcert", "sslcert", "sslkey":
		default:
			return "", invalid
		}
		if len(values) != 1 {
			return "", invalid
		}
	}
	if q.Get("sslmode") == "" {
		return "", invalid
	}
	q.Set("connect_timeout", "5")
	q.Set("lock_timeout", fmt.Sprint(o.LockTimeout.Milliseconds()))
	q.Set("statement_timeout", fmt.Sprint(o.StatementTimeout.Milliseconds()))
	u.RawQuery = q.Encode()
	return u.String(), nil
}

func randomIdentity() [16]byte { var id [16]byte; rand.Read(id[:]); return id }

func drainChild(conn *sql.Conn, application string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	rows, err := conn.QueryContext(ctx, `SELECT pg_terminate_backend(pid,2000) FROM pg_stat_activity
 WHERE application_name=$1 AND usename=current_user AND datname=current_database() AND pid<>pg_backend_pid()`, application)
	if err != nil {
		return errors.New("migration session cleanup uncertain; reconcile owner sessions before retry")
	}
	defer rows.Close()
	for rows.Next() {
		var stopped bool
		if rows.Scan(&stopped) != nil {
			return errors.New("migration session cleanup uncertain; reconcile owner sessions before retry")
		}
	}
	if rows.Err() != nil || rows.Close() != nil {
		return errors.New("migration session cleanup uncertain; reconcile owner sessions before retry")
	}
	// A session can exit between the activity snapshot and termination. A false
	// signal result is safe only when the final observation confirms absence.
	var remaining int
	if err = conn.QueryRowContext(ctx, `SELECT count(*) FROM pg_stat_activity WHERE application_name=$1 AND usename=current_user AND datname=current_database()`, application).Scan(&remaining); err != nil || remaining != 0 {
		return errors.New("migration session cleanup uncertain; reconcile owner sessions before retry")
	}
	return nil
}
