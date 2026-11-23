package main

// fixture.go — the fixture principal: what a test's dependency stack may ask
// of this agent, the same on both backends.
//
// A suite seeds rows for several tenants, empties tables between tests and
// asserts across tenants. Under FORCE ROW LEVEL SECURITY that takes a login
// that bypasses row security. The owner connection is such a login only by
// accident of the backend: the container's POSTGRES_USER is a superuser, the
// native run server's migration owner is not (nixpg.go), and should not be.
//
// So the capability is its own principal, asked for by name:
//
//   - a run asks by supplying the principal's password, POSTGRES_FIXTURE_PASSWORD
//     in the service's "postgres" secret configuration, the way every other
//     principal's password arrives. It is never derived: no ask, no principal.
//   - only a disposable run is given one: a run whose naming scope its own
//     invocation generated (core's runners/runstate), so nothing it holds can
//     be a developer's. Any other run that asks is refused at Init, by name,
//     before anything is started.
//   - it is exported as fixture-connection, beside owner-connection, whose
//     meaning does not change.
//
// The principal is a LOGIN with BYPASSRLS and the migration owner's authority,
// no more: a member of the owner, so it holds the owner's rights on the owner's
// relations (DDL, TRUNCATE) and roles; able to create roles and databases, as
// a migration suite does; and a superuser only where the owner already is one
// (ensureFixtureRole). On the run server, which the run's services share, it
// is not, and it reaches nothing of another service's database.
//
// It goes when the service is released (Stop, Destroy), and an Init that does
// not ask removes one an interrupted run left, so a database that is not being
// tested holds none.

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	basev0 "github.com/codefly-dev/core/generated/go/codefly/base/v0"
	"github.com/codefly-dev/core/resources"
	"github.com/codefly-dev/core/runners/runstate"
	"github.com/codefly-dev/core/wool"
	"github.com/lib/pq"
)

const (
	// fixtureConnectionKey is the exported connection of the fixture principal.
	fixtureConnectionKey = "fixture-connection"

	// fixturePasswordKey is the ask: the fixture principal's password in the
	// "postgres" secret configuration.
	fixturePasswordKey = "POSTGRES_FIXTURE_PASSWORD"

	// fixtureRetireTimeout bounds removing the principal on a release whose
	// caller's context is very often already spent.
	fixtureRetireTimeout = 10 * time.Second
)

// fixtureRole is a database's fixture principal, named after the database the
// way its owner and runtime roles are.
func fixtureRole(database string) string {
	return runtimeRolePrefix(database) + "_fixture"
}

// admitFixturePrincipal refuses a run that asks for the fixture principal and
// is not disposable. It reads the ask alone, before any credential is loaded or
// any server reached, so a refused run has started nothing.
func (s *Runtime) admitFixturePrincipal(ctx context.Context, configuration *basev0.Configuration) error {
	if configuration == nil {
		return nil
	}
	asked, err := resources.GetConfigurationValue(ctx, configuration, "postgres", fixturePasswordKey)
	if err != nil || asked == "" {
		return err
	}
	if runstate.For(s.Identity.WorkspacePath, s.Environment).Disposable {
		return nil
	}
	return s.Wool.NewError(
		"the fixture principal is refused: %s asks for a login that bypasses row security, and only a disposable run is given one "+
			"(a run whose naming scope its own invocation generated, such as a test's dependency stack); "+
			"this run's database is kept, so remove %s from the postgres configuration this run reads",
		fixturePasswordKey, fixturePasswordKey)
}

// fixtureRequested reports whether this run asked for the fixture principal.
// Init admitted the ask before loading it.
func (s *Service) fixtureRequested() bool {
	return s.fixturePassword != ""
}

// withFixtureConnection adds the fixture principal's connection to what Init
// hands out for one network instance.
func (s *Service) withFixtureConnection(configuration *basev0.Configuration, instance *basev0.NetworkInstance) {
	connection := postgresConnectionString(instance.Address, s.DatabaseName, fixtureRole(s.DatabaseName), s.fixturePassword, false, false)
	for _, info := range configuration.Infos {
		if info.Name == "postgres" {
			info.ConfigurationValues = append(info.ConfigurationValues,
				&basev0.ConfigurationValue{Key: fixtureConnectionKey, Value: connection, Secret: true})
		}
	}
}

// reconcileFixturePrincipal makes the database hold the fixture principal when
// this run asked for it, and none otherwise. The caller holds the control
// plane.
func (s *Runtime) reconcileFixturePrincipal(ctx context.Context) error {
	db, err := sql.Open("postgres", s.extensionConnection())
	if err != nil {
		return s.Wool.Wrapf(err, "cannot open database to reconcile the fixture principal")
	}
	defer db.Close()
	role := fixtureRole(s.DatabaseName)
	if !s.fixtureRequested() {
		disabled, err := retireFixtureRole(ctx, db, role, s.postgresUser)
		if err != nil && !disabled {
			return s.Wool.Wrapf(err, "cannot remove the fixture principal an earlier run left")
		}
		if err != nil {
			s.Wool.Warn("the fixture principal an earlier run left is disabled but could not be dropped", wool.ErrField(err))
		}
		return nil
	}
	if err := ensureFixtureRole(ctx, db, role, s.postgresUser, s.fixturePassword); err != nil {
		return s.Wool.Wrapf(err, "cannot provision the fixture principal")
	}
	s.fixtureProvisioned = true
	return nil
}

// retireFixturePrincipal removes the principal this invocation provisioned,
// while the server it lives on is still up. A failure is reported, not
// returned: it must not keep a service from being released, and the next Init
// of this database reconciles it again.
func (s *Runtime) retireFixturePrincipal(ctx context.Context) {
	if !s.fixtureProvisioned {
		return
	}
	s.fixtureProvisioned = false
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), fixtureRetireTimeout)
	defer cancel()
	db, err := sql.Open("postgres", s.extensionConnection())
	if err == nil {
		defer db.Close()
		_, err = retireFixtureRole(ctx, db, fixtureRole(s.DatabaseName), s.postgresUser)
	}
	if err != nil {
		s.Wool.Warn("cannot remove the fixture principal", wool.ErrField(err))
	}
}

// ensureFixtureRole creates or reconfigures the fixture principal. It is this
// agent's to create: one that is already granted to another role was created
// by a role of the database (PostgreSQL 16 grants a created role back to its
// creator), and adopting it would leave that creator able to take it.
func ensureFixtureRole(ctx context.Context, db *sql.DB, role, owner, password string) error {
	var exists, granted bool
	if err := db.QueryRowContext(ctx, `
		SELECT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = $1),
		       EXISTS (SELECT 1 FROM pg_auth_members m
		               JOIN pg_roles r ON r.oid = m.roleid
		               WHERE r.rolname = $1)`, role).Scan(&exists, &granted); err != nil {
		return fmt.Errorf("look up the fixture principal: %w", err)
	}
	if granted {
		return fmt.Errorf("role %q is granted to another role, so it was not created as this database's fixture principal: remove it", role)
	}
	quoted := pq.QuoteIdentifier(role)
	if !exists {
		if _, err := db.ExecContext(ctx, `CREATE ROLE `+quoted); err != nil {
			return fmt.Errorf("create the fixture principal: %w", err)
		}
	}
	// The principal holds the owner's authority, and membership does not carry
	// a superuser's: the roles a superuser's migrations created answer to
	// superusers alone. So where the owner is one (a container's POSTGRES_USER,
	// on a server that is this service's alone) the principal is one too, and
	// where it is not (the run server, shared by the run's services) the
	// principal is not either.
	var ownerIsSuperuser bool
	if err := db.QueryRowContext(ctx, `SELECT rolsuper FROM pg_roles WHERE rolname = $1`, owner).Scan(&ownerIsSuperuser); err != nil {
		return fmt.Errorf("look up the migration owner: %w", err)
	}
	superuser := "NOSUPERUSER"
	if ownerIsSuperuser {
		superuser = "SUPERUSER"
	}
	statements := []string{
		`ALTER ROLE ` + quoted + ` WITH LOGIN ` + superuser + ` INHERIT BYPASSRLS CREATEROLE CREATEDB NOREPLICATION PASSWORD ` + pq.QuoteLiteral(password),
		`GRANT ` + pq.QuoteIdentifier(owner) + ` TO ` + quoted,
	}
	// A suite hands relations to roles it creates and takes them back, which a
	// superuser does without holding those roles. From PostgreSQL 16 a role's
	// creator is granted it WITH ADMIN OPTION only, and this setting is the
	// server's own way to give the creator the rest. Earlier servers have no
	// such setting and make the creator a full member already.
	var selfGrant bool
	if err := db.QueryRowContext(ctx, `SELECT current_setting('server_version_num')::int >= 160000`).Scan(&selfGrant); err != nil {
		return fmt.Errorf("read the server version: %w", err)
	}
	if selfGrant {
		statements = append(statements, `ALTER ROLE `+quoted+` SET createrole_self_grant TO 'set, inherit'`)
	}
	for _, statement := range statements {
		if _, err := db.ExecContext(ctx, statement); err != nil {
			return fmt.Errorf("configure the fixture principal: %w", err)
		}
	}
	return nil
}

// retireFixtureRole removes the fixture principal: its sessions are ended,
// what it created is handed to the migration owner, and the role is dropped.
// A role that cannot be dropped (it owns objects in a database this connection
// cannot reach) is left unable to log in or to bypass anything, and reported:
// disabled says the role, if it is still there, is no longer a principal.
func retireFixtureRole(ctx context.Context, db *sql.DB, role, owner string) (disabled bool, _ error) {
	var exists bool
	if err := db.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = $1)`, role).Scan(&exists); err != nil {
		return false, fmt.Errorf("look up the fixture principal: %w", err)
	}
	if !exists {
		return true, nil
	}
	quoted := pq.QuoteIdentifier(role)
	// Disabled first: nothing can log in as it while it is being removed, and
	// whatever follows fails, it is no longer a principal.
	if _, err := db.ExecContext(ctx, `ALTER ROLE `+quoted+` WITH NOLOGIN NOSUPERUSER NOBYPASSRLS NOCREATEROLE NOCREATEDB PASSWORD NULL`); err != nil {
		return false, fmt.Errorf("disable the fixture principal: %w", err)
	}
	if _, err := db.ExecContext(ctx, `SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE usename = $1`, role); err != nil {
		return true, fmt.Errorf("end the fixture principal's sessions: %w", err)
	}
	var failures []error
	for _, statement := range []string{
		`REASSIGN OWNED BY ` + quoted + ` TO ` + pq.QuoteIdentifier(owner),
		`DROP OWNED BY ` + quoted,
		`DROP ROLE ` + quoted,
	} {
		if _, err := db.ExecContext(ctx, statement); err != nil {
			failures = append(failures, err)
		}
	}
	if len(failures) > 0 {
		return true, fmt.Errorf("drop the disabled fixture principal %q: %w", role, errors.Join(failures...))
	}
	return true, nil
}
