package main

// nixpg.go — Docker-free postgres runtime.
//
// The postgres service agent runs the database in a container by default
// (NewDockerHeadlessEnvironment). On hosts without Docker, the same agent can
// run postgres NATIVELY using a nix-provisioned binary: the codefly
// NixEnvironment materializes `postgresql_17` from the embedded flake (so no
// system install is required), and this file drives the native postgres
// lifecycle the Docker image's entrypoint would otherwise handle — initdb on
// first boot, launch `postgres`, and create the configured database.
//
// Both runtimes serve the same postgres 17 + the same connection string, so the
// rest of the agent (migrations, readiness, configuration) is unchanged.

import (
	"context"
	"crypto/sha256"
	"database/sql"
	_ "embed"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/codefly-dev/core/resources"
	runners "github.com/codefly-dev/core/runners/base"
	"github.com/codefly-dev/core/shared"
	"github.com/lib/pq"
)

//go:embed nix/flake.nix
var pgFlakeNix string

//go:embed nix/flake.lock
var pgFlakeLock string

// nixPostgres runs a native postgres server off a nix-provisioned binary.
type nixPostgres struct {
	env       *runners.NixEnvironment
	flakeDir  string
	dataDir   string
	socketDir string
	port      uint16
	user      string
	password  string
	dbName    string
	logLevel  string
	walBudget postgresWALBudget
	out       io.Writer
	proc      runners.Proc
	// serverCancel cancels serverCtx — the context the postgres process runs
	// under. It MUST outlive Init: starting postgres under the Init RPC's ctx
	// kills it ("smart shutdown") the instant Init returns and that ctx is
	// cancelled. Cancelled only by Stop.
	serverCtx    context.Context
	serverCancel context.CancelFunc
	// serverExit reports the process's real terminal result. Readiness observes
	// it so a bind failure cannot be hidden by an unrelated database already
	// listening on the proposed TCP port.
	serverExit <-chan error
	// binDir is the absolute nix store bin dir holding initdb + postgres.
	// Resolved once after materialization and used for ALL postgres invocations
	// so PATH contamination (e.g. a system Homebrew postgres) can never make
	// initdb pick a different-version postgres than itself.
	binDir string
}

// newNixPostgres materializes the embedded flake and prepares a native postgres
// whose runtime state (data dir, nix cache, flake, unix socket) lives ENTIRELY
// OUTSIDE the user's source tree.
//
// stateKey is derived from the agent's service location and the authoritative
// Codefly naming scope. The source repo is later consumed as a nix flake `path:`
// input, so runtime state cannot live below it. The scoped key also prevents
// independent Codefly flows from sharing credentials or database contents,
// while an unscoped restart retains the historical per-location cluster.
func newNixPostgres(ctx context.Context, stateKey string, port uint16, user, password, dbName, logLevel string, walBudget postgresWALBudget, out io.Writer) (*nixPostgres, error) {
	if strings.TrimSpace(password) == "" {
		return nil, fmt.Errorf("postgres password is required for the native runtime")
	}
	runtimeRoot, err := nixRuntimeRoot(stateKey)
	if err != nil {
		return nil, err
	}
	flakeDir := filepath.Join(runtimeRoot, "nix")
	if err := os.MkdirAll(flakeDir, 0o755); err != nil {
		return nil, fmt.Errorf("create nix flake dir: %w", err)
	}
	if err := os.WriteFile(filepath.Join(flakeDir, "flake.nix"), []byte(pgFlakeNix), 0o644); err != nil {
		return nil, fmt.Errorf("write flake.nix: %w", err)
	}
	if err := os.WriteFile(filepath.Join(flakeDir, "flake.lock"), []byte(pgFlakeLock), 0o644); err != nil {
		return nil, fmt.Errorf("write flake.lock: %w", err)
	}
	env, err := runners.NewNixEnvironment(ctx, flakeDir)
	if err != nil {
		return nil, fmt.Errorf("nix environment (is nix installed?): %w", err)
	}
	env.WithCacheDir(filepath.Join(runtimeRoot, ".nix-cache"))

	// The unix socket path has a ~104-char limit, so it cannot live under a deep
	// cache path. Use an unpredictable, owner-only temporary directory: a stable
	// /tmp name can be pre-created or symlinked by another local user.
	socketDir, err := os.MkdirTemp("", "cfpg-"+serviceHash(stateKey)[:8]+"-")
	if err != nil {
		return nil, fmt.Errorf("create postgres socket dir: %w", err)
	}
	if err := os.Chmod(socketDir, 0o700); err != nil {
		return nil, fmt.Errorf("secure postgres socket dir: %w", err)
	}

	return &nixPostgres{
		env:       env,
		flakeDir:  flakeDir,
		dataDir:   filepath.Join(runtimeRoot, "pgdata"),
		socketDir: socketDir,
		port:      port,
		user:      user,
		password:  password,
		dbName:    dbName,
		logLevel:  logLevel,
		walBudget: walBudget,
		out:       out,
	}, nil
}

// nixPostgresStateKey preserves the existing unscoped data location while
// making Codefly's advanced naming-scope isolation apply equally to the Nix
// and Docker Postgres runtimes. The separator is unambiguous and the resulting
// value is hashed before it is used as a filesystem component.
func nixPostgresStateKey(serviceLocation, namingScope string) string {
	if namingScope == "" {
		return serviceLocation
	}
	return serviceLocation + "\x00naming-scope\x00" + namingScope
}

// serviceHash is the hex sha256 of a service's scoped state key.
func serviceHash(stateKey string) string {
	sum := sha256.Sum256([]byte(stateKey))
	return hex.EncodeToString(sum[:])
}

// nixRuntimeRoot is the stable, out-of-source runtime root for a postgres
// service (data dir, nix cache, flake), keyed by its scoped state identity so
// same-scope restarts reuse the cluster without crossing isolation scopes.
// Falls back to the OS temp dir if no user cache dir is available.
func nixRuntimeRoot(stateKey string) (string, error) {
	cache, err := os.UserCacheDir()
	if err != nil {
		cache = os.TempDir()
	}
	return filepath.Join(cache, "codefly", "postgres", serviceHash(stateKey)[:16]), nil
}

// Init materializes the nix env, initdb's the cluster on first boot, launches
// postgres in the background, waits for readiness, and creates the database.
func (n *nixPostgres) Init(ctx context.Context) (initErr error) {
	defer func() {
		if initErr == nil {
			return
		}
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		initErr = errors.Join(initErr, n.Stop(cleanupCtx))
	}()
	if err := n.env.Init(ctx); err != nil {
		return fmt.Errorf("materialize nix postgres env: %w", err)
	}
	storage, err := resources.InspectStorageFilesystem(n.dataDir)
	if err != nil {
		return fmt.Errorf("inspect nix postgres storage: %w", err)
	}
	if err := validateWALBudgetStorage(n.walBudget, storage); err != nil {
		return err
	}
	if err := n.resolveBinDir(); err != nil {
		return err
	}
	if err := n.initdbIfNeeded(ctx); err != nil {
		return err
	}
	if err := n.clearStalePostmasterPid(); err != nil {
		return err
	}
	if err := n.startServer(ctx); err != nil {
		return err
	}
	if err := n.waitReady(ctx); err != nil {
		return err
	}
	if err := n.ensureAuthentication(ctx); err != nil {
		return err
	}
	return n.ensureDatabase(ctx)
}

// clearStalePostmasterPid removes a leftover postmaster.pid when no live
// postmaster owns it. The nix runner launches `postgres` directly (not
// pg_ctl), so it must replicate pg_ctl's stale-lock cleanup — otherwise a
// crashed or SIGKILL'd prior run (codefly currently reaps orphaned nix deps
// only on the NEXT startup, after a fresh run already tried to start) leaves a
// pid file that aborts boot: `FATAL: lock file "postmaster.pid" is empty` /
// "is the remnant of a previous server startup crash". A pid file owned by a
// LIVE process is left untouched so we never stomp a concurrent postmaster.
func (n *nixPostgres) clearStalePostmasterPid() error {
	pidPath := filepath.Join(n.dataDir, "postmaster.pid")
	data, err := os.ReadFile(pidPath)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return nil // best-effort; let postgres surface any real error
	}
	// Line 1 of postmaster.pid is the postmaster PID. An empty/corrupt file is
	// stale by definition.
	fields := strings.Fields(string(data))
	if len(fields) > 0 {
		if pid, perr := strconv.Atoi(fields[0]); perr == nil && pid > 0 && processAlive(pid) {
			return nil // a live process owns the lock — do NOT remove it
		}
	}
	return os.Remove(pidPath)
}

// processAlive reports whether a PID names a live process (signal 0 probe).
func processAlive(pid int) bool {
	p, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	return p.Signal(syscall.Signal(0)) == nil
}

// initdbIfNeeded creates the cluster the first time (PG_VERSION marks an
// initialized data dir). Both local and TCP connections require SCRAM; the
// bootstrap password is passed through an owner-only temporary file, never
// argv or the environment.
func (n *nixPostgres) initdbIfNeeded(ctx context.Context) error {
	if _, err := os.Stat(filepath.Join(n.dataDir, "PG_VERSION")); err == nil {
		return nil // already initialized
	}
	if err := os.MkdirAll(n.dataDir, 0o700); err != nil {
		return fmt.Errorf("create data dir: %w", err)
	}
	passwordFile, err := n.writeInitPasswordFile()
	if err != nil {
		return err
	}
	defer os.Remove(passwordFile)
	proc, err := n.env.NewProcess(filepath.Join(n.binDir, "initdb"), n.initdbArgs(passwordFile)...)
	if err != nil {
		return err
	}
	if n.out != nil {
		proc.WithOutput(n.out)
	}
	if err := proc.Run(ctx); err != nil {
		return fmt.Errorf("initdb: %w", err)
	}
	return nil
}

func (n *nixPostgres) initdbArgs(passwordFile string) []string {
	return []string{
		"-D", n.dataDir,
		"-U", n.user,
		"--auth-local=scram-sha-256",
		"--auth-host=scram-sha-256",
		"--pwfile=" + passwordFile,
		"--no-locale",
		"-E", "UTF8",
	}
}

func (n *nixPostgres) writeInitPasswordFile() (string, error) {
	file, err := os.CreateTemp(filepath.Dir(n.dataDir), ".initdb-password-*")
	if err != nil {
		return "", fmt.Errorf("create initdb password file: %w", err)
	}
	path := file.Name()
	if err := file.Chmod(0o600); err != nil {
		_ = file.Close()
		_ = os.Remove(path)
		return "", fmt.Errorf("secure initdb password file: %w", err)
	}
	if _, err := io.WriteString(file, n.password+"\n"); err != nil {
		_ = file.Close()
		_ = os.Remove(path)
		return "", fmt.Errorf("write initdb password file: %w", err)
	}
	if err := file.Close(); err != nil {
		_ = os.Remove(path)
		return "", fmt.Errorf("close initdb password file: %w", err)
	}
	return path, nil
}

// startServer launches postgres listening on 127.0.0.1:port. Quietened to the
// configured log level when set (mirrors the Docker -c flags).
func (n *nixPostgres) startServer(ctx context.Context) error {
	args := []string{
		"-D", n.dataDir,
		"-p", fmt.Sprintf("%d", n.port),
		"-k", n.socketDir,
		"-c", "listen_addresses=127.0.0.1",
	}
	args = append(args, n.walBudget.postgresArguments()...)
	if lvl := strings.ToLower(strings.TrimSpace(n.logLevel)); lvl != "" {
		args = append(args,
			"-c", "log_min_messages="+lvl,
			"-c", "log_statement=none",
			"-c", "log_connections=off",
			"-c", "log_disconnections=off",
		)
	}
	proc, err := n.env.NewProcess(filepath.Join(n.binDir, "postgres"), args...)
	if err != nil {
		return err
	}
	if n.out != nil {
		proc.WithOutput(n.out)
	}
	// Run postgres under a context that outlives Init — NOT the Init RPC ctx,
	// which is cancelled the moment Init returns and would SIGTERM the server.
	n.serverCtx, n.serverCancel = context.WithCancel(context.Background())
	if err := proc.Start(n.serverCtx); err != nil {
		n.serverCancel()
		return fmt.Errorf("start postgres: %w", err)
	}
	n.proc = proc
	exit := make(chan error, 1)
	go func() {
		exit <- proc.Wait(context.Background())
		close(exit)
	}()
	n.serverExit = exit
	return nil
}

// Supervise watches the running postgres process after startup and invokes
// onExit exactly once if the postmaster terminates for any reason OTHER than a
// deliberate Stop. The Nix runtime is a host process the agent owns directly:
// without this the postmaster can exit mid-run (crash, an external SIGTERM, an
// invalidated data-directory lock) while the agent keeps reporting STARTED,
// leaving codefly's Follow loop blind and every dependent wedged on connection
// refused (codefly-dev/cli#380). This mirrors the user-binary supervision
// service-go performs by feeding the exit into MarkRunnerExited.
//
// Call it once, after a successful Init/Start: startServer has populated
// serverExit and serverCtx, and waitReady has finished observing serverExit, so
// this goroutine is the sole remaining reader of the channel.
func (n *nixPostgres) Supervise(onExit func(error)) {
	exit := n.serverExit
	if exit == nil {
		return
	}
	// Stop cancels serverCtx before terminating the process, so a cancelled
	// context is the authoritative "this shutdown was orderly" signal.
	var stopped <-chan struct{}
	if n.serverCtx != nil {
		stopped = n.serverCtx.Done()
	}
	go func() {
		err, ok := <-exit
		if !ok {
			return
		}
		if stopped != nil {
			select {
			case <-stopped:
				return
			default:
			}
		}
		onExit(err)
	}()
}

// adminDSN reaches this runtime's private Unix socket. Bootstrap work must not
// use the public TCP mapping: another backend or stale process can still own
// that port, and accepting its successful ping would authenticate, migrate,
// and report readiness for the wrong database.
func (n *nixPostgres) adminDSN() string {
	u := &url.URL{
		Scheme: "postgresql",
		User:   url.UserPassword(n.user, n.password),
		Path:   "/postgres",
	}
	query := u.Query()
	query.Set("host", n.socketDir)
	query.Set("port", strconv.Itoa(int(n.port)))
	query.Set("sslmode", "disable")
	u.RawQuery = query.Encode()
	return u.String()
}

// ensureAuthentication upgrades legacy trust-initialized clusters in place
// and pins pg_hba.conf to password authentication. Updating the role before
// reloading the HBA keeps existing developer data while closing the old
// unauthenticated local/TCP access.
func (n *nixPostgres) ensureAuthentication(ctx context.Context) error {
	db, err := sql.Open("postgres", n.adminDSN())
	if err != nil {
		return fmt.Errorf("open postgres for auth hardening: %w", err)
	}
	defer db.Close()
	statement := fmt.Sprintf("ALTER ROLE %s WITH PASSWORD %s", pq.QuoteIdentifier(n.user), pq.QuoteLiteral(n.password))
	if _, err := db.ExecContext(ctx, statement); err != nil {
		return fmt.Errorf("set postgres role password: %w", err)
	}
	hba := []byte("local all all scram-sha-256\n" +
		"host all all 127.0.0.1/32 scram-sha-256\n" +
		"host all all ::1/128 scram-sha-256\n")
	hbaPath := filepath.Join(n.dataDir, "pg_hba.conf")
	if err := shared.WriteFileAtomic(ctx, hbaPath, hba, 0o600); err != nil {
		return fmt.Errorf("write secure pg_hba.conf: %w", err)
	}
	if _, err := db.ExecContext(ctx, "SELECT pg_reload_conf()"); err != nil {
		return fmt.Errorf("reload secure pg_hba.conf: %w", err)
	}
	return nil
}

// waitReady polls this process's private socket and also observes its exit. A
// public TCP ping is insufficient because a stale Docker proxy can own the
// proposed port while the newly launched Nix postgres dies during bind.
func (n *nixPostgres) waitReady(ctx context.Context) error {
	deadline := time.NewTimer(30 * time.Second)
	defer deadline.Stop()
	retry := time.NewTicker(500 * time.Millisecond)
	defer retry.Stop()
	var lastErr error
	for {
		select {
		case exitErr := <-n.serverExit:
			return postgresExitedBeforeReady(exitErr)
		default:
		}
		db, err := sql.Open("postgres", n.adminDSN())
		if err == nil {
			pingCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
			lastErr = db.PingContext(pingCtx)
			cancel()
			_ = db.Close()
			if lastErr == nil {
				select {
				case exitErr := <-n.serverExit:
					return postgresExitedBeforeReady(exitErr)
				default:
					return nil
				}
			}
		} else {
			lastErr = err
		}
		select {
		case exitErr := <-n.serverExit:
			return postgresExitedBeforeReady(exitErr)
		case <-ctx.Done():
			return fmt.Errorf("wait for postgres readiness: %w", ctx.Err())
		case <-deadline.C:
			if lastErr == nil {
				lastErr = errors.New("no readiness probe completed")
			}
			return fmt.Errorf("postgres did not become ready: %w", lastErr)
		case <-retry.C:
		}
	}
}

func postgresExitedBeforeReady(err error) error {
	if err == nil {
		return errors.New("postgres exited before becoming ready")
	}
	return fmt.Errorf("postgres exited before becoming ready: %w", err)
}

// ensureDatabase creates the configured database if it does not exist (the
// Docker image does this via POSTGRES_DB; natively we do it ourselves).
func (n *nixPostgres) ensureDatabase(ctx context.Context) error {
	db, err := sql.Open("postgres", n.adminDSN())
	if err != nil {
		return err
	}
	defer func() { _ = db.Close() }()

	var exists bool
	if err := db.QueryRowContext(ctx, "SELECT EXISTS (SELECT 1 FROM pg_database WHERE datname=$1)", n.dbName).Scan(&exists); err != nil {
		return fmt.Errorf("check database exists: %w", err)
	}
	if exists {
		return nil
	}
	// Database names cannot be parameterized; quote to avoid injection.
	if _, err := db.ExecContext(ctx, fmt.Sprintf("CREATE DATABASE %s", pgQuoteIdent(n.dbName))); err != nil {
		return fmt.Errorf("create database %q: %w", n.dbName, err)
	}
	return nil
}

// Stop terminates the postgres server.
func (n *nixPostgres) Stop(ctx context.Context) error {
	if n.serverCancel != nil {
		n.serverCancel()
	}
	var stopErr error
	if n.proc != nil {
		stopErr = n.proc.Stop(ctx)
	}
	removeErr := os.RemoveAll(n.socketDir)
	return errors.Join(stopErr, removeErr)
}

// resolveBinDir locates the nix store bin dir that holds postgres 17's initdb,
// so every invocation uses that exact build. env.Init has already materialized
// (downloaded) the package, so it is present in the store. Using the absolute
// dir — rather than the bare command on PATH — guarantees initdb and postgres
// are the same version even when a different system postgres shadows PATH.
func (n *nixPostgres) resolveBinDir() error {
	// Broad glob: match BOTH the plain `postgresql-17*` build AND the
	// `withPackages` wrapper (`postgresql-and-plugins-17*`) that bundles
	// pgvector. The old pattern `*-postgresql-17*` did NOT match the wrapper
	// (its name is "postgresql-and-plugins-17…", which has no "postgresql-17"
	// substring), so it always resolved to the PLAIN build — whose extension
	// dir has no vector.control. Mind's KG migration does `CREATE EXTENSION
	// vector`, which then aborts mid-migration (golang-migrate goes dirty) and
	// kg_nodes is never created.
	matches, err := filepath.Glob("/nix/store/*postgresql*17*/bin/initdb")
	if err != nil {
		return fmt.Errorf("glob nix postgres: %w", err)
	}
	var fallback string
	for _, m := range matches {
		binDir := filepath.Dir(m)
		// Must have the postgres server binary alongside initdb (skip
		// lib/man/doc-only outputs).
		if _, err := os.Stat(filepath.Join(binDir, "postgres")); err != nil {
			continue
		}
		// PREFER a build whose extension dir ships pgvector — that is the
		// withPackages wrapper the flake builds. <prefix>/bin/initdb →
		// <prefix>/share/postgresql/extension/vector.control.
		vectorControl := filepath.Join(filepath.Dir(binDir), "share", "postgresql", "extension", "vector.control")
		if _, err := os.Stat(vectorControl); err == nil {
			n.binDir = binDir
			return nil
		}
		if fallback == "" {
			fallback = binDir
		}
	}
	if fallback != "" {
		// No pgvector-enabled build found — use a plain one so non-vector
		// schemas still work; CREATE EXTENSION vector will then fail loudly
		// rather than us silently skipping a vector build that does exist.
		n.binDir = fallback
		return nil
	}
	return fmt.Errorf("no nix postgresql-17 with both initdb+postgres found in /nix/store (materialization may have failed)")
}

// pgQuoteIdent double-quotes a postgres identifier, escaping embedded quotes.
func pgQuoteIdent(name string) string {
	return `"` + strings.ReplaceAll(name, `"`, `""`) + `"`
}
