package main

// nixpg.go — Docker-free postgres runtime.
//
// The postgres service agent runs the database in a container by default
// (NewDockerHeadlessEnvironment). On hosts without Docker, the same agent can
// run postgres NATIVELY using a nix-provisioned binary: the codefly
// NixEnvironment materializes `postgresql_16` from the embedded flake (so no
// system install is required), and this file drives the native postgres
// lifecycle the Docker image's entrypoint would otherwise handle — initdb on
// first boot, launch `postgres`, and create the configured database.
//
// Both runtimes serve the same postgres 16 + the same connection string, so the
// rest of the agent (migrations, readiness, configuration) is unchanged.

import (
	"context"
	"database/sql"
	_ "embed"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	runners "github.com/codefly-dev/core/runners/base"
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
	out       io.Writer
	proc      runners.Proc
	// serverCancel cancels serverCtx — the context the postgres process runs
	// under. It MUST outlive Init: starting postgres under the Init RPC's ctx
	// kills it ("smart shutdown") the instant Init returns and that ctx is
	// cancelled. Cancelled only by Stop.
	serverCtx    context.Context
	serverCancel context.CancelFunc
	// binDir is the absolute nix store bin dir holding initdb + postgres.
	// Resolved once after materialization and used for ALL postgres invocations
	// so PATH contamination (e.g. a system Homebrew postgres) can never make
	// initdb pick a different-version postgres than itself.
	binDir string
}

// newNixPostgres materializes the embedded flake under baseDir/nix and prepares a
// native postgres rooted at baseDir/pgdata. baseDir is the agent's local service
// dir, so the data dir persists across restarts exactly like a Docker volume.
func newNixPostgres(ctx context.Context, baseDir string, port uint16, user, password, dbName, logLevel string, out io.Writer) (*nixPostgres, error) {
	flakeDir := filepath.Join(baseDir, "nix")
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
	env.WithCacheDir(filepath.Join(baseDir, ".nix-cache"))

	// Unix socket dir must be short (socket path has a ~104 char limit). Keep it
	// at baseDir, which the agent already keeps short.
	return &nixPostgres{
		env:       env,
		flakeDir:  flakeDir,
		dataDir:   filepath.Join(baseDir, "pgdata"),
		socketDir: baseDir,
		port:      port,
		user:      user,
		password:  password,
		dbName:    dbName,
		logLevel:  logLevel,
		out:       out,
	}, nil
}

// Init materializes the nix env, initdb's the cluster on first boot, launches
// postgres in the background, waits for readiness, and creates the database.
func (n *nixPostgres) Init(ctx context.Context) error {
	if err := n.env.Init(ctx); err != nil {
		return fmt.Errorf("materialize nix postgres env: %w", err)
	}
	if err := n.resolveBinDir(); err != nil {
		return err
	}
	if err := n.initdbIfNeeded(ctx); err != nil {
		return err
	}
	if err := n.startServer(ctx); err != nil {
		return err
	}
	if err := n.waitReady(ctx); err != nil {
		return err
	}
	return n.ensureDatabase(ctx)
}

// initdbIfNeeded creates the cluster the first time (PG_VERSION marks an
// initialized data dir). Uses trust auth — this is a local dev runtime; the
// connection password is still accepted (and ignored), matching the Docker path.
func (n *nixPostgres) initdbIfNeeded(ctx context.Context) error {
	if _, err := os.Stat(filepath.Join(n.dataDir, "PG_VERSION")); err == nil {
		return nil // already initialized
	}
	if err := os.MkdirAll(n.dataDir, 0o700); err != nil {
		return fmt.Errorf("create data dir: %w", err)
	}
	proc, err := n.env.NewProcess(filepath.Join(n.binDir, "initdb"),
		"-D", n.dataDir,
		"-U", n.user,
		"--auth=trust",
		"--no-locale",
		"-E", "UTF8",
	)
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

// startServer launches postgres listening on 127.0.0.1:port. Quietened to the
// configured log level when set (mirrors the Docker -c flags).
func (n *nixPostgres) startServer(ctx context.Context) error {
	args := []string{
		"-D", n.dataDir,
		"-p", fmt.Sprintf("%d", n.port),
		"-k", n.socketDir,
		"-c", "listen_addresses=127.0.0.1",
	}
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
	return nil
}

func (n *nixPostgres) adminDSN() string {
	return fmt.Sprintf("postgresql://%s:%s@127.0.0.1:%d/postgres?sslmode=disable",
		n.user, n.password, n.port)
}

// waitReady polls until the server accepts connections.
func (n *nixPostgres) waitReady(ctx context.Context) error {
	deadline := time.Now().Add(30 * time.Second)
	var lastErr error
	for time.Now().Before(deadline) {
		db, err := sql.Open("postgres", n.adminDSN())
		if err == nil {
			pingCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
			lastErr = db.PingContext(pingCtx)
			cancel()
			_ = db.Close()
			if lastErr == nil {
				return nil
			}
		} else {
			lastErr = err
		}
		time.Sleep(500 * time.Millisecond)
	}
	return fmt.Errorf("postgres did not become ready: %w", lastErr)
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
	if n.proc == nil {
		return nil
	}
	return n.proc.Stop(ctx)
}

// resolveBinDir locates the nix store bin dir that holds postgres 16's initdb,
// so every invocation uses that exact build. env.Init has already materialized
// (downloaded) the package, so it is present in the store. Using the absolute
// dir — rather than the bare command on PATH — guarantees initdb and postgres
// are the same version even when a different system postgres shadows PATH.
func (n *nixPostgres) resolveBinDir() error {
	matches, err := filepath.Glob("/nix/store/*-postgresql-16*/bin/initdb")
	if err != nil {
		return fmt.Errorf("glob nix postgres: %w", err)
	}
	for _, m := range matches {
		// Skip the lib-only output (no postgres binary alongside).
		if _, err := os.Stat(filepath.Join(filepath.Dir(m), "postgres")); err == nil {
			n.binDir = filepath.Dir(m)
			return nil
		}
	}
	return fmt.Errorf("no nix postgresql-16 with both initdb+postgres found in /nix/store (materialization may have failed)")
}

// pgQuoteIdent double-quotes a postgres identifier, escaping embedded quotes.
func pgQuoteIdent(name string) string {
	return `"` + strings.ReplaceAll(name, `"`, `""`) + `"`
}
