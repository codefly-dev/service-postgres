package main

// nixpg.go — the Docker-free postgres runtime: ONE server per run.
//
// The postgres service agent runs the database in a container by default
// (NewDockerHeadlessEnvironment). On the native runtime it runs postgres from a
// nix-provisioned binary instead: the codefly NixEnvironment materializes
// `postgresql_17` (with pgvector) from the embedded flake, so no system install
// is required.
//
// A composed run declares one Postgres service per database. A postmaster per
// service costs one System V shared-memory segment each (macOS allows 32 on the
// whole machine) and a cluster directory each, so a platform run exhausted the
// host. Every Postgres service of a run therefore shares ONE server, the way a
// deployed environment binds its databases to one instance: each service keeps
// its own database, its own migration owner and its own runtime logins, and
// none of them can connect to another's database.
//
// The run is the workspace and its naming scope, the identity Codefly already
// isolates concurrent runs by. Its server
//
//   - is started by whichever of the run's agents initializes first, detached
//     through pg_ctl so that no single agent's lifetime is the server's;
//   - listens on no TCP port at all: it is reached through a private Unix
//     socket, and each service's agent publishes the service's own allocated
//     port by forwarding it to that socket (forward.go), so every address and
//     connection string a consumer receives keeps its shape;
//   - is administered by a bootstrap superuser whose password lives only in an
//     owner-only file under the run's root; no service ever receives it;
//   - records each agent that uses it (holders/) and is stopped by the last one
//     to release it, which is what Stop, Destroy and an interrupted run's
//     orderly shutdown all do; and
//   - when every recorded holder is gone without releasing (the run was killed),
//     is stopped by the next agent that initializes on this machine.
//
// Stopping the server releases its shared memory and semaphores; the cluster
// directory is retained, exactly as a per-service cluster was (no operation of
// this agent deletes data, codefly-dev/core#424).

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	_ "embed"
	"encoding/hex"
	"encoding/json"
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

	runners "github.com/codefly-dev/core/runners/base"
	"github.com/gofrs/flock"
	"github.com/lib/pq"
)

//go:embed nix/flake.nix
var pgFlakeNix string

//go:embed nix/flake.lock
var pgFlakeLock string

const (
	// nativeMajor is the PostgreSQL major the embedded flake provisions. It is
	// part of a run server's identity: a cluster directory only opens under the
	// major that initialized it.
	nativeMajor = "17"

	// serverAdminRole is the run server's bootstrap superuser. Only the agents
	// of the run hold its password; it provisions each service's database and
	// owner, creates extensions and reconciles runtime grants.
	serverAdminRole = "codefly_admin"

	// serverSocketPort names the socket file (.s.PGSQL.<port>). The server
	// binds no TCP port, so nothing is allocated for it.
	serverSocketPort = 5432

	// serverMaxConnections is the run server's connection budget. Each service
	// used to have a server with PostgreSQL's default of 100 to itself; one
	// server now carries every service of the run.
	serverMaxConnections = 500

	// serverStartSeconds bounds pg_ctl's wait for a started server to accept
	// connections, and serverStopTimeout a fast shutdown.
	serverStartSeconds = 60
	serverStopTimeout  = 60 * time.Second

	// serverWatchInterval paces the supervision of the shared postmaster.
	serverWatchInterval = 2 * time.Second
)

// runServersDir is the machine directory holding every run server's root.
// Tests point it elsewhere.
var runServersDir = func() (string, error) {
	cache, err := os.UserCacheDir()
	if err != nil {
		cache = os.TempDir()
	}
	return filepath.Join(cache, "codefly", "postgres", "run"), nil
}

// runServerKey identifies a run's server: its workspace, its naming scope and
// the PostgreSQL major. The separators are unambiguous and the key is hashed
// before it names a directory.
func runServerKey(workspacePath, namingScope string) string {
	return workspacePath + "\x00naming-scope\x00" + namingScope + "\x00postgres\x00" + nativeMajor
}

// serviceHash is the hex sha256 of a key.
func serviceHash(key string) string {
	sum := sha256.Sum256([]byte(key))
	return hex.EncodeToString(sum[:])
}

// nixPostgres is one agent's attachment to its run's server: the server's
// location and administration, this agent's holder record, and the forwarder
// that publishes this service's endpoint on it.
type nixPostgres struct {
	root          string
	dataDir       string
	socketDir     string
	adminPassword string
	holder        string
	forwarder     *socketForwarder

	// serverCancel cancels serverCtx, which supervision watches: a postmaster
	// that disappears while this agent still holds the server is reported, one
	// that goes away after this agent released it is not.
	serverCtx    context.Context
	serverCancel context.CancelFunc
	// serverExit reports the shared postmaster's disappearance.
	serverExit <-chan error
}

// processMark is a process's identity as far as liveness goes: the PID plus
// the start facts that distinguish it from a later process reusing the number.
type processMark struct {
	PID     int    `json:"pid"`
	StartID uint64 `json:"start"`
	BootID  string `json:"boot"`
}

func markProcess(pid int) (processMark, error) {
	identity, err := runners.InspectProcess(pid)
	if err != nil {
		return processMark{}, err
	}
	return processMark{PID: pid, StartID: identity.StartID, BootID: identity.BootID}, nil
}

// alive reports whether the marked process still runs. An inspection that
// fails for any reason other than the process being gone counts as alive: a
// wrong "dead" stops a server a live run is using.
func (m processMark) alive() bool {
	identity, err := runners.InspectProcess(m.PID)
	if err != nil {
		return !errors.Is(err, runners.ErrProcessNotFound)
	}
	return identity.StartID == m.StartID && identity.BootID == m.BootID
}

// serverHolder records one agent using a run server: the agent and the
// codefly run that launched it. An agent whose run is gone is orphaned, and
// its run's server is no longer anybody's.
type serverHolder struct {
	Service string       `json:"service"`
	Agent   processMark  `json:"agent"`
	Run     *processMark `json:"run,omitempty"`
}

func (h serverHolder) alive() bool {
	if !h.Agent.alive() {
		return false
	}
	return h.Run == nil || h.Run.alive()
}

// acquireRunServer attaches this agent to its run's server, starting the
// server when no live one exists, and records this agent as a holder.
func acquireRunServer(ctx context.Context, key, service, logLevel string, out io.Writer) (_ *nixPostgres, acquireErr error) {
	servers, err := runServersDir()
	if err != nil {
		return nil, err
	}
	root := filepath.Join(servers, serviceHash(key)[:16])
	if err := os.MkdirAll(filepath.Join(root, "holders"), 0o700); err != nil {
		return nil, fmt.Errorf("create run server directory: %w", err)
	}
	collectAbandonedServers(ctx, servers, root)

	unlock, err := lockRunServer(ctx, root)
	if err != nil {
		return nil, err
	}
	defer unlock()

	n := &nixPostgres{root: root, dataDir: filepath.Join(root, "pgdata")}
	live, err := pruneHolders(root)
	if err != nil {
		return nil, err
	}
	pid, socketDir, running := runningPostmaster(n.dataDir)
	if !running {
		// A server this call starts and then cannot hand out is nobody's: stop
		// it rather than leave it for the next run's collection.
		defer func() {
			if acquireErr != nil && live == 0 {
				_, _ = stopServer(n.dataDir)
			}
		}()
		if err := n.start(ctx, logLevel, out); err != nil {
			return nil, err
		}
		if pid, socketDir, running = runningPostmaster(n.dataDir); !running {
			return nil, fmt.Errorf("postgres reported started but %s names no live postmaster; see %s",
				filepath.Join(n.dataDir, "postmaster.pid"), n.logPath())
		}
	}
	n.socketDir = socketDir
	if n.adminPassword, err = n.readAdminPassword(); err != nil {
		return nil, err
	}
	postmaster, err := markProcess(pid)
	if err != nil {
		return nil, fmt.Errorf("inspect the run's postmaster (pid %d): %w", pid, err)
	}
	if err := n.ping(ctx); err != nil {
		return nil, fmt.Errorf("the run's postgres server (pid %d) does not answer on %s: %w; see %s",
			pid, n.socketDir, err, n.logPath())
	}
	if err := n.register(service); err != nil {
		return nil, err
	}
	n.watch(postmaster)
	return n, nil
}

// lockRunServer serializes every start, attach, release and collection of one
// run server across the run's agent processes.
func lockRunServer(ctx context.Context, root string) (func(), error) {
	lock := flock.New(filepath.Join(root, "lock"))
	locked, err := lock.TryLockContext(ctx, 100*time.Millisecond)
	if err != nil {
		return nil, fmt.Errorf("lock the run's postgres server: %w", err)
	}
	if !locked {
		return nil, fmt.Errorf("lock the run's postgres server: not acquired")
	}
	return func() { _ = lock.Unlock() }, nil
}

func (n *nixPostgres) logPath() string { return filepath.Join(n.root, "server.log") }

// start initializes the cluster on first use and launches it detached. The
// caller holds the run server's lock.
func (n *nixPostgres) start(ctx context.Context, logLevel string, out io.Writer) error {
	flakeDir := filepath.Join(n.root, "nix")
	if err := os.MkdirAll(flakeDir, 0o700); err != nil {
		return fmt.Errorf("create nix flake dir: %w", err)
	}
	if err := os.WriteFile(filepath.Join(flakeDir, "flake.nix"), []byte(pgFlakeNix), 0o644); err != nil {
		return fmt.Errorf("write flake.nix: %w", err)
	}
	if err := os.WriteFile(filepath.Join(flakeDir, "flake.lock"), []byte(pgFlakeLock), 0o644); err != nil {
		return fmt.Errorf("write flake.lock: %w", err)
	}
	env, err := runners.NewNixEnvironment(ctx, flakeDir)
	if err != nil {
		return fmt.Errorf("nix environment (is nix installed?): %w", err)
	}
	env.WithCacheDir(filepath.Join(n.root, ".nix-cache"))
	if err := env.Init(ctx); err != nil {
		return fmt.Errorf("materialize nix postgres env: %w", err)
	}
	binDir, err := resolveBinDir()
	if err != nil {
		return err
	}
	if err := n.initdbIfNeeded(ctx, env, binDir, out); err != nil {
		return err
	}
	if err := n.clearStalePostmasterPid(); err != nil {
		return err
	}
	// The socket path is limited to ~104 bytes, so it cannot live under a deep
	// cache path. An unpredictable, owner-only temporary directory: a stable
	// name can be pre-created or symlinked by another local user.
	socketDir, err := os.MkdirTemp("", "cfpg-"+filepath.Base(n.root)[:8]+"-")
	if err != nil {
		return fmt.Errorf("create postgres socket dir: %w", err)
	}
	if err := os.Chmod(socketDir, 0o700); err != nil {
		_ = os.RemoveAll(socketDir)
		return fmt.Errorf("secure postgres socket dir: %w", err)
	}
	options, err := serverOptions(socketDir, logLevel)
	if err != nil {
		_ = os.RemoveAll(socketDir)
		return err
	}
	// pg_ctl detaches the postmaster into its own session and waits until it
	// accepts connections; the server outlives the agent that started it.
	proc, err := env.NewProcess(filepath.Join(binDir, "pg_ctl"),
		"start", "-D", n.dataDir, "-w", "-t", strconv.Itoa(serverStartSeconds), "-l", n.logPath(), "-o", options)
	if err != nil {
		_ = os.RemoveAll(socketDir)
		return err
	}
	if out != nil {
		proc.WithOutput(out)
	}
	if err := proc.Run(ctx); err != nil {
		_ = os.RemoveAll(socketDir)
		return fmt.Errorf("start the run's postgres server: %w%s", err, n.logTail())
	}
	return n.restrictMaintenanceDatabases(ctx, socketDir)
}

// serverOptions are the postmaster's options, passed through pg_ctl's shell.
// No TCP listener; the private socket directory; the run-wide connection
// budget; and the starting service's quietening when it configured one.
func serverOptions(socketDir, logLevel string) (string, error) {
	if strings.ContainsAny(socketDir, " \t\n'\"\\$`") {
		return "", fmt.Errorf("postgres socket dir %q cannot be passed to pg_ctl", socketDir)
	}
	options := []string{
		"-c listen_addresses=''",
		"-k " + socketDir,
		"-p " + strconv.Itoa(serverSocketPort),
		"-c max_connections=" + strconv.Itoa(serverMaxConnections),
	}
	if lvl := strings.ToLower(strings.TrimSpace(logLevel)); lvl != "" {
		for _, r := range lvl {
			if (r < 'a' || r > 'z') && (r < '0' || r > '9') {
				return "", fmt.Errorf("log-level %q is not a postgres log level", logLevel)
			}
		}
		options = append(options,
			"-c log_min_messages="+lvl,
			"-c log_statement=none",
			"-c log_connections=off",
			"-c log_disconnections=off",
		)
	}
	return strings.Join(options, " "), nil
}

// logTail is the end of the server log, for a refusal that has to say why.
func (n *nixPostgres) logTail() string {
	data, err := os.ReadFile(n.logPath())
	if err != nil || len(data) == 0 {
		return ""
	}
	lines := strings.Split(strings.TrimRight(string(data), "\n"), "\n")
	if len(lines) > 20 {
		lines = lines[len(lines)-20:]
	}
	return "\nserver log (" + n.logPath() + "):\n" + strings.Join(lines, "\n")
}

// restrictMaintenanceDatabases closes the maintenance and template databases
// to every role but the administrator, so a service's logins reach only the
// database granted to them.
func (n *nixPostgres) restrictMaintenanceDatabases(ctx context.Context, socketDir string) error {
	n.socketDir = socketDir
	password, err := n.readAdminPassword()
	if err != nil {
		return err
	}
	n.adminPassword = password
	db, err := sql.Open("postgres", n.adminDSN("postgres"))
	if err != nil {
		return err
	}
	defer db.Close()
	for _, statement := range []string{
		`REVOKE ALL ON DATABASE postgres FROM PUBLIC`,
		`REVOKE ALL ON DATABASE template1 FROM PUBLIC`,
	} {
		if _, err := db.ExecContext(ctx, statement); err != nil {
			return fmt.Errorf("restrict the run server's maintenance databases: %w", err)
		}
	}
	return nil
}

// runningPostmaster reads the cluster's postmaster.pid: the live postmaster's
// PID and the socket directory it listens in.
func runningPostmaster(dataDir string) (int, string, bool) {
	file, err := os.Open(filepath.Join(dataDir, "postmaster.pid"))
	if err != nil {
		return 0, "", false
	}
	defer file.Close()
	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() && len(lines) < 5 {
		lines = append(lines, strings.TrimSpace(scanner.Text()))
	}
	if len(lines) < 5 {
		return 0, "", false
	}
	pid, err := strconv.Atoi(lines[0])
	if err != nil || pid <= 0 || !processAlive(pid) {
		return 0, "", false
	}
	return pid, lines[4], lines[4] != ""
}

// clearStalePostmasterPid removes a leftover postmaster.pid when no live
// postmaster owns it. A crashed or SIGKILL'd server leaves a pid file that
// aborts the next boot (`FATAL: lock file "postmaster.pid" is empty` / "is the
// remnant of a previous server startup crash"). A pid file owned by a LIVE
// process is left untouched so a concurrent postmaster is never stomped.
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
// initialized data dir), with a freshly generated administrator password.
// Both local and TCP connections require SCRAM; the password reaches initdb
// through an owner-only file, never argv or the environment.
func (n *nixPostgres) initdbIfNeeded(ctx context.Context, env *runners.NixEnvironment, binDir string, out io.Writer) error {
	if _, err := os.Stat(filepath.Join(n.dataDir, "PG_VERSION")); err == nil {
		return nil
	}
	if err := os.RemoveAll(n.dataDir); err != nil {
		return fmt.Errorf("clear an uninitialized data dir: %w", err)
	}
	if err := os.MkdirAll(n.dataDir, 0o700); err != nil {
		return fmt.Errorf("create data dir: %w", err)
	}
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return fmt.Errorf("generate the run server's administrator password: %w", err)
	}
	if err := writeOwnerOnly(n.adminPasswordPath(), hex.EncodeToString(secret)+"\n"); err != nil {
		return fmt.Errorf("write the run server's administrator password: %w", err)
	}
	proc, err := env.NewProcess(filepath.Join(binDir, "initdb"), n.initdbArgs(n.adminPasswordPath())...)
	if err != nil {
		return err
	}
	if out != nil {
		proc.WithOutput(out)
	}
	if err := proc.Run(ctx); err != nil {
		return fmt.Errorf("initdb: %w", err)
	}
	return nil
}

func (n *nixPostgres) initdbArgs(passwordFile string) []string {
	return []string{
		"-D", n.dataDir,
		"-U", serverAdminRole,
		"--auth-local=scram-sha-256",
		"--auth-host=scram-sha-256",
		"--pwfile=" + passwordFile,
		"--no-locale",
		"-E", "UTF8",
	}
}

func (n *nixPostgres) adminPasswordPath() string { return filepath.Join(n.root, "admin.password") }

func (n *nixPostgres) readAdminPassword() (string, error) {
	data, err := os.ReadFile(n.adminPasswordPath())
	if err != nil {
		return "", fmt.Errorf("read the run server's administrator password (remove %s to start this run's databases over): %w", n.root, err)
	}
	password := strings.TrimSpace(string(data))
	if password == "" {
		return "", fmt.Errorf("the run server's administrator password at %s is empty", n.adminPasswordPath())
	}
	return password, nil
}

func writeOwnerOnly(path, content string) error {
	temporary, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+"-*")
	if err != nil {
		return err
	}
	name := temporary.Name()
	defer os.Remove(name)
	if err := temporary.Chmod(0o600); err != nil {
		_ = temporary.Close()
		return err
	}
	if _, err := io.WriteString(temporary, content); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	return os.Rename(name, path)
}

// adminDSN reaches one database of the run's server as its administrator,
// through the private socket. Bootstrap work never uses a public TCP mapping:
// another process can own that port, and accepting its successful ping would
// authenticate, migrate and report readiness for the wrong database.
func (n *nixPostgres) adminDSN(database string) string {
	u := &url.URL{
		Scheme: "postgresql",
		User:   url.UserPassword(serverAdminRole, n.adminPassword),
		Path:   "/" + database,
	}
	query := u.Query()
	query.Set("host", n.socketDir)
	query.Set("port", strconv.Itoa(serverSocketPort))
	query.Set("sslmode", "disable")
	u.RawQuery = query.Encode()
	return u.String()
}

func (n *nixPostgres) socketPath() string {
	return filepath.Join(n.socketDir, ".s.PGSQL."+strconv.Itoa(serverSocketPort))
}

func (n *nixPostgres) ping(ctx context.Context) error {
	db, err := sql.Open("postgres", n.adminDSN("postgres"))
	if err != nil {
		return err
	}
	defer db.Close()
	pingCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	return db.PingContext(pingCtx)
}

// provisionDatabase gives one service its database on the run's server: the
// database, owned by the service's own migration owner, closed to every other
// role. The owner may create roles (its migrations create the application's
// NOLOGIN roles) and databases (the migration test control plane creates
// isolated ones it owns), but it is not a superuser: it cannot connect to
// another service's database, copy it, or alter another service's roles. A
// database another service of the run already claimed is refused by name.
func (n *nixPostgres) provisionDatabase(ctx context.Context, service, database, owner, password string) error {
	db, err := sql.Open("postgres", n.adminDSN("postgres"))
	if err != nil {
		return err
	}
	defer db.Close()

	var exists bool
	if err := db.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = $1)`, owner).Scan(&exists); err != nil {
		return fmt.Errorf("look up the migration owner: %w", err)
	}
	quotedOwner := pq.QuoteIdentifier(owner)
	if !exists {
		if _, err := db.ExecContext(ctx, `CREATE ROLE `+quotedOwner); err != nil {
			return fmt.Errorf("create the migration owner: %w", err)
		}
	}
	if _, err := db.ExecContext(ctx, `ALTER ROLE `+quotedOwner+
		` WITH LOGIN NOSUPERUSER CREATEROLE CREATEDB NOREPLICATION NOBYPASSRLS PASSWORD `+pq.QuoteLiteral(password)); err != nil {
		return fmt.Errorf("configure the migration owner: %w", err)
	}

	marker := databaseClaim(service)
	var claim sql.NullString
	err = db.QueryRowContext(ctx,
		`SELECT shobj_description(oid, 'pg_database') FROM pg_database WHERE datname = $1`, database).Scan(&claim)
	quotedDatabase := pq.QuoteIdentifier(database)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		if _, err := db.ExecContext(ctx, `CREATE DATABASE `+quotedDatabase+` OWNER `+quotedOwner); err != nil {
			return fmt.Errorf("create database %q: %w", database, err)
		}
		if _, err := db.ExecContext(ctx, `COMMENT ON DATABASE `+quotedDatabase+` IS `+pq.QuoteLiteral(marker)); err != nil {
			return fmt.Errorf("record database %q's service: %w", database, err)
		}
	case err != nil:
		return fmt.Errorf("look up database %q: %w", database, err)
	case claim.String != marker:
		return fmt.Errorf("database %q on this run's postgres server belongs to %s, not %s: give each service of a run its own database-name",
			database, strings.TrimPrefix(claim.String, databaseClaimPrefix), service)
	}
	for _, statement := range []string{
		`ALTER DATABASE ` + quotedDatabase + ` OWNER TO ` + quotedOwner,
		`REVOKE ALL ON DATABASE ` + quotedDatabase + ` FROM PUBLIC`,
	} {
		if _, err := db.ExecContext(ctx, statement); err != nil {
			return fmt.Errorf("restrict database %q to its service: %w", database, err)
		}
	}
	return nil
}

const databaseClaimPrefix = "codefly service "

func databaseClaim(service string) string { return databaseClaimPrefix + service }

// register records this agent, and the run that launched it, as a holder.
func (n *nixPostgres) register(service string) error {
	agent, err := markProcess(os.Getpid())
	if err != nil {
		return fmt.Errorf("inspect this agent: %w", err)
	}
	holder := serverHolder{Service: service, Agent: agent}
	if parent := os.Getppid(); parent > 1 {
		if run, err := markProcess(parent); err == nil {
			holder.Run = &run
		}
	}
	data, err := json.Marshal(holder)
	if err != nil {
		return err
	}
	n.holder = filepath.Join(n.root, "holders", serviceHash(service)[:16]+".json")
	return writeOwnerOnly(n.holder, string(data))
}

// pruneHolders removes the records of agents that are gone and returns how
// many live ones remain. The caller holds the run server's lock.
func pruneHolders(root string) (int, error) {
	dir := filepath.Join(root, "holders")
	entries, err := os.ReadDir(dir)
	if errors.Is(err, os.ErrNotExist) {
		return 0, nil
	}
	if err != nil {
		return 0, fmt.Errorf("read the run server's holders: %w", err)
	}
	live := 0
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		path := filepath.Join(dir, entry.Name())
		data, err := os.ReadFile(path)
		var holder serverHolder
		if err == nil && json.Unmarshal(data, &holder) == nil && holder.alive() {
			live++
			continue
		}
		_ = os.Remove(path)
	}
	return live, nil
}

// watch supervises the shared postmaster for as long as this agent holds it.
func (n *nixPostgres) watch(postmaster processMark) {
	n.serverCtx, n.serverCancel = context.WithCancel(context.Background())
	exit := make(chan error, 1)
	n.serverExit = exit
	go func(ctx context.Context) {
		ticker := time.NewTicker(serverWatchInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if !postmaster.alive() {
					exit <- fmt.Errorf("the run's postgres server (pid %d) is gone; see %s", postmaster.PID, n.logPath())
					close(exit)
					return
				}
			}
		}
	}(n.serverCtx)
}

// Supervise invokes onExit exactly once if the run's postmaster terminates
// while this agent still holds it. Without it the server can disappear mid-run
// (a crash, an external signal) while the agent keeps reporting STARTED,
// leaving codefly's Follow loop blind and every dependent wedged on connection
// refused (codefly-dev/cli#380).
//
// Call it once, after a successful Init/Start.
func (n *nixPostgres) Supervise(onExit func(error)) {
	exit := n.serverExit
	if exit == nil {
		return
	}
	// release cancels serverCtx before the server can stop, so a cancelled
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

// release closes this service's endpoint and removes this agent's holder
// record; the last holder stops the server. It reports whether it did.
func (n *nixPostgres) release(ctx context.Context) (bool, error) {
	if n.serverCancel != nil {
		n.serverCancel()
	}
	var forwardErr error
	if n.forwarder != nil {
		forwardErr = n.forwarder.Close()
		n.forwarder = nil
	}
	if n.root == "" {
		return false, forwardErr
	}
	unlock, err := lockRunServer(ctx, n.root)
	if err != nil {
		return false, errors.Join(forwardErr, err)
	}
	defer unlock()
	if n.holder != "" {
		if err := os.Remove(n.holder); err != nil && !errors.Is(err, os.ErrNotExist) {
			return false, errors.Join(forwardErr, err)
		}
		n.holder = ""
	}
	live, err := pruneHolders(n.root)
	if err != nil || live > 0 {
		return false, errors.Join(forwardErr, err)
	}
	stopped, err := stopServer(n.dataDir)
	return stopped, errors.Join(forwardErr, err)
}

// stopServer shuts the cluster's postmaster down (fast shutdown: sessions are
// disconnected, the server exits cleanly and removes its shared memory) and
// removes its socket directory. It reports whether a server was running.
func stopServer(dataDir string) (bool, error) {
	pid, socketDir, running := runningPostmaster(dataDir)
	if !running {
		return false, nil
	}
	process, err := os.FindProcess(pid)
	if err != nil {
		return false, err
	}
	if err := process.Signal(syscall.SIGINT); err != nil && processAlive(pid) {
		return false, fmt.Errorf("stop the run's postgres server (pid %d): %w", pid, err)
	}
	if !waitGone(pid, serverStopTimeout) {
		// Immediate shutdown: the server still releases its shared memory.
		_ = process.Signal(syscall.SIGQUIT)
		if !waitGone(pid, 10*time.Second) {
			return false, fmt.Errorf("the run's postgres server (pid %d) did not stop", pid)
		}
	}
	if strings.HasPrefix(filepath.Base(socketDir), "cfpg-") {
		_ = os.RemoveAll(socketDir)
	}
	return true, nil
}

func waitGone(pid int, budget time.Duration) bool {
	deadline := time.Now().Add(budget)
	for time.Now().Before(deadline) {
		if !processAlive(pid) {
			return true
		}
		time.Sleep(100 * time.Millisecond)
	}
	return !processAlive(pid)
}

// collectAbandonedServers stops every other run server on this machine whose
// holders are all gone: a run that was killed rather than stopped. A server
// whose lock is taken is being started, attached or released right now, and is
// left alone.
func collectAbandonedServers(ctx context.Context, servers, self string) {
	entries, err := os.ReadDir(servers)
	if err != nil {
		return
	}
	for _, entry := range entries {
		root := filepath.Join(servers, entry.Name())
		if !entry.IsDir() || root == self || ctx.Err() != nil {
			continue
		}
		lock := flock.New(filepath.Join(root, "lock"))
		locked, err := lock.TryLock()
		if err != nil || !locked {
			continue
		}
		if live, err := pruneHolders(root); err == nil && live == 0 {
			_, _ = stopServer(filepath.Join(root, "pgdata"))
		}
		_ = lock.Unlock()
	}
}

// resolveBinDir locates the nix store bin dir that holds postgres 17's initdb,
// pg_ctl and postgres, so every invocation uses that exact build. The package
// is materialized by then. Using the absolute dir — rather than the bare
// command on PATH — guarantees one version even when a different system
// postgres shadows PATH.
func resolveBinDir() (string, error) {
	// Broad glob: match BOTH the plain `postgresql-17*` build AND the
	// `withPackages` wrapper (`postgresql-and-plugins-17…`) that bundles
	// pgvector, whose name has no "postgresql-17" substring.
	matches, err := filepath.Glob("/nix/store/*postgresql*" + nativeMajor + "*/bin/initdb")
	if err != nil {
		return "", fmt.Errorf("glob nix postgres: %w", err)
	}
	var fallback string
	for _, m := range matches {
		binDir := filepath.Dir(m)
		// Must have the server and its control binary alongside initdb (skip
		// lib/man/doc-only outputs).
		if !hasFiles(binDir, "postgres", "pg_ctl") {
			continue
		}
		// PREFER a build whose extension dir ships pgvector — the withPackages
		// wrapper the flake builds. A plain build would make CREATE EXTENSION
		// vector fail mid-migration.
		vectorControl := filepath.Join(filepath.Dir(binDir), "share", "postgresql", "extension", "vector.control")
		if _, err := os.Stat(vectorControl); err == nil {
			return binDir, nil
		}
		if fallback == "" {
			fallback = binDir
		}
	}
	if fallback != "" {
		// No pgvector-enabled build found — use a plain one so non-vector
		// schemas still work; CREATE EXTENSION vector will then fail loudly.
		return fallback, nil
	}
	return "", fmt.Errorf("no nix postgresql-%s with initdb, pg_ctl and postgres found in /nix/store (materialization may have failed)", nativeMajor)
}

func hasFiles(dir string, names ...string) bool {
	for _, name := range names {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			return false
		}
	}
	return true
}
