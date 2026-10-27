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

// confirmed is alive's opposite default, and it is the only question a signal
// may be sent on. A PID says nothing on its own: the number is reused, so a
// process that merely answers to it can be anything this user happens to be
// running. An inspection that does not positively re-establish the recorded
// birth therefore means "do not signal", where alive means "keep holding".
func (m processMark) confirmed() bool {
	identity, err := runners.InspectProcess(m.PID)
	return err == nil && identity.StartID == m.StartID && identity.BootID == m.BootID
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
	record, running, err := attachedPostmaster(n.root, n.dataDir)
	if err != nil {
		return nil, err
	}
	if !running {
		// A server this call starts and then cannot hand out is nobody's: stop
		// it rather than leave it for the next run's collection.
		defer func() {
			if acquireErr != nil && live == 0 {
				_, _ = stopServer(n.root, n.dataDir)
			}
		}()
		if record, err = n.start(ctx, logLevel, out); err != nil {
			return nil, err
		}
	}
	n.socketDir = record.SocketDir
	if n.adminPassword, err = n.readAdminPassword(); err != nil {
		return nil, err
	}
	if err := n.ping(ctx); err != nil {
		return nil, fmt.Errorf("the run's postgres server (pid %d) does not answer on %s: %w; see %s",
			record.Postmaster.PID, n.socketDir, err, n.logPath())
	}
	if err := n.register(service); err != nil {
		return nil, err
	}
	n.watch(record.Postmaster)
	return n, nil
}

// lockRunServer serializes every start, attach, release and collection of one
// run server across the run's agent processes, including database provisioning.
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

// start initializes the cluster on first use, launches it detached, and
// records the postmaster it started. The caller holds the run server's lock.
func (n *nixPostgres) start(ctx context.Context, logLevel string, out io.Writer) (postmasterRecord, error) {
	flakeDir := filepath.Join(n.root, "nix")
	if err := os.MkdirAll(flakeDir, 0o700); err != nil {
		return postmasterRecord{}, fmt.Errorf("create nix flake dir: %w", err)
	}
	if err := os.WriteFile(filepath.Join(flakeDir, "flake.nix"), []byte(pgFlakeNix), 0o644); err != nil {
		return postmasterRecord{}, fmt.Errorf("write flake.nix: %w", err)
	}
	if err := os.WriteFile(filepath.Join(flakeDir, "flake.lock"), []byte(pgFlakeLock), 0o644); err != nil {
		return postmasterRecord{}, fmt.Errorf("write flake.lock: %w", err)
	}
	env, err := runners.NewNixEnvironment(ctx, flakeDir)
	if err != nil {
		return postmasterRecord{}, fmt.Errorf("nix environment (is nix installed?): %w", err)
	}
	env.WithCacheDir(filepath.Join(n.root, ".nix-cache"))
	if err := env.Init(ctx); err != nil {
		return postmasterRecord{}, fmt.Errorf("materialize nix postgres env: %w", err)
	}
	binDir, err := resolveBinDir()
	if err != nil {
		return postmasterRecord{}, err
	}
	if err := n.initdbIfNeeded(ctx, env, binDir, out); err != nil {
		return postmasterRecord{}, err
	}
	// The socket path is limited to ~104 bytes, so it cannot live under a deep
	// cache path. An unpredictable, owner-only temporary directory: a stable
	// name can be pre-created or symlinked by another local user.
	socketDir, err := os.MkdirTemp("", "cfpg-"+filepath.Base(n.root)[:8]+"-")
	if err != nil {
		return postmasterRecord{}, fmt.Errorf("create postgres socket dir: %w", err)
	}
	if err := os.Chmod(socketDir, 0o700); err != nil {
		_ = os.RemoveAll(socketDir)
		return postmasterRecord{}, fmt.Errorf("secure postgres socket dir: %w", err)
	}
	options, err := serverOptions(socketDir, logLevel)
	if err != nil {
		_ = os.RemoveAll(socketDir)
		return postmasterRecord{}, err
	}
	// pg_ctl detaches the postmaster into its own session and waits until it
	// accepts connections; the server outlives the agent that started it.
	proc, err := env.NewProcess(filepath.Join(binDir, "pg_ctl"),
		"start", "-D", n.dataDir, "-w", "-t", strconv.Itoa(serverStartSeconds), "-l", n.logPath(), "-o", options)
	if err != nil {
		_ = os.RemoveAll(socketDir)
		return postmasterRecord{}, err
	}
	if out != nil {
		proc.WithOutput(out)
	}
	if err := proc.Run(ctx); err != nil {
		_ = os.RemoveAll(socketDir)
		return postmasterRecord{}, fmt.Errorf("start the run's postgres server: %w%s", err, n.logTail())
	}
	// The one moment postmaster.pid is authoritative: pg_ctl -w has just
	// reported the server it started is accepting connections, this call holds
	// the run lock, and any pid file that was not this postmaster's was
	// already cleared. Its birth is recorded here so that every later decision
	// — attach, release, collection — rests on the identity rather than on the
	// number in a file that outlives the process.
	pid, ok := postmasterPidFileOwner(filepath.Join(n.dataDir, "postmaster.pid"))
	if !ok {
		return postmasterRecord{}, fmt.Errorf("postgres reported started but %s names no live postmaster; see %s",
			filepath.Join(n.dataDir, "postmaster.pid"), n.logPath())
	}
	postmaster, err := markProcess(pid)
	if err != nil {
		return postmasterRecord{}, fmt.Errorf("inspect the run's postmaster (pid %d): %w", pid, err)
	}
	record := postmasterRecord{Postmaster: postmaster, SocketDir: socketDir}
	if err := writePostmasterRecord(n.root, record); err != nil {
		return postmasterRecord{}, fmt.Errorf("record the run's postmaster: %w", err)
	}
	if err := n.restrictMaintenanceDatabases(ctx, socketDir); err != nil {
		return postmasterRecord{}, err
	}
	return record, nil
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

// postmasterRecord is what the run knows about its own server: the birth of
// the postmaster it started, and where that postmaster listens. It is written
// when the server starts, under the run's own 0700 root.
//
// The record — never postmaster.pid — is what authorizes a signal. A pid file
// outlives the process that wrote it (SIGKILL, OOM, a machine that lost
// power), PIDs are reused, and this agent collects the servers of OTHER runs
// on every native start. Trusting the number in that file would make an
// unrelated process of this user, which merely inherited the number, the
// target of the collection.
type postmasterRecord struct {
	Postmaster processMark `json:"postmaster"`
	SocketDir  string      `json:"socket"`
}

func postmasterRecordPath(root string) string { return filepath.Join(root, "postmaster.json") }

// readPostmasterRecord returns the recorded postmaster, if one was recorded.
// An unreadable or unparseable record is no record: nothing may be signalled
// on it, and the cluster is treated as having no server of ours.
func readPostmasterRecord(root string) (postmasterRecord, bool) {
	data, err := os.ReadFile(postmasterRecordPath(root))
	if err != nil {
		return postmasterRecord{}, false
	}
	var record postmasterRecord
	if err := json.Unmarshal(data, &record); err != nil || record.Postmaster.PID <= 0 {
		return postmasterRecord{}, false
	}
	return record, true
}

func writePostmasterRecord(root string, record postmasterRecord) error {
	data, err := json.Marshal(record)
	if err != nil {
		return err
	}
	return writeOwnerOnly(postmasterRecordPath(root), string(data))
}

// attachedPostmaster returns the run's live server, when there is one this
// run recorded and that is still the same process. Otherwise it reports no
// server, having first made sure the cluster can actually be started: see
// clearDisownedPostmasterPid.
func attachedPostmaster(root, dataDir string) (postmasterRecord, bool, error) {
	record, recorded := readPostmasterRecord(root)
	if recorded && record.Postmaster.alive() && record.SocketDir != "" {
		return record, true, nil
	}
	if err := clearDisownedPostmasterPid(dataDir, record, recorded); err != nil {
		return postmasterRecord{}, false, err
	}
	return postmasterRecord{}, false, nil
}

// clearDisownedPostmasterPid removes a postmaster.pid this run's server no
// longer owns, and refuses when it cannot prove that.
//
// A crashed or SIGKILL'd server leaves a pid file that aborts the next boot
// (`FATAL: lock file "postmaster.pid" is empty` / "is the remnant of a
// previous server startup crash"), so a stale one has to go. But a pid file
// whose PID is alive is two completely different situations:
//
//   - the number was reused by an unrelated process of this user. The file is
//     stale, and leaving it would wedge every later start of this run behind a
//     process that has nothing to do with postgres.
//   - a postmaster really does hold this cluster. Removing its lock file would
//     let a second postmaster start on the same data directory, which is how a
//     cluster is corrupted. It is refused, by name, rather than worked around.
//
// The two are told apart by inspecting the process, never by signalling it.
func clearDisownedPostmasterPid(dataDir string, record postmasterRecord, recorded bool) error {
	pidPath := filepath.Join(dataDir, "postmaster.pid")
	pid, ok := postmasterPidFileOwner(pidPath)
	if !ok {
		// Absent, unreadable, corrupt, or naming a process that is gone.
		if err := os.Remove(pidPath); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("remove the stale postgres lock file %s: %w", pidPath, err)
		}
		return nil
	}
	identity, err := runners.InspectProcess(pid)
	if err != nil {
		if errors.Is(err, runners.ErrProcessNotFound) {
			return os.Remove(pidPath)
		}
		return fmt.Errorf("inspect the process holding %s (pid %d): %w", pidPath, pid, err)
	}
	if isPostmasterExecutable(identity.Executable) {
		if recorded {
			return fmt.Errorf("the postgres server at %s is held by pid %d, which is not the postmaster this run started (pid %d): stop it before running again",
				dataDir, pid, record.Postmaster.PID)
		}
		return fmt.Errorf("the postgres server at %s is held by pid %d, which this run did not start: stop it before running again",
			dataDir, pid)
	}
	// Provably not a postmaster, so the number was reused and the file is a
	// leftover. Nothing is signalled: the lock file is simply dropped.
	return os.Remove(pidPath)
}

// postmasterPidFileOwner reads line 1 of a postmaster.pid and reports the PID
// when the file names a live process. Everything else — absent, unreadable,
// empty, corrupt, a process that is gone — reads as no owner.
func postmasterPidFileOwner(pidPath string) (int, bool) {
	data, err := os.ReadFile(pidPath)
	if err != nil {
		return 0, false
	}
	fields := strings.Fields(string(data))
	if len(fields) == 0 {
		return 0, false
	}
	pid, err := strconv.Atoi(fields[0])
	if err != nil || pid <= 0 || !processAlive(pid) {
		return 0, false
	}
	return pid, true
}

// isPostmasterExecutable reports whether an inspected process is a postgres
// server. core reports the executable's base name, and both the nix build and
// the historical name are accepted.
func isPostmasterExecutable(executable string) bool {
	return executable == "postgres" || executable == "postmaster"
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
	unlock, err := lockRunServer(ctx, n.root)
	if err != nil {
		return err
	}
	defer unlock()

	db, err := sql.Open("postgres", n.adminDSN("postgres"))
	if err != nil {
		return err
	}
	defer db.Close()

	// The database records the service it belongs to, and that record is a
	// comment any role with CREATEDB could have written on a database of its
	// own. Its current owner is the half that cannot be forged: a service
	// creating a database owns it, and it cannot hand ownership to an owner
	// role it is not a member of — which the membership check above is what
	// keeps true. A database owned by this service's own owner with no comment
	// yet is the one legitimate gap, between CREATE DATABASE and COMMENT, and
	// the comment is simply written.
	marker := databaseClaim(service)
	var claim sql.NullString
	var currentOwner string
	err = db.QueryRowContext(ctx,
		`SELECT shobj_description(oid, 'pg_database'), pg_get_userbyid(datdba) FROM pg_database WHERE datname = $1`,
		database).Scan(&claim, &currentOwner)
	createDatabase := errors.Is(err, sql.ErrNoRows)
	switch {
	case err != nil && !createDatabase:
		return fmt.Errorf("look up database %q: %w", database, err)
	case !createDatabase && currentOwner != owner:
		return fmt.Errorf("database %q on this run's postgres server is owned by %q, not by %s's migration owner: give each service of a run its own database-name",
			database, currentOwner, service)
	case !createDatabase && claim.Valid && claim.String != marker:
		return fmt.Errorf("database %q on this run's postgres server belongs to %s, not %s: give each service of a run its own database-name",
			database, strings.TrimPrefix(claim.String, databaseClaimPrefix), service)
	}

	// A migration owner may create roles, because its migrations create the
	// application's own NOLOGIN roles. On PostgreSQL 16 and later a role
	// created that way is granted back to its creator WITH ADMIN OPTION, so a
	// service that creates a role named after ANOTHER service's database —
	// before that service first runs — would be adopted here as that
	// database's owner and keep the admin grant, which is enough to take the
	// role and read the data. An owner role is this server's to create: one
	// that already carries a membership was not created by this agent.
	var exists, granted bool
	if err := db.QueryRowContext(ctx, `
		SELECT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = $1),
		       EXISTS (SELECT 1 FROM pg_auth_members m
		               JOIN pg_roles r ON r.oid = m.roleid
		               WHERE r.rolname = $1)`, owner).Scan(&exists, &granted); err != nil {
		return fmt.Errorf("look up the migration owner: %w", err)
	}
	if granted {
		return fmt.Errorf("migration owner %q on this run's postgres server is granted to another role, so it was not created for %s: remove it, or give this service its own database-name",
			owner, service)
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

	quotedDatabase := pq.QuoteIdentifier(database)
	if createDatabase {
		if _, err := db.ExecContext(ctx, `CREATE DATABASE `+quotedDatabase+` OWNER `+quotedOwner); err != nil {
			return fmt.Errorf("create database %q: %w", database, err)
		}
	}
	if !claim.Valid {
		if _, err := db.ExecContext(ctx, `COMMENT ON DATABASE `+quotedDatabase+` IS `+pq.QuoteLiteral(marker)); err != nil {
			return fmt.Errorf("record database %q's service: %w", database, err)
		}
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
	stopped, err := stopServer(n.root, n.dataDir)
	return stopped, errors.Join(forwardErr, err)
}

// stopServer shuts a run's own postmaster down (fast shutdown: sessions are
// disconnected, the server exits cleanly and removes its shared memory) and
// removes its socket directory. It reports whether a server was running.
//
// It signals the recorded birth and nothing else. With no record, or a record
// whose process cannot be re-confirmed, there is no server of this run's left
// to stop — whatever else may hold that PID by now is not this function's to
// touch, least of all on the machine-wide collection path.
func stopServer(root, dataDir string) (bool, error) {
	record, recorded := readPostmasterRecord(root)
	if !recorded || !record.Postmaster.confirmed() {
		forgetPostmasterRecord(root, recorded)
		return false, nil
	}
	pid := record.Postmaster.PID
	if err := signalPostmaster(record.Postmaster, syscall.SIGINT); err != nil {
		if !record.Postmaster.confirmed() {
			forgetPostmasterRecord(root, true)
			return false, nil
		}
		return false, fmt.Errorf("stop the run's postgres server (pid %d): %w", pid, err)
	}
	if !waitGone(record.Postmaster, serverStopTimeout) {
		// Immediate shutdown: the server still releases its shared memory. The
		// birth is re-confirmed inside signalPostmaster, because a minute is
		// long enough for the postmaster to have exited and its number to have
		// been handed to somebody else.
		_ = signalPostmaster(record.Postmaster, syscall.SIGQUIT)
		if !waitGone(record.Postmaster, 10*time.Second) {
			return false, fmt.Errorf("the run's postgres server (pid %d) did not stop", pid)
		}
	}
	if strings.HasPrefix(filepath.Base(record.SocketDir), "cfpg-") {
		_ = os.RemoveAll(record.SocketDir)
	}
	forgetPostmasterRecord(root, true)
	// The postmaster removes its own lock file on an orderly exit; a SIGQUIT
	// leaves it, and the next start would then have to tell that leftover
	// apart from a live server all over again.
	_ = os.Remove(filepath.Join(dataDir, "postmaster.pid"))
	return true, nil
}

// signalPostmaster re-establishes the recorded birth, then delegates delivery
// to Core's kernel-bound process handle. A PID reused after inspection cannot
// receive the signal; PostgreSQL shutdown policy remains here.
func signalPostmaster(postmaster processMark, signal syscall.Signal) error {
	identity, err := runners.InspectProcess(postmaster.PID)
	if err != nil {
		return err
	}
	if identity.StartID != postmaster.StartID || identity.BootID != postmaster.BootID {
		return fmt.Errorf("postgres server %d is no longer the process this run started: %w", postmaster.PID, runners.ErrProcessNotFound)
	}
	return runners.SignalProcess(context.Background(), identity, signal)
}

// forgetPostmasterRecord drops a record no server answers to any more, so a
// later start is not told about a postmaster that is gone.
func forgetPostmasterRecord(root string, recorded bool) {
	if !recorded {
		return
	}
	_ = os.Remove(postmasterRecordPath(root))
}

// waitGone waits for a recorded birth to end. A PID that is answered by some
// other process already counts as gone: the postmaster this run started is
// what has to stop, not whatever inherits its number.
func waitGone(postmaster processMark, budget time.Duration) bool {
	deadline := time.Now().Add(budget)
	for time.Now().Before(deadline) {
		if !postmaster.confirmed() {
			return true
		}
		time.Sleep(100 * time.Millisecond)
	}
	return !postmaster.confirmed()
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
			_, _ = stopServer(root, filepath.Join(root, "pgdata"))
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
