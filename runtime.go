package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/codefly-dev/core/agents/helpers/code"

	"github.com/codefly-dev/core/agents/services"
	basev0 "github.com/codefly-dev/core/generated/go/codefly/base/v0"
	"github.com/codefly-dev/core/wool"

	runtimev0 "github.com/codefly-dev/core/generated/go/codefly/services/runtime/v0"
	"github.com/codefly-dev/core/resources"
	dockerrun "github.com/codefly-dev/core/runners/dockerrun"
	_ "github.com/golang-migrate/migrate/v4/source/file"
	_ "github.com/lib/pq"
)

const (
	postgresDataCacheKey  = "postgres-data"
	postgresDataDirectory = "/var/lib/postgresql/data"

	// readinessProbeInterval paces the readiness loop. The number of attempts
	// is whatever the readiness budget affords, not a separate knob.
	readinessProbeInterval = 3 * time.Second
)

type persistentCacheMounter interface {
	WithPersistentCacheMount(context.Context, string, string) (string, error)
}

// mountPersistentPostgresData layers the Codefly-owned persistent directory
// over the image's data directory and returns that host path, which is where
// the database survives every lifecycle operation.
func mountPersistentPostgresData(ctx context.Context, runner persistentCacheMounter) (string, error) {
	return runner.WithPersistentCacheMount(ctx, postgresDataCacheKey, postgresDataDirectory)
}

type Runtime struct {
	services.RuntimeServer
	*Service

	// internal
	runnerEnvironment *dockerrun.DockerEnvironment

	// nixRuntime is set instead of runnerEnvironment when the caller requests
	// RuntimeContextNix — postgres then runs natively from a nix-provisioned
	// binary (no Docker), serving the same connection string + database.
	nixRuntime *nixPostgres

	postgresPort uint16

	// lifecycleMu serializes Stop and Destroy. Both act on runnerEnvironment,
	// and the CLI can overlap them: it bounds each Stop at ten seconds and then
	// fans out Destroy as soon as that deadline passes, while the abandoned Stop
	// handler is still inside the docker client. DockerEnvironment.instance is
	// written by Shutdown and read by Stop with no lock of its own, so without
	// this the two race on the same handle.
	lifecycleMu sync.Mutex

	// released records that Stop already gave up this invocation's execution
	// resources. Start probes the database for ninety seconds before giving up,
	// which is a long way to discover that the server it is waiting for was
	// deliberately stopped.
	released bool

	// retainedDataPath is where this invocation's database state lives on disk —
	// the Codefly-owned cache directory bind-mounted into the container, or the
	// nix cluster's data directory. Reported in Stop/Destroy results so a caller
	// sees what was kept without having to inspect the backend.
	retainedDataPath string

	// migrationReload serializes hot-reload migration work against this
	// database. Deciding what to apply reads the ledger and applies it in
	// separate statements, so two reloads at once would both plan from the same
	// version.
	migrationReload sync.Mutex
}

func NewRuntime() *Runtime {
	return &Runtime{
		Service: NewService(),
	}
}

func (s *Runtime) Load(ctx context.Context, req *runtimev0.LoadRequest) (*runtimev0.LoadResponse, error) {
	defer s.Wool.Catch()

	response, err := s.Runtime.LoadService(ctx, req, services.RuntimeLoad{
		Settings:     s.Settings,
		Requirements: requirements,
		ResolveEndpoints: func(ctx context.Context, endpoints []*basev0.Endpoint) error {
			s.Wool.Debug("endpoints", wool.Field("endpoints", resources.MakeManyEndpointSummary(endpoints)))
			endpoint, err := resources.FindTCPEndpoint(ctx, endpoints)
			if err != nil {
				return s.Wool.Wrapf(err, "cannot find TCP endpoint")
			}
			s.TcpEndpoint = endpoint
			return nil
		},
	})
	if err != nil {
		return response, err
	}
	if err = s.Settings.Timeouts.validate(); err != nil {
		return s.Runtime.LoadError(err)
	}
	return response, nil
}

func (s *Runtime) Init(ctx context.Context, req *runtimev0.InitRequest) (*runtimev0.InitResponse, error) {
	defer s.Wool.Catch()
	ctx = s.Wool.Inject(ctx)

	s.Runtime.LogInitRequest(req)
	s.Runtime.WithContext(req.GetRuntimeContext())

	w := s.Wool.In("runtime::init")

	s.NetworkMappings = req.ProposedNetworkMappings

	configuration := req.GetConfiguration()

	net, err := resources.FindNetworkMapping(ctx, s.NetworkMappings, s.TcpEndpoint)
	if err != nil {
		return s.Runtime.InitError(err)
	}

	if net == nil {
		return s.Runtime.InitError(w.NewError("network mapping is nil"))
	}

	// ARCHITECTURE: the Postgres container publishes a port to the agent host,
	// and migrations/runtime-role reconciliation execute in this host agent
	// process. Always select the native mapping for those control-plane calls.
	// A container mapping such as host.docker.internal is for a *consumer*
	// running in another container; it is not a portable hostname on the host
	// itself (notably on Linux and several macOS Docker backends).
	instance, err := resources.FindNetworkInstanceInNetworkMappings(ctx, s.NetworkMappings, s.TcpEndpoint, resources.NewNativeNetworkAccess())
	if err != nil {
		return s.Runtime.InitError(err)
	}

	if instance == nil {
		return s.Runtime.InitError(w.NewError("network instance is nil"))
	}

	w.Debug("tcp network instance", wool.Field("instance", instance))

	s.Infof("will run on %s", instance.Host)
	s.postgresPort = 5432

	// Create connection string resources for the network instance
	for _, inst := range net.Instances {
		conf, errConn := s.CreateConnectionConfiguration(ctx, configuration, inst, false)
		if errConn != nil {
			return s.Runtime.InitError(errConn)
		}
		w.Debug("adding configuration", wool.Field("config", resources.MakeConfigurationSummary(conf)), wool.Field("instance", inst))
		s.Runtime.RuntimeConfigurations = append(s.Runtime.RuntimeConfigurations, conf)
	}
	s.Wool.Debug("sending runtime configuration", wool.Field("conf", resources.MakeManyConfigurationSummary(s.Runtime.RuntimeConfigurations)))

	w.Debug("setting up connection string for migrations")
	// Setup a connection string for migration
	hostInstance, err := resources.FindNetworkInstanceInNetworkMappings(ctx, s.NetworkMappings, s.TcpEndpoint, resources.NewNativeNetworkAccess())
	if err != nil {
		return s.Runtime.InitError(err)

	}

	connection, err := s.createOwnerConnectionString(ctx, configuration, hostInstance.Address, false)
	if err != nil {
		return s.Runtime.InitError(err)
	}
	s.connection, err = withConnectTimeout(connection, s.Settings.Timeouts.connect())
	if err != nil {
		return s.Runtime.InitError(err)
	}

	// Configuration (postgres user/password) is needed by both runtimes.
	err = s.LoadConfiguration(ctx, configuration)
	if err != nil {
		return s.Runtime.InitError(err)
	}

	// Nix runtime: run postgres natively from a nix-provisioned binary instead
	// of a Docker container — selected when the caller requests
	// RuntimeContextNix (e.g. a host without Docker). Same connection string +
	// database as the Docker path, so the rest of the agent is unchanged.
	if rc := req.GetRuntimeContext(); rc != nil && rc.Kind == resources.RuntimeContextNix {
		w.Debug("using nix runtime for postgres", wool.Field("port", instance.Port))
		nixpg, errNix := newNixPostgres(ctx, nixPostgresStateKey(s.Location, s.Environment.NamingScope), uint16(instance.Port),
			s.postgresUser, s.postgresPassword, s.DatabaseName, s.LogLevel, newPGLogWriter(s.Wool))
		if errNix != nil {
			return s.Runtime.InitError(errNix)
		}
		if errNix = nixpg.Init(ctx); errNix != nil {
			return s.Runtime.InitError(errNix)
		}
		s.nixRuntime = nixpg
		s.retainedDataPath = nixpg.dataDir
		s.released = false
		s.Wool.Debug("nix postgres init successful")
		if errNix = s.migrateOnInit(ctx); errNix != nil {
			return s.Runtime.InitError(errNix)
		}
		return s.Runtime.InitResponse()
	}

	// Docker
	runner, err := dockerrun.NewDockerHeadlessEnvironment(ctx, s.dockerImage(), s.UniqueWithWorkspace())
	if err != nil {
		return s.Runtime.InitError(err)
	}
	dataPath, err := mountPersistentPostgresData(ctx, runner)
	if err != nil {
		return s.Runtime.InitError(s.Wool.Wrapf(err, "cannot configure persistent postgres data"))
	}
	s.retainedDataPath = dataPath

	runner.WithOutput(newPGLogWriter(s.Wool))
	runner.WithPortMapping(ctx, uint16(instance.Port), s.postgresPort)

	runner.WithEnvironmentVariables(
		ctx,
		resources.Env("POSTGRES_USER", s.postgresUser),
		resources.Env("POSTGRES_PASSWORD", s.postgresPassword),
		resources.Env("POSTGRES_DB", s.DatabaseName))

	// Quieten the server when a log level is configured. The official
	// postgres image's ENTRYPOINT is docker-entrypoint.sh and its
	// default CMD is `postgres`. WithCommand only overrides CMD, so
	// we provide just `postgres <flags>` — the entrypoint still runs
	// initdb on first boot, then execs our postgres + flags. The
	// `-c` args are passed straight to the server and override the
	// equivalent postgresql.conf entries.
	if lvl := strings.ToLower(strings.TrimSpace(s.LogLevel)); lvl != "" {
		runner.WithCommand(
			"postgres",
			"-c", "log_min_messages="+lvl,
			"-c", "log_statement=none",
			"-c", "log_connections=off",
			"-c", "log_disconnections=off",
		)
	}

	s.runnerEnvironment = runner

	w.Debug("init for runner environment: will start container")
	err = s.runnerEnvironment.Init(ctx)
	if err != nil {
		return s.Runtime.InitError(err)
	}

	s.released = false

	s.Wool.Debug("init successful")
	if err := s.migrateOnInit(ctx); err != nil {
		return s.Runtime.InitError(err)
	}
	return s.Runtime.InitResponse()
}

// migrateOnInit applies schema migrations DURING Init — after the database is
// up but BEFORE Init returns. This closes a readiness race: the codefly
// --exclude-root readiness gate every WithDependencies consumer uses is a plain
// TCP dial on the postgres port (cli/pkg/orchestration/flow.go networkMapping
// TCPReachable), and that port opens in Init. When migrations ran only in Start
// (after Init exposed the port), a fast consumer could be told "ready" and
// connect mid-migration — reading an incomplete schema, or tearing the stack
// down and leaving golang-migrate "dirty" at a random version. Running them in
// Init makes "port reachable" imply "schema migrated". Start still calls
// applyMigration; with the schema already current it is an idempotent no-op
// (migrate.ErrNoChange).
func (s *Runtime) migrateOnInit(ctx context.Context) error {
	// Resolve the declared prerequisites BEFORE waiting on the database: a typo
	// in a source path, a duplicate lineage, or an unsafe name must fail without
	// touching a schema.
	prerequisites, err := s.resolveSchemaPrerequisites()
	if err != nil {
		return err
	}
	if err := s.WaitForReady(ctx); err != nil {
		return err
	}
	if err := s.applySchema(ctx, prerequisites); err != nil {
		return err
	}
	return s.ensureRuntimeAccess(ctx)
}

// applySchema brings the database up to the resolved prerequisites: extensions
// first, so migration files can rely on them, then every migration lineage.
// Extensions are not migrations — they are ensured even when NoMigration is set,
// so "port reachable" also implies "declared extensions available".
func (s *Runtime) applySchema(ctx context.Context, prerequisites *schemaPrerequisites) error {
	// Deferred so a skipped prerequisite is reported even when a later step
	// fails: a migration that needs an extension reports only the missing
	// function, and the skip is the reason it is missing.
	defer s.reportSchemaPrerequisites(prerequisites)
	if err := s.ensureExtensions(ctx, prerequisites); err != nil {
		return err
	}
	if !s.Settings.NoMigration {
		if err := s.applyMigration(ctx, prerequisites.sources); err != nil {
			return err
		}
	}
	return nil
}

// ensureExtensions CREATE EXTENSION IF NOT EXISTS for every resolved request.
// An explicitly declared extension is required: its failure — an absent shared
// library, a migration owner without the privilege, a lost connection — fails
// readiness rather than leaving the service running against a schema it cannot
// use. The convenience defaults and declarations marked optional record a
// structured skip instead.
func (s *Runtime) ensureExtensions(ctx context.Context, prerequisites *schemaPrerequisites) error {
	db, err := sql.Open("postgres", s.connection)
	if err != nil {
		return s.Wool.Wrapf(err, "cannot open database to create extensions")
	}
	defer db.Close()

	for _, extension := range prerequisites.extensions {
		// Extension names cannot be parameterized; resolveExtensions restricts
		// them to [A-Za-z0-9_-] so the quoted identifier is injection-safe.
		if _, err := db.ExecContext(ctx, `CREATE EXTENSION IF NOT EXISTS "`+extension.name+`"`); err != nil {
			if extension.required {
				return s.Wool.Wrapf(err,
					"cannot create required extension %q: the configured image must ship its library and the migration owner must be allowed to install it",
					extension.name)
			}
			prerequisites.skipped = append(prerequisites.skipped, skippedPrerequisite{
				kind:   prerequisiteExtension,
				name:   extension.name,
				reason: err.Error(),
			})
			continue
		}
		s.Wool.Debug("extension ready", wool.Field("extension", extension.name))
	}
	return nil
}

// validExtName reports whether name is a safe postgres extension identifier.
func validExtName(name string) bool {
	if name == "" {
		return false
	}
	for _, r := range name {
		ok := r == '_' || r == '-' ||
			(r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9')
		if !ok {
			return false
		}
	}
	return true
}

func (s *Runtime) WaitForReady(ctx context.Context) error {
	defer s.Wool.Catch()
	ctx = s.Wool.Inject(ctx)

	budget := s.Settings.Timeouts.readiness()
	s.Wool.Debug("waiting for database readiness", wool.Field("budget", budget.String()))

	// One pool, opened once and reused for every probe. sql.Open is lazy
	// (it doesn't dial until Ping), so a single *sql.DB pinged in a loop is
	// the idiomatic readiness check. The old code opened a NEW *sql.DB every
	// iteration and never closed any of them — up to 30 leaked connection
	// pools per Init, which alone can exhaust Postgres' default 100-conn limit.
	db, err := sql.Open("postgres", s.connection)
	if err != nil {
		return s.Wool.Wrapf(err, "cannot open database")
	}
	defer db.Close()

	deadline, cancel := context.WithTimeout(ctx, budget)
	defer cancel()

	retry := time.NewTicker(readinessProbeInterval)
	defer retry.Stop()

	// The last probe failure that came from the database rather than from our
	// own budget running out: that is what tells the user why postgres never
	// answered, and it is lost if a cancellation overwrites it.
	var lastProbeErr error
	for {
		err = probeReady(deadline, db)
		if err == nil {
			s.Wool.Debug("database ready!")
			return nil
		}
		if !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) {
			lastProbeErr = err
		}
		s.Wool.Debug("waiting for database to be ready", wool.ErrField(err))
		select {
		case <-deadline.Done():
			return s.readinessFailure(ctx, budget, deadline.Err(), lastProbeErr)
		case <-retry.C:
		}
	}
}

// probeReady answers whether postgres is accepting work, and returns as soon as
// ctx is done. Establishment is bounded by the DSN's connect_timeout rather
// than by ctx — libpq reads the startup handshake off a raw socket deadline —
// so a peer that accepts TCP and then goes silent would otherwise hold a
// cancelled caller for the whole connect budget.
func probeReady(ctx context.Context, db *sql.DB) error {
	probe := make(chan error, 1)
	go func() {
		if err := db.PingContext(ctx); err != nil {
			probe <- err
			return
		}
		// A backend that accepts connections is not necessarily one that runs
		// queries: postgres answers the handshake during crash recovery and
		// refuses statements until it finishes.
		_, err := db.ExecContext(ctx, "SELECT 1")
		probe <- err
	}()
	select {
	case err := <-probe:
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}

// readinessFailure names the phase, says whether the budget ran out or the
// caller gave up, and carries the last database-side failure. The connection
// string is never included: it holds the migration-owner password.
func (s *Runtime) readinessFailure(ctx context.Context, budget time.Duration, ended, lastProbeErr error) error {
	phase := fmt.Sprintf("database readiness budget of %s expired", budget)
	if errors.Is(ended, context.Canceled) {
		phase = "database readiness wait cancelled"
	}
	if lastProbeErr == nil {
		lastProbeErr = ended
	}
	// Tail container logs so the user sees the real failure (bad CMD,
	// disk full, port collision, ...) instead of a generic timeout.
	tail := ""
	if s.runnerEnvironment != nil {
		tail = s.runnerEnvironment.TailLogs(ctx, 30)
	}
	if tail != "" {
		return s.Wool.NewError("%s (last probe: %v); container logs (tail 30):\n%s", phase, lastProbeErr, tail)
	}
	return s.Wool.NewError("%s (last probe: %v)", phase, lastProbeErr)
}

func (s *Runtime) Start(ctx context.Context, req *runtimev0.StartRequest) (*runtimev0.StartResponse, error) {
	defer s.Wool.Catch()
	ctx = s.Wool.Inject(ctx)

	s.Wool.Debug("starting")

	// Stop released this invocation's postmaster or container, and nothing but
	// Init brings one back. Without this, WaitForReady spends ninety seconds
	// probing a database that was deliberately shut down before reporting a
	// generic timeout.
	if s.released {
		return s.Runtime.StartError(s.Wool.NewError("postgres was stopped by this invocation: run Init before Start"))
	}

	s.Wool.Debug("waiting for ready")

	prerequisites, err := s.resolveSchemaPrerequisites()
	if err != nil {
		return s.Runtime.StartError(err)
	}

	err = s.WaitForReady(ctx)
	if err != nil {
		return s.Runtime.StartError(err)
	}

	if err := s.applySchema(ctx, prerequisites); err != nil {
		return s.Runtime.StartError(err)
	}

	if !s.Settings.NoMigration && s.Settings.HotReload {
		watch, errWatch := s.migrationWatchRequirements(ctx)
		if errWatch != nil {
			s.Wool.Warn("cannot resolve migration watch roots", wool.ErrField(errWatch))
		} else if errWatch = s.SetupWatcher(ctx, services.NewWatchConfiguration(watch), s.EventHandler); errWatch != nil {
			s.Wool.Warn("error in watcher", wool.ErrField(errWatch))
		}
	}
	if err := s.ensureRuntimeAccess(ctx); err != nil {
		return s.Runtime.StartError(err)
	}
	s.Wool.Debug("start done")
	// Commit StartStatus=STARTED BEFORE arming supervision. StartResponse and
	// MarkRunnerExited both write StartStatus under the same lock, so ordering is
	// by wall-clock, not data race: if Supervise were armed first, a postmaster
	// death already buffered in serverExit (a crash in the Init->Start window)
	// would let the watcher goroutine flip StartStatus to ERROR, and this
	// StartResponse would then clobber it back to STARTED — masking the very
	// death we exist to report (codefly-dev/cli#380). Arming after the commit
	// guarantees any ERROR the watcher writes lands strictly after STARTED.
	resp, err := s.Runtime.StartResponse()
	if err != nil {
		return resp, err
	}
	// Report a mid-run death of the managed postgres process so codefly's Follow
	// loop observes StartStatus ERROR and tears down loudly instead of leaving
	// dependents to spin on connection refused (codefly-dev/cli#380). Docker
	// runtimes are supervised by the container engine and reported via the
	// runner environment; the Nix host process has no such supervisor.
	if s.nixRuntime != nil {
		s.nixRuntime.Supervise(func(err error) {
			if err != nil {
				s.Wool.Error("nix postgres exited unexpectedly", wool.ErrField(err))
			} else {
				s.Wool.Error("nix postgres exited unexpectedly (clean exit, not stopped)")
			}
			s.Runtime.MarkRunnerExited(err)
		})
	}
	return resp, nil
}

func (s *Runtime) Information(ctx context.Context, req *runtimev0.InformationRequest) (*runtimev0.InformationResponse, error) {
	return s.Runtime.InformationResponse(ctx, req)
}

// Postgres lifecycle operations share one state-ownership contract, and it is
// the same contract on both backends:
//
//	operation             execution resources           database state
//	Stop                  released                      retained
//	Stop + keep-running   retained (docker only)        retained
//	Destroy               released, container removed   retained
//
// keep-running is the one row that is not backend-independent: reuse means the
// next invocation reattaches to a live server, and only the container backend
// can do that. See Stop.
//
// Releasing execution resources means terminating the postmaster (nix) or
// stopping the container (docker) so the assigned port is free again and a
// later Init cannot end up running a second postmaster against the same data
// directory.
//
// No operation deletes data. Dropping a database or a data directory requires
// an explicit authorization proving that state is disposable and owned by the
// caller; neither StopRequest nor DestroyRequest carries one, so an agent must
// never infer the right to reset from the fact that it started the process
// (codefly-dev/core#424).
//
// Stop releases only what THIS invocation holds a handle to: a runtime that
// never ran Init owns no postmaster and no container, and stops nothing.
func (s *Runtime) Stop(ctx context.Context, req *runtimev0.StopRequest) (*runtimev0.StopResponse, error) {
	defer s.Wool.Catch()
	ctx = s.Wool.Inject(ctx)

	s.lifecycleMu.Lock()
	defer s.lifecycleMu.Unlock()

	// keep-running asks for a server the NEXT invocation reattaches to, and only
	// the container backend can reattach: GetContainer adopts an existing
	// container by name. nixPostgres has no such path — Init always launches a
	// new postmaster, and clearStalePostmasterPid deliberately leaves a live
	// owner's lock file alone, so a retained nix postmaster makes the next Init
	// start a second postmaster against the same data directory and port, which
	// postgres refuses. Honouring the setting there would trade a cold start for
	// a broken one, so nix stops and keeps the half of the contract it can: the
	// data.
	if s.Settings.KeepRunning {
		if s.nixRuntime == nil && !s.Runtime.IsNixRuntime() {
			s.Wool.Debug("keep-running is set: leaving postgres up for reuse")
			return s.stopResponse("kept postgres running for reuse")
		}
		s.Wool.Warn("keep-running is not available on the nix runtime: stopping postgres, its data is retained")
	}

	if s.nixRuntime != nil {
		if err := s.nixRuntime.Stop(ctx); err != nil {
			return s.Runtime.StopError(err)
		}
		// Stop removes the handle's socket directory, so it can never serve a
		// second run — drop it instead of leaving a dead handle behind.
		s.nixRuntime = nil
		s.released = true
		return s.stopResponse("stopped native postgres")
	}

	if s.runnerEnvironment != nil {
		if err := s.stopContainer(ctx); err != nil {
			return s.Runtime.StopError(err)
		}
		// The docker handle stays usable after its container stops: stopping
		// twice is a no-op, and Destroy still needs it to close the client and
		// log stream this invocation opened.
		s.released = true
		return s.stopResponse("stopped postgres container")
	}

	return s.stopResponse("no postgres owned by this invocation")
}

func (s *Runtime) Destroy(ctx context.Context, req *runtimev0.DestroyRequest) (*runtimev0.DestroyResponse, error) {
	defer s.Wool.Catch()
	ctx = s.Wool.Inject(ctx)

	s.lifecycleMu.Lock()
	defer s.lifecycleMu.Unlock()

	s.Wool.Debug("Destroying")

	if s.nixRuntime != nil {
		if err := s.nixRuntime.Stop(ctx); err != nil {
			return s.Runtime.DestroyError(err)
		}
		s.nixRuntime = nil
		s.released = true
		return s.destroyResponse("stopped native postgres")
	}
	// A nix invocation has no container to remove, and reaching for one would
	// demand a docker daemon from a host that was very likely chosen for not
	// having one.
	if s.Runtime.IsNixRuntime() {
		return s.destroyResponse("native postgres already stopped")
	}

	// Prefer the environment this invocation started: shutting that one down
	// also closes the docker client and log stream it opened. Resolving the
	// container by name remains the fallback so destroy keeps working for a
	// caller that only loaded the service.
	runner := s.runnerEnvironment
	if runner == nil {
		var err error
		runner, err = dockerrun.NewDockerHeadlessEnvironment(ctx, s.dockerImage(), s.UniqueWithWorkspace())
		if err != nil {
			return s.Runtime.DestroyError(err)
		}
	}
	if err := runner.Shutdown(ctx); err != nil {
		return s.Runtime.DestroyError(err)
	}
	s.runnerEnvironment = nil
	s.released = true
	return s.destroyResponse("removed postgres container")
}

// stopContainer stops the container, retrying once for a caller that is still
// listening. Core bounds its stop call at ten seconds against the docker
// daemon, and a loaded daemon can blow that deadline after it has already
// accepted the stop: the container is on its way down but the call reports
// failure. A second call is a no-op against a container that has since stopped
// and a real second attempt against one that has not.
//
// The retry is only worth spending when someone will still read the answer.
// codefly's own teardown bounds Stop at ten seconds — the same budget the first
// attempt just consumed — so by now it has abandoned this call and moved on to
// Destroy; retrying would spend another ten seconds producing a status nobody
// receives, while holding the handle Destroy is waiting for. Callers without
// that deadline (the MCP stop tool passes its request context straight through)
// do still get the second attempt.
func (s *Runtime) stopContainer(ctx context.Context) error {
	err := s.runnerEnvironment.Stop(ctx)
	if err == nil {
		return nil
	}
	if ctxErr := ctx.Err(); ctxErr != nil {
		return err
	}
	s.Wool.Warn("postgres container stop did not confirm; retrying", wool.ErrField(err))
	return s.runnerEnvironment.Stop(ctx)
}

// stopResponse and destroyResponse report SUCCESS together with what the
// operation released and where the state it kept now lives, so a caller learns
// the retention outcome from the result instead of by inspecting the backend.
// Only paths are reported, never a credential or a connection string.
func (s *Runtime) stopResponse(action string) (*runtimev0.StopResponse, error) {
	return &runtimev0.StopResponse{Status: &runtimev0.StopStatus{
		State:   runtimev0.StopStatus_SUCCESS,
		Message: s.retentionSummary(action),
	}}, nil
}

func (s *Runtime) destroyResponse(action string) (*runtimev0.DestroyResponse, error) {
	return &runtimev0.DestroyResponse{Status: &runtimev0.DestroyStatus{
		State:   runtimev0.DestroyStatus_SUCCESS,
		Message: s.retentionSummary(action),
	}}, nil
}

func (s *Runtime) retentionSummary(action string) string {
	if s.retainedDataPath == "" {
		return action + "; database state retained"
	}
	return action + "; database state retained at " + s.retainedDataPath
}

func (s *Runtime) Test(ctx context.Context, req *runtimev0.TestRequest) (*runtimev0.TestResponse, error) {
	return s.Runtime.TestResponse()
}

/* Details

 */

// EventHandler reacts to one watched file change. Errors are reported and
// swallowed: an edit that cannot be applied — an already-applied migration, a
// dirty ledger, bad SQL — must leave hot reload armed so fixing the source or
// adding a new migration gets another attempt.
func (s *Runtime) EventHandler(event code.Change) error {
	ctx := context.Background()
	applied, err := s.applyMigrationChange(ctx, event.Path)
	if err != nil {
		s.Wool.Warn("cannot apply migration change", wool.ErrField(err))
	}
	// Reconcile whenever SQL reached the database: an apply failure reports
	// applied=false, so an error here is a cleanup failure over a schema that
	// already changed and still needs its runtime grants.
	if !applied {
		return nil
	}
	if err := s.ensureRuntimeAccess(ctx); err != nil {
		s.Wool.Warn("cannot reconcile runtime access after migration", wool.ErrField(err))
	}
	return nil
}
