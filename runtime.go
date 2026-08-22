package main

import (
	"context"
	"database/sql"
	"strings"
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
)

type persistentCacheMounter interface {
	WithPersistentCacheMount(context.Context, string, string) (string, error)
}

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
}

func NewRuntime() *Runtime {
	return &Runtime{
		Service: NewService(),
	}
}

func (s *Runtime) Load(ctx context.Context, req *runtimev0.LoadRequest) (*runtimev0.LoadResponse, error) {
	defer s.Wool.Catch()

	return s.Runtime.LoadService(ctx, req, services.RuntimeLoad{
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
}

func (s *Runtime) Init(ctx context.Context, req *runtimev0.InitRequest) (*runtimev0.InitResponse, error) {
	defer s.Wool.Catch()
	ctx = s.Wool.Inject(ctx)

	s.Runtime.LogInitRequest(req)
	s.Runtime.WithContext(req.GetRuntimeContext())

	w := s.Wool.In("runtime::init")
	walBudget, err := s.effectiveWALBudget()
	if err != nil {
		return s.Runtime.InitError(err)
	}
	reportWALBudget(w, walBudget)

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

	s.connection, err = s.createOwnerConnectionString(ctx, configuration, hostInstance.Address, false)
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
			s.postgresUser, s.postgresPassword, s.DatabaseName, s.LogLevel, walBudget, newPGLogWriter(s.Wool))
		if errNix != nil {
			return s.Runtime.InitError(errNix)
		}
		if errNix = nixpg.Init(ctx); errNix != nil {
			return s.Runtime.InitError(errNix)
		}
		s.nixRuntime = nixpg
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
	postgresDataPath, err := mountPersistentPostgresData(ctx, runner)
	if err != nil {
		return s.Runtime.InitError(s.Wool.Wrapf(err, "cannot configure persistent postgres data"))
	}
	storage, err := resources.InspectStorageFilesystem(postgresDataPath)
	if err != nil {
		return s.Runtime.InitError(s.Wool.Wrapf(err, "cannot inspect persistent postgres storage"))
	}
	if err = validateWALBudgetStorage(walBudget, storage); err != nil {
		return s.Runtime.InitError(err)
	}

	runner.WithOutput(newPGLogWriter(s.Wool))
	runner.WithPortMapping(ctx, uint16(instance.Port), s.postgresPort)

	runner.WithEnvironmentVariables(
		ctx,
		resources.Env("POSTGRES_USER", s.postgresUser),
		resources.Env("POSTGRES_PASSWORD", s.postgresPassword),
		resources.Env("POSTGRES_DB", s.DatabaseName))

	runner.WithCommand(postgresCommand(walBudget, s.LogLevel)...)

	s.runnerEnvironment = runner

	w.Debug("init for runner environment: will start container")
	err = s.runnerEnvironment.Init(ctx)
	if err != nil {
		return s.Runtime.InitError(err)
	}

	s.Wool.Debug("init successful")
	if err := s.migrateOnInit(ctx); err != nil {
		return s.Runtime.InitError(err)
	}
	return s.Runtime.InitResponse()
}

func postgresCommand(walBudget postgresWALBudget, logLevel string) []string {
	args := append([]string{"postgres"}, walBudget.postgresArguments()...)
	if level := strings.ToLower(strings.TrimSpace(logLevel)); level != "" {
		args = append(args,
			"-c", "log_min_messages="+level,
			"-c", "log_statement=none",
			"-c", "log_connections=off",
			"-c", "log_disconnections=off",
		)
	}
	return args
}

func reportWALBudget(w *wool.Wool, budget postgresWALBudget) {
	w.Info("effective postgres WAL budget",
		wool.Field("max_wal_size_mb", budget.maxSizeMB),
		wool.Field("checkpoint_timeout_seconds", budget.checkpointTimeoutSeconds),
	)
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
	if err := s.WaitForReady(ctx); err != nil {
		return err
	}
	// Extensions are not migrations — ensure them even when NoMigration is set,
	// so "port reachable" also implies "configured extensions available".
	if err := s.ensureExtensions(ctx); err != nil {
		return err
	}
	if !s.Settings.NoMigration {
		if err := s.applyMigration(ctx); err != nil {
			return err
		}
	}
	return s.ensureRuntimeAccess(ctx)
}

// ensureExtensions CREATE EXTENSION IF NOT EXISTS for the always-on defaults
// plus anything in Settings.Extensions, BEFORE migrations run (so schema files
// can rely on them). Best-effort per extension: a name whose shared library is
// absent from the image (e.g. postgis on the pgvector image) is logged and
// skipped, never fatal — point Settings.DockerImage at an image that ships it.
func (s *Runtime) ensureExtensions(ctx context.Context) error {
	exts := append([]string{}, defaultExtensions...)
	exts = append(exts, s.Settings.Extensions...)

	db, err := sql.Open("postgres", s.connection)
	if err != nil {
		return s.Wool.Wrapf(err, "cannot open database to create extensions")
	}
	defer db.Close()

	seen := make(map[string]bool, len(exts))
	for _, ext := range exts {
		ext = strings.TrimSpace(ext)
		if ext == "" || seen[ext] {
			continue
		}
		seen[ext] = true
		if !validExtName(ext) {
			s.Wool.Warn("skipping extension with unsafe name", wool.Field("extension", ext))
			continue
		}
		// Extension names cannot be parameterized; validExtName above restricts
		// them to [A-Za-z0-9_-] so the quoted identifier is injection-safe.
		if _, err := db.ExecContext(ctx, `CREATE EXTENSION IF NOT EXISTS "`+ext+`"`); err != nil {
			s.Wool.Warn("could not create extension (is its library in the image?)",
				wool.Field("extension", ext), wool.ErrField(err))
			continue
		}
		s.Wool.Debug("extension ready", wool.Field("extension", ext))
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

	s.Wool.Debug("waiting for database readiness")

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
	maxRetry := 30
	var lastErr error
	for range maxRetry {
		err = db.Ping()
		if err == nil {
			s.Wool.Debug("ping successful")
			// Try to execute a simple query
			_, err = db.Exec("SELECT 1")
			if err == nil {
				s.Wool.Debug("database ready!")
				return nil
			}
		}
		lastErr = err
		s.Wool.Debug("waiting for database to be ready", wool.ErrField(err))
		time.Sleep(3 * time.Second)
	}
	// Tail container logs so the user sees the real failure (bad CMD,
	// disk full, port collision, ...) instead of a generic timeout.
	tail := ""
	if s.runnerEnvironment != nil {
		tail = s.runnerEnvironment.TailLogs(ctx, 30)
	}
	if tail != "" {
		return s.Wool.NewError("database not ready after %d retries (last probe: %v); container logs (tail 30):\n%s", maxRetry, lastErr, tail)
	}
	return s.Wool.NewError("database not ready after %d retries (last probe: %v)", maxRetry, lastErr)
}

func (s *Runtime) Start(ctx context.Context, req *runtimev0.StartRequest) (*runtimev0.StartResponse, error) {
	defer s.Wool.Catch()
	ctx = s.Wool.Inject(ctx)

	s.Wool.Debug("starting")

	s.Wool.Debug("waiting for ready")

	err := s.WaitForReady(ctx)
	if err != nil {
		return s.Runtime.StartError(err)
	}

	if err := s.ensureExtensions(ctx); err != nil {
		return s.Runtime.StartError(err)
	}

	if !s.Settings.NoMigration {
		s.Wool.Debug("applying migrations")
		err = s.applyMigration(ctx)
		if err != nil {
			return s.Runtime.StartError(err)
		}

		if s.Settings.HotReload {
			conf := services.NewWatchConfiguration(requirements)
			err := s.SetupWatcher(ctx, conf, s.EventHandler)
			if err != nil {
				s.Wool.Warn("error in watcher", wool.ErrField(err))
			}
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

func (s *Runtime) Stop(ctx context.Context, req *runtimev0.StopRequest) (*runtimev0.StopResponse, error) {
	defer s.Wool.Catch()
	ctx = s.Wool.Inject(ctx)

	// ARCHITECTURE: Nix postgres is a host process, not a persistent container.
	// Stop must terminate it while retaining dataDir so validation/CI flows can
	// release the assigned port and a later Init can safely reuse the cluster.
	// Leaving it alive makes the next phase launch a second postmaster against
	// the same port and data directory. Docker retains its historical behavior:
	// its Codefly-owned stateful container stays available for fast reuse.
	if s.nixRuntime != nil {
		if err := s.nixRuntime.Stop(ctx); err != nil {
			return s.Runtime.StopError(err)
		}
		s.nixRuntime = nil
		s.Wool.Debug("stopped nix postgres runtime; persistent data retained")
		return s.Runtime.StopResponse()
	}

	s.Wool.Debug("nothing to stop: keep docker environment alive")

	return s.Runtime.StopResponse()
}

func (s *Runtime) Destroy(ctx context.Context, req *runtimev0.DestroyRequest) (*runtimev0.DestroyResponse, error) {
	defer s.Wool.Catch()
	ctx = s.Wool.Inject(ctx)

	s.Wool.Debug("Destroying")

	// Nix runtime: stop the native postgres process.
	if s.nixRuntime != nil {
		if err := s.nixRuntime.Stop(ctx); err != nil {
			return s.Runtime.DestroyError(err)
		}
		return s.Runtime.DestroyResponse()
	}

	// Get the runner environment
	runner, err := dockerrun.NewDockerHeadlessEnvironment(ctx, s.dockerImage(), s.UniqueWithWorkspace())
	if err != nil {
		return s.Runtime.DestroyError(err)
	}

	err = runner.Shutdown(ctx)
	if err != nil {
		return s.Runtime.DestroyError(err)
	}
	return s.Runtime.DestroyResponse()
}

func (s *Runtime) Test(ctx context.Context, req *runtimev0.TestRequest) (*runtimev0.TestResponse, error) {
	return s.Runtime.TestResponse()
}

/* Details

 */

func (s *Runtime) EventHandler(event code.Change) error {
	if strings.Contains(event.Path, "migrations") {
		err := s.updateMigration(context.Background(), event.Path)
		if err != nil {
			s.Wool.Warn("cannot apply migration", wool.ErrField(err))
			return nil
		}
		if err := s.ensureRuntimeAccess(context.Background()); err != nil {
			s.Wool.Warn("cannot reconcile runtime access after migration", wool.ErrField(err))
		}
	}
	return nil
}
