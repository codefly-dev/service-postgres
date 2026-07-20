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

	s.NetworkMappings = req.ProposedNetworkMappings

	s.Configuration = req.Configuration

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
		conf, errConn := s.CreateConnectionConfiguration(ctx, s.Configuration, inst, false)
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

	s.connection, err = s.createOwnerConnectionString(ctx, s.Configuration, hostInstance.Address, false)
	if err != nil {
		return s.Runtime.InitError(err)
	}

	// Configuration (postgres user/password) is needed by both runtimes.
	err = s.LoadConfiguration(ctx, s.Configuration)
	if err != nil {
		return s.Runtime.InitError(err)
	}

	// Nix runtime: run postgres natively from a nix-provisioned binary instead
	// of a Docker container — selected when the caller requests
	// RuntimeContextNix (e.g. a host without Docker). Same connection string +
	// database as the Docker path, so the rest of the agent is unchanged.
	if rc := req.GetRuntimeContext(); rc != nil && rc.Kind == resources.RuntimeContextNix {
		w.Debug("using nix runtime for postgres", wool.Field("port", instance.Port))
		nixpg, errNix := newNixPostgres(ctx, s.Location, uint16(instance.Port),
			s.postgresUser, s.postgresPassword, s.DatabaseName, s.LogLevel, newPGLogWriter(s.Wool))
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
	return s.Runtime.StartResponse()
}

func (s *Runtime) Information(ctx context.Context, req *runtimev0.InformationRequest) (*runtimev0.InformationResponse, error) {
	return s.Runtime.InformationResponse(ctx, req)
}

func (s *Runtime) Stop(ctx context.Context, req *runtimev0.StopRequest) (*runtimev0.StopResponse, error) {
	defer s.Wool.Catch()

	s.Wool.Debug("nothing to stop: keep environment alive")

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
