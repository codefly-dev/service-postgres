package main

import (
	"context"
	"database/sql"
	basev0 "github.com/codefly-dev/core/generated/go/codefly/base/v0"
	"os"
	"strings"
	"time"

	"github.com/codefly-dev/core/agents/helpers/code"

	"github.com/codefly-dev/core/agents/services"
	"github.com/codefly-dev/core/wool"

	runtimev0 "github.com/codefly-dev/core/generated/go/codefly/services/runtime/v0"
	"github.com/codefly-dev/core/resources"
	runners "github.com/codefly-dev/core/runners/base"
	_ "github.com/golang-migrate/migrate/v4/source/file"
	_ "github.com/lib/pq"
)

type Runtime struct {
	services.RuntimeServer
	*Service

	// internal
	runnerEnvironment *runners.DockerEnvironment

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
	ctx = s.Wool.Inject(ctx)

	s.Runtime.LogLoadRequest(req)

	err := s.Base.Load(ctx, req.Identity, s.Settings)
	if err != nil {
		return s.Runtime.LoadErrorf(err, "loading base")
	}

	s.Runtime.SetEnvironment(req.Environment)

	requirements.Localize(s.Location)

	// Endpoints
	s.Endpoints, err = s.Base.Service.LoadEndpoints(ctx)
	if err != nil {
		return s.Runtime.LoadErrorf(err, "cannot load endpoints")
	}

	s.Wool.Debug("endpoints", wool.Field("endpoints", resources.MakeManyEndpointSummary(s.Endpoints)))

	s.TcpEndpoint, err = resources.FindTCPEndpoint(ctx, s.Endpoints)
	if err != nil {
		return s.Runtime.LoadErrorf(err, "cannot find TCP endpoint")
	}

	return s.Runtime.LoadResponse()
}

func CallingContext() *basev0.NetworkAccess {
	if _, err := os.Stat("/.dockerenv"); err == nil {
		return resources.NewContainerNetworkAccess()
	}
	return resources.NewNativeNetworkAccess()
}

func (s *Runtime) Init(ctx context.Context, req *runtimev0.InitRequest) (*runtimev0.InitResponse, error) {
	defer s.Wool.Catch()
	ctx = s.Wool.Inject(ctx)

	s.Runtime.LogInitRequest(req)

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

	instance, err := resources.FindNetworkInstanceInNetworkMappings(ctx, s.NetworkMappings, s.TcpEndpoint, CallingContext())
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
	hostInstance, err := resources.FindNetworkInstanceInNetworkMappings(ctx, s.NetworkMappings, s.TcpEndpoint, CallingContext())
	if err != nil {
		return s.Runtime.InitError(err)

	}

	s.connection, err = s.createConnectionString(ctx, s.Configuration, hostInstance.Address, false)
	if err != nil {
		return s.Runtime.InitError(err)
	}

	w.Debug("connection string", wool.Field("connection", s.connection))

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
			s.postgresUser, s.postgresPassword, s.DatabaseName, s.LogLevel, s.Wool)
		if errNix != nil {
			return s.Runtime.InitError(errNix)
		}
		if errNix = nixpg.Init(ctx); errNix != nil {
			return s.Runtime.InitError(errNix)
		}
		s.nixRuntime = nixpg
		s.Wool.Debug("nix postgres init successful")
		return s.Runtime.InitResponse()
	}

	// Docker
	runner, err := runners.NewDockerHeadlessEnvironment(ctx, image, s.UniqueWithWorkspace())
	if err != nil {
		return s.Runtime.InitError(err)
	}

	runner.WithOutput(s.Wool)
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
	return s.Runtime.InitResponse()
}

func (s *Runtime) WaitForReady(ctx context.Context) error {
	defer s.Wool.Catch()
	ctx = s.Wool.Inject(ctx)

	s.Wool.Debug("waiting for ready", wool.Field("connection", s.connection))

	maxRetry := 30
	var lastErr error
	for retry := 0; retry < maxRetry; retry++ {
		db, err := sql.Open("postgres", s.connection)
		if err != nil {
			return s.Wool.Wrapf(err, "cannot open database")
		}

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
	runner, err := runners.NewDockerHeadlessEnvironment(ctx, image, s.UniqueWithWorkspace())
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
		}
	}
	return nil
}
