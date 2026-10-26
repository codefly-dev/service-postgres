package main

import (
	"context"
	"database/sql"
	"github.com/codefly-dev/core/runners/dockerrun"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	basev0 "github.com/codefly-dev/core/generated/go/codefly/base/v0"
	runtimev0 "github.com/codefly-dev/core/generated/go/codefly/services/runtime/v0"
	"github.com/codefly-dev/core/resources"
	runners "github.com/codefly-dev/core/runners/base"
	"github.com/codefly-dev/core/shared"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

func localServerRequest(t *testing.T) (*Runtime, *runtimev0.InitRequest) {
	t.Helper()
	s := &Runtime{Service: newTestPostgresService()}
	s.LocalServer = "test/server"
	s.DatabaseName = "borrowed"
	s.postgresUser = "borrowed_owner"
	endpoint := &basev0.Endpoint{Module: "test", Service: "server", Name: "tcp", Api: "tcp"}
	instance := resources.NewNetworkInstance("localhost", 12345)
	instance.Access = resources.NewNativeNetworkAccess()
	provider := newTestPostgresService()
	provider.DatabaseName = "server"
	provider.SharedLocalServer = true
	c, err := provider.CreateConnectionConfiguration(context.Background(), testPostgresConfiguration("server_owner", "owner", "reader", "writer"), instance, false)
	require.NoError(t, err)
	c.Origin = "test/server"
	return s, &runtimev0.InitRequest{DependenciesNetworkMappings: []*basev0.NetworkMapping{{Endpoint: endpoint, Instances: []*basev0.NetworkInstance{instance}}}, DependenciesConfigurations: []*basev0.Configuration{c}}
}

func TestLocalServerRequiresResolvedOptInDependency(t *testing.T) {
	cases := map[string]func(*Runtime, *runtimev0.InitRequest){
		"missing mapping":       func(s *Runtime, r *runtimev0.InitRequest) { r.DependenciesNetworkMappings = nil },
		"missing configuration": func(s *Runtime, r *runtimev0.InitRequest) { r.DependenciesConfigurations = nil },
		"wrong origin":          func(s *Runtime, r *runtimev0.InitRequest) { r.DependenciesConfigurations[0].Origin = "other/server" },
		"missing opt in": func(s *Runtime, r *runtimev0.InitRequest) {
			r.DependenciesConfigurations[0].Infos[0].ConfigurationValues = nil
		},
		"wrong address": func(s *Runtime, r *runtimev0.InitRequest) {
			r.DependenciesNetworkMappings[0].Instances[0].Address = "other:12345"
		},
		"no native mapping": func(s *Runtime, r *runtimev0.InitRequest) {
			r.DependenciesNetworkMappings[0].Instances[0].Access = resources.NewContainerNetworkAccess()
		},
		"duplicate mapping": func(s *Runtime, r *runtimev0.InitRequest) {
			r.DependenciesNetworkMappings = append(r.DependenciesNetworkMappings, r.DependenciesNetworkMappings[0])
		},
		"duplicate configuration": func(s *Runtime, r *runtimev0.InitRequest) {
			r.DependenciesConfigurations = append(r.DependenciesConfigurations, r.DependenciesConfigurations[0])
		},
		"same owner":              func(s *Runtime, r *runtimev0.InitRequest) { s.postgresUser = "server_owner" },
		"same database":           func(s *Runtime, r *runtimev0.InitRequest) { s.DatabaseName = "server" },
		"system database":         func(s *Runtime, r *runtimev0.InitRequest) { s.DatabaseName = "postgres" },
		"truncated database":      func(s *Runtime, r *runtimev0.InitRequest) { s.DatabaseName = strings.Repeat("a", 64) },
		"custom image":            func(s *Runtime, r *runtimev0.InitRequest) { s.Image = "different:18" },
		"identity authentication": func(s *Runtime, r *runtimev0.InitRequest) { s.AuthMode = authModeExternalIdentity },
		"keep running":            func(s *Runtime, r *runtimev0.InitRequest) { s.KeepRunning = true },
		"self":                    func(s *Runtime, r *runtimev0.InitRequest) { s.LocalServer = s.Unique() },
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			s, r := localServerRequest(t)
			change(s, r)
			_, _, err := s.resolveLocalServer(context.Background(), r)
			require.Error(t, err)
		})
	}
	s, r := localServerRequest(t)
	_, connection, err := s.resolveLocalServer(context.Background(), r)
	require.NoError(t, err)
	require.NotEmpty(t, connection)
}

func TestLocalServerConfigurationNeverForwardsBootstrap(t *testing.T) {
	s := newTestPostgresService()
	s.DatabaseName = "borrower"
	s.LocalServer = "test/server"
	instance := resources.NewNetworkInstance("localhost", 12345)
	instance.Access = resources.NewNativeNetworkAccess()
	c, err := s.CreateConnectionConfiguration(context.Background(), testPostgresConfiguration("owner", "owner-password", "reader-password", "writer-password"), instance, false)
	require.NoError(t, err)
	require.Empty(t, configurationValue(t, c, localServerConnectionKey))
	require.NotEmpty(t, configurationValue(t, c, readOnlyConnectionKey))
}

// Uses the actual generated lifecycle request/response types and exported
// dependency configurations, with one real server and two independently
// migrated logical services. No fixed database address or credential lookup.
func TestLocalServerLifecycleNix(t *testing.T) {
	if !runners.CheckNixInstalled() || !runners.IsNixSupported() {
		t.Skip("nix not installed/supported")
	}
	assertLocalServerLifecycle(t, resources.NewRuntimeContextNix())
}

func TestLocalServerLifecycleDocker(t *testing.T) {
	_, err := dockerrun.NewDockerHeadlessEnvironment(context.Background(), testRuntimeImage(t), uniqueDockerName("shared-server-prerequisite"))
	if err != nil {
		if os.Getenv(testRuntimeImageEnv) == "" && dockerDaemonUnavailable(err) {
			t.Skip("docker daemon unavailable")
		}
		t.Fatal(err)
	}
	assertLocalServerLifecycle(t, resources.NewRuntimeContextContainer())
}

func assertLocalServerLifecycle(t *testing.T, runtimeContext *basev0.RuntimeContext) {
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	serverFixture := newPostgresFixture(t, ctx, runtimeContext)
	load := func(f *postgresFixture, localServer string) *Runtime {
		s := NewRuntime()
		_, err := s.Load(ctx, &runtimev0.LoadRequest{Identity: f.identity, Environment: shared.Must(f.environment.Proto()), DisableCatch: true})
		require.NoError(t, err)
		s.DatabaseName = f.serviceName
		s.LocalServer = localServer
		s.SharedLocalServer = localServer == ""
		if localServer == "" && runtimeContext.Kind == resources.RuntimeContextContainer {
			s.Image = testRuntimeImage(t).String()
		}
		return s
	}
	request := func(f *postgresFixture, provider *runtimev0.InitResponse) *runtimev0.InitRequest {
		r := &runtimev0.InitRequest{RuntimeContext: f.runtimeContext, Configuration: f.configuration, ProposedNetworkMappings: f.networkMappings}
		if provider != nil {
			r.DependenciesNetworkMappings = provider.NetworkMappings
			r.DependenciesConfigurations = provider.RuntimeConfigurations
		}
		return r
	}
	initOK := func(s *Runtime, r *runtimev0.InitRequest) *runtimev0.InitResponse {
		result, err := s.Init(ctx, r)
		require.NoError(t, err)
		require.Equal(t, runtimev0.InitStatus_READY, result.GetStatus().GetState(), result.GetStatus().GetMessage())
		return result
	}
	startOK := func(s *Runtime) {
		r, err := s.Start(ctx, &runtimev0.StartRequest{})
		require.NoError(t, err)
		require.Equal(t, runtimev0.StartStatus_STARTED, r.GetStatus().GetState(), r.GetStatus().GetMessage())
	}
	server := load(serverFixture, "")
	provider := initOK(server, request(serverFixture, nil))
	startOK(server)
	t.Cleanup(func() { _, _ = server.Destroy(context.Background(), &runtimev0.DestroyRequest{}) })
	fixtures := []*postgresFixture{newPostgresFixture(t, ctx, runtimeContext), newPostgresFixture(t, ctx, runtimeContext)}
	borrowers := make([]*Runtime, 2)
	responses := make([]*runtimev0.InitResponse, 2)
	errs := make([]error, 2)
	for i, f := range fixtures {
		f.configuration.Infos[0].ConfigurationValues[0].Value = f.serviceName + "_owner"
		borrowers[i] = load(f, server.Unique())
	}
	var wg sync.WaitGroup
	for i := range borrowers {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			responses[i], errs[i] = borrowers[i].Init(ctx, request(fixtures[i], provider))
		}(i)
	}
	wg.Wait()
	const sentinel = "00000000-0000-0000-0000-000000000193"
	for i, s := range borrowers {
		require.NoError(t, errs[i])
		require.Equal(t, runtimev0.InitStatus_READY, responses[i].GetStatus().GetState(), responses[i].GetStatus().GetMessage())
		startOK(s)
		require.Nil(t, s.nixRuntime)
		require.Nil(t, s.runnerEnvironment)
		native := resources.FilterNetworkInstance(ctx, responses[i].NetworkMappings[0].Instances, resources.NewNativeNetworkAccess())
		require.Equal(t, serverFixture.address, native.Address)
		require.Equal(t, fixtures[i].identity.Name, responses[i].NetworkMappings[0].Endpoint.Service)
		writeSentinel(t, ctx, s.connection, fixtures[i].serviceName, sentinel)
	}
	reader := func(i int) string {
		configs := resources.FilterConfigurations(responses[i].RuntimeConfigurations, resources.NewRuntimeContextNative())
		require.Len(t, configs, 1)
		return configurationValue(t, configs[0], readOnlyConnectionKey)
	}
	for i := range borrowers {
		require.True(t, hasSentinel(t, ctx, reader(i), fixtures[i].serviceName, sentinel))
		for _, target := range []string{borrowers[1-i].DatabaseName, server.DatabaseName} {
			u, err := url.Parse(reader(i))
			require.NoError(t, err)
			u.Path = "/" + target
			db, err := sql.Open("postgres", u.String())
			require.NoError(t, err)
			err = db.PingContext(ctx)
			db.Close()
			require.ErrorContains(t, err, "permission denied for database")
		}
	}

	// Respect the existing lock budget/cancellation rather than waiting forever
	// behind a peer. Releasing that peer permits an unchanged retry.
	bootstrap := configurationValue(t, resources.FilterConfigurations(provider.RuntimeConfigurations, resources.NewRuntimeContextNative())[0], localServerConnectionKey)
	blockerDB, err := sql.Open("postgres", bootstrap)
	require.NoError(t, err)
	defer blockerDB.Close()
	blocker, err := blockerDB.Conn(ctx)
	require.NoError(t, err)
	defer blocker.Close()
	_, err = blocker.ExecContext(ctx, `SELECT pg_advisory_lock(193, 1)`)
	require.NoError(t, err)
	retry := load(fixtures[0], server.Unique())
	short, cancelShort := context.WithTimeout(ctx, 100*time.Millisecond)
	blocked, err := retry.Init(short, request(fixtures[0], provider))
	cancelShort()
	require.NoError(t, err)
	require.Equal(t, runtimev0.InitStatus_ERROR, blocked.GetStatus().GetState())
	require.Contains(t, blocked.GetStatus().GetMessage(), "role allocation lock")
	_, err = blocker.ExecContext(ctx, `SELECT pg_advisory_unlock(193, 1)`)
	require.NoError(t, err)
	require.NoError(t, blocker.Close())
	require.NoError(t, blockerDB.Close())
	initOK(retry, request(fixtures[0], provider))
	_, err = retry.Destroy(ctx, &runtimev0.DestroyRequest{})
	require.NoError(t, err)
	// A role collision fails before changing the peer's credentials or data.
	conflicting := load(fixtures[1], server.Unique())
	conflictRequest := request(fixtures[1], provider)
	conflictRequest.Configuration = proto.Clone(conflictRequest.Configuration).(*basev0.Configuration)
	conflictRequest.Configuration.Infos[0].ConfigurationValues[0].Value = borrowers[0].postgresUser
	refused, err := conflicting.Init(ctx, conflictRequest)
	require.NoError(t, err)
	require.Equal(t, runtimev0.InitStatus_ERROR, refused.GetStatus().GetState())
	require.Contains(t, refused.GetStatus().GetMessage(), "already claimed")
	require.True(t, hasSentinel(t, ctx, reader(0), fixtures[0].serviceName, sentinel))
	for _, s := range borrowers {
		_, err := s.Stop(ctx, &runtimev0.StopRequest{})
		require.NoError(t, err)
		_, err = s.Destroy(ctx, &runtimev0.DestroyRequest{})
		require.NoError(t, err)
		requireListener(t, serverFixture.address)
	}
	// The server owner alone releases the process; a later whole composition
	// start sees both databases and their migration ledgers unchanged.
	_, err = server.Stop(ctx, &runtimev0.StopRequest{})
	require.NoError(t, err)
	requireNoListener(t, serverFixture.address)
	server = load(serverFixture, "")
	provider = initOK(server, request(serverFixture, nil))
	startOK(server)
	for _, f := range fixtures {
		s := load(f, server.Unique())
		initOK(s, request(f, provider))
		startOK(s)
		require.True(t, hasSentinel(t, ctx, s.connection, f.serviceName, sentinel))
		_, err = s.Destroy(ctx, &runtimev0.DestroyRequest{})
		require.NoError(t, err)
	}
}

func TestLocalServerClaimsNormalizedRoleNames(t *testing.T) {
	s := &Runtime{Service: newTestPostgresService()}
	s.DatabaseName = "accounts"
	s.postgresUser = "accounts_owner"
	s.RuntimeReadWriteRoles = []string{" accounts_writer ", "accounts_writer"}
	roles, err := s.localDatabaseRoles()
	require.NoError(t, err)
	require.Contains(t, roles, "accounts_writer")
	require.NotContains(t, roles, " accounts_writer ")
	require.Len(t, roles, 4)
}
