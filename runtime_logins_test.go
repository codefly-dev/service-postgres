package main

import (
	"context"
	"net/url"
	"strings"
	"testing"

	basev0 "github.com/codefly-dev/core/generated/go/codefly/base/v0"
	builderv0 "github.com/codefly-dev/core/generated/go/codefly/services/builder/v0"
	"github.com/codefly-dev/core/resources"
	"github.com/stretchr/testify/require"
)

func maintenanceLogin() []RuntimeLogin {
	return []RuntimeLogin{{Name: "maintenance", ReadWriteRoles: []string{"app_runtime"}}}
}

// A declared login resolves to its own role under the database's managed
// prefix, its own password and connection keys, and its own role set.
func TestRuntimeLoginsResolveToTheirOwnPrincipal(t *testing.T) {
	settings := &Settings{
		DatabaseName:          "runtime",
		RuntimeReadWriteRoles: []string{"app_runtime_request"},
		RuntimeLogins:         maintenanceLogin(),
	}
	logins, err := resolveRuntimeLogins(settings)
	require.NoError(t, err)
	require.Len(t, logins, 1)
	readOnlyRole, readWriteRole := runtimeRoleNames("runtime")
	login := logins[0]
	require.Equal(t, strings.TrimSuffix(readWriteRole, "_rw")+"_maintenance", login.role)
	require.NotEqual(t, readOnlyRole, login.role)
	require.NotEqual(t, readWriteRole, login.role)
	require.LessOrEqual(t, len(login.role), 63)
	require.Equal(t, "POSTGRES_MAINTENANCE_PASSWORD", login.passwordKey)
	require.Equal(t, "maintenance-connection", login.connectionKey)
	require.Equal(t, []string{"app_runtime"}, login.readWriteRoles)
}

func TestRuntimeLoginsRefuseWhatARenderCannotCarry(t *testing.T) {
	long := strings.Repeat("a", maxRuntimeLoginNameLength+1)
	for name, settings := range map[string]*Settings{
		"empty name":             {DatabaseName: "db", RuntimeLogins: []RuntimeLogin{{Name: "", ReadWriteRoles: []string{"app"}}}},
		"upper case":             {DatabaseName: "db", RuntimeLogins: []RuntimeLogin{{Name: "Worker", ReadWriteRoles: []string{"app"}}}},
		"leading digit":          {DatabaseName: "db", RuntimeLogins: []RuntimeLogin{{Name: "1worker", ReadWriteRoles: []string{"app"}}}},
		"trailing dash":          {DatabaseName: "db", RuntimeLogins: []RuntimeLogin{{Name: "worker-", ReadWriteRoles: []string{"app"}}}},
		"underscore":             {DatabaseName: "db", RuntimeLogins: []RuntimeLogin{{Name: "a_b", ReadWriteRoles: []string{"app"}}}},
		"too long":               {DatabaseName: "db", RuntimeLogins: []RuntimeLogin{{Name: long, ReadWriteRoles: []string{"app"}}}},
		"reserved read-write":    {DatabaseName: "db", RuntimeLogins: []RuntimeLogin{{Name: "read-write", ReadWriteRoles: []string{"app"}}}},
		"reserved owner":         {DatabaseName: "db", RuntimeLogins: []RuntimeLogin{{Name: "owner", ReadWriteRoles: []string{"app"}}}},
		"duplicate":              {DatabaseName: "db", RuntimeLogins: []RuntimeLogin{{Name: "worker", ReadWriteRoles: []string{"a"}}, {Name: "worker", ReadWriteRoles: []string{"b"}}}},
		"no delegated role":      {DatabaseName: "db", RuntimeLogins: []RuntimeLogin{{Name: "worker"}}},
		"unsafe role":            {DatabaseName: "db", RuntimeLogins: []RuntimeLogin{{Name: "worker", ReadWriteRoles: []string{"app; DROP"}}}},
		"managed role as target": {DatabaseName: "db", RuntimeLogins: []RuntimeLogin{{Name: "worker", ReadWriteRoles: []string{managedReadWriteRole("db")}}}},
		"external identity":      {DatabaseName: "db", AuthMode: authModeExternalIdentity, RuntimeLogins: []RuntimeLogin{{Name: "worker", ReadWriteRoles: []string{"app"}}}},
		"external instance": {DatabaseName: "db", ExternalInstances: map[string]ExternalInstance{"prod": {Host: "db.example.com"}},
			RuntimeLogins: []RuntimeLogin{{Name: "worker", ReadWriteRoles: []string{"app"}}}},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := resolveRuntimeLogins(settings)
			require.Error(t, err)
		})
	}
}

func managedReadWriteRole(database string) string {
	_, readWrite := runtimeRoleNames(database)
	return readWrite
}

// Locally the login's password is its own primitive when configured and a
// domain-separated derivation of the owner secret otherwise; either way it is
// exported as <name>-connection naming the login's own role.
func TestLocalConnectionConfigurationExportsEachLogin(t *testing.T) {
	for name, configured := range map[string]string{"configured": "maintenance-secret", "derived": ""} {
		t.Run(name, func(t *testing.T) {
			svc := newTestPostgresService()
			svc.DatabaseName = "runtime"
			svc.RuntimeReadWriteRoles = []string{"app_runtime_request"}
			svc.RuntimeLogins = maintenanceLogin()
			conf := testPostgresConfiguration("migration-owner", "owner-secret", "reader-secret", "writer-secret")
			if configured != "" {
				conf.Infos[0].ConfigurationValues = append(conf.Infos[0].ConfigurationValues,
					&basev0.ConfigurationValue{Key: "POSTGRES_MAINTENANCE_PASSWORD", Value: configured})
			}
			configuration, err := svc.CreateConnectionConfiguration(context.Background(), conf,
				&basev0.NetworkInstance{Address: "localhost:5432", Access: resources.NewNativeNetworkAccess()}, false)
			require.NoError(t, err)
			logins, err := svc.runtimeLogins()
			require.NoError(t, err)
			want := configured
			if want == "" {
				want = deriveRuntimePassword("owner-secret", "runtime", "maintenance-connection")
			}
			assertConnectionIdentity(t, configurationValue(t, configuration, "maintenance-connection"), logins[0].role, want)
			// The managed read-write login is unchanged by the declaration.
			_, readWriteRole := runtimeRoleNames("runtime")
			assertConnectionIdentity(t, configurationValue(t, configuration, readWriteConnectionKey), readWriteRole, "writer-secret")
		})
	}
}

func TestLoginPasswordsMustBeDistinct(t *testing.T) {
	svc := newTestPostgresService()
	svc.DatabaseName = "runtime"
	svc.RuntimeLogins = maintenanceLogin()
	conf := testPostgresConfiguration("migration-owner", "owner-secret", "reader-secret", "writer-secret")
	conf.Infos[0].ConfigurationValues = append(conf.Infos[0].ConfigurationValues,
		&basev0.ConfigurationValue{Key: "POSTGRES_MAINTENANCE_PASSWORD", Value: "writer-secret"})
	require.ErrorContains(t, svc.LoadConfiguration(context.Background(), conf), "distinct")
}

// The restricted render stores only primitives: the login's connection is a
// template over its own password, and the Deploy demands a Secret reference
// for that password and hands it to the bootstrap Job that sets it.
func TestRestrictedRenderTemplatesEachLoginOverItsOwnPassword(t *testing.T) {
	builder, networkMappings := newDeploymentTestBuilder(t)
	builder.RuntimeReadWriteRoles = []string{"app_runtime_request"}
	builder.RuntimeLogins = maintenanceLogin()
	references := promotablePostgresSecretReferences()
	passwordKey := resources.ServiceSecretConfigurationKeyFromUnique("module/postgres", "postgres", "POSTGRES_MAINTENANCE_PASSWORD")

	// Without the login's primitive the render is refused, naming it.
	destination := t.TempDir()
	response, err := builder.Deploy(context.Background(), promotableDeploymentRequest(destination, networkMappings, references))
	require.NoError(t, err)
	require.Equal(t, builderv0.DeploymentStatus_ERROR, response.GetState().GetState())
	require.Contains(t, response.GetState().GetMessage(), "POSTGRES_MAINTENANCE_PASSWORD")

	references[passwordKey] = &builderv0.KubernetesSecretKeyReference{Name: "postgres-secrets", Key: passwordKey}
	destination = t.TempDir()
	response, err = builder.Deploy(context.Background(), promotableDeploymentRequest(destination, networkMappings, references))
	require.NoError(t, err)
	require.Equal(t, builderv0.DeploymentStatus_SUCCESS, response.GetState().GetState(), response.GetState().GetMessage())

	logins, err := builder.runtimeLogins()
	require.NoError(t, err)
	var login *basev0.ConfigurationValue
	for _, value := range response.GetConfiguration().GetInfos()[0].GetConfigurationValues() {
		if value.GetKey() == "maintenance-connection" {
			login = value
		}
	}
	require.NotNil(t, login, "the login's connection is exported")
	require.Empty(t, login.GetValue())
	require.NoError(t, resources.ValidateTemplatedConfigurationValue(login))
	var literals strings.Builder
	var referenced []*basev0.ConfigurationValueReference
	for _, segment := range login.GetTemplate().GetSegments() {
		if reference := segment.GetReference(); reference != nil {
			referenced = append(referenced, reference)
			continue
		}
		literals.WriteString(segment.GetLiteral())
	}
	require.Len(t, referenced, 1)
	require.Equal(t, "POSTGRES_MAINTENANCE_PASSWORD", referenced[0].GetKey())
	require.Equal(t, "postgresql://"+logins[0].role+":@postgres.example.com:5432/test?sslmode=disable", literals.String())

	job := readDeploymentFile(t, destination, "base", "job.yaml")
	require.Contains(t, job, "name: POSTGRES_MAINTENANCE_PASSWORD")
}

func TestRuntimeAccessTemplateProvisionsEachLoginWithItsOwnRoles(t *testing.T) {
	parameters := testBootstrapTemplating()
	parameters.Schemas = []string{"public"}
	parameters.ReadWriteRoles = []string{"app_runtime_request"}
	parameters.DefaultReadWriteRole = "app_runtime_request"
	parameters.Logins = []BootstrapLogin{{
		Role:             "codefly_app_maintenance",
		PasswordVariable: "POSTGRES_MAINTENANCE_PASSWORD",
		ReadWriteRoles:   []string{"app_runtime"},
		DefaultRole:      "app_runtime",
	}}
	accessSQL := renderRuntimeAccessTemplate(t, parameters)
	for _, required := range []string{
		`\getenv login_0_password POSTGRES_MAINTENANCE_PASSWORD`,
		`'codefly_app_maintenance', :'login_0_password'`,
		`EXECUTE format('GRANT %I TO %I', 'app_runtime', 'codefly_app_maintenance');`,
		`SELECT format('ALTER ROLE %I SET role = %L', 'codefly_app_maintenance', 'app_runtime')`,
		`WHERE principal.rolname = 'codefly_app_maintenance'`,
	} {
		require.Contains(t, accessSQL, required)
	}
	// The login never receives the managed login's role, nor direct DML.
	require.NotContains(t, accessSQL, `EXECUTE format('GRANT %I TO %I', 'app_runtime_request', 'codefly_app_maintenance');`)
	require.NotContains(t, accessSQL, "GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES")
	// Everything runs inside the one locked transaction.
	require.Less(t, strings.Index(accessSQL, "codefly_app_maintenance"), strings.LastIndex(accessSQL, "COMMIT;"))
}

// TestDeclaredRuntimeLoginIsSeparateFromTheReadWriteLoginDocker reconciles a
// real server: the managed read-write login and a declared login each write
// through their own delegated role by default, and neither can assume the
// other's. That separation is the whole point of declaring a second login.
func TestDeclaredRuntimeLoginIsSeparateFromTheReadWriteLoginDocker(t *testing.T) {
	ctx := context.Background()
	fixture := newPostgresFixture(t, ctx, resources.NewRuntimeContextContainer())
	runtime, init := fixture.start(t, ctx)
	relation := fixture.serviceName

	owner, err := openPostgresCapabilityProbe(ctx, runtime.connection)
	require.NoError(t, err)
	defer owner.Close()
	const requestRole, maintenanceRole = "app_request", "app_maintenance"
	require.NoError(t, owner.InstallDelegatedWriteRole(ctx, requestRole, relation))
	require.NoError(t, owner.InstallDelegatedWriteRole(ctx, maintenanceRole, relation))

	runtime.RuntimeReadWriteRoles = []string{requestRole}
	runtime.RuntimeLogins = []RuntimeLogin{{Name: "maintenance", ReadWriteRoles: []string{maintenanceRole}}}
	runtime.loginPasswords = map[string]string{"maintenance": "maintenance-password"}
	require.NoError(t, runtime.ensureRuntimeAccess(ctx))
	// Reconciling twice is a fixed point.
	require.NoError(t, runtime.ensureRuntimeAccess(ctx))

	configuration, err := resources.ExtractConfiguration(init.RuntimeConfigurations, resources.NewRuntimeContextNative())
	require.NoError(t, err)
	readWriteConnection, err := resources.GetConfigurationValue(ctx, configuration, "postgres", readWriteConnectionKey)
	require.NoError(t, err)
	logins, err := runtime.runtimeLogins()
	require.NoError(t, err)
	parsed, err := url.Parse(readWriteConnection)
	require.NoError(t, err)
	parsed.User = url.UserPassword(logins[0].role, "maintenance-password")
	maintenanceConnection := parsed.String()

	maintenance, err := openPostgresCapabilityProbe(ctx, maintenanceConnection)
	require.NoError(t, err)
	defer maintenance.Close()
	require.NoError(t, maintenance.AppendFixture(ctx, relation, "20000000-0000-0000-0000-000000000001"),
		"the declared login writes through its own default role")
	require.Error(t, maintenance.AppendFixtureAsRole(ctx, requestRole, relation, "20000000-0000-0000-0000-000000000002"),
		"the declared login must not assume the read-write login's role")
	require.Error(t, maintenance.CreateRelation(ctx, "maintenance_escape"), "the declared login must not create schema objects")

	writer, err := openPostgresCapabilityProbe(ctx, readWriteConnection)
	require.NoError(t, err)
	defer writer.Close()
	require.NoError(t, writer.AppendFixture(ctx, relation, "20000000-0000-0000-0000-000000000003"),
		"the read-write login keeps its own default role")
	require.Error(t, writer.AppendFixtureAsRole(ctx, maintenanceRole, relation, "20000000-0000-0000-0000-000000000004"),
		"the read-write login must not assume the declared login's role")
}
