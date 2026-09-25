package main

import (
	"context"
	"net/url"
	"strings"
	"testing"

	basev0 "github.com/codefly-dev/core/generated/go/codefly/base/v0"
	builderv0 "github.com/codefly-dev/core/generated/go/codefly/services/builder/v0"
	"github.com/codefly-dev/core/resources"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/require"
)

// sampleRuntimePasswords are what a runtime password can be: generated hex,
// and operator-supplied values carrying every URL delimiter, a space, a plus,
// a percent, quotes, template delimiters and non-ASCII.
var sampleRuntimePasswords = []string{
	"4f3c2a1b0e9d8c7b6a5f4e3d2c1b0a99",
	"p@ss:w/rd?#[]",
	"with space+plus",
	"100%literal",
	`quote"'back\slash`,
	"{{ .inject }}",
	"$&,;=!*()",
	"unicodé-ß-密码",
}

// The restricted render hands every consumer a template, never a value: the
// role, address, database and sslmode as literals, and the password as a
// reference to this service's own runtime password — the primitive the store
// already holds for the bootstrap Job, and nothing else.
func TestRestrictedConnectionsAreTemplatesOverTheServicesOwnPasswords(t *testing.T) {
	builder, networkMappings := newDeploymentTestBuilder(t)
	references := promotablePostgresSecretReferences()
	response, err := builder.Deploy(context.Background(), promotableDeploymentRequest(t.TempDir(), networkMappings, references))
	require.NoError(t, err)
	require.Equal(t, builderv0.DeploymentStatus_SUCCESS, response.GetState().GetState(), response.GetState().GetMessage())

	readOnlyRole, readWriteRole := runtimeRoleNames(builder.DatabaseName)
	expected := map[string]struct{ role, password string }{
		readOnlyConnectionKey:  {readOnlyRole, "POSTGRES_READ_ONLY_PASSWORD"},
		readWriteConnectionKey: {readWriteRole, "POSTGRES_READ_WRITE_PASSWORD"},
	}
	values := response.GetConfiguration().GetInfos()[0].GetConfigurationValues()
	require.Len(t, values, len(expected))
	for _, value := range values {
		want, ok := expected[value.GetKey()]
		require.True(t, ok, "unexpected configuration value %q", value.GetKey())
		require.NoError(t, resources.ValidateTemplatedConfigurationValue(value))
		require.Empty(t, value.GetValue())

		var literals strings.Builder
		var referenced []*basev0.ConfigurationValueReference
		for _, segment := range value.GetTemplate().GetSegments() {
			if reference := segment.GetReference(); reference != nil {
				referenced = append(referenced, reference)
				continue
			}
			literals.WriteString(segment.GetLiteral())
		}
		require.Len(t, referenced, 1, "%s must reference exactly its own password", value.GetKey())
		require.Equal(t, "postgres", referenced[0].GetConfiguration())
		require.Equal(t, want.password, referenced[0].GetKey())
		require.Equal(t, basev0.ConfigurationValueEscape_CONFIGURATION_VALUE_ESCAPE_URL_USERINFO, referenced[0].GetEscape())
		// The referenced primitive is one the Deploy itself demanded a Secret
		// reference for, so the store the consumer's value is assembled from
		// already holds it.
		require.Contains(t, references, resources.ServiceSecretConfigurationKeyFromUnique(builder.Unique(), "postgres", want.password))

		require.Equal(t, "postgresql://"+want.role+":@postgres.example.com:5432/test", literals.String())
	}
}

func TestExternalIdentityConnectionsCarryNoTemplate(t *testing.T) {
	builder, networkMappings := newDeploymentTestBuilder(t)
	builder.AuthMode = authModeExternalIdentity
	response, err := builder.Deploy(context.Background(), promotableDeploymentRequest(t.TempDir(), networkMappings, nil))
	require.NoError(t, err)
	require.Equal(t, builderv0.DeploymentStatus_SUCCESS, response.GetState().GetState(), response.GetState().GetMessage())
	for _, value := range response.GetConfiguration().GetInfos()[0].GetConfigurationValues() {
		require.Nil(t, value.GetTemplate(), "%s: external identity holds no password to assemble from", value.GetKey())
	}
}

// Assembling the template reproduces the connection this agent renders when it
// holds the password itself: byte for byte for a generated password, and
// component for component — as both lib/pq's URL parser and pgx see it — for
// any password at all.
func TestConnectionTemplateAssemblesTheRenderedConnection(t *testing.T) {
	cases := []struct {
		address string
		withSSL bool
	}{
		{"store.platform.svc.cluster.local:5432", true},
		{"store.platform.svc.cluster.local:31544", false},
		{"localhost:5432", true},
		{"[fd00::1]:6432", true},
	}
	readOnlyRole, _ := runtimeRoleNames("accounts")
	for _, c := range cases {
		template := postgresConnectionTemplate(c.address, "accounts", readOnlyRole, "POSTGRES_READ_ONLY_PASSWORD", c.withSSL)
		require.NoError(t, resources.ValidateConfigurationValueTemplate(template))
		for _, password := range sampleRuntimePasswords {
			assembled, err := resources.EvaluateConfigurationValueTemplate(template, func(configuration, key string) (string, bool) {
				return password, configuration == "postgres" && key == "POSTGRES_READ_ONLY_PASSWORD"
			})
			require.NoError(t, err)
			rendered := postgresConnectionString(c.address, "accounts", readOnlyRole, password, c.withSSL, false)
			if strings.Trim(password, "0123456789abcdef") == "" {
				require.Equal(t, rendered, assembled)
			}

			assembledURL, err := url.Parse(assembled)
			require.NoError(t, err, "assembled %q", assembled)
			renderedURL, err := url.Parse(rendered)
			require.NoError(t, err)
			assembledPassword, _ := assembledURL.User.Password()
			require.Equal(t, password, assembledPassword)
			require.Equal(t, renderedURL.User.Username(), assembledURL.User.Username())
			require.Equal(t, renderedURL.Host, assembledURL.Host)
			require.Equal(t, renderedURL.Path, assembledURL.Path)
			require.Equal(t, renderedURL.Query(), assembledURL.Query())

			assembledConfig, err := pgconn.ParseConfig(assembled)
			require.NoError(t, err)
			renderedConfig, err := pgconn.ParseConfig(rendered)
			require.NoError(t, err)
			require.Equal(t, password, assembledConfig.Password)
			require.Equal(t, renderedConfig.User, assembledConfig.User)
			require.Equal(t, renderedConfig.Host, assembledConfig.Host)
			require.Equal(t, renderedConfig.Port, assembledConfig.Port)
			require.Equal(t, renderedConfig.Database, assembledConfig.Database)
			require.Equal(t, renderedConfig.TLSConfig == nil, assembledConfig.TLSConfig == nil)
			require.Equal(t, len(renderedConfig.Fallbacks), len(assembledConfig.Fallbacks))
		}
	}
}

// The restricted bootstrap Job pins sslmode exactly when the rendered owner
// connection would.
func TestRestrictedBootstrapJobPinsSSLModeOnlyWithoutSSL(t *testing.T) {
	builder, networkMappings := newDeploymentTestBuilder(t)
	builder.WithoutSSL = true
	destination := t.TempDir()
	response, err := builder.Deploy(context.Background(), promotableDeploymentRequest(destination, networkMappings, promotablePostgresSecretReferences()))
	require.NoError(t, err)
	require.Equal(t, builderv0.DeploymentStatus_SUCCESS, response.GetState().GetState(), response.GetState().GetMessage())
	job := readDeploymentFile(t, destination, "base", "job.yaml")
	require.Contains(t, job, "name: PGSSLMODE\n              value: \"disable\"")
	require.NotContains(t, job, migrationConnectionEnvironmentKey)
}
