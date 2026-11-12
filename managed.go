package main

import (
	"context"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/fs"
	"regexp"
	"slices"
	"strings"

	"cloud.google.com/go/cloudsqlconn/instance"
	"github.com/codefly-dev/core/agents/services"
	v0 "github.com/codefly-dev/core/generated/go/codefly/base/v0"
	builderv0 "github.com/codefly-dev/core/generated/go/codefly/services/builder/v0"
	"github.com/codefly-dev/core/shared"
	postgres "github.com/codefly-dev/service-postgres/libs/go"
	"github.com/codefly-dev/service-postgres/libs/go/bootstrap"
)

// Managed mode — the owner's rule (2026-11-12): "for postgres service in
// codefly, we should have 'managed' vs non-managed, so when render a managed, we
// ONLY render and build the migration so we are SURE we don't deploy PG in k8s".
//
// The mode is the ENVIRONMENT's declaration: its managed-services entry for this
// store, which the CLI hands this agent's Deploy as the `managed-service`
// configuration information (codefly-dev/cli#1346). It is never a service
// setting, because the same store is a composed server on a laptop and a cloud
// instance in a cell.
//
// It is held structurally, not by a flag inside one template set: a managed
// Deploy renders from managedDeploymentFS, which contains the migration Job and
// nothing else, and never calls prepareDeployment or reads deploymentFS. No code
// on this path can emit a StatefulSet, a Service, a Secret, a volume claim or the
// server image, because none of those templates is reachable from it.
const (
	managedServiceInformation = "managed-service"
	// Key names are chosen so no configuration classifier reads them as
	// credentials (none of these values is one): the entry's `auth-mode` and
	// `instance-connection-name` arrive as `login-mode` and `instance`.
	managedAuthModeKey = "login-mode"
	managedInstanceKey = "instance"
	managedOwnerKey    = "owner-principal"
	managedRuntimeKey  = "runtime-principals"

	// managedAuthMode is the one managed mode: the cloud issues every login's
	// credential, and no password exists to seed, store or rotate.
	managedAuthMode = authModeExternalIdentity
)

//go:embed templates/managed/templates/deployment
var managedDeploymentRaw embed.FS

// managedDeploymentFS is the managed template set rooted where the deployment
// renderer looks ("templates/deployment/kustomize").
var managedDeploymentFS = shared.Must(fs.Sub(managedDeploymentRaw, "templates/managed"))

const managedJobTemplatePath = "templates/deployment/kustomize/base/job.yaml.tmpl"

// gcpServiceAccountEmail is the shape of a principal the environment names: a
// service account, whose Cloud SQL login is the email without its suffix.
var gcpServiceAccountEmail = regexp.MustCompile(`^[a-z][a-z0-9-]{4,28}[a-z0-9]@[a-z0-9][a-z0-9.:-]{4,28}[a-z0-9]\.iam\.gserviceaccount\.com$`)

// managedDeployment is the environment's statement about this store.
type managedDeployment struct {
	Instance      string
	OwnerLogin    string
	RuntimeLogins []string
}

// managedDeploymentOf reads the environment's managed-service declaration from
// the Deploy request. Absent, the store is composed in the cluster; present, it
// is managed and every value must be there — a declaration missing one is
// refused by name rather than falling back to deploying a server.
func managedDeploymentOf(configuration *v0.Configuration) (*managedDeployment, error) {
	var declared *v0.ConfigurationInformation
	for _, information := range configuration.GetInfos() {
		if information.GetName() != managedServiceInformation {
			continue
		}
		if declared != nil {
			return nil, fmt.Errorf("the environment declares %s twice for this store", managedServiceInformation)
		}
		declared = information
	}
	if declared == nil {
		return nil, nil
	}
	values := map[string]string{}
	for _, value := range declared.GetConfigurationValues() {
		values[value.GetKey()] = strings.TrimSpace(value.GetValue())
	}
	for _, key := range []string{managedAuthModeKey, managedInstanceKey, managedOwnerKey, managedRuntimeKey} {
		if values[key] == "" {
			return nil, fmt.Errorf("the environment declares this store managed but its %s has no %s: a managed store renders its migration and nothing else, so it is refused rather than deployed in the cluster", managedServiceInformation, key)
		}
	}
	if values[managedAuthModeKey] != managedAuthMode {
		return nil, fmt.Errorf("managed store %s %q: the only managed mode is %q, where the cloud issues every credential", managedAuthModeKey, values[managedAuthModeKey], managedAuthMode)
	}
	if _, err := instance.ParseConnName(values[managedInstanceKey]); err != nil {
		return nil, fmt.Errorf("managed store %s %q is not a project:region:instance connection name", managedInstanceKey, values[managedInstanceKey])
	}
	owner, err := cloudSQLLogin(managedOwnerKey, values[managedOwnerKey])
	if err != nil {
		return nil, err
	}
	managed := &managedDeployment{Instance: values[managedInstanceKey], OwnerLogin: owner}
	for _, principal := range strings.Split(values[managedRuntimeKey], ",") {
		login, err := cloudSQLLogin(managedRuntimeKey, strings.TrimSpace(principal))
		if err != nil {
			return nil, err
		}
		if login == owner || slices.Contains(managed.RuntimeLogins, login) {
			return nil, fmt.Errorf("managed store %s names %q twice or as the migration owner: each login is distinct", managedRuntimeKey, login)
		}
		managed.RuntimeLogins = append(managed.RuntimeLogins, login)
	}
	slices.Sort(managed.RuntimeLogins)
	return managed, nil
}

func cloudSQLLogin(key, email string) (string, error) {
	if !gcpServiceAccountEmail.MatchString(email) {
		return "", fmt.Errorf("managed store %s %q is not a service account principal", key, email)
	}
	return strings.TrimSuffix(email, ".gserviceaccount.com"), nil
}

// ManagedDeploymentParameters is everything the managed Job renders from.
type ManagedDeploymentParameters struct {
	BootstrapJobName            string
	BootstrapJobDeadlineSeconds int
	Instance                    string
	ExternalIdentity            string
	// Binding is the managed-bootstrap binding as one JSON value.
	Binding string
}

// deployManaged renders the migration Job for a managed store, and hands its
// dependents the connection: the database, reached through the connector as
// each dependent's own login, so there is no host, login or password to hand.
func (s *Builder) deployManaged(ctx context.Context, req *builderv0.DeploymentRequest, managed *managedDeployment) (*builderv0.DeploymentResponse, error) {
	binding, err := s.managedBinding(managed)
	if err != nil {
		return s.Builder.DeployError(err)
	}
	parameters := &ManagedDeploymentParameters{
		BootstrapJobDeadlineSeconds: s.Settings.Timeouts.BootstrapJobSeconds(),
		Instance:                    managed.Instance,
		ExternalIdentity:            postgres.IssuerGCPCloudSQL,
		Binding:                     binding,
	}
	var restrictedConfiguration *v0.Configuration
	response, err := s.Builder.DeployKustomize(ctx, req, services.KustomizeDeployment{
		EnvironmentVariables: s.EnvironmentVariables,
		Templates:            managedDeploymentFS,
		Parameters:           parameters,
		Prepare: func(ctx context.Context, deployment *services.KustomizeDeploymentContext) error {
			name, nameErr := s.immutableJobName(deployment, managedDeploymentFS, managedJobTemplatePath, parameters)
			if nameErr != nil {
				return nameErr
			}
			parameters.BootstrapJobName = name
			configuration := s.managedConnectionConfiguration()
			if restrictedOutput(deployment.Profile) {
				restrictedConfiguration = configuration
				return nil
			}
			return deployment.ExportConfiguration(ctx, configuration)
		},
	})
	if err != nil || response.GetState().GetState() != builderv0.DeploymentStatus_SUCCESS || restrictedConfiguration == nil {
		return response, err
	}
	response.Configuration = restrictedConfiguration
	return response, nil
}

// managedBinding is the binding managed-bootstrap verifies before it connects:
// the exact plan the image carries (computed the way Build stages it), the
// migration owner, and the runtime logins granted read-write access.
func (s *Builder) managedBinding(managed *managedDeployment) (string, error) {
	prerequisites, err := s.resolveSchemaPrerequisites()
	if err != nil {
		return "", err
	}
	plan, err := buildSchemaPlan(prerequisites, s.Settings)
	if err != nil {
		return "", err
	}
	if err = plan.attest(); err != nil {
		return "", err
	}
	artifact, err := planArtifactBytes(plan)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(artifact)
	encoded, err := json.Marshal(bootstrap.Binding{
		PlanSHA256:          hex.EncodeToString(digest[:]),
		PlanDigest:          plan.artifact().Digest,
		OwnerRole:           managed.OwnerLogin,
		ReadOnlyPrincipals:  []string{},
		ReadWritePrincipals: managed.RuntimeLogins,
	})
	if err != nil {
		return "", err
	}
	return string(encoded), nil
}

// managedConnectionConfiguration is what dependents are handed: the database
// alone. The connector reaches the instance and logs in as the dependent's own
// identity, so no host, login or password belongs in it.
func (s *Builder) managedConnectionConfiguration() *v0.Configuration {
	connection := "postgres:///" + s.DatabaseName
	values := []*v0.ConfigurationValue{
		{Key: readOnlyConnectionKey, Value: connection, Secret: true},
		{Key: readWriteConnectionKey, Value: connection, Secret: true},
	}
	logins, _ := s.runtimeLogins()
	for _, login := range logins {
		values = append(values, &v0.ConfigurationValue{Key: login.connectionKey, Value: connection, Secret: true})
	}
	return &v0.Configuration{
		Origin: s.Unique(),
		Infos:  []*v0.ConfigurationInformation{{Name: "postgres", ConfigurationValues: values}},
	}
}
