package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"fmt"
	"io/fs"
	"strings"
	"text/template"

	"github.com/codefly-dev/core/agents/communicate"
	dockerhelpers "github.com/codefly-dev/core/agents/helpers/docker"
	v0 "github.com/codefly-dev/core/generated/go/codefly/base/v0"
	"github.com/codefly-dev/core/resources"
	"github.com/codefly-dev/core/standards"
	"github.com/codefly-dev/core/wool"

	"github.com/codefly-dev/core/agents/services"
	"github.com/codefly-dev/core/agents/services/upgrade"
	builderv0 "github.com/codefly-dev/core/generated/go/codefly/services/builder/v0"
	"github.com/codefly-dev/core/shared"
	"gopkg.in/yaml.v3"
)

type Builder struct {
	services.BuilderServer
	*Service
}

func NewBuilder() *Builder {
	return &Builder{
		Service: NewService(),
	}
}

func (s *Builder) Load(ctx context.Context, req *builderv0.LoadRequest) (*builderv0.LoadResponse, error) {
	defer s.Wool.Catch()

	return s.Builder.LoadService(ctx, req, services.BuilderLoad{
		Settings:         s.Settings,
		Requirements:     requirements,
		FactoryTemplates: factoryFS,
		ResolveEndpoints: func(ctx context.Context, endpoints []*v0.Endpoint) error {
			endpoint, err := resources.FindTCPEndpoint(ctx, endpoints)
			if err != nil {
				return err
			}
			s.TcpEndpoint = endpoint
			s.Wool.Debug("endpoint", wool.Field("tcp", endpoint))
			return nil
		},
	})
}

func (s *Builder) Init(ctx context.Context, req *builderv0.InitRequest) (*builderv0.InitResponse, error) {
	defer s.Wool.Catch()

	return s.Builder.InitResponse()
}

func (s *Builder) Update(ctx context.Context, req *builderv0.UpdateRequest) (*builderv0.UpdateResponse, error) {
	defer s.Wool.Catch()

	return &builderv0.UpdateResponse{}, nil
}

func (s *Builder) Sync(ctx context.Context, req *builderv0.SyncRequest) (*builderv0.SyncResponse, error) {
	defer s.Wool.Catch()
	ctx = s.Wool.Inject(ctx)

	return s.Builder.SyncResponse()
}

// Audit scans the configured postgres image for known HIGH/CRITICAL CVEs.
func (s *Builder) Audit(ctx context.Context, req *builderv0.AuditRequest) (*builderv0.AuditResponse, error) {
	defer s.Wool.Catch()
	ctx = s.Wool.Inject(ctx)
	return s.Builder.AuditContainer(ctx, req, s.dockerImage().FullName())
}

func (s *Builder) SBOM(ctx context.Context, _ *builderv0.SBOMRequest) (*builderv0.SBOMResponse, error) {
	defer s.Wool.Catch()
	ctx = s.Wool.Inject(ctx)
	return s.Builder.SBOMContainer(ctx, s.dockerImage().FullName())
}

// Upgrade reports an available tag bump for the managed postgres image.
func (s *Builder) Upgrade(ctx context.Context, req *builderv0.UpgradeRequest) (*builderv0.UpgradeResponse, error) {
	defer s.Wool.Catch()
	ctx = s.Wool.Inject(ctx)
	res, err := upgrade.Docker(ctx, image.FullName(), upgrade.Options{
		IncludeMajor: req.IncludeMajor,
		DryRun:       req.DryRun,
	})
	if err != nil {
		return s.Builder.UpgradeError(err)
	}
	return s.Builder.UpgradeResponse(res.Changes, res.LockfileDiff)
}

type DockerTemplating struct {
	MigrationConnectionKeyHolder string
	WithMigration                bool
	ReadOnlyRole                 string
	ReadWriteRole                string
	Schemas                      []string
	ReadWriteRoles               []string
}

func (s *Builder) WithMigration() bool {
	return !s.Settings.NoMigration
}

func (s *Builder) Build(ctx context.Context, req *builderv0.BuildRequest) (*builderv0.BuildResponse, error) {
	defer s.Wool.Catch()

	s.Wool.Debug("building database bootstrap image")

	ctx = s.Wool.Inject(ctx)

	dockerRequest, err := s.Builder.DockerBuildRequest(ctx, req)
	if err != nil {
		return nil, s.Wool.Wrapf(err, "can only do docker build request")
	}

	img := s.DockerImage(dockerRequest)

	if !dockerhelpers.IsValidDockerImageName(img.Name) {
		return s.Builder.BuildError(fmt.Errorf("invalid docker image name: %s", img.Name))
	}

	readOnlyRole, readWriteRole := runtimeRoleNames(s.DatabaseName)
	schemas, err := normalizedRuntimeSchemas(s.RuntimeSchemas)
	if err != nil {
		return s.Builder.BuildError(err)
	}
	readWriteRoles, err := normalizedRuntimeReadWriteRoles(s.RuntimeReadWriteRoles, readOnlyRole, readWriteRole)
	if err != nil {
		return s.Builder.BuildError(err)
	}
	docker := DockerTemplating{
		MigrationConnectionKeyHolder: fmt.Sprintf("{%s}", migrationConnectionEnvironmentKey),
		WithMigration:                s.WithMigration(),
		ReadOnlyRole:                 readOnlyRole,
		ReadWriteRole:                readWriteRole,
		Schemas:                      schemas,
		ReadWriteRoles:               readWriteRoles,
	}

	err = shared.DeleteFile(ctx, s.Local("builder/Dockerfile"))
	if err != nil {
		return s.Builder.BuildError(err)
	}

	err = s.Templates(ctx, docker, services.WithBuilder(builderFS))
	if err != nil {
		return s.Builder.BuildError(err)
	}

	builder, err := dockerhelpers.NewBuilder(dockerhelpers.BuilderConfiguration{
		Root:        s.Location,
		Dockerfile:  "builder/Dockerfile",
		Destination: img,
		Output:      s.Wool,
	})
	if err != nil {
		return s.Builder.BuildError(err)
	}
	_, err = builder.Build(ctx)
	if err != nil {
		return s.Builder.BuildError(err)
	}

	s.Builder.WithDockerImages(img)

	return s.Builder.BuildResponse()
}

func (s *Builder) Deploy(ctx context.Context, req *builderv0.DeploymentRequest) (*builderv0.DeploymentResponse, error) {
	defer s.Wool.Catch()
	walBudget, err := s.effectiveWALBudget()
	if err != nil {
		return s.Builder.DeployError(err)
	}
	if err = validateWALBudgetStorage(walBudget, managedPostgresStorage()); err != nil {
		return s.Builder.DeployError(err)
	}
	reportWALBudget(s.Wool.In("builder::deploy"), walBudget)

	parameters := &DeploymentTemplateParameters{
		WithBootstrap:         true,
		ManagedImage:          s.dockerImage().FullName(),
		PostgresArguments:     append([]string{"postgres"}, walBudget.postgresArguments()...),
		WALBudgetMaxSizeMB:    walBudget.maxSizeMB,
		WALStoragePercent:     maximumWALStoragePercent,
		ManagedStorageSizeGiB: managedPostgresStorageMB / 1024,
		DatabaseName:          s.DatabaseName,
	}
	var restrictedConfiguration *v0.Configuration
	response, err := s.Builder.DeployKustomize(ctx, req, services.KustomizeDeployment{
		EnvironmentVariables: s.EnvironmentVariables,
		Templates:            deploymentFS,
		Parameters:           parameters,
		Prepare: func(ctx context.Context, deployment *services.KustomizeDeploymentContext) error {
			configuration, prepareErr := s.prepareDeployment(ctx, deployment, parameters)
			if prepareErr != nil {
				return prepareErr
			}
			bootstrapJobName, nameErr := s.immutableBootstrapJobName(deployment, parameters)
			if nameErr != nil {
				return nameErr
			}
			parameters.BootstrapJobName = bootstrapJobName
			s.Wool.Debug("exporting configuration", wool.Field("conf", resources.MakeConfigurationSummary(configuration)))
			if services.IsRestrictedOutputProfile(deployment.Profile) {
				restrictedConfiguration = configuration
				return nil
			}
			return deployment.ExportConfiguration(ctx, configuration)
		},
	})
	if err != nil ||
		response.GetState().GetState() != builderv0.DeploymentStatus_SUCCESS ||
		restrictedConfiguration == nil {
		return response, err
	}
	response.Configuration = restrictedConfiguration
	return response, nil
}

const bootstrapJobTemplatePath = "templates/deployment/kustomize/base/job.yaml.tmpl"

func (s *Builder) immutableBootstrapJobName(
	deployment *services.KustomizeDeploymentContext,
	parameters *DeploymentTemplateParameters,
) (string, error) {
	service := shared.ToDNSCase(s.Identity.Name)
	if service == "" {
		return "", fmt.Errorf("bootstrap service name is required")
	}

	source, err := fs.ReadFile(deploymentFS, bootstrapJobTemplatePath)
	if err != nil {
		return "", fmt.Errorf("read bootstrap Job template: %w", err)
	}
	jobTemplate, err := template.New(bootstrapJobTemplatePath).Parse(string(source))
	if err != nil {
		return "", fmt.Errorf("parse bootstrap Job template: %w", err)
	}
	renderContext := &services.DeploymentWrapper{
		DeploymentBase: &services.DeploymentBase{
			Information: s.Information,
			Namespace:   deployment.Kubernetes.GetNamespace(),
			Image:       s.DockerImage(deployment.Kubernetes.GetBuildContext()),
			Profile:     deployment.Profile,
			Restricted:  services.IsRestrictedOutputProfile(deployment.Profile),
		},
		Deployment: services.DeploymentParameters{Parameters: parameters},
	}
	var rendered bytes.Buffer
	if err = jobTemplate.Execute(&rendered, renderContext); err != nil {
		return "", fmt.Errorf("render bootstrap Job template: %w", err)
	}
	var job struct {
		Spec struct {
			Template yaml.Node `yaml:"template"`
		} `yaml:"spec"`
	}
	if err = yaml.Unmarshal(rendered.Bytes(), &job); err != nil {
		return "", fmt.Errorf("parse rendered bootstrap Job: %w", err)
	}
	if job.Spec.Template.Kind == 0 {
		return "", fmt.Errorf("rendered bootstrap Job is missing spec.template")
	}
	podTemplate, err := yaml.Marshal(&job.Spec.Template)
	if err != nil {
		return "", fmt.Errorf("encode bootstrap Job pod template: %w", err)
	}
	contentDigest := sha256.Sum256(podTemplate)

	const suffixLength = 12
	const maxServiceLength = 63 - 1 - suffixLength
	if len(service) > maxServiceLength {
		service = strings.TrimRight(service[:maxServiceLength], "-")
	}
	return service + "-" + hex.EncodeToString(contentDigest[:])[:suffixLength], nil
}

func (s *Builder) prepareDeployment(
	ctx context.Context,
	deployment *services.KustomizeDeploymentContext,
	parameters *DeploymentTemplateParameters,
) (*v0.Configuration, error) {
	req := deployment.Request
	instance, err := resources.FindNetworkInstanceInNetworkMappings(
		ctx,
		req.GetNetworkMappings(),
		s.TcpEndpoint,
		resources.NewPublicNetworkAccess(),
	)
	if err != nil {
		return nil, err
	}
	if services.IsRestrictedOutputProfile(deployment.Profile) {
		workloadReferences, referencesErr := s.selectPromotableSecretReferences(
			deployment.Kubernetes.GetSecretReferences(),
		)
		if referencesErr != nil {
			return nil, referencesErr
		}
		parameters.StatefulSetSecretReferences = workloadReferences.StatefulSet
		parameters.BootstrapJobSecretReferences = workloadReferences.BootstrapJob
		return s.promotableConnectionConfiguration(instance), nil
	}

	configuration, err := s.CreateConnectionConfiguration(ctx, req.GetConfiguration(), instance, !s.WithoutSSL)
	if err != nil {
		return nil, err
	}
	ownerConnection, err := s.createOwnerConnectionString(ctx, req.GetConfiguration(), instance.Address, !s.WithoutSSL)
	if err != nil {
		return nil, err
	}
	// These raw workload values stay in the ephemeral profile's generated
	// Secret; callers receive only the managed-resource configuration.
	deployment.AddSecrets(
		resources.Env("POSTGRES_USER", s.postgresUser),
		resources.Env("POSTGRES_PASSWORD", s.postgresPassword),
		resources.Env("POSTGRES_DB", s.DatabaseName),
		resources.Env("POSTGRES_READ_ONLY_PASSWORD", s.readOnlyPassword),
		resources.Env("POSTGRES_READ_WRITE_PASSWORD", s.readWritePassword),
		resources.Env(migrationConnectionEnvironmentKey, ownerConnection),
	)
	return configuration, nil
}

type promotableWorkloadSecretReferences struct {
	StatefulSet  map[string]*builderv0.KubernetesSecretKeyReference
	BootstrapJob map[string]*builderv0.KubernetesSecretKeyReference
}

func (s *Builder) selectPromotableSecretReferences(
	configured map[string]*builderv0.KubernetesSecretKeyReference,
) (*promotableWorkloadSecretReferences, error) {
	// The restricted deploy build never loads runtime credentials, so this is
	// the only place the auth mode is checked on this path: reject a mistyped
	// mode here rather than silently demanding password Secret references.
	if err := s.validateAuthMode(); err != nil {
		return nil, err
	}
	// External-identity mode holds no passwords, so the deploy build promotes no
	// credential Secret references; infra's guard forbids any Secret in the
	// db-auth stack.
	if s.externalIdentity() {
		return &promotableWorkloadSecretReferences{
			StatefulSet:  map[string]*builderv0.KubernetesSecretKeyReference{},
			BootstrapJob: map[string]*builderv0.KubernetesSecretKeyReference{},
		}, nil
	}
	statefulSetEnvironmentVariables := []string{
		"POSTGRES_USER",
		"POSTGRES_PASSWORD",
	}
	bootstrapJobEnvironmentVariables := []string{
		"POSTGRES_USER",
		"POSTGRES_READ_ONLY_PASSWORD",
		"POSTGRES_READ_WRITE_PASSWORD",
	}
	selected := make(map[string]*builderv0.KubernetesSecretKeyReference, 5)
	secretName := ""
	for _, environmentVariable := range []string{
		"POSTGRES_USER",
		"POSTGRES_PASSWORD",
		"POSTGRES_READ_ONLY_PASSWORD",
		"POSTGRES_READ_WRITE_PASSWORD",
	} {
		configurationKey := resources.ServiceSecretConfigurationKeyFromUnique(
			s.Unique(),
			"postgres",
			environmentVariable,
		)
		reference := configured[configurationKey]
		if reference == nil || reference.GetName() == "" || reference.GetKey() == "" {
			return nil, fmt.Errorf("postgres deployment requires a typed Kubernetes Secret reference for %s", configurationKey)
		}
		if reference.GetOptional() {
			return nil, fmt.Errorf("%s Kubernetes Secret reference must not be optional", configurationKey)
		}
		if secretName == "" {
			secretName = reference.GetName()
		} else if secretName != reference.GetName() {
			return nil, fmt.Errorf("postgres credential references must use one Kubernetes Secret")
		}
		selected[environmentVariable] = reference
	}
	selected[migrationConnectionEnvironmentKey] = &builderv0.KubernetesSecretKeyReference{
		Name: secretName,
		Key:  migrationConnectionEnvironmentKey,
	}
	bootstrapJobEnvironmentVariables = append(bootstrapJobEnvironmentVariables, migrationConnectionEnvironmentKey)
	selectForWorkload := func(environmentVariables []string) map[string]*builderv0.KubernetesSecretKeyReference {
		workloadReferences := make(map[string]*builderv0.KubernetesSecretKeyReference, len(environmentVariables))
		for _, environmentVariable := range environmentVariables {
			workloadReferences[environmentVariable] = selected[environmentVariable]
		}
		return workloadReferences
	}
	return &promotableWorkloadSecretReferences{
		StatefulSet:  selectForWorkload(statefulSetEnvironmentVariables),
		BootstrapJob: selectForWorkload(bootstrapJobEnvironmentVariables),
	}, nil
}

type create struct {
	DatabaseName string
	TableName    string
}

func (s *Builder) Create(ctx context.Context, req *builderv0.CreateRequest) (*builderv0.CreateResponse, error) {
	defer s.Wool.Catch()

	// Use defaults
	s.Settings.HotReload = true
	if s.Settings.DatabaseName == "" {
		s.Settings.DatabaseName = s.Base.Identity.Module
	}

	c := create{DatabaseName: s.Settings.DatabaseName, TableName: s.Builder.Service.Name}

	err := s.Templates(ctx, c, services.WithFactory(factoryFS))
	if err != nil {
		return s.Builder.CreateError(err)
	}

	err = s.CreateEndpoints(ctx)
	if err != nil {
		return s.Builder.CreateErrorf(err, "cannot create endpoints")
	}

	s.Wool.Debug("created endpoints", wool.Field("endpoints", resources.MakeManyEndpointSummary(s.Endpoints)))

	return s.Builder.CreateResponse(ctx, s.Settings)
}

func (s *Builder) CreateEndpoints(ctx context.Context) error {
	tcp, err := resources.LoadTCPAPI(ctx)
	if err != nil {
		return s.Wool.Wrapf(err, "cannot load tcp api")
	}
	endpoint := s.Base.BaseEndpoint(standards.TCP)
	endpoint.Visibility = resources.VisibilityExternal
	s.TcpEndpoint, err = resources.NewAPI(ctx, endpoint, resources.ToTCPAPI(tcp))
	s.Endpoints = []*v0.Endpoint{s.TcpEndpoint}
	return nil
}

func (s *Builder) Communicate(stream builderv0.Builder_CommunicateServer) error {
	asker := communicate.NewQuestionAsker(stream)
	_, err := asker.RunSequence(nil)
	return err
}

//go:embed templates/factory
var factoryFS embed.FS

//go:embed templates/builder
var builderFS embed.FS

//go:embed templates/deployment
var deploymentFS embed.FS
