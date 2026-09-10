package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
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

// bootstrapDirectory is the agent-owned staging root written into the build
// context. It carries the generated bootstrap program, the plan identity, and
// one immutable copy of every packaged migration source.
const bootstrapDirectory = "bootstrap"

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

// DockerTemplating renders the bootstrap image: the Dockerfile, the generated
// bootstrap program, and the SQL it applies. Every field is derived from the
// schema plan, so the image can only carry what the plan declares.
type DockerTemplating struct {
	MigrationConnectionEnvironment string
	// RuntimeAccessLockID is the advisory-lock expression the bootstrap script
	// takes, shared verbatim with the agent so the two cannot drift apart.
	RuntimeAccessLockID     string
	ReadinessTimeoutSeconds int
	ReadOnlyRole            string
	ReadWriteRole           string
	Schemas                 []string
	ReadWriteRoles          []string
	// DefaultReadWriteRole is the application role the managed read-write login
	// selects on connect. See defaultRuntimeReadWriteRole.
	DefaultReadWriteRole string
	Extensions           []BootstrapExtension
	Lineages             []BootstrapLineage
}

// Bootstrap resolves the locked bootstrap inputs the Dockerfile renders from. A
// method, not a field: the template dereferences it on its first line, so a
// constructed value must not be able to omit it.
func (DockerTemplating) Bootstrap() *bootstrapImageLock {
	return bootstrapLock
}

// BootstrapLineage is one migration lineage as the generated bootstrap program
// sees it: the staged directory inside the image and the ledger it owns.
type BootstrapLineage struct {
	Label  string
	Stage  string
	Ledger string
}

// bootstrapLineages projects the plan's lineages onto the staged layout the
// image carries, in declared order.
func bootstrapLineages(plan *schemaPlan) []BootstrapLineage {
	lineages := make([]BootstrapLineage, 0, len(plan.lineages))
	for _, lineage := range plan.lineages {
		lineages = append(lineages, BootstrapLineage{
			Label:  lineage.label(),
			Stage:  lineage.stage,
			Ledger: lineage.trackingTable(),
		})
	}
	return lineages
}

// BootstrapExtension is one extension as the generated SQL sees it. A required
// extension aborts the bootstrap when it cannot be created, exactly as it fails
// the local runtime's readiness; an optional one is reported and skipped.
type BootstrapExtension struct {
	Name     string
	Required bool
}

func bootstrapExtensions(plan *schemaPlan) []BootstrapExtension {
	extensions := make([]BootstrapExtension, 0, len(plan.extensions))
	for _, extension := range plan.extensions {
		extensions = append(extensions, BootstrapExtension{Name: extension.name, Required: extension.required})
	}
	return extensions
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

	// The declared schema prerequisites are resolved here as well as at runtime,
	// so a typo'd source path or a colliding lineage fails the build instead of
	// producing a bootstrap image that quietly ships an incomplete schema. The
	// build then packages exactly what that resolution returned, so the image
	// applies the same lineages and extensions the runtime does.
	prerequisites, err := s.resolveSchemaPrerequisites()
	if err != nil {
		return s.Builder.BuildError(err)
	}
	if err = s.Settings.Timeouts.validate(); err != nil {
		return s.Builder.BuildError(err)
	}
	plan, err := buildSchemaPlan(prerequisites, s.Settings)
	if err != nil {
		return s.Builder.BuildError(err)
	}
	if err = plan.attest(); err != nil {
		return s.Builder.BuildError(err)
	}
	s.reportSchemaPrerequisites(prerequisites)
	docker := DockerTemplating{
		MigrationConnectionEnvironment: migrationConnectionEnvironmentKey,
		RuntimeAccessLockID:            runtimeAccessLockID,
		ReadinessTimeoutSeconds:        s.Settings.Timeouts.BootstrapReadinessSeconds(),
		ReadOnlyRole:                   plan.access.readOnlyRole,
		ReadWriteRole:                  plan.access.readWriteRole,
		Schemas:                        plan.access.schemas,
		ReadWriteRoles:                 plan.access.readWriteRoles,
		DefaultReadWriteRole:           defaultRuntimeReadWriteRole(plan.access.readWriteRoles),
		Extensions:                     bootstrapExtensions(plan),
		Lineages:                       bootstrapLineages(plan),
	}

	if outputDirectory := req.GetOutputDirectory(); outputDirectory != "" {
		return s.buildRecipe(ctx, outputDirectory, img, plan, docker)
	}

	err = shared.DeleteFile(ctx, s.Local("builder/Dockerfile"))
	if err != nil {
		return s.Builder.BuildError(err)
	}

	err = s.Templates(ctx, docker, services.WithBuilder(builderFS))
	if err != nil {
		return s.Builder.BuildError(err)
	}

	if err = s.stageBootstrapContext(ctx, plan, docker, s.Location); err != nil {
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

// buildRecipe renders the bootstrap image's recipe into the caller-owned output
// directory and returns a reproducible build plan instead of running docker
// itself. The CLI builds the emitted recipe multi-arch and pushes a manifest
// list, so a consumer can rebuild the image without the agent toolchain.
// The CLI resolves the recipe's "." context to the service directory
// (s.Location), not the recipe tree, so the bootstrap tree the Dockerfile COPYs
// is staged into both: into the service directory for the build the CLI runs,
// and into the recipe tree so the emitted artifact is a self-contained context
// a consumer can build directly. Both stagings write identical bytes.
func (s *Builder) buildRecipe(
	ctx context.Context,
	outputDirectory string,
	img *resources.DockerImage,
	plan *schemaPlan,
	docker DockerTemplating,
) (*builderv0.BuildResponse, error) {
	// The build plan inventories the whole output directory and the recipe
	// context is its root, so any pre-existing content the caller left here
	// would be digested into the plan and copied into the image. Empty the
	// directory the agent fully owns before rendering, as the deployment
	// emitter does.
	if err := shared.EmptyDir(ctx, outputDirectory); err != nil {
		return s.Builder.BuildError(err)
	}

	if err := s.Templates(ctx, docker, services.WithBuilder(builderFS).WithDestination("%s", filepath.Join(outputDirectory, "builder"))); err != nil {
		return s.Builder.BuildError(err)
	}

	for _, contextRoot := range []string{s.Location, outputDirectory} {
		if err := s.stageBootstrapContext(ctx, plan, docker, contextRoot); err != nil {
			return s.Builder.BuildError(err)
		}
	}

	buildPlan, err := services.BuildDockerBuildPlan(outputDirectory, []*builderv0.DockerBuildRecipe{{
		Name:       "bootstrap",
		Dockerfile: "builder/Dockerfile",
		Context:    ".",
		Image:      img.FullName(),
		Platforms:  bootstrapRecipePlatforms(),
		// The recipe carries the resolved bootstrap inputs it was rendered from, so a
		// consumer reads the base, package and migrate identities off the plan
		// instead of re-resolving them.
		BuildArgs: docker.Bootstrap().RecipeBuildArgs(),
	}})
	if err != nil {
		return s.Builder.BuildError(err)
	}

	s.Builder.WithBuildPlan(buildPlan)
	return s.Builder.BuildResponse()
}

// stageBootstrapContext writes the complete bootstrap artifact into a build
// context root: the generated bootstrap program and SQL, the plan identity, and
// one immutable copy of every resolved migration source under its own staged
// directory. Sibling sources live outside the build context, so staging is what
// makes them reachable at all — a Dockerfile COPY cannot leave its context.
func (s *Builder) stageBootstrapContext(
	ctx context.Context,
	plan *schemaPlan,
	docker DockerTemplating,
	contextRoot string,
) error {
	root := filepath.Join(contextRoot, bootstrapDirectory)
	// A source removed from the settings must disappear from the image, so the
	// agent-owned staging root is rebuilt rather than merged into.
	if err := os.RemoveAll(root); err != nil {
		return err
	}
	if err := s.Templates(ctx, docker, services.WithTemplate(bootstrapFS, "bootstrap", "").WithDestination("%s", root)); err != nil {
		return err
	}
	// Every resolved lineage is staged, including one that carries no migration
	// yet, so the plan artifact's staged paths always describe real directories.
	for _, lineage := range plan.lineages {
		if err := stageLineage(ctx, lineage, filepath.Join(root, "sources", lineage.stage)); err != nil {
			return fmt.Errorf("stage migration source %q: %w", lineage.label(), err)
		}
	}
	artifact, err := json.MarshalIndent(plan.artifact(), "", "  ")
	if err != nil {
		return err
	}
	if err = os.WriteFile(filepath.Join(root, "plan.json"), append(artifact, '\n'), 0o644); err != nil {
		return err
	}
	return s.renderRuntimeAccess(ctx, docker, contextRoot)
}

// stageLineage copies one lineage's inventoried files into its staged directory
// and re-checks each digest, so the plan artifact describes exactly the bytes
// the image carries even if a file changed while the build was running.
func stageLineage(ctx context.Context, lineage schemaLineage, destination string) error {
	if err := os.MkdirAll(destination, 0o755); err != nil {
		return err
	}
	for _, file := range lineage.files {
		staged := filepath.Join(destination, file.name)
		if err := shared.CopyFile(ctx, filepath.Join(lineage.dir, file.name), staged); err != nil {
			return err
		}
		digest, err := fileDigest(staged)
		if err != nil {
			return err
		}
		if digest != file.digest {
			return fmt.Errorf("%s changed while it was being staged", file.name)
		}
	}
	return nil
}

// renderRuntimeAccess renders runtime-access.sql into the build context root, the
// directory docker builds from. The Dockerfile COPYs it from there, so it must
// sit beside the staged bootstrap tree rather than under builder/.
func (s *Builder) renderRuntimeAccess(ctx context.Context, docker DockerTemplating, contextRoot string) error {
	return s.Templates(ctx, docker, services.WithTemplate(runtimeFS, "runtime", "").WithDestination("%s", contextRoot))
}

func (s *Builder) Deploy(ctx context.Context, req *builderv0.DeploymentRequest) (*builderv0.DeploymentResponse, error) {
	defer s.Wool.Catch()

	if err := s.Settings.Timeouts.validate(); err != nil {
		return s.Builder.DeployError(err)
	}
	parameters := &DeploymentTemplateParameters{
		WithBootstrap:               true,
		ManagedImage:                s.dockerImage().FullName(),
		DatabaseName:                s.DatabaseName,
		BootstrapJobDeadlineSeconds: s.Settings.Timeouts.BootstrapJobSeconds(),
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

// all: so the scaffolded .gitignore (a dotfile go:embed skips by default) is
// carried into the factory tree and rendered into new services.
//
//go:embed all:templates/factory
var factoryFS embed.FS

//go:embed templates/builder
var builderFS embed.FS

//go:embed templates/bootstrap
var bootstrapFS embed.FS

//go:embed templates/runtime
var runtimeFS embed.FS

//go:embed templates/deployment
var deploymentFS embed.FS
