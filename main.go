package main

import (
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"

	"github.com/codefly-dev/core/agents"
	"github.com/codefly-dev/core/agents/contract"
	"github.com/codefly-dev/core/agents/services"
	"github.com/codefly-dev/core/builders"
	basev0 "github.com/codefly-dev/core/generated/go/codefly/base/v0"
	agentv0 "github.com/codefly-dev/core/generated/go/codefly/services/agent/v0"
	builderv0 "github.com/codefly-dev/core/generated/go/codefly/services/builder/v0"
	"github.com/codefly-dev/core/resources"
	runnersbase "github.com/codefly-dev/core/runners/base"
	"github.com/codefly-dev/core/shared"
	"github.com/codefly-dev/core/templates"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"gopkg.in/yaml.v3"
)

// Agent version
var agent = shared.Must(resources.LoadFromFs[resources.Agent](shared.Embed(infoFS)))

var requirements = builders.NewDependencies(agent.Name,
	builders.NewDependency("service.codefly.yaml"),
	builders.NewDependency("migrations", "migrations").WithPathSelect(shared.NewSelect("*.sql")),
)

type Settings struct {
	DatabaseName string `yaml:"database-name"`
	HotReload    bool   `yaml:"hot-reload"`

	// ExternalInstances binds named deployment environments to Postgres servers
	// provisioned outside this service. DatabaseName and RuntimeReadWriteRoles
	// attest that each environment targets this service's logical database
	// contract.
	ExternalInstances map[string]ExternalInstance `yaml:"external-instances"`

	// AuthMode selects how runtime login principals authenticate. Empty is the
	// default password mode: the service owns password-authenticated login
	// roles and exports credentialed connection strings. "external-identity" is
	// for managed cloud Postgres with password auth disabled — login principals
	// are provisioned out-of-band by the cloud identity provider (Entra ID /
	// Cloud SQL IAM) and consumers acquire a short-lived token at connect time,
	// so no password is generated, required, or embedded in any connection
	// string or Kubernetes Secret. See templates/agent/README.md.tmpl.
	AuthMode string `yaml:"auth-mode"`

	WithoutSSL  bool `yaml:"without-ssl"`  // Default to SSL
	NoMigration bool `yaml:"no-migration"` // Developer only

	// KeepRunning makes Stop leave this service's postgres container running so
	// the next invocation reuses the warm server instead of paying for a cold
	// start. Off by default: Stop otherwise releases the postmaster (nix) or the
	// container (docker) and retains the data either way, so warm reuse is
	// something a workspace asks for by name rather than something one backend
	// does silently. Destroy still tears the server down.
	//
	// Docker only. The nix runtime cannot reattach to a running postmaster, so
	// it stops anyway (warning as it does) rather than leave one that would make
	// the next Init fail on a locked data directory.
	KeepRunning bool `yaml:"keep-running"`

	// LogLevel controls postgres server log verbosity. When set, the
	// agent passes `-c log_min_messages=<lvl>` plus a handful of
	// quietening knobs to suppress per-statement / per-connection
	// chatter. Accepts postgres' native values: debug5..debug1,
	// log, notice, warning, error, fatal, panic. Empty = postgres
	// default (warning, but image emits a lot of startup chatter).
	LogLevel string `yaml:"log-level"`

	// Image overrides the default postgres image — bring your own extensions.
	// e.g. "postgis/postgis:17-3.5" for PostGIS, or any image that ships the
	// .so files the extensions you list below need. Format "name:tag" or
	// "name@sha256:...". Empty = the default pgvector image (see the `image`
	// var). Image-scope SBOM needs the digest form: a tag serves whatever was
	// pushed to it last, so its inventory is not coverage of what runs.
	Image string `yaml:"docker-image"`

	// ImagePlatforms are the os/arch platforms the overridden image ships.
	// Image inventories describe one platform each, and nothing else can tell
	// this service what an image it does not own carries, so a multi-platform
	// override has to name them or its evidence cannot be produced at all.
	// Empty is right for a single-platform override: the scanner resolves that
	// one on its own.
	//
	//   docker-image: postgres:17-alpine
	//   docker-image-platforms: [linux/amd64, linux/arm64]
	ImagePlatforms []string `yaml:"docker-image-platforms"`

	// Extensions are CREATE EXTENSION IF NOT EXISTS'd at startup, on top of the
	// always-on defaults (defaultExtensions). The extension's shared library
	// must exist in the image; the default pgvector image ships the standard
	// contrib set + vector. A declared extension is REQUIRED: if it cannot be
	// created — absent library, or a migration owner without the privilege —
	// startup fails. Point Settings.Image at an image that ships it, or declare
	// the extension optional.
	//
	//   extensions:
	//     - postgis                    # required
	//     - name: pg_stat_statements
	//       optional: true             # reported as skipped when unavailable
	Extensions []Extension `yaml:"extensions"`

	// RuntimeSchemas is the explicit allow-list of schemas exposed through the
	// non-owner runtime roles. Empty means ["public"]. Runtime roles never own
	// objects and never receive CREATE on these schemas.
	RuntimeSchemas []string `yaml:"runtime-schemas"`

	// RuntimeReadWriteRoles is the explicit allow-list of application-defined
	// NOLOGIN roles that the managed read-write principal may assume with
	// SET ROLE. When non-empty, these roles are the principal's exclusive source
	// of DML authority; the managed login receives no direct table or sequence
	// grants. The roles must be created by migrations. This lets an application
	// keep request, worker, and RLS capabilities in its own schema contract
	// without exporting the database-owner credential.
	//
	// The FIRST entry is the principal's session default (see
	// defaultRuntimeReadWriteRole), so a consumer of read-write-connection writes
	// without selecting anything. Order is therefore part of the contract:
	// appending a role is safe, reordering changes what every consumer of the
	// exported credential starts as.
	RuntimeReadWriteRoles []string `yaml:"runtime-read-write-roles"`

	// RuntimeLogins declares further read-write login principals beside the
	// managed read-write one, each for one kind of consumer that must hold a
	// DIFFERENT delegated role set. A process that must never be able to assume
	// another's role (a request API refusing any session that can reach a
	// maintenance role, say) cannot share the one read-write login; it takes a
	// login of its own here.
	//
	// Each entry is its own LOGIN principal (NOINHERIT, NOBYPASSRLS, no direct
	// DML) whose only write authority is membership of its read-write-roles,
	// which migrations create; the first is its session default. It has its own
	// primitive password, POSTGRES_<NAME>_PASSWORD in the "postgres" secret
	// configuration (derived from the owner secret locally when absent), and is
	// exported as <name>-connection, templated over that password in a
	// restricted render. The managed read-write login's role set is unchanged
	// by it.
	//
	//   runtime-logins:
	//     - name: maintenance
	//       read-write-roles: [app_runtime]
	RuntimeLogins []RuntimeLogin `yaml:"runtime-logins"`

	// MigrationSources lets SEVERAL services share this ONE database while each
	// owns its own migrations/ folder. Each source is applied with its own
	// golang-migrate tracking table (schema_migrations_<name>), so the per-source
	// integer version sequences never collide. This service's own ./migrations
	// dir is always applied first with the default table (schema_migrations).
	//
	//   migration-sources:
	//     - name: api          # applies ../api/migrations (default path)
	//     - name: billing
	//       path: ../billing/db/migrations
	//
	// Paths are relative to this service's directory (or absolute). A declared
	// source is REQUIRED: a missing or empty directory fails before the database
	// is touched, unless the source declares `optional: true`.
	MigrationSources []MigrationSource `yaml:"migration-sources"`

	// Timeouts bounds every wait this agent performs or renders: readiness
	// probing, connection establishment, migration locking and statements, and
	// the deployed bootstrap Job. See Timeouts for the keys and defaults.
	Timeouts Timeouts `yaml:"timeouts"`
}

// RuntimeLogin is one declared read-write login principal. See
// Settings.RuntimeLogins.
type RuntimeLogin struct {
	// Name is lower-case letters, digits and dashes, starting with a letter; it
	// names the exported <name>-connection key and the password key.
	Name string `yaml:"name"`
	// ReadWriteRoles is the login's exclusive delegated role set; required.
	ReadWriteRoles []string `yaml:"read-write-roles"`
}

type ExternalInstance struct {
	Host                  string   `yaml:"host"`
	Port                  uint16   `yaml:"port"`
	DatabaseName          string   `yaml:"database-name"`
	RuntimeReadWriteRoles []string `yaml:"runtime-read-write-roles"`
}

// MigrationSource declares one additional service contributing migrations to
// the shared database. See Settings.MigrationSources.
type MigrationSource struct {
	// Name identifies the lineage and names its tracking table
	// (schema_migrations_<name>). Must be a safe SQL identifier ([A-Za-z0-9_])
	// short enough for that table to fit PostgreSQL's 63-byte identifier limit,
	// and distinct from every other declared name.
	Name string `yaml:"name"`
	// Path is the migrations directory, relative to this service's directory or
	// absolute. Empty defaults to ../<name>/migrations (the sibling-service
	// layout used inside a module).
	Path string `yaml:"path"`
	// Optional turns an absent or empty directory into a reported skip instead
	// of a startup failure — for a service that declares this database before it
	// ships any migration. A directory that exists but is unreadable or holds a
	// misnamed migration file still fails.
	Optional bool `yaml:"optional"`
}

// Extension declares one PostgreSQL extension to create at startup. It accepts
// either a bare name or a mapping carrying `optional`.
type Extension struct {
	Name     string `yaml:"name"`
	Optional bool   `yaml:"optional"`
}

// UnmarshalYAML accepts the bare-name form alongside the mapping form, so
// `extensions: [postgis, hstore]` keeps working unchanged.
func (e *Extension) UnmarshalYAML(value *yaml.Node) error {
	if value.Kind == yaml.ScalarNode {
		return value.Decode(&e.Name)
	}
	type extension Extension
	var declared extension
	if err := value.Decode(&declared); err != nil {
		return err
	}
	*e = Extension(declared)
	return nil
}

const HotReload = "hot-reload"
const DatabaseName = "database-name"

// The managed image adds pgvector to the official Postgres 17 Alpine image
// while preserving its entrypoint and contrib extensions. The nix runtime gets
// pgvector via nix/flake.nix, keeping both runtimes at parity.
var image = shared.Must(parseRuntimeImageLock(runtimeImageLockJSON))

// runtimeImage is the managed image's checked-in identity: the immutable
// reference, and every platform the manifest list that digest names ships.
// Image inventories describe one platform each, so the platform set has to be
// part of the lock rather than something a scan is left to pick for itself.
type runtimeImage struct {
	*resources.DockerImage
	Platforms []string
}

type runtimeImageLock struct {
	Name      string   `json:"name"`
	Tag       string   `json:"tag"`
	Digest    string   `json:"digest"`
	Platforms []string `json:"platforms"`
}

func parseRuntimeImageLock(content []byte) (*runtimeImage, error) {
	var lock runtimeImageLock
	if err := json.Unmarshal(content, &lock); err != nil {
		return nil, fmt.Errorf("parse runtime image lock: %w", err)
	}
	if lock.Name == "" {
		return nil, fmt.Errorf("runtime image name is required")
	}
	if lock.Tag == "" {
		return nil, fmt.Errorf("runtime image tag is required")
	}
	if lock.Digest == "" {
		return nil, fmt.Errorf("runtime image digest is required")
	}
	if err := validateSHA256Digest("runtime image digest", lock.Digest); err != nil {
		return nil, err
	}
	if len(lock.Platforms) == 0 {
		return nil, fmt.Errorf("runtime image platforms are required")
	}
	for _, platform := range lock.Platforms {
		if err := validatePlatform("runtime image platform", platform); err != nil {
			return nil, err
		}
	}
	return &runtimeImage{
		DockerImage: &resources.DockerImage{
			Name:   lock.Name,
			Tag:    lock.Tag,
			Digest: lock.Digest,
		},
		Platforms: lock.Platforms,
	}, nil
}

// validatePlatform accepts the "os/arch" form image evidence is keyed by, the
// same form the scanner selects a manifest with.
func validatePlatform(field, value string) error {
	operatingSystem, architecture, found := strings.Cut(value, "/")
	if !found || operatingSystem == "" || architecture == "" {
		return fmt.Errorf("%s %q must be os/arch", field, value)
	}
	return nil
}

type DeploymentTemplateParameters struct {
	WithBootstrap                bool
	ExternalInstance             bool
	ExternalBindingID            string
	ExternalHost                 string
	ExternalPort                 uint16
	ExternalSSLMode              string
	ReadOnlyRole                 string
	ReadWriteRole                string
	ManagedImage                 string
	BootstrapJobName             string
	DatabaseName                 string
	BootstrapJobDeadlineSeconds  int
	StatefulSetSecretReferences  map[string]*builderv0.KubernetesSecretKeyReference
	BootstrapJobSecretReferences map[string]*builderv0.KubernetesSecretKeyReference
	// ServicePort is the in-cluster port core allocated to the tcp endpoint and
	// handed to every consumer in its network mapping. The Service publishes it
	// and folds it onto 5432, the port the container listens on. Zero leaves the
	// template on 5432.
	ServicePort uint32
	// OwnerFromLibpqEnvironment makes the restricted bootstrap Job reach the
	// managed server as the migration owner through PGHOST, PGPORT, PGDATABASE,
	// PGSSLMODE (when pinned), PGUSER and PGPASSWORD instead of an assembled
	// owner connection string.
	OwnerFromLibpqEnvironment bool
	OwnerHost                 string
	OwnerPort                 string
	OwnerSSLMode              string
}

// defaultExtensions are CREATE EXTENSION'd on every start. They are convenience
// defaults nobody asked for, so they stay best-effort: one that the configured
// image does not ship is reported as skipped, never fatal. Settings.Extensions
// adds required declarations on top — and naming a default there makes it
// required.
var defaultExtensions = []string{
	"vector",    // pgvector — embeddings / similarity search
	"pgcrypto",  // gen_random_uuid(), digests, crypt()
	"uuid-ossp", // uuid_generate_v4() and friends
	"pg_trgm",   // trigram fuzzy text search + GIN/GiST indexes
	"citext",    // case-insensitive text (emails, usernames)
	"btree_gin", // GIN indexes over scalar/btree types
}

// dockerImage returns the configured postgres image: the Settings.DockerImage
// override if set, else the default pgvector image.
func (s *Service) dockerImage() *resources.DockerImage {
	if s.Settings != nil && s.Settings.Image != "" {
		// NewDockerImage splits on ":", which a digest reference also carries, so
		// it would file the digest as a tag and leave "name@sha256" as the image
		// name. A registry host with a port takes it out of range entirely.
		if name, digest, pinned := strings.Cut(s.Settings.Image, "@"); pinned {
			return &resources.DockerImage{Name: name, Digest: digest}
		}
		return resources.NewDockerImage(s.Settings.Image)
	}
	return image.DockerImage
}

type Service struct {
	*services.Base

	// Settings
	*Settings

	postgresUser      string
	postgresPassword  string
	readOnlyPassword  string
	readWritePassword string
	// loginPasswords holds each declared runtime login's password by login name.
	loginPasswords map[string]string
	connectionKey  string
	connection     string

	TcpEndpoint *basev0.Endpoint
}

func (s *Service) GetAgentInformation(ctx context.Context, _ *agentv0.AgentInformationRequest) (*agentv0.AgentInformation, error) {

	readme, err := templates.ApplyTemplateFrom(ctx, shared.Embed(readmeFS), "templates/agent/README.md", s.Information)
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	advertisement := services.Advertisement{
		Backends: runnersbase.BackendSupport{
			Nix:    true,
			Docker: true,
		},
		ReadMe: readme,
		Config: []*agentv0.ConfigurationValueDetail{
			{
				Name: "postgres", Description: "capability-scoped Postgres workload bindings",
				Fields: []*agentv0.ConfigurationValueInformation{
					{
						Name: ownerConnectionKey, Description: "local migration-owner connection; never a toolbox binding or normal runtime credential",
					},
					{
						Name: readOnlyConnectionKey, Description: "non-owner, read-only connection string",
					},
					{
						Name: readWriteConnectionKey, Description: "non-owner, read-write connection string",
					},
				}},
		},
	}.Build()

	// The shared server fills the contract in only when a handler leaves it
	// absent, and that shared value carries the capabilities its own
	// implementation promises — not one this agent adds. Declaring explicitly
	// means carrying those promises forward rather than replacing them.
	advertisement.Contract = contract.Current()
	advertisement.Contract.Capabilities = append(advertisement.Contract.Capabilities, hostResourceRecoveryCapability)

	return advertisement, nil
}

func NewService() *Service {
	service := &Service{
		Base:     services.NewServiceBase(context.Background(), agent.Of(resources.ServiceAgent)),
		Settings: &Settings{},
	}
	service.RegisterCommand(recoverHostResourcesCommand(), runRecoverHostResources)
	return service
}

func (s *Service) LoadConfiguration(ctx context.Context, conf *basev0.Configuration) error {
	var err error
	s.postgresUser, err = resources.GetConfigurationValue(ctx, conf, "postgres", "POSTGRES_USER")
	if err != nil {
		return s.Wool.Wrapf(err, "cannot get user")
	}
	s.postgresPassword, err = resources.GetConfigurationValue(ctx, conf, "postgres", "POSTGRES_PASSWORD")
	if err != nil {
		return s.Wool.Wrapf(err, "cannot get password")
	}
	s.readOnlyPassword, err = resources.GetConfigurationValue(ctx, conf, "postgres", "POSTGRES_READ_ONLY_PASSWORD")
	if err != nil {
		return s.Wool.Wrapf(err, "cannot get read-only runtime password")
	}
	s.readWritePassword, err = resources.GetConfigurationValue(ctx, conf, "postgres", "POSTGRES_READ_WRITE_PASSWORD")
	if err != nil {
		return s.Wool.Wrapf(err, "cannot get read-write runtime password")
	}
	// ARCHITECTURE: older generated services only carry the migration-owner
	// secret. Keep those services bootable without copying developer-local
	// configuration into isolated worktrees by deriving capability passwords
	// from that owner secret. The one-way, domain-separated derivation keeps
	// the exported credentials distinct and stable; newly generated services
	// still receive independent explicit secrets from the factory template.
	if strings.TrimSpace(s.readOnlyPassword) == "" {
		s.readOnlyPassword = deriveRuntimePassword(s.postgresPassword, s.DatabaseName, readOnlyConnectionKey)
	}
	if strings.TrimSpace(s.readWritePassword) == "" {
		s.readWritePassword = deriveRuntimePassword(s.postgresPassword, s.DatabaseName, readWriteConnectionKey)
	}
	logins, err := s.runtimeLogins()
	if err != nil {
		return err
	}
	s.loginPasswords = make(map[string]string, len(logins))
	for _, login := range logins {
		password, err := resources.GetConfigurationValue(ctx, conf, "postgres", login.passwordKey)
		if err != nil {
			return s.Wool.Wrapf(err, "cannot get the %s login password", login.name)
		}
		if strings.TrimSpace(password) == "" {
			password = deriveRuntimePassword(s.postgresPassword, s.DatabaseName, login.connectionKey)
		}
		s.loginPasswords[login.name] = password
	}
	return s.validateCredentials()
}

func (s *Service) createOwnerConnectionString(ctx context.Context, conf *basev0.Configuration, address string, withSSL bool) (string, error) {
	defer s.Wool.Catch()
	ctx = s.Wool.Inject(ctx)

	err := s.LoadConfiguration(ctx, conf)
	if err != nil {
		return "", s.Wool.Wrapf(err, "cannot get user and password")
	}

	return postgresConnectionString(address, s.DatabaseName, s.postgresUser, s.postgresPassword, withSSL, s.externalIdentity()), nil
}

func (s *Service) CreateConnectionConfiguration(ctx context.Context, conf *basev0.Configuration, instance *basev0.NetworkInstance, withSSL bool) (*basev0.Configuration, error) {
	defer s.Wool.Catch()
	ctx = s.Wool.Inject(ctx)
	if err := s.LoadConfiguration(ctx, conf); err != nil {
		return nil, s.Wool.Wrapf(err, "cannot load postgres credentials")
	}
	readOnlyRole, readWriteRole := runtimeRoleNames(s.DatabaseName)
	passwordless := s.externalIdentity()
	ownerConnection := postgresConnectionString(instance.Address, s.DatabaseName, s.postgresUser, s.postgresPassword, withSSL, passwordless)
	readOnlyConnection := postgresConnectionString(instance.Address, s.DatabaseName, readOnlyRole, s.readOnlyPassword, withSSL, passwordless)
	readWriteConnection := postgresConnectionString(instance.Address, s.DatabaseName, readWriteRole, s.readWritePassword, withSSL, passwordless)

	// The delegated read-write principal reaches its write authority through the
	// application role it defaults to on login, not through anything encoded in
	// this DSN: ensureRuntimeAccess and runtime-access.sql set that default
	// server-side (see ensureDefaultRole). A `role` startup parameter here would
	// make a role the principal cannot yet assume a FATAL that refuses the
	// connection outright, and would never reach the restricted deploy profile,
	// which exports these keys without values.
	values := []*basev0.ConfigurationValue{
		{Key: ownerConnectionKey, Value: ownerConnection, Secret: true},
		{Key: readOnlyConnectionKey, Value: readOnlyConnection, Secret: true},
		{Key: readWriteConnectionKey, Value: readWriteConnection, Secret: true},
	}
	logins, err := s.runtimeLogins()
	if err != nil {
		return nil, err
	}
	for _, login := range logins {
		connection := postgresConnectionString(instance.Address, s.DatabaseName, login.role, s.loginPasswords[login.name], withSSL, passwordless)
		values = append(values, &basev0.ConfigurationValue{Key: login.connectionKey, Value: connection, Secret: true})
	}
	outputConf := &basev0.Configuration{
		Origin:         s.Unique(),
		RuntimeContext: resources.RuntimeContextFromInstance(instance),
		Infos: []*basev0.ConfigurationInformation{
			{Name: "postgres", ConfigurationValues: values},
		},
	}
	return outputConf, nil
}

// promotableConnectionConfiguration describes the capability-scoped handoff
// without embedding credentials. The migration owner remains private to the
// bootstrap Job and is never advertised to dependent workloads.
//
// Each connection carries a template instead of a value: the role, address,
// database and sslmode are known here and are not secret, and the password is
// a reference to this service's own runtime password. Whoever delivers the
// value (the CLI's ExternalSecret projection) assembles it where the passwords
// are, so a secret store holds only the passwords the bootstrap Job sets on the
// roles, and nobody assembles a connection string by hand.
//
// External-identity mode holds no password, so there is nothing to assemble a
// value from: its connections stay keys without values, as before.
func (s *Service) promotableConnectionConfiguration(instance *basev0.NetworkInstance, withSSL bool) *basev0.Configuration {
	readOnly := &basev0.ConfigurationValue{Key: readOnlyConnectionKey, Secret: true}
	readWrite := &basev0.ConfigurationValue{Key: readWriteConnectionKey, Secret: true}
	if !s.externalIdentity() {
		readOnlyRole, readWriteRole := runtimeRoleNames(s.DatabaseName)
		readOnly.Template = postgresConnectionTemplate(
			instance.Address, s.DatabaseName, readOnlyRole, "POSTGRES_READ_ONLY_PASSWORD", withSSL,
		)
		readWrite.Template = postgresConnectionTemplate(
			instance.Address, s.DatabaseName, readWriteRole, "POSTGRES_READ_WRITE_PASSWORD", withSSL,
		)
	}
	values := []*basev0.ConfigurationValue{readOnly, readWrite}
	// Settings were validated before any render reached here, so a resolution
	// error cannot occur; an empty set renders no login.
	logins, _ := s.runtimeLogins()
	for _, login := range logins {
		value := &basev0.ConfigurationValue{Key: login.connectionKey, Secret: true}
		if !s.externalIdentity() {
			value.Template = postgresConnectionTemplate(instance.Address, s.DatabaseName, login.role, login.passwordKey, withSSL)
		}
		values = append(values, value)
	}
	return &basev0.Configuration{
		Origin:         s.Unique(),
		RuntimeContext: resources.RuntimeContextFromInstance(instance),
		Infos: []*basev0.ConfigurationInformation{
			{Name: "postgres", ConfigurationValues: values},
		},
	}
}

// postgresSSLMode is the sslmode a connection to address pins, or "" when it
// pins none and leaves the client's default.
func postgresSSLMode(address string, withSSL bool) string {
	if !withSSL || strings.Contains(address, "localhost") || strings.Contains(address, "host.docker.internal") {
		return "disable"
	}
	return ""
}

func postgresConnectionString(address, database, user, password string, withSSL, passwordless bool) string {
	query := url.Values{}
	if sslMode := postgresSSLMode(address, withSSL); sslMode != "" {
		query.Set("sslmode", sslMode)
	}
	// External-identity mode carries no password: the consumer acquires a
	// short-lived token at connect time, so the DSN keeps only the principal.
	// The mode is authoritative — a stray password must never leak into the DSN.
	userinfo := url.User(user)
	if !passwordless {
		userinfo = url.UserPassword(user, password)
	}
	connection := &url.URL{
		Scheme:   "postgresql",
		User:     userinfo,
		Host:     address,
		Path:     "/" + database,
		RawQuery: query.Encode(),
	}
	return connection.String()
}

// postgresConnectionTemplate is postgresConnectionString with the password
// left as a reference to passwordKey in this service's "postgres" secret
// configuration. Every other part is built by the same url.URL encoding, so the
// assembled value addresses the same role, host, database and sslmode as the
// value this agent renders when it holds the password itself.
func postgresConnectionTemplate(address, database, user, passwordKey string, withSSL bool) *basev0.ConfigurationValueTemplate {
	withoutPassword := postgresConnectionString(address, database, user, "", withSSL, true)
	// withoutPassword is "postgresql://<user>@<host>/<database>[?query]"; the
	// escaped user never contains "@", so the first one separates the userinfo.
	userinfo, target, _ := strings.Cut(withoutPassword, "@")
	return &basev0.ConfigurationValueTemplate{Segments: []*basev0.ConfigurationValueTemplateSegment{
		{Content: &basev0.ConfigurationValueTemplateSegment_Literal{Literal: userinfo + ":"}},
		{Content: &basev0.ConfigurationValueTemplateSegment_Reference{Reference: &basev0.ConfigurationValueReference{
			Configuration: "postgres",
			Key:           passwordKey,
			Escape:        basev0.ConfigurationValueEscape_CONFIGURATION_VALUE_ESCAPE_URL_USERINFO,
		}}},
		{Content: &basev0.ConfigurationValueTemplateSegment_Literal{Literal: "@" + target}},
	}}
}

func main() {
	svc := NewService()
	agents.Serve(agents.PluginRegistration{
		Agent:   svc,
		Runtime: NewRuntime(),
		Builder: NewBuilder(),
	})
}

//go:embed agent.codefly.yaml
var infoFS embed.FS

//go:embed templates/agent
var readmeFS embed.FS

//go:embed runtime-image.json
var runtimeImageLockJSON []byte
