package main

import (
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"

	"github.com/codefly-dev/core/agents"
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
	// .so files the extensions you list below need. Format "name:tag". Empty =
	// the default pgvector image (see the `image` var).
	Image string `yaml:"docker-image"`

	// Extensions are CREATE EXTENSION IF NOT EXISTS'd at startup, on top of the
	// always-on defaults (defaultExtensions). The extension's shared library
	// must exist in the image; the default pgvector image ships the standard
	// contrib set + vector. A missing extension is logged and skipped, never
	// fatal. e.g. ["postgis", "hstore", "unaccent"].
	Extensions []string `yaml:"extensions"`

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
	// Paths are relative to this service's directory (or absolute). A source
	// whose directory is missing is skipped with a warning.
	MigrationSources []MigrationSource `yaml:"migration-sources"`

	// Timeouts bounds every wait this agent performs or renders: readiness
	// probing, connection establishment, migration locking and statements, and
	// the deployed bootstrap Job. See Timeouts for the keys and defaults.
	Timeouts Timeouts `yaml:"timeouts"`
}

// MigrationSource declares one additional service contributing migrations to
// the shared database. See Settings.MigrationSources.
type MigrationSource struct {
	// Name identifies the lineage and names its tracking table
	// (schema_migrations_<name>). Must be a safe SQL identifier ([A-Za-z0-9_]).
	Name string `yaml:"name"`
	// Path is the migrations directory, relative to this service's directory or
	// absolute. Empty defaults to ../<name>/migrations (the sibling-service
	// layout used inside a module).
	Path string `yaml:"path"`
}

const HotReload = "hot-reload"
const DatabaseName = "database-name"

// The managed image adds pgvector to the official Postgres 17 Alpine image
// while preserving its entrypoint and contrib extensions. The nix runtime gets
// pgvector via nix/flake.nix, keeping both runtimes at parity.
var image = shared.Must(parseRuntimeImageLock(runtimeImageLockJSON))

type runtimeImageLock struct {
	Name   string `json:"name"`
	Tag    string `json:"tag"`
	Digest string `json:"digest"`
}

func parseRuntimeImageLock(content []byte) (*resources.DockerImage, error) {
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
	return &resources.DockerImage{
		Name:   lock.Name,
		Tag:    lock.Tag,
		Digest: lock.Digest,
	}, nil
}

type DeploymentTemplateParameters struct {
	WithBootstrap                bool
	ManagedImage                 string
	BootstrapJobName             string
	DatabaseName                 string
	BootstrapJobDeadlineSeconds  int
	StatefulSetSecretReferences  map[string]*builderv0.KubernetesSecretKeyReference
	BootstrapJobSecretReferences map[string]*builderv0.KubernetesSecretKeyReference
}

// defaultExtensions are CREATE EXTENSION'd on every start (best-effort). They
// all ship in the pgvector / postgres-contrib image, so they "just work" with
// zero config; Settings.Extensions adds more on top.
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
		return resources.NewDockerImage(s.Settings.Image)
	}
	return image
}

type Service struct {
	*services.Base

	// Settings
	*Settings

	postgresUser      string
	postgresPassword  string
	readOnlyPassword  string
	readWritePassword string
	connectionKey     string
	connection        string

	TcpEndpoint *basev0.Endpoint
}

func (s *Service) GetAgentInformation(ctx context.Context, _ *agentv0.AgentInformationRequest) (*agentv0.AgentInformation, error) {

	readme, err := templates.ApplyTemplateFrom(ctx, shared.Embed(readmeFS), "templates/agent/README.md", s.Information)
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	return services.Advertisement{
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
	}.Build(), nil
}

func NewService() *Service {
	return &Service{
		Base:     services.NewServiceBase(context.Background(), agent.Of(resources.ServiceAgent)),
		Settings: &Settings{},
	}
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
	outputConf := &basev0.Configuration{
		Origin:         s.Unique(),
		RuntimeContext: resources.RuntimeContextFromInstance(instance),
		Infos: []*basev0.ConfigurationInformation{
			{Name: "postgres",
				ConfigurationValues: []*basev0.ConfigurationValue{
					{Key: ownerConnectionKey, Value: ownerConnection, Secret: true},
					{Key: readOnlyConnectionKey, Value: readOnlyConnection, Secret: true},
					{Key: readWriteConnectionKey, Value: readWriteConnection, Secret: true},
				},
			},
		},
	}
	return outputConf, nil
}

// promotableConnectionConfiguration describes the capability-scoped handoff
// without embedding credentials. The migration owner remains private to the
// bootstrap Job and is never advertised to dependent workloads.
func (s *Service) promotableConnectionConfiguration(instance *basev0.NetworkInstance) *basev0.Configuration {
	return &basev0.Configuration{
		Origin:         s.Unique(),
		RuntimeContext: resources.RuntimeContextFromInstance(instance),
		Infos: []*basev0.ConfigurationInformation{
			{
				Name: "postgres",
				ConfigurationValues: []*basev0.ConfigurationValue{
					{Key: readOnlyConnectionKey, Secret: true},
					{Key: readWriteConnectionKey, Secret: true},
				},
			},
		},
	}
}

func postgresConnectionString(address, database, user, password string, withSSL, passwordless bool) string {
	query := url.Values{}
	if !withSSL || strings.Contains(address, "localhost") || strings.Contains(address, "host.docker.internal") {
		query.Set("sslmode", "disable")
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
