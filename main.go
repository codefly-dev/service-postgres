package main

import (
	"context"
	"embed"
	"fmt"
	"github.com/codefly-dev/core/builders"
	basev0 "github.com/codefly-dev/core/generated/go/codefly/base/v0"
	"github.com/codefly-dev/core/templates"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"strings"

	"github.com/codefly-dev/core/agents"
	"github.com/codefly-dev/core/agents/services"
	agentv0 "github.com/codefly-dev/core/generated/go/codefly/services/agent/v0"
	"github.com/codefly-dev/core/resources"
	"github.com/codefly-dev/core/shared"
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

	WithoutSSL  bool `yaml:"without-ssl"`  // Default to SSL
	NoMigration bool `yaml:"no-migration"` // Developer only

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
}

const HotReload = "hot-reload"
const DatabaseName = "database-name"

// pgvector/pgvector:pg17 is the official Postgres 17 image with the pgvector
// extension preinstalled (same docker-entrypoint as the stock postgres image,
// so the full contrib set — pgcrypto, uuid-ossp, pg_trgm, citext, btree_gin, …
// — is available too). Required so `CREATE EXTENSION vector` works — consumers
// like Mind's knowledge-graph migration (vector(1024) column) depend on it. The
// nix runtime gets pgvector via nix/flake.nix; this keeps both runtimes at
// parity. Override per-service via Settings.DockerImage (e.g. for PostGIS).
var image = &resources.DockerImage{Name: "pgvector/pgvector", Tag: "pg17"}

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

	postgresUser     string
	postgresPassword string
	connectionKey    string
	connection       string

	TcpEndpoint *basev0.Endpoint
}

func (s *Service) GetAgentInformation(ctx context.Context, _ *agentv0.AgentInformationRequest) (*agentv0.AgentInformation, error) {

	readme, err := templates.ApplyTemplateFrom(ctx, shared.Embed(readmeFS), "templates/agent/README.md", s.Information)
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	return &agentv0.AgentInformation{
		RuntimeRequirements: []*agentv0.Runtime{},
		Capabilities: []*agentv0.Capability{
			{Type: agentv0.Capability_BUILDER},
			{Type: agentv0.Capability_RUNTIME},
		},
		Protocols: []*agentv0.Protocol{},
		ConfigurationDetails: []*agentv0.ConfigurationValueDetail{
			{
				Name: "postgres", Description: "postgres credentials",
				Fields: []*agentv0.ConfigurationValueInformation{
					{
						Name: "connection", Description: "connection string",
					},
				}},
		},
		ReadMe: readme,
	}, nil
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
	return nil
}

func (s *Service) createConnectionString(ctx context.Context, conf *basev0.Configuration, address string, withSSL bool) (string, error) {
	defer s.Wool.Catch()
	ctx = s.Wool.Inject(ctx)

	err := s.LoadConfiguration(ctx, conf)
	if err != nil {
		return "", s.Wool.Wrapf(err, "cannot get user and password")
	}

	conn := fmt.Sprintf("postgresql://%s:%s@%s/%s", s.postgresUser, s.postgresPassword, address, s.DatabaseName)
	if !withSSL || strings.Contains(address, "localhost") || strings.Contains(address, "host.docker.internal") {
		conn += "?sslmode=disable"
	}
	return conn, nil
}

func (s *Service) CreateConnectionConfiguration(ctx context.Context, conf *basev0.Configuration, instance *basev0.NetworkInstance, withSSL bool) (*basev0.Configuration, error) {
	defer s.Wool.Catch()
	ctx = s.Wool.Inject(ctx)
	connection, err := s.createConnectionString(ctx, conf, instance.Address, withSSL)
	if err != nil {
		return nil, s.Wool.Wrapf(err, "cannot create connection string")
	}

	outputConf := &basev0.Configuration{
		Origin:         s.Base.Unique(),
		RuntimeContext: resources.RuntimeContextFromInstance(instance),
		Infos: []*basev0.ConfigurationInformation{
			{Name: "postgres",
				ConfigurationValues: []*basev0.ConfigurationValue{
					{Key: "connection", Value: connection, Secret: true},
				},
			},
		},
	}
	return outputConf, nil
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
