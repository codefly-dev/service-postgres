package postgres

import (
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/jackc/pgx/v5/pgxpool"
)

// ConnectionTransport selects an explicit connection contract. The zero value
// retains legacy pgx parsing for existing callers; it is not a hosted profile.
type ConnectionTransport string

const (
	VerifiedTLS        ConnectionTransport = "verified-tls"
	LocalIdentityProxy ConnectionTransport = "local-identity-proxy"
)

var ErrConnectionProfile = errors.New("invalid Postgres connection profile")

var ErrConnectionUnavailable = errors.New("Postgres connection capability unavailable")

func profileConnectionError(profile ConnectionProfile, err error) error {
	if profile.Transport != "" {
		return ErrConnectionUnavailable
	}
	return err
}

// ConnectionProfile constrains the actual driver config used for a capability.
// ApplicationRole is the exact startup role required in the URL; empty forbids
// a startup role. It grants no membership. Optional identity fields bind a
// deployment projection to its expected physical endpoint, database and login.
// OpenMaintenance still owns its separate applicationRole argument and check.
type ConnectionProfile struct {
	Transport       ConnectionTransport
	ApplicationRole string
	Host            string
	Port            uint16
	Database        string
	User            string
}

// WithConnectionProfiles validates both request capabilities before either pool
// is created. Each capability retains its independent transport and role policy.
func WithConnectionProfiles(reader, writer ConnectionProfile) Option {
	return func(c *config) error {
		if reader.validate() != nil || writer.validate() != nil {
			return ErrConnectionProfile
		}
		c.readerProfile, c.writerProfile = reader, writer
		return nil
	}
}

// WithMaintenanceConnectionProfile validates the separately wired maintenance
// capability before its pool is created. It does not change request profiles.
func WithMaintenanceConnectionProfile(profile ConnectionProfile) Option {
	return func(c *config) error {
		if profile.validate() != nil {
			return ErrConnectionProfile
		}
		c.maintenanceProfile = profile
		return nil
	}
}

// WithDistinctProxySockets requires separately projected local reader/writer
// sockets. The composing service selects this requirement; transport validation
// cannot attest the proxy's remote identity or TLS/IAM configuration.
func WithDistinctProxySockets() Option {
	return func(c *config) error { c.distinctProxySockets = true; return nil }
}

func (p ConnectionProfile) validate() error {
	switch p.Transport {
	case "":
		if p != (ConnectionProfile{}) {
			return ErrConnectionProfile
		}
	case VerifiedTLS, LocalIdentityProxy:
	default:
		return ErrConnectionProfile
	}
	return nil
}

// ParseConnection parses once and validates the returned configuration without
// opening a connection or executing SQL. Open/OpenMaintenance use this same
// function. It supports trusted legacy pool composition: the caller must use the
// returned config, not validate and then reparse the original string. tokenHook
// declares whether that pool will replace credentials before connecting.
// Explicit profiles accept canonical URLs only and never consult PG* variables,
// passfiles or implicit client certificate files. Explicit-profile errors contain
// no binding data; the zero profile preserves legacy driver error behavior.
func ParseConnection(connection string, profile ConnectionProfile, tokenHook bool) (*pgxpool.Config, error) {
	if profile.validate() != nil {
		return nil, ErrConnectionProfile
	}
	if profile.Transport == "" {
		return pgxpool.ParseConfig(connection)
	}
	for _, entry := range os.Environ() {
		if strings.HasPrefix(entry, "PG") {
			return nil, ErrConnectionProfile
		}
	}
	u, err := url.Parse(connection)
	if err != nil || (u.Scheme != "postgres" && u.Scheme != "postgresql") || u.Opaque != "" || u.Fragment != "" || u.User == nil || u.User.Username() == "" || !strings.HasPrefix(u.Path, "/") || u.Path == "/" || strings.ContainsAny(strings.TrimPrefix(u.Path, "/"), "/\x00\r\n") || strings.ContainsAny(u.User.Username(), "\x00\r\n") {
		return nil, ErrConnectionProfile
	}
	q, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		return nil, ErrConnectionProfile
	}
	for key, values := range q {
		if len(values) != 1 || strings.ContainsAny(values[0], "\x00\r\n") {
			return nil, ErrConnectionProfile
		}
		switch key {
		case "role":
			if profile.ApplicationRole == "" || values[0] != profile.ApplicationRole {
				return nil, ErrConnectionProfile
			}
		case "sslmode", "passfile":
		case "host", "port":
			if profile.Transport != LocalIdentityProxy {
				return nil, ErrConnectionProfile
			}
		case "sslrootcert", "sslcert", "sslkey", "connect_timeout", "pool_max_conns", "pool_min_conns", "pool_min_idle_conns", "pool_max_conn_lifetime", "pool_max_conn_idle_time", "pool_health_check_period", "pool_max_conn_lifetime_jitter", "application_name":
			if profile.Transport != VerifiedTLS {
				return nil, ErrConnectionProfile
			}
		default:
			return nil, ErrConnectionProfile
		}
	}
	if q.Get("role") != profile.ApplicationRole {
		return nil, ErrConnectionProfile
	}
	host := u.Hostname()
	port := uint64(5432)
	password, hasPassword := u.User.Password()
	if strings.ContainsAny(password, "\x00\r\n") {
		return nil, ErrConnectionProfile
	}
	if profile.Transport == LocalIdentityProxy {
		host = q.Get("host")
		if u.Host != "" || hasPassword || tokenHook || q.Get("sslmode") != "disable" || q.Get("passfile") != "/dev/null" || !filepath.IsAbs(host) || filepath.Clean(host) != host || host == "/" || strings.ContainsAny(host, ",\x00\r\n") || strings.Contains(host, ".s.PGSQL.") {
			return nil, ErrConnectionProfile
		}
		port, err = strconv.ParseUint(q.Get("port"), 10, 16)
		if err != nil || port == 0 || strconv.FormatUint(port, 10) != q.Get("port") || len(host+"/.s.PGSQL."+q.Get("port")) > 103 {
			return nil, ErrConnectionProfile
		}
	} else {
		if host == "" || strings.ContainsAny(host, ",/\x00\r\n") || q.Get("sslmode") != "verify-full" {
			return nil, ErrConnectionProfile
		}
		if u.Port() != "" {
			port, err = strconv.ParseUint(u.Port(), 10, 16)
			if err != nil || port == 0 {
				return nil, ErrConnectionProfile
			}
		}
		if value, exists := q["passfile"]; exists && value[0] != "/dev/null" {
			return nil, ErrConnectionProfile
		}
	}
	// Explicit empty settings override pgx's home-directory certificate defaults.
	// Explicit trust roots/client credentials remain allowed in verified TLS only.
	for _, key := range []string{"sslrootcert", "sslcert", "sslkey"} {
		if _, exists := q[key]; !exists {
			q.Set(key, "")
		}
	}
	q.Set("passfile", os.DevNull)
	u.RawQuery = q.Encode()
	pc, err := pgxpool.ParseConfig(u.String())
	if err != nil {
		return nil, ErrConnectionProfile
	}
	c := pc.ConnConfig
	if c.Host != host || c.Port != uint16(port) || c.Database != strings.TrimPrefix(u.Path, "/") || c.User != u.User.Username() || c.Password != password || len(c.Fallbacks) != 0 {
		return nil, ErrConnectionProfile
	}
	if profile.Host != "" && c.Host != profile.Host || profile.Port != 0 && c.Port != profile.Port || profile.Database != "" && c.Database != profile.Database || profile.User != "" && c.User != profile.User {
		return nil, ErrConnectionProfile
	}
	for key, value := range c.RuntimeParams {
		if key == "role" && value == profile.ApplicationRole && profile.ApplicationRole != "" {
			continue
		}
		if key == "application_name" && profile.Transport == VerifiedTLS && value == q.Get(key) {
			continue
		}
		return nil, ErrConnectionProfile
	}
	if profile.Transport == LocalIdentityProxy {
		if c.TLSConfig != nil || c.Password != "" {
			return nil, ErrConnectionProfile
		}
	} else if c.TLSConfig == nil || c.TLSConfig.InsecureSkipVerify || c.TLSConfig.ServerName != host || c.TLSConfig.VerifyPeerCertificate != nil || c.TLSConfig.VerifyConnection != nil {
		return nil, ErrConnectionProfile
	}
	return pc, nil
}
