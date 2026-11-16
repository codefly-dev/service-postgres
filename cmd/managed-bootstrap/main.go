// managed-bootstrap is the store's migration runner, for both store kinds: a
// managed server (Cloud SQL through the connector, the Job's own cloud
// identity) and a self-hosted in-cluster server (the owner's password). It
// does not start a service, create cloud identities, or acquire provider
// credentials.
package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/codefly-dev/service-postgres/libs/go/bootstrap"
	"github.com/codefly-dev/service-postgres/libs/go/controlplane"
)

// managedBindingEnvironment carries the binding as a value; the agent's managed
// Job renders it under this name. Its absence selects the self-hosted run.
const managedBindingEnvironment = "CODEFLY_POSTGRES_MANAGED_BINDING"

func main() {
	var o bootstrap.Options
	var binding string
	flag.StringVar(&o.Directory, "package", "/app/bootstrap", "staged bootstrap directory containing plan.json and sources")
	flag.StringVar(&binding, "binding", "", "secret-free managed identity binding JSON file (default: the "+managedBindingEnvironment+" value)")
	flag.StringVar(&o.MigrateExecutable, "migrate", "/usr/local/bin/migrate", "absolute path to the pinned golang-migrate executable")
	flag.DurationVar(&o.Timeout, "timeout", 10*time.Minute, "total execution budget")
	flag.DurationVar(&o.LockTimeout, "lock-timeout", 30*time.Second, "database lock budget")
	flag.DurationVar(&o.StatementTimeout, "statement-timeout", 5*time.Minute, "statement budget")
	flag.Parse()
	if flag.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "unexpected positional arguments")
		os.Exit(2)
	}
	configure := managed
	if binding == "" && os.Getenv(managedBindingEnvironment) == "" {
		configure = selfHosted
	}
	if err := configure(&o, binding); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	result, err := bootstrap.Run(ctx, o)
	json.NewEncoder(os.Stdout).Encode(result)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

// managed reads the environment the managed Job renders.
func managed(o *bootstrap.Options, binding string) error {
	// The binding is configuration, so a deployment delivers it as a value
	// (CODEFLY_POSTGRES_MANAGED_BINDING) and mounts nothing; -binding keeps the
	// file form for an operator running the command by hand.
	read := func() error { return bootstrap.ReadJSON(binding, &o.Binding) }
	if binding == "" {
		read = func() error { return bootstrap.ReadJSONValue(os.Getenv(managedBindingEnvironment), &o.Binding) }
	}
	if err := read(); err != nil {
		return err
	}
	o.Connection = os.Getenv("CODEFLY_POSTGRES_MIGRATION_CONNECTION")
	// Delivered as configuration beside the connection they describe, never as
	// flags: a Job's command line is readable by anything in its pod. Neither is
	// a secret — an issuer names who mints the credential, and a certificate
	// authority is public — but a credential minted FROM the issuer is, so it
	// never appears here at all.
	o.ExternalIdentity = os.Getenv("CODEFLY_POSTGRES_EXTERNAL_IDENTITY")
	o.ServerTrustAnchorPEM = os.Getenv("CODEFLY_POSTGRES_SERVER_AUTHORITY_PEM")
	// A Cloud SQL instance is reached through the connector, which needs neither
	// a connection URL nor an authority: it asks the cloud for both as this Job.
	o.CloudSQLInstance = os.Getenv("CODEFLY_POSTGRES_CLOUD_SQL_INSTANCE")
	return nil
}

// selfHosted reads the environment the in-cluster Job delivers: the owner's
// connection (an owner URL, or libpq's PG* variables when the restricted
// profile assembles none), the runtime logins' passwords, and the package's own
// self-hosted.json. The plan is the image's own, so its identity is read from
// the staged file rather than bound from outside.
func selfHosted(o *bootstrap.Options, _ string) error {
	var pkg bootstrap.SelfHostedPackage
	if err := bootstrap.ReadJSON(filepath.Join(o.Directory, bootstrap.SelfHostedFile), &pkg); err != nil {
		return err
	}
	plan, err := os.ReadFile(filepath.Join(o.Directory, "plan.json"))
	if err != nil {
		return errors.New("cannot read the staged schema plan")
	}
	var identity struct {
		Digest string `json:"digest"`
	}
	if err = json.Unmarshal(plan, &identity); err != nil {
		return errors.New("invalid staged schema plan")
	}
	sum := sha256.Sum256(plan)
	connection, owner, password, err := ownerConnection()
	if err != nil {
		return err
	}
	o.Binding = bootstrap.Binding{PlanSHA256: hex.EncodeToString(sum[:]), PlanDigest: identity.Digest, OwnerRole: owner}
	o.Connection = connection
	o.ReadinessTimeout = time.Duration(pkg.ReadinessSeconds) * time.Second
	o.Password = &bootstrap.Password{Owner: password, ReadOnly: os.Getenv("POSTGRES_READ_ONLY_PASSWORD"), ReadWrite: os.Getenv("POSTGRES_READ_WRITE_PASSWORD")}
	for _, login := range pkg.Logins {
		o.Password.Logins = append(o.Password.Logins, controlplane.PasswordLogin{Role: login.Role, Password: os.Getenv(login.PasswordVariable), ReadWriteRoles: login.ReadWriteRoles})
	}
	return nil
}

// ownerConnection returns the owner's passwordless URL, its role and its
// password, which Run supplies at connect time rather than in the URL.
func ownerConnection() (connection, owner, password string, err error) {
	var u *url.URL
	if os.Getenv("CODEFLY_POSTGRES_OWNER_FROM_LIBPQ_ENVIRONMENT") == "true" {
		port := os.Getenv("PGPORT")
		if port == "" {
			port = "5432"
		}
		u = &url.URL{Host: net.JoinHostPort(os.Getenv("PGHOST"), port), Path: "/" + os.Getenv("PGDATABASE"),
			User: url.UserPassword(os.Getenv("PGUSER"), os.Getenv("PGPASSWORD")), RawQuery: url.Values{"sslmode": {os.Getenv("PGSSLMODE")}}.Encode()}
	} else if u, err = url.Parse(os.Getenv("CODEFLY_POSTGRES_MIGRATION_CONNECTION")); err != nil || u.User == nil || (u.Scheme != "postgres" && u.Scheme != "postgresql") {
		return "", "", "", errors.New("CODEFLY_POSTGRES_MIGRATION_CONNECTION is not an owner postgres URL")
	}
	owner = u.User.Username()
	password, _ = u.User.Password()
	if owner == "" || password == "" {
		return "", "", "", errors.New("the owner connection names no user or password")
	}
	q := u.Query()
	// libpq's own default when nothing pins it: TLS when the server offers it.
	if q.Get("sslmode") == "" {
		q.Set("sslmode", "prefer")
	}
	u.Scheme, u.User, u.RawQuery = "postgres", url.User(owner), q.Encode()
	return u.String(), owner, password, nil
}
