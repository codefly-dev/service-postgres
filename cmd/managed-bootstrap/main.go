// managed-bootstrap is an explicit migration-owner command. It does not start
// a service, create cloud identities, or acquire provider credentials.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/codefly-dev/service-postgres/libs/go/bootstrap"
	"os"
	"os/signal"
	"syscall"
	"time"
)

// managedBindingEnvironment carries the binding as a value; the agent's managed
// Job renders it under this name.
const managedBindingEnvironment = "CODEFLY_POSTGRES_MANAGED_BINDING"

func main() {
	var o bootstrap.Options
	var binding string
	flag.StringVar(&o.Directory, "package", "", "staged bootstrap directory containing plan.json and sources")
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
	// The binding is configuration, so a deployment delivers it as a value
	// (CODEFLY_POSTGRES_MANAGED_BINDING) and mounts nothing; -binding keeps the
	// file form for an operator running the command by hand.
	read := func() error { return bootstrap.ReadJSON(binding, &o.Binding) }
	if binding == "" {
		read = func() error { return bootstrap.ReadJSONValue(os.Getenv(managedBindingEnvironment), &o.Binding) }
	}
	if err := read(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	o.Connection = os.Getenv("CODEFLY_POSTGRES_MIGRATION_CONNECTION")
	// Delivered as configuration beside the connection they describe, never as
	// flags: a Job's command line is readable by anything in its pod, and these
	// two are the deployment's statement about where this database is. Neither is
	// a secret — an issuer names who mints the credential, and a certificate
	// authority is public — but a credential minted FROM the issuer is, so it
	// never appears here at all. Absent means the password-authenticated
	// behaviour every existing deployment has.
	o.ExternalIdentity = os.Getenv("CODEFLY_POSTGRES_EXTERNAL_IDENTITY")
	o.ServerTrustAnchorPEM = os.Getenv("CODEFLY_POSTGRES_SERVER_AUTHORITY_PEM")
	// A Cloud SQL instance is reached through the connector, which needs neither
	// a connection URL nor an authority: it asks the cloud for both as this Job.
	o.CloudSQLInstance = os.Getenv("CODEFLY_POSTGRES_CLOUD_SQL_INSTANCE")
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	result, err := bootstrap.Run(ctx, o)
	json.NewEncoder(os.Stdout).Encode(result)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
