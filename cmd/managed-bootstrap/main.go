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

func main() {
	var o bootstrap.Options
	var binding string
	flag.StringVar(&o.Directory, "package", "", "staged bootstrap directory containing plan.json and sources")
	flag.StringVar(&binding, "binding", "", "secret-free managed identity binding JSON")
	flag.StringVar(&o.MigrateExecutable, "migrate", "/usr/local/bin/migrate", "absolute path to the pinned golang-migrate executable")
	flag.DurationVar(&o.Timeout, "timeout", 10*time.Minute, "total execution budget")
	flag.DurationVar(&o.LockTimeout, "lock-timeout", 30*time.Second, "database lock budget")
	flag.DurationVar(&o.StatementTimeout, "statement-timeout", 5*time.Minute, "statement budget")
	flag.Parse()
	if flag.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "unexpected positional arguments")
		os.Exit(2)
	}
	if err := bootstrap.ReadJSON(binding, &o.Binding); err != nil {
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
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	result, err := bootstrap.Run(ctx, o)
	json.NewEncoder(os.Stdout).Encode(result)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
