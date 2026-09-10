//go:build controlplaneintegration

package controlplane

import (
	"context"
	"database/sql"
	"errors"
	"net/url"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/lib/pq"
)

// Only a disposable loopback fixture is accepted. The dedicated workflow and
// qualify-controlplane.py own its lifecycle; no managed/cloud DSN is accepted.
func fixtureDB(t *testing.T, database, user string) *sql.DB {
	t.Helper()
	u, err := url.Parse(os.Getenv("SERVICE_POSTGRES_CONTROLPLANE_TEST_DSN"))
	if err != nil || u == nil || u.Scheme != "postgres" || u.Hostname() != "127.0.0.1" || u.Port() == "" {
		t.Fatal("use scripts/qualify-controlplane.py with an isolated PostgreSQL fixture")
	}
	u.Path, u.User, u.RawQuery = "/"+database, url.User(user), "sslmode=disable&connect_timeout=5"
	db, err := sql.Open("postgres", u.String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func fixtureSQL(t *testing.T, db *sql.DB, statement string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, err := db.ExecContext(ctx, statement); err != nil {
		t.Fatal(err)
	}
}

func fixtureValue(t *testing.T, db *sql.DB, statement string) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	var value string
	if err := db.QueryRowContext(ctx, statement).Scan(&value); err != nil {
		t.Fatal(err)
	}
	return value
}

func reconcileFixture(db *sql.DB, access RuntimeAccess) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, "SELECT pg_advisory_xact_lock(hashtext('codefly-runtime-access:' || current_database()))"); err != nil {
		return err
	}
	if err := ReconcileRuntimeAccess(ctx, tx, access); err != nil {
		return err
	}
	return tx.Commit()
}

func TestExternalIdentityRestrictedAdministrator(t *testing.T) {
	bootstrap := fixtureDB(t, "postgres", "postgres")
	t.Log("fixture:", fixtureValue(t, bootstrap, "SHOW server_version"))
	fixtureSQL(t, bootstrap, "CREATE ROLE access_owner LOGIN CREATEROLE CREATEDB")
	for _, principal := range []string{"access_reader", "access_writer", "access_writer2"} {
		fixtureSQL(t, bootstrap, "CREATE ROLE "+pq.QuoteIdentifier(principal)+" LOGIN INHERIT PASSWORD 'fixture-only'")
	}
	fixtureSQL(t, bootstrap, "CREATE ROLE unrelated NOLOGIN")
	fixtureSQL(t, bootstrap, "GRANT unrelated TO access_writer")
	fixtureSQL(t, bootstrap, "CREATE DATABASE access_proof OWNER access_owner")
	owner := fixtureDB(t, "access_proof", "access_owner")
	fixtureSQL(t, owner, "CREATE TABLE before_reconcile(id integer PRIMARY KEY, value text)")
	access := RuntimeAccess{
		Database: "access_proof", OwnerRole: "access_owner", Schemas: []string{"public"},
		ReadOnlyRole: "proof_ro", ReadWriteRole: "proof_rw", AuthMode: AuthModeExternalIdentity,
		ReadOnlyPrincipals: []string{"access_reader"}, ReadWritePrincipals: []string{"access_writer"},
	}
	password := fixtureValue(t, bootstrap, "SELECT rolpassword FROM pg_authid WHERE rolname='access_writer'")
	for n := 0; n < 2; n++ {
		if err := reconcileFixture(owner, access); err != nil {
			t.Fatalf("restricted reconciliation %d: %v", n, err)
		}
	}
	fixtureSQL(t, owner, "CREATE TABLE after_reconcile(id serial PRIMARY KEY, value text)")
	writer := fixtureDB(t, "access_proof", "access_writer")
	reader := fixtureDB(t, "access_proof", "access_reader")
	fixtureSQL(t, writer, "INSERT INTO before_reconcile VALUES (1,'before')")
	fixtureSQL(t, writer, "INSERT INTO after_reconcile(value) VALUES ('after')")
	if fixtureValue(t, reader, "SELECT value FROM after_reconcile") != "after" {
		t.Fatal("default privileges did not permit reader")
	}
	for _, statement := range []string{"CREATE TABLE forbidden(id integer)", "ALTER TABLE after_reconcile ADD COLUMN forbidden text"} {
		if _, err := writer.Exec(statement); err == nil {
			t.Fatal("writer DDL succeeded")
		}
	}
	if _, err := reader.Exec("INSERT INTO after_reconcile(value) VALUES ('forbidden')"); err == nil {
		t.Fatal("reader write succeeded")
	}
	for _, role := range []string{"proof_ro", "proof_rw"} {
		if fixtureValue(t, bootstrap, "SELECT (rolcanlogin OR rolsuper OR rolcreatedb OR rolcreaterole OR rolinherit OR rolreplication OR rolbypassrls)::text FROM pg_roles WHERE rolname="+pq.QuoteLiteral(role)) != "false" {
			t.Fatal("unsafe group attributes")
		}
	}
	broken := access
	broken.ReadWritePrincipals = []string{"missing_principal"}
	if err := reconcileFixture(owner, broken); err == nil {
		t.Fatal("missing principal accepted")
	}
	if fixtureValue(t, bootstrap, "SELECT pg_has_role('access_writer','proof_rw','MEMBER')::text") != "true" {
		t.Fatal("failed reconciliation changed membership")
	}
	access.ReadWritePrincipals = []string{"access_writer2"}
	if err := reconcileFixture(owner, access); err != nil {
		t.Fatal("replacement:", err)
	}
	if fixtureValue(t, bootstrap, "SELECT pg_has_role('access_writer','proof_rw','MEMBER')::text") != "false" || fixtureValue(t, bootstrap, "SELECT pg_has_role('access_writer','unrelated','MEMBER')::text") != "true" {
		t.Fatal("membership reconciliation did not preserve the ownership boundary")
	}
	if fixtureValue(t, bootstrap, "SELECT rolpassword FROM pg_authid WHERE rolname='access_writer'") != password {
		t.Fatal("external password changed")
	}
	version, err := strconv.Atoi(fixtureValue(t, bootstrap, "SHOW server_version_num"))
	if err != nil {
		t.Fatal(err)
	}
	if version >= 160000 {
		if fixtureValue(t, bootstrap, "SELECT (admin_option AND NOT inherit_option AND NOT set_option)::text FROM pg_auth_members m JOIN pg_roles r ON r.oid=m.roleid JOIN pg_roles u ON u.oid=m.member WHERE r.rolname='proof_rw' AND u.rolname='access_owner'") != "true" {
			t.Fatal("creator's administration-only membership was lost or broadened")
		}
	}
	// Do not silently accept elevated groups or broaden the administrator's
	// authority. Any insufficient-privilege error must roll back the transaction.
	for _, flag := range []string{"SUPERUSER", "REPLICATION", "BYPASSRLS"} {
		t.Run(flag, func(t *testing.T) {
			fixtureSQL(t, bootstrap, "ALTER ROLE proof_rw "+flag)
			err := reconcileFixture(owner, access)
			var pgerr *pq.Error
			if !errors.As(err, &pgerr) || pgerr.Code != "42501" {
				t.Fatalf("expected insufficient privilege for elevated group, got %v", err)
			}
			fixtureSQL(t, bootstrap, "ALTER ROLE proof_rw NO"+flag)
		})
	}
	if err := reconcileFixture(owner, access); err != nil {
		t.Fatal("recovery:", err)
	}
	// Mutable ordinary attributes must still be hardened, and a qualified
	// superuser must retain the original elevated-group repair behavior.
	fixtureSQL(t, bootstrap, "ALTER ROLE proof_rw LOGIN CREATEDB CREATEROLE INHERIT")
	if err := reconcileFixture(owner, access); err != nil {
		t.Fatal("ordinary attribute hardening:", err)
	}
	fixtureSQL(t, bootstrap, "ALTER ROLE proof_rw SUPERUSER REPLICATION BYPASSRLS")
	adminDB := fixtureDB(t, "access_proof", "postgres")
	// Exercise attribute repair directly: changing the membership reconciler's
	// grantor is a separate PostgreSQL privilege dependency operation.
	repair, err := adminDB.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer repair.Rollback()
	if err := ensureGroupRole(context.Background(), repair, "proof_rw"); err != nil {
		t.Fatal("privileged hardening regression:", err)
	}
	if err := repair.Commit(); err != nil {
		t.Fatal(err)
	}
	if fixtureValue(t, bootstrap, "SELECT (rolcanlogin OR rolsuper OR rolcreatedb OR rolcreaterole OR rolinherit OR rolreplication OR rolbypassrls)::text FROM pg_roles WHERE rolname='proof_rw'") != "false" {
		t.Fatal("hardening omitted a role attribute")
	}
	fixtureSQL(t, bootstrap, "CREATE ROLE no_role_admin LOGIN")
	noAdmin := fixtureDB(t, "access_proof", "no_role_admin")
	unowned := access
	unowned.ReadOnlyRole, unowned.ReadWriteRole = "unowned_ro", "unowned_rw"
	if err := reconcileFixture(noAdmin, unowned); err == nil {
		t.Fatal("unprivileged user reconciled groups")
	}
	if fixtureValue(t, bootstrap, "SELECT count(*)::text FROM pg_roles WHERE rolname IN ('unowned_ro','unowned_rw')") != "0" {
		t.Fatal("failed role creation was not atomic")
	}
}
