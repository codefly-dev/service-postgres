//go:build controlplaneintegration

package controlplane

import (
	"database/sql"
	"testing"

	"github.com/lib/pq"
)

func TestDelegatedReaderRolesTransitions(t *testing.T) {
	bootstrap := fixtureDB(t, "postgres", "postgres")
	fixtureSQL(t, bootstrap, "CREATE ROLE reader_owner LOGIN CREATEROLE CREATEDB")
	fixtureSQL(t, bootstrap, "CREATE ROLE reader_login LOGIN INHERIT")
	fixtureSQL(t, bootstrap, "CREATE ROLE reader_writer_login LOGIN INHERIT")
	fixtureSQL(t, bootstrap, "CREATE DATABASE reader_proof OWNER reader_owner")
	// PostgreSQL 14's public schema retains the bootstrap owner after CREATE
	// DATABASE; the managed migration contract requires the actual schema owner.
	fixtureSQL(t, fixtureDB(t, "reader_proof", "postgres"), "ALTER SCHEMA public OWNER TO reader_owner")
	owner := fixtureDB(t, "reader_proof", "reader_owner")
	fixtureSQL(t, owner, `
 CREATE ROLE app_reader_a NOLOGIN;
 CREATE ROLE app_reader_b NOLOGIN;
 CREATE TABLE scoped(tenant text, value text);
 INSERT INTO scoped VALUES ('a','one'),('b','two');
 CREATE TABLE unscoped(value text);
 INSERT INTO unscoped VALUES ('private');
 ALTER TABLE scoped ENABLE ROW LEVEL SECURITY;
 ALTER TABLE scoped FORCE ROW LEVEL SECURITY;
 CREATE POLICY tenant_read ON scoped FOR SELECT TO app_reader_a,app_reader_b
   USING (tenant=current_setting('app.tenant',true));
 GRANT USAGE ON SCHEMA public TO app_reader_a,app_reader_b;
 GRANT SELECT ON scoped TO app_reader_a,app_reader_b;
 `)
	access := RuntimeAccess{Database: "reader_proof", OwnerRole: "reader_owner", ReadOnlyRole: "reader_group", ReadWriteRole: "reader_writer_group", Schemas: []string{"public"}, AuthMode: AuthModeExternalIdentity, ReadOnlyPrincipals: []string{"reader_login"}, ReadWritePrincipals: []string{"reader_writer_login"}}
	if err := reconcileFixture(owner, access); err != nil {
		t.Fatal(err)
	}
	// Connect catalog observations to this database; role membership is global,
	// but object names and default ACLs are not.
	if fixtureValue(t, owner, "SELECT has_table_privilege('reader_group','unscoped','SELECT')::text") != "true" {
		t.Fatal("legacy reader access changed")
	}
	access.ReconcileReadOnlyRoleMemberships = true
	access.ReadOnlyRoles = []string{"app_reader_a"}
	for n := 0; n < 2; n++ {
		if err := reconcileFixture(owner, access); err != nil {
			t.Fatalf("delegated reader reconciliation %d: %v", n, err)
		}
	}
	fixtureSQL(t, owner, "CREATE TABLE after_reader_transition(value text)")
	for _, table := range []string{"unscoped", "scoped", "after_reader_transition"} {
		if fixtureValue(t, owner, "SELECT has_table_privilege('reader_group',"+pq.QuoteLiteral(table)+",'SELECT')::text") != "false" {
			t.Fatal("delegated group retained direct/default SELECT:", table)
		}
	}
	reader := fixtureDB(t, "reader_proof", "reader_login")
	checkReader := func(role, tenant string) {
		t.Helper()
		tx, err := reader.Begin()
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback()
		if _, err = tx.Exec("SET LOCAL ROLE " + pq.QuoteIdentifier(role)); err != nil {
			t.Fatal(err)
		}
		if _, err = tx.Exec("SELECT set_config('app.tenant',$1,true)", tenant); err != nil {
			t.Fatal(err)
		}
		var count int
		if err = tx.QueryRow("SELECT count(*) FROM scoped").Scan(&count); err != nil || count != 1 {
			t.Fatalf("tenant isolation: count=%d err=%v", count, err)
		}
	}
	checkReader("app_reader_a", "a")
	checkReader("app_reader_a", "b")
	denied := func(db *sql.DB, role, statement string) {
		t.Helper()
		tx, err := db.Begin()
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback()
		if role != "" {
			if _, err = tx.Exec("SET LOCAL ROLE " + pq.QuoteIdentifier(role)); err != nil {
				t.Fatal(err)
			}
		}
		if _, err = tx.Exec(statement); err == nil {
			t.Fatal("unexpected authority:", statement)
		}
	}
	for _, statement := range []string{"INSERT INTO scoped VALUES ('a','bad')", "UPDATE scoped SET value='bad'", "DELETE FROM scoped", "CREATE TABLE forbidden(id int)", "SELECT * FROM unscoped", "SET ROLE reader_writer_group", "SET ROLE reader_owner"} {
		denied(reader, "app_reader_a", statement)
	}
	// A rejected candidate cannot revoke the currently working binding.
	fixtureSQL(t, owner, `
 CREATE ROLE app_reader_write NOLOGIN;
 GRANT INSERT ON scoped TO app_reader_write;
 CREATE ROLE app_reader_noinherit NOLOGIN NOINHERIT;
 GRANT app_reader_write TO app_reader_noinherit;
 CREATE ROLE app_reader_column_write NOLOGIN;
 GRANT UPDATE(value) ON scoped TO app_reader_column_write;
 CREATE ROLE app_reader_create NOLOGIN;
 GRANT CREATE ON SCHEMA public TO app_reader_create;
 CREATE ROLE app_reader_child NOLOGIN;
 `)
	fixtureSQL(t, bootstrap, "CREATE ROLE app_reader_elevated NOLOGIN BYPASSRLS; GRANT app_reader_elevated TO app_reader_child")
	for _, role := range []string{"missing_reader", "reader_login", "reader_owner", "reader_writer_group", "app_reader_write", "app_reader_noinherit", "app_reader_column_write", "app_reader_create", "app_reader_elevated", "app_reader_child"} {
		candidate := access
		candidate.ReadOnlyRoles = []string{role}
		if err := reconcileFixture(owner, candidate); err == nil {
			t.Fatal("non-reader role accepted:", role)
		}
		if fixtureValue(t, owner, "SELECT pg_has_role('reader_login','app_reader_a','MEMBER')::text") != "true" {
			t.Fatal("failed reconciliation changed membership")
		}
	}
	access.ReadOnlyRoles = []string{"app_reader_b"}
	if err := reconcileFixture(owner, access); err != nil {
		t.Fatal(err)
	}
	if fixtureValue(t, owner, "SELECT pg_has_role('reader_login','app_reader_a','MEMBER')::text") != "false" {
		t.Fatal("replaced reader membership survived")
	}
	checkReader("app_reader_b", "a")
	access.ReadOnlyRoles = nil
	for n := 0; n < 2; n++ {
		if err := reconcileFixture(owner, access); err != nil {
			t.Fatal(err)
		}
	}
	if fixtureValue(t, owner, "SELECT pg_has_role('reader_login','app_reader_b','MEMBER')::text") != "false" {
		t.Fatal("removed reader membership survived")
	}
	denied(reader, "", "SET ROLE app_reader_b")
	denied(reader, "reader_group", "SELECT * FROM scoped")
	denied(reader, "reader_group", "SELECT * FROM unscoped")
	if fixtureValue(t, owner, "SELECT has_table_privilege('reader_group','unscoped','SELECT')::text") != "false" {
		t.Fatal("empty delegation restored blanket SELECT")
	}
}
