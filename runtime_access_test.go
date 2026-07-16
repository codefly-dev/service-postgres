package main

import (
	"context"
	"net/url"
	"regexp"
	"testing"

	basev0 "github.com/codefly-dev/core/generated/go/codefly/base/v0"
	"github.com/codefly-dev/core/resources"
)

func TestConnectionConfigurationExposesExplicitCapabilities(t *testing.T) {
	svc := newTestPostgresService()
	svc.DatabaseName = "accounts"
	configuration, err := svc.CreateConnectionConfiguration(
		context.Background(),
		testPostgresConfiguration("migration-owner", "owner-secret", "reader-secret", "writer-secret"),
		&basev0.NetworkInstance{Address: "database.internal:5432", Access: resources.NewNativeNetworkAccess()},
		true,
	)
	if err != nil {
		t.Fatal(err)
	}

	readOnly := configurationValue(t, configuration, readOnlyConnectionKey)
	readWrite := configurationValue(t, configuration, readWriteConnectionKey)
	owner := configurationValue(t, configuration, ownerConnectionKey)

	readOnlyRole, readWriteRole := runtimeRoleNames(svc.DatabaseName)
	assertConnectionIdentity(t, owner, "migration-owner", "owner-secret")
	assertConnectionIdentity(t, readOnly, readOnlyRole, "reader-secret")
	assertConnectionIdentity(t, readWrite, readWriteRole, "writer-secret")
	if readOnlyRole == "migration-owner" || readWriteRole == "migration-owner" {
		t.Fatal("runtime connection reused the migration owner")
	}
}

func TestConnectionConfigurationPreservesReservedCredentialCharacters(t *testing.T) {
	svc := newTestPostgresService()
	svc.DatabaseName = "accounts"
	configuration, err := svc.CreateConnectionConfiguration(
		context.Background(),
		testPostgresConfiguration("migration-owner", "owner:/?#[]@", "reader:/?#[]@", "writer:/?#[]@"),
		&basev0.NetworkInstance{Address: "localhost:5432", Access: resources.NewNativeNetworkAccess()},
		false,
	)
	if err != nil {
		t.Fatal(err)
	}
	_, readWriteRole := runtimeRoleNames(svc.DatabaseName)
	assertConnectionIdentity(t, configurationValue(t, configuration, ownerConnectionKey), "migration-owner", "owner:/?#[]@")
	assertConnectionIdentity(t, configurationValue(t, configuration, readWriteConnectionKey), readWriteRole, "writer:/?#[]@")
}

func TestCredentialsFailClosed(t *testing.T) {
	tests := []struct {
		name   string
		owner  string
		reader string
		writer string
	}{
		{name: "missing owner", reader: "reader", writer: "writer"},
		{name: "missing reader", owner: "owner", writer: "writer"},
		{name: "missing writer", owner: "owner", reader: "reader"},
		{name: "owner equals reader", owner: "same", reader: "same", writer: "writer"},
		{name: "owner equals writer", owner: "same", reader: "reader", writer: "same"},
		{name: "reader equals writer", owner: "owner", reader: "same", writer: "same"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			svc := newTestPostgresService()
			svc.DatabaseName = "accounts"
			if err := svc.LoadConfiguration(context.Background(), testPostgresConfiguration("migration-owner", test.owner, test.reader, test.writer)); err == nil {
				t.Fatal("invalid credentials were accepted")
			}
		})
	}
}

func TestRuntimeRoleNamesAreStableDistinctAndSafe(t *testing.T) {
	readOnly, readWrite := runtimeRoleNames("Customer Accounts / Production 🚀 with a very long database name")
	if readOnly == readWrite {
		t.Fatal("read-only and read-write roles are identical")
	}
	validRole := regexp.MustCompile(`^[a-z0-9_]{1,63}$`)
	for _, role := range []string{readOnly, readWrite} {
		if !validRole.MatchString(role) {
			t.Fatalf("unsafe runtime role %q", role)
		}
	}
	readOnlyAgain, readWriteAgain := runtimeRoleNames("Customer Accounts / Production 🚀 with a very long database name")
	if readOnly != readOnlyAgain || readWrite != readWriteAgain {
		t.Fatal("runtime role names are not deterministic")
	}
}

func TestRuntimeSchemasAreExplicitValidatedAndDeduplicated(t *testing.T) {
	defaults, err := normalizedRuntimeSchemas(nil)
	if err != nil || len(defaults) != 1 || defaults[0] != "public" {
		t.Fatalf("unexpected default schemas: %v, %v", defaults, err)
	}
	schemas, err := normalizedRuntimeSchemas([]string{"app", " app ", "audit"})
	if err != nil {
		t.Fatal(err)
	}
	if len(schemas) != 2 || schemas[0] != "app" || schemas[1] != "audit" {
		t.Fatalf("unexpected normalized schemas: %v", schemas)
	}
	if _, err := normalizedRuntimeSchemas([]string{"public; DROP SCHEMA public"}); err == nil {
		t.Fatal("unsafe schema identifier was accepted")
	}
}

func TestRuntimeReadWriteRolesAreValidatedAndDeduplicated(t *testing.T) {
	roles, err := normalizedRuntimeReadWriteRoles([]string{"app_tenant", " app_tenant ", "app_worker"}, "managed_ro", "managed_rw")
	if err != nil {
		t.Fatal(err)
	}
	if len(roles) != 2 || roles[0] != "app_tenant" || roles[1] != "app_worker" {
		t.Fatalf("roles: got %v", roles)
	}
	if _, err := normalizedRuntimeReadWriteRoles([]string{"app; DROP ROLE app"}); err == nil {
		t.Fatal("expected unsafe role to be rejected")
	}
	if _, err := normalizedRuntimeReadWriteRoles([]string{"managed_rw"}, "managed_ro", "managed_rw"); err == nil {
		t.Fatal("expected managed-role conflict to be rejected")
	}
}

func testPostgresConfiguration(user, ownerPassword, readerPassword, writerPassword string) *basev0.Configuration {
	return &basev0.Configuration{
		Infos: []*basev0.ConfigurationInformation{{
			Name: "postgres",
			ConfigurationValues: []*basev0.ConfigurationValue{
				{Key: "POSTGRES_USER", Value: user},
				{Key: "POSTGRES_PASSWORD", Value: ownerPassword},
				{Key: "POSTGRES_READ_ONLY_PASSWORD", Value: readerPassword},
				{Key: "POSTGRES_READ_WRITE_PASSWORD", Value: writerPassword},
			},
		}},
	}
}

func newTestPostgresService() *Service {
	svc := NewService()
	svc.Identity = &resources.ServiceIdentity{Name: "store", Module: "test"}
	return svc
}

func configurationValue(t *testing.T, configuration *basev0.Configuration, key string) string {
	t.Helper()
	value, err := resources.GetConfigurationValue(context.Background(), configuration, "postgres", key)
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func assertConnectionIdentity(t *testing.T, connection, expectedUser, expectedPassword string) {
	t.Helper()
	parsed, err := url.Parse(connection)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.User == nil {
		t.Fatal("connection has no user information")
	}
	if parsed.User.Username() != expectedUser {
		t.Fatalf("connection user = %q, want %q", parsed.User.Username(), expectedUser)
	}
	password, ok := parsed.User.Password()
	if !ok || password != expectedPassword {
		t.Fatal("connection password did not round trip")
	}
}
