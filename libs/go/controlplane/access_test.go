package controlplane

import (
	"context"
	"database/sql"
	"testing"
)

var _ func(context.Context, *sql.Tx, RuntimeAccess) error = ReconcileRuntimeAccess

func TestReconcileRuntimeAccessFailsClosedBeforeSQL(t *testing.T) {
	valid := RuntimeAccess{
		Database: "application", OwnerRole: "owner", ReadOnlyRole: "reader", ReadWriteRole: "writer", Schemas: []string{"public"},
	}
	if err := ReconcileRuntimeAccess(nil, nil, valid); err == nil {
		t.Fatal("nil context was accepted")
	}
	if err := ReconcileRuntimeAccess(context.Background(), nil, valid); err == nil {
		t.Fatal("nil transaction was accepted")
	}
	for name, mutate := range map[string]func(*RuntimeAccess){
		"database": func(access *RuntimeAccess) { access.Database = "" },
		"owner":    func(access *RuntimeAccess) { access.OwnerRole = "" },
		"reader":   func(access *RuntimeAccess) { access.ReadOnlyRole = "" },
		"writer":   func(access *RuntimeAccess) { access.ReadWriteRole = "" },
		"schemas":  func(access *RuntimeAccess) { access.Schemas = nil },
		"same role": func(access *RuntimeAccess) {
			access.ReadWriteRole = access.ReadOnlyRole
		},
		"reader roles without opt in": func(access *RuntimeAccess) {
			access.ReadOnlyRoles = []string{"app_reader"}
		},
		"reader role is owner": func(access *RuntimeAccess) {
			access.ReconcileReadOnlyRoleMemberships = true
			access.ReadOnlyRoles = []string{access.OwnerRole}
		},
		"reader role is writer": func(access *RuntimeAccess) {
			access.ReconcileReadOnlyRoleMemberships = true
			access.ReadOnlyRoles = []string{access.ReadWriteRole}
		},
		"reader role shared with writer": func(access *RuntimeAccess) {
			access.ReconcileReadOnlyRoleMemberships, access.ReconcileReadWriteRoleMemberships = true, true
			access.ReadOnlyRoles, access.ReadWriteRoles = []string{"app_role"}, []string{"app_role"}
		},
		"duplicate reader role": func(access *RuntimeAccess) {
			access.ReconcileReadOnlyRoleMemberships = true
			access.ReadOnlyRoles = []string{"app_role", "app_role"}
		},
	} {
		t.Run(name, func(t *testing.T) {
			candidate := valid
			mutate(&candidate)
			if err := validateRuntimeAccess(candidate); err == nil {
				t.Fatal("invalid runtime-access contract was accepted")
			}
		})
	}
}

func TestValidateRuntimeAccessAuthMode(t *testing.T) {
	base := RuntimeAccess{
		Database: "application", OwnerRole: "owner", ReadOnlyRole: "reader", ReadWriteRole: "writer", Schemas: []string{"public"},
	}
	for name, mutate := range map[string]func(*RuntimeAccess){
		"unknown mode": func(access *RuntimeAccess) { access.AuthMode = "kerberos" },
		"principals without external mode": func(access *RuntimeAccess) {
			access.ReadOnlyPrincipals = []string{"cloud_reader"}
		},
		"empty external principal": func(access *RuntimeAccess) {
			access.AuthMode = AuthModeExternalIdentity
			access.ReadWritePrincipals = []string{"  "}
		},
	} {
		t.Run(name, func(t *testing.T) {
			candidate := base
			mutate(&candidate)
			if err := validateRuntimeAccess(candidate); err == nil {
				t.Fatal("invalid auth-mode contract was accepted")
			}
		})
	}

	valid := base
	valid.AuthMode = AuthModeExternalIdentity
	valid.ReadOnlyPrincipals = []string{"cloud_reader"}
	valid.ReadWritePrincipals = []string{"cloud_writer"}
	if err := validateRuntimeAccess(valid); err != nil {
		t.Fatalf("valid external-identity contract rejected: %v", err)
	}
}
