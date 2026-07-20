package controlplane

import (
	"context"
	"testing"
)

func TestReconcileRuntimeAccessFailsClosedBeforeSQL(t *testing.T) {
	valid := RuntimeAccess{
		Database: "application", OwnerRole: "owner", ReadOnlyRole: "reader", ReadWriteRole: "writer", Schemas: []string{"public"},
	}
	if err := ReconcileRuntimeAccess(nil, nil, valid); err == nil {
		t.Fatal("nil context was accepted")
	}
	if err := ReconcileRuntimeAccess(context.Background(), nil, valid); err == nil {
		t.Fatal("nil executor was accepted")
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
