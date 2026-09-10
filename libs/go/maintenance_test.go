package postgres

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/jackc/pgx/v5"
)

func TestMaintenanceUsesSharedTransactionsWithoutTenantImpersonation(t *testing.T) {
	for _, fail := range []bool{false, true} {
		backend := &fakeBeginner{tx: &fakeTransaction{}}
		c, err := configured(WithReadIsolation(pgx.RepeatableRead))
		if err != nil {
			t.Fatal(err)
		}
		m := &Maintenance{backend: backend, config: c}
		reader, err := m.Reader(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		callbackErr := errors.New("callback failed")
		err = reader.InTransaction(context.Background(), func(context.Context, ReadTx) error {
			if fail {
				return callbackErr
			}
			return nil
		})
		if fail != errors.Is(err, callbackErr) || backend.tx.committed == fail {
			t.Fatalf("transaction result: %v, committed %v", err, backend.tx.committed)
		}
		if backend.options.AccessMode != pgx.ReadOnly || backend.options.IsoLevel != pgx.RepeatableRead {
			t.Fatal("lost read snapshot semantics")
		}
		if !reflect.DeepEqual(backend.tx.executions[0].arguments, []any{"codefly.current_tenant_id", "", "codefly.current_user_id", ""}) {
			t.Fatal("maintenance impersonated a tenant")
		}
	}
}

func TestMaintenanceInvalidCompositionFailsClosed(t *testing.T) {
	var m *Maintenance
	if _, err := m.Reader(context.Background()); err == nil {
		t.Fatal("nil maintenance reader")
	}
	if _, err := m.Writer(context.Background()); err == nil {
		t.Fatal("nil maintenance writer")
	}
	if _, err := NewMaintenance(nil); err == nil {
		t.Fatal("nil maintenance pool")
	}
	if _, err := configured(WithReadIsolation("invalid")); err == nil {
		t.Fatal("invalid isolation accepted")
	}
	if _, _, err := OpenMaintenance(context.Background(), "postgres://user@localhost/db?role=owner", "app_worker"); err == nil {
		t.Fatal("conflicting role accepted")
	}
}
