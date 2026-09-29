package postgres

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

func policyPoolConfig(t *testing.T) *pgxpool.Config {
	t.Helper()
	pc, err := pgxpool.ParseConfig("postgres://reader:secret@localhost/db")
	if err != nil {
		t.Fatal(err)
	}
	return pc
}

func recordingPolicy(order *[]string, name string, err error) ConnectionPolicy {
	return func(context.Context, *pgx.Conn) error {
		*order = append(*order, name)
		return err
	}
}

func TestConnectionPoliciesInstallNothingWhenNil(t *testing.T) {
	c, err := configured(WithConnectionPolicies(nil, nil), WithMaintenanceConnectionPolicy(nil))
	if err != nil {
		t.Fatal(err)
	}
	if c.readerPolicy != nil || c.writerPolicy != nil || c.maintenancePolicy != nil {
		t.Fatal("nil policies were stored")
	}
	for _, capability := range []string{"read-only", "read-write", "maintenance"} {
		pc := policyPoolConfig(t)
		installConnectionValidation(pc, c, connectionValidation{capability: capability})
		if pc.AfterConnect != nil || pc.PrepareConn != nil || pc.BeforeAcquire != nil {
			t.Fatalf("%s installed hooks with no checks to run", capability)
		}
	}
}

func TestConnectionPoliciesStayOnTheirCapability(t *testing.T) {
	var order []string
	c, err := configured(
		WithConnectionPolicies(recordingPolicy(&order, "reader", nil), recordingPolicy(&order, "writer", nil)),
		WithMaintenanceConnectionPolicy(recordingPolicy(&order, "maintenance", nil)),
	)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		capability string
		policy     ConnectionPolicy
		want       string
	}{
		{capability: "read-only", policy: c.readerPolicy, want: "reader"},
		{capability: "read-write", policy: c.writerPolicy, want: "writer"},
		{capability: "maintenance", policy: c.maintenancePolicy, want: "maintenance"},
	} {
		pc := policyPoolConfig(t)
		installConnectionValidation(pc, c, connectionValidation{capability: test.capability, policy: test.policy})
		order = nil
		if err := pc.AfterConnect(context.Background(), nil); err != nil {
			t.Fatal(err)
		}
		if ok, err := pc.PrepareConn(context.Background(), nil); !ok || err != nil {
			t.Fatalf("%s checkout = %v, %v", test.capability, ok, err)
		}
		// Each capability runs its own policy on both boundaries, and no other.
		if strings.Join(order, ",") != test.want+","+test.want {
			t.Fatalf("%s ran %v", test.capability, order)
		}
	}
}

func TestConnectionValidationOrdersMandatoryChecksBeforeThePolicy(t *testing.T) {
	var order []string
	pc := policyPoolConfig(t)
	pc.AfterConnect = func(context.Context, *pgx.Conn) error { order = append(order, "prior-connect"); return nil }
	pc.BeforeAcquire = func(context.Context, *pgx.Conn) bool { order = append(order, "prior-checkout"); return true }
	c, err := configured(WithConnectionPolicies(recordingPolicy(&order, "policy", nil), nil))
	if err != nil {
		t.Fatal(err)
	}
	installConnectionValidation(pc, c, connectionValidation{
		capability: "read-only",
		onConnect:  recordingPolicy(&order, "mandatory", nil),
		policy:     c.readerPolicy,
	})
	if pc.BeforeAcquire != nil {
		t.Fatal("deprecated hook left set: pgx ignores it once PrepareConn exists")
	}
	if err := pc.AfterConnect(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	if strings.Join(order, ",") != "prior-connect,mandatory,policy" {
		t.Fatalf("connect order %v", order)
	}
	order = nil
	if ok, err := pc.PrepareConn(context.Background(), nil); !ok || err != nil {
		t.Fatalf("checkout = %v, %v", ok, err)
	}
	// The mandatory connect-only check must not run again on the checkout path.
	if strings.Join(order, ",") != "prior-checkout,policy" {
		t.Fatalf("checkout order %v", order)
	}
}

func TestConnectionValidationPreservesPriorHookVerdicts(t *testing.T) {
	refused := errors.New("prior refusal")
	for _, test := range []struct {
		name       string
		ok         bool
		err        error
		wantOK     bool
		wantErr    error
		policyRuns bool
	}{
		{name: "admitted", ok: true, wantOK: true, policyRuns: true},
		{name: "released with error", ok: true, err: refused, wantOK: true, wantErr: refused},
		{name: "destroyed for retry", ok: false, wantOK: false},
		{name: "destroyed with error", ok: false, err: refused, wantOK: false, wantErr: refused},
	} {
		t.Run(test.name, func(t *testing.T) {
			var order []string
			pc := policyPoolConfig(t)
			pc.PrepareConn = func(context.Context, *pgx.Conn) (bool, error) {
				order = append(order, "prior")
				return test.ok, test.err
			}
			c, err := configured(WithConnectionPolicies(recordingPolicy(&order, "policy", nil), nil))
			if err != nil {
				t.Fatal(err)
			}
			installConnectionValidation(pc, c, connectionValidation{capability: "read-only", policy: c.readerPolicy})
			ok, err := pc.PrepareConn(context.Background(), nil)
			if ok != test.wantOK || !errors.Is(err, test.wantErr) {
				t.Fatalf("verdict = %v, %v; want %v, %v", ok, err, test.wantOK, test.wantErr)
			}
			ran := strings.Join(order, ",") == "prior,policy"
			if ran != test.policyRuns {
				t.Fatalf("policy ran = %v, want %v (%v)", ran, test.policyRuns, order)
			}
		})
	}
}

func TestConnectionValidationFoldsTheHookPgxWouldIgnore(t *testing.T) {
	var order []string
	pc := policyPoolConfig(t)
	// pgx ignores BeforeAcquire when PrepareConn is set, and so must the chain.
	pc.PrepareConn = func(context.Context, *pgx.Conn) (bool, error) { order = append(order, "prepare"); return true, nil }
	pc.BeforeAcquire = func(context.Context, *pgx.Conn) bool { order = append(order, "acquire"); return true }
	c, err := configured(WithConnectionPolicies(recordingPolicy(&order, "policy", nil), nil))
	if err != nil {
		t.Fatal(err)
	}
	installConnectionValidation(pc, c, connectionValidation{capability: "read-only", policy: c.readerPolicy})
	if ok, err := pc.PrepareConn(context.Background(), nil); !ok || err != nil {
		t.Fatalf("checkout = %v, %v", ok, err)
	}
	if strings.Join(order, ",") != "prepare,policy" {
		t.Fatalf("chain ran %v", order)
	}
}

func TestConnectionPolicyRefusalIsInspectable(t *testing.T) {
	refused := errors.New("authority is not acceptable")
	c, err := configured(WithConnectionPolicies(func(context.Context, *pgx.Conn) error { return refused }, nil))
	if err != nil {
		t.Fatal(err)
	}
	pc := policyPoolConfig(t)
	installConnectionValidation(pc, c, connectionValidation{capability: "read-only", policy: c.readerPolicy})
	connectErr := pc.AfterConnect(context.Background(), nil)
	if !errors.Is(connectErr, refused) || !strings.Contains(connectErr.Error(), "read-only") {
		t.Fatalf("connect refusal = %v", connectErr)
	}
	ok, checkoutErr := pc.PrepareConn(context.Background(), nil)
	// (false, err) destroys this connection and fails the acquisition. (false,
	// nil) would make pgx retry up to MaxConns+1 times and then report a generic
	// hook bug instead of the refusal.
	if ok || !errors.Is(checkoutErr, refused) || !strings.Contains(checkoutErr.Error(), "read-only") {
		t.Fatalf("checkout refusal = %v, %v", ok, checkoutErr)
	}
}

func TestConnectionValidationBoundsEachBoundaryOnce(t *testing.T) {
	var deadlines []time.Time
	var captured context.Context
	record := func(ctx context.Context, _ *pgx.Conn) error {
		captured = ctx
		deadline, ok := ctx.Deadline()
		if !ok {
			t.Error("policy ran without a deadline under an operation timeout")
		}
		deadlines = append(deadlines, deadline)
		return nil
	}
	c, err := configured(WithConnectionPolicies(record, nil), WithOperationTimeout(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	pc := policyPoolConfig(t)
	installConnectionValidation(pc, c, connectionValidation{
		capability: "read-only", onConnect: record, policy: c.readerPolicy,
	})
	if err := pc.AfterConnect(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	if len(deadlines) != 2 || !deadlines[0].Equal(deadlines[1]) {
		t.Fatalf("each check got its own budget: %v", deadlines)
	}
	if time.Until(deadlines[0]) > time.Minute {
		t.Fatal("bound exceeded the configured operation timeout")
	}
	if captured.Err() == nil {
		t.Fatal("bounded context was not cancelled when the boundary returned")
	}

	// An earlier caller deadline is never extended.
	deadlines = nil
	parent, stop := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer stop()
	if err := pc.AfterConnect(parent, nil); err != nil {
		t.Fatal(err)
	}
	if time.Until(deadlines[0]) > 50*time.Millisecond {
		t.Fatal("caller deadline was extended by the policy bound")
	}
}

func TestConnectionValidationRefusesAnExpiredCheck(t *testing.T) {
	// A check that cooperates with its context but reports success anyway has
	// validated nothing current, so expiry must still refuse the connection.
	expired := func(ctx context.Context, _ *pgx.Conn) error {
		<-ctx.Done()
		return nil
	}
	c, err := configured(WithConnectionPolicies(expired, nil), WithOperationTimeout(20*time.Millisecond))
	if err != nil {
		t.Fatal(err)
	}
	pc := policyPoolConfig(t)
	installConnectionValidation(pc, c, connectionValidation{capability: "read-only", policy: c.readerPolicy})
	if err := pc.AfterConnect(context.Background(), nil); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expired connect check = %v", err)
	}
	ok, err := pc.PrepareConn(context.Background(), nil)
	if ok || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expired checkout = %v, %v", ok, err)
	}
}

func TestRestrictedSessionInstallsBothBoundariesWithoutAPolicy(t *testing.T) {
	c, err := configured(WithRestrictedSession("background_jobs"))
	if err != nil {
		t.Fatal(err)
	}
	pc := policyPoolConfig(t)
	installConnectionValidation(pc, c, connectionValidation{capability: "read-only"})
	if pc.AfterConnect == nil || pc.PrepareConn == nil {
		t.Fatal("restricted sessions lost a lifecycle boundary")
	}
}

func TestMandatoryConnectCheckNeedsNoCheckoutHook(t *testing.T) {
	c, err := configured()
	if err != nil {
		t.Fatal(err)
	}
	pc := policyPoolConfig(t)
	installConnectionValidation(pc, c, connectionValidation{
		capability: "maintenance",
		onConnect:  func(context.Context, *pgx.Conn) error { return nil },
	})
	if pc.AfterConnect == nil {
		t.Fatal("mandatory connect check was not installed")
	}
	if pc.PrepareConn != nil {
		t.Fatal("connect-only check added a checkout cost")
	}
}
