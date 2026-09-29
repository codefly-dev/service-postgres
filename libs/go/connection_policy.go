package postgres

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ConnectionPolicy decides whether one library-owned physical connection may
// serve application traffic. It runs on a connection the library owns, never on
// a caller-supplied pool, and it must only read: the connection is about to
// carry an application transaction, so mutating session state here would leak
// into it. A nil error admits the connection; any error refuses it.
//
// Applications keep their own authority rules in their own repository. This
// library supplies the lifecycle and carries the verdict.
type ConnectionPolicy func(context.Context, *pgx.Conn) error

// WithConnectionPolicies validates the reader and writer connections Open owns,
// each with its own policy, on every new physical connection and every pool
// checkout, after the restricted-session checks when those are also enabled. A
// refusal destroys that connection before it serves application traffic, and
// the acquisition fails with the policy's own error.
//
// Either policy may be nil, which installs nothing for that capability. The
// policies reach only the pools Open creates: the maintenance capability has
// WithMaintenanceConnectionPolicy, and pools the caller builds and hands to
// NewFactory stay the caller's qualification responsibility -- nothing here
// rewires them.
//
// A policy runs on the checkout path, so it costs whatever it queries on every
// transaction. It is a point-in-time check: a GRANT landing after a connection
// is validated is not fenced, and operators must still drain workloads around
// authority changes.
func WithConnectionPolicies(reader, writer ConnectionPolicy) Option {
	return func(c *config) error {
		c.readerPolicy, c.writerPolicy = reader, writer
		return nil
	}
}

// WithMaintenanceConnectionPolicy validates the separately wired maintenance
// connection OpenMaintenance owns. It is a distinct capability with a distinct
// login and application role, so reader and writer policies never apply to it
// and this one never applies to them. It neither replaces nor relaxes the
// mandatory maintenance role qualification, which still runs first. A nil
// policy installs nothing.
func WithMaintenanceConnectionPolicy(policy ConnectionPolicy) Option {
	return func(c *config) error {
		c.maintenancePolicy = policy
		return nil
	}
}

// connectionValidation is one capability's validation chain. onConnect is a
// mandatory library check for new physical connections only; policy is the
// application's, and runs on both lifecycle boundaries.
type connectionValidation struct {
	capability string
	onConnect  ConnectionPolicy
	policy     ConnectionPolicy
}

// installConnectionValidation composes a capability's validation onto its pool
// configuration, preserving whatever hooks the caller already set. Both
// lifecycle boundaries run the same ordered chain: the caller's own hook, then
// this library's mandatory checks, then the restricted-session policy, then the
// capability's connection policy.
func installConnectionValidation(pc *pgxpool.Config, c config, v connectionValidation) {
	var restricted ConnectionPolicy
	if c.restrictedSession {
		restricted = func(ctx context.Context, conn *pgx.Conn) error {
			return checkRestrictedSession(ctx, conn, c.deniedRoles)
		}
	}
	var applied ConnectionPolicy
	if v.policy != nil {
		applied = func(ctx context.Context, conn *pgx.Conn) error {
			if err := v.policy(ctx, conn); err != nil {
				return fmt.Errorf("%s Postgres capability connection policy: %w", v.capability, err)
			}
			return nil
		}
	}
	onConnect := []ConnectionPolicy{v.onConnect, restricted, applied}
	onCheckout := []ConnectionPolicy{restricted, applied}
	if !anyCheck(onConnect) {
		return
	}
	// One bounded context covers a whole boundary, not one timeout per callback,
	// so a chain cannot outlast the caller's operation budget by running several
	// checks back to back. puddle hands the connect path a context whose
	// deadline and cancellation come from the pool rather than from the caller
	// (it deliberately lets a connection finish after its Acquire is cancelled),
	// so without this bound a connect-time check has no deadline at all.
	//
	// The bound cannot stop a callback that ignores its context; it can only
	// refuse the connection afterwards. Nothing here runs a check in a detached
	// goroutine, so no callback keeps using a connection after it is refused.
	validate := func(ctx context.Context, conn *pgx.Conn, checks []ConnectionPolicy) error {
		if c.operationTimeout > 0 {
			var cancel context.CancelFunc
			ctx, cancel = context.WithTimeout(ctx, c.operationTimeout)
			defer cancel()
		}
		for _, check := range checks {
			if check == nil {
				continue
			}
			if err := check(ctx, conn); err != nil {
				return err
			}
			// A check that returned nil after its context expired validated
			// nothing current, so expiry refuses the connection either way.
			if err := ctx.Err(); err != nil {
				return err
			}
		}
		return nil
	}
	afterConnect := pc.AfterConnect
	pc.AfterConnect = func(ctx context.Context, conn *pgx.Conn) error {
		if afterConnect != nil {
			if err := afterConnect(ctx, conn); err != nil {
				return err
			}
		}
		return validate(ctx, conn, onConnect)
	}
	if !anyCheck(onCheckout) {
		return
	}
	// pgx gives PrepareConn precedence and ignores BeforeAcquire entirely once
	// PrepareConn is set, so a prior BeforeAcquire is folded in here and cleared
	// rather than left behind looking live while never running again.
	prepare := pc.PrepareConn
	if prepare == nil && pc.BeforeAcquire != nil {
		beforeAcquire := pc.BeforeAcquire
		prepare = func(ctx context.Context, conn *pgx.Conn) (bool, error) {
			return beforeAcquire(ctx, conn), nil
		}
	}
	pc.BeforeAcquire = nil
	pc.PrepareConn = func(ctx context.Context, conn *pgx.Conn) (bool, error) {
		if prepare != nil {
			// Anything other than (true, nil) is the prior hook's own verdict and
			// is returned unchanged: (true, err) releases the connection and
			// fails the query, (false, nil) asks pgx to retry on a fresh one.
			if ok, err := prepare(ctx, conn); !ok || err != nil {
				return ok, err
			}
		}
		if err := validate(ctx, conn, onCheckout); err != nil {
			// Refusing with an error destroys this connection and fails the
			// acquisition. Refusing with a nil error would instead make pgx retry
			// on a fresh connection up to MaxConns+1 times and then report a
			// generic hook bug, losing the reason and paying a reconnect storm
			// for every refusal.
			return false, err
		}
		return true, nil
	}
}

func anyCheck(checks []ConnectionPolicy) bool {
	for _, check := range checks {
		if check != nil {
			return true
		}
	}
	return false
}
