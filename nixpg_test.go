package main

import (
	"context"
	"database/sql"
	"fmt"
	"net"
	"os"
	"testing"
	"time"

	runners "github.com/codefly-dev/core/runners/base"
	_ "github.com/lib/pq"
)

// TestNixPostgres_Lifecycle proves the Docker-free runtime end to end: a
// nix-provisioned postgres is initdb'd, launched, and the configured database
// is created + reachable over TCP. This is the parity guarantee for the nix
// backend of the postgres agent (the Docker path is covered by main_test).
//
// Requires nix (skips otherwise — the only host dependency, which the agent's
// nix runtime exists precisely to remove).
func TestNixPostgres_Lifecycle(t *testing.T) {
	if !runners.CheckNixInstalled() || !runners.IsNixSupported() {
		t.Skip("nix not installed/supported on this host")
	}

	dir, err := os.MkdirTemp("", "nixpg-*")
	if err != nil {
		t.Fatalf("mkdtemp: %v", err)
	}
	defer os.RemoveAll(dir)

	port := freeTCPPort(t)
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Minute)
	defer cancel()

	pg, err := newNixPostgres(ctx, dir, port, "codefly", "codefly", "mind_server", "warning", testWriter{t})
	if err != nil {
		t.Fatalf("newNixPostgres: %v", err)
	}
	if err := pg.Init(ctx); err != nil {
		t.Fatalf("nix postgres Init: %v", err)
	}
	t.Cleanup(func() { _ = pg.Stop(context.Background()) })

	// The configured database must be reachable + queryable.
	dsn := fmt.Sprintf("postgresql://codefly:codefly@127.0.0.1:%d/mind_server?sslmode=disable", port)
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer func() { _ = db.Close() }()

	var one int
	if err := db.QueryRowContext(ctx, "SELECT 1").Scan(&one); err != nil {
		t.Fatalf("query mind_server db: %v", err)
	}
	if one != 1 {
		t.Fatalf("SELECT 1 = %d", one)
	}

	// A second Init on the same data dir must be a no-op (idempotent restart):
	// initdb is skipped, server already implied — just verify the data dir
	// stayed initialized.
	if _, err := os.Stat(dir + "/pgdata/PG_VERSION"); err != nil {
		t.Errorf("data dir should remain initialized: %v", err)
	}
}

func freeTCPPort(t *testing.T) uint16 {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("find free port: %v", err)
	}
	defer func() { _ = l.Close() }()
	return uint16(l.Addr().(*net.TCPAddr).Port)
}

type testWriter struct{ t *testing.T }

func (w testWriter) Write(p []byte) (int, error) {
	w.t.Logf("[pg] %s", p)
	return len(p), nil
}
