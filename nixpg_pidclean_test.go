package main

import (
	"os"
	"path/filepath"
	"strconv"
	"testing"
)

// TestClearStalePostmasterPid verifies the pg_ctl-style stale-lock cleanup:
// a postmaster.pid owned by a dead/empty/corrupt entry is removed, but one
// owned by a live process is preserved (never stomp a concurrent postmaster).
func TestClearStalePostmasterPid(t *testing.T) {
	write := func(dir, content string) string {
		t.Helper()
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		p := filepath.Join(dir, "postmaster.pid")
		if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	exists := func(p string) bool {
		_, err := os.Stat(p)
		return err == nil
	}

	t.Run("missing file is a no-op", func(t *testing.T) {
		n := &nixPostgres{dataDir: t.TempDir()}
		if err := n.clearStalePostmasterPid(); err != nil {
			t.Fatalf("clear: %v", err)
		}
	})

	t.Run("empty file is removed", func(t *testing.T) {
		dir := t.TempDir()
		p := write(dir, "")
		n := &nixPostgres{dataDir: dir}
		if err := n.clearStalePostmasterPid(); err != nil {
			t.Fatalf("clear: %v", err)
		}
		if exists(p) {
			t.Fatal("empty postmaster.pid should have been removed")
		}
	})

	t.Run("dead pid is removed", func(t *testing.T) {
		dir := t.TempDir()
		// PID 2^31-1 is not a live process on any sane host.
		p := write(dir, "2147483646\n/data\n1700000000\n5432\n")
		n := &nixPostgres{dataDir: dir}
		if err := n.clearStalePostmasterPid(); err != nil {
			t.Fatalf("clear: %v", err)
		}
		if exists(p) {
			t.Fatal("stale (dead-pid) postmaster.pid should have been removed")
		}
	})

	t.Run("live pid is preserved", func(t *testing.T) {
		dir := t.TempDir()
		// Our own PID is definitely alive — must NOT be removed.
		p := write(dir, "")
		if err := os.WriteFile(p, []byte(strconv.Itoa(os.Getpid())+"\n/data\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		n := &nixPostgres{dataDir: dir}
		if err := n.clearStalePostmasterPid(); err != nil {
			t.Fatalf("clear: %v", err)
		}
		if !exists(p) {
			t.Fatal("postmaster.pid owned by a LIVE process must be preserved")
		}
	})
}
