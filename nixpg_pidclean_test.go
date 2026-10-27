package main

import (
	"os"
	"path/filepath"
	"strconv"
	"testing"
)

// TestClearDisownedPostmasterPid verifies the pg_ctl-style stale-lock
// cleanup: a postmaster.pid that is empty, corrupt, or names a process that
// is gone is removed, and so is one whose live PID is provably not a postgres
// server, because the number was reused and the run would otherwise wait on a
// stranger. A lock file a real postmaster holds is refused instead, which
// TestLockFileHeldByARealPostmasterIsRefused covers.
func TestClearDisownedPostmasterPid(t *testing.T) {
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
		if err := clearDisownedPostmasterPid(t.TempDir(), postmasterRecord{}, false); err != nil {
			t.Fatalf("clear: %v", err)
		}
	})

	t.Run("empty file is removed", func(t *testing.T) {
		dir := t.TempDir()
		p := write(dir, "")
		if err := clearDisownedPostmasterPid(dir, postmasterRecord{}, false); err != nil {
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
		if err := clearDisownedPostmasterPid(dir, postmasterRecord{}, false); err != nil {
			t.Fatalf("clear: %v", err)
		}
		if exists(p) {
			t.Fatal("stale (dead-pid) postmaster.pid should have been removed")
		}
	})

	t.Run("live pid that is not a postmaster is removed", func(t *testing.T) {
		dir := t.TempDir()
		// This test binary is alive and is certainly not a postgres server,
		// so the lock file naming it is a leftover with a reused number.
		p := write(dir, strconv.Itoa(os.Getpid())+"\n/data\n")
		if err := clearDisownedPostmasterPid(dir, postmasterRecord{}, false); err != nil {
			t.Fatalf("clear: %v", err)
		}
		if exists(p) {
			t.Fatal("postmaster.pid naming a live non-postgres process should have been removed")
		}
	})
}
