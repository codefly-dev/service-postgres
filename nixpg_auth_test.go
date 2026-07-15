package main

import (
	"context"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestNewNixPostgresRejectsEmptyPasswordBeforeProvisioning(t *testing.T) {
	if _, err := newNixPostgres(context.Background(), t.TempDir(), 5432, "postgres", "", "postgres", "", nil); err == nil {
		t.Fatal("native postgres accepted an empty password")
	}
}

func TestInitdbUsesPrivatePasswordFileAndSCRAM(t *testing.T) {
	root := t.TempDir()
	n := &nixPostgres{dataDir: filepath.Join(root, "data"), user: "postgres", password: `s p#ss"word`}
	if err := os.MkdirAll(n.dataDir, 0o700); err != nil {
		t.Fatal(err)
	}
	passwordFile, err := n.writeInitPasswordFile()
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(passwordFile)
	info, err := os.Stat(passwordFile)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("password file permissions = %o, want 600", got)
	}
	args := n.initdbArgs(passwordFile)
	if !slices.Contains(args, "--auth-local=scram-sha-256") || !slices.Contains(args, "--auth-host=scram-sha-256") {
		t.Fatalf("initdb args do not require SCRAM: %q", args)
	}
	joined := strings.Join(args, " ")
	if strings.Contains(joined, "trust") || strings.Contains(joined, n.password) {
		t.Fatalf("unsafe initdb args: %q", args)
	}
}

func TestAdminDSNEncodesCredentials(t *testing.T) {
	n := &nixPostgres{user: "db user", password: `p@ss:/?#[]`, port: 5432}
	parsed, err := url.Parse(n.adminDSN())
	if err != nil {
		t.Fatal(err)
	}
	if parsed.User.Username() != n.user {
		t.Fatalf("username = %q, want %q", parsed.User.Username(), n.user)
	}
	password, ok := parsed.User.Password()
	if !ok || password != n.password {
		t.Fatalf("password did not round trip: %q", password)
	}
	if parsed.Host != "127.0.0.1:5432" || parsed.Query().Get("sslmode") != "disable" {
		t.Fatalf("unexpected DSN %q", parsed.String())
	}
}
