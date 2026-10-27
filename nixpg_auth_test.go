package main

import (
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/lib/pq"
)

func TestInitdbUsesPrivatePasswordFileAndSCRAM(t *testing.T) {
	root := t.TempDir()
	n := &nixPostgres{root: root, dataDir: filepath.Join(root, "pgdata")}
	const password = `s p#ss"word`
	if err := writeOwnerOnly(n.adminPasswordPath(), password+"\n"); err != nil {
		t.Fatal(err)
	}
	passwordFile := n.adminPasswordPath()
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
	if strings.Contains(joined, "trust") || strings.Contains(joined, password) {
		t.Fatalf("unsafe initdb args: %q", args)
	}
	if !slices.Contains(args, serverAdminRole) {
		t.Fatalf("initdb args do not name the run server's administrator: %q", args)
	}
	read, err := n.readAdminPassword()
	if err != nil || read != password {
		t.Fatalf("administrator password did not round trip: %q, %v", read, err)
	}
}

func TestAdminDSNEncodesCredentialsAndTargetsOwnedSocket(t *testing.T) {
	n := &nixPostgres{
		adminPassword: `p@ss:/?#[]`,
		socketDir:     filepath.Join(t.TempDir(), "private socket"),
	}
	parsed, err := url.Parse(n.adminDSN("orders db"))
	if err != nil {
		t.Fatal(err)
	}
	if parsed.User.Username() != serverAdminRole {
		t.Fatalf("username = %q, want %q", parsed.User.Username(), serverAdminRole)
	}
	if parsed.Path != "/orders db" {
		t.Fatalf("database = %q, want the service's", parsed.Path)
	}
	password, ok := parsed.User.Password()
	if !ok || password != n.adminPassword {
		t.Fatalf("password did not round trip: %q", password)
	}
	if parsed.Host != "" || parsed.Query().Get("host") != n.socketDir ||
		parsed.Query().Get("port") != "5432" || parsed.Query().Get("sslmode") != "disable" {
		t.Fatalf("unexpected DSN %q", parsed.String())
	}
	pqDSN, err := pq.ParseURL(n.adminDSN("orders db"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(pqDSN, "host='"+n.socketDir+"'") || !strings.Contains(pqDSN, "port='5432'") {
		t.Fatalf("lib/pq DSN = %q, want owned socket and port", pqDSN)
	}
}
