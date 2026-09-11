// Package bootstrap applies an attested schema package through the existing
// golang-migrate executable and the canonical controlplane access reconciler.
// It is a migration-owner boundary, never an application runtime capability.
package bootstrap

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/codefly-dev/service-postgres/libs/go/schemaplan"
)

var migrationName = regexp.MustCompile(schemaplan.MigrationFileNamePattern)
var ledgerName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,62}$`)

// Binding is explicit, secret-free deployment input. The expected plan digest
// binds both SQL and group-role policy; cloud login principals are separate
// deployment bindings and must already exist. The owner must be the connected
// current_user so migrations and default privileges have the same owner.
type Binding struct {
	PlanSHA256          string   `json:"plan-sha256"`
	PlanDigest          string   `json:"plan-digest"`
	OwnerRole           string   `json:"owner-role"`
	ReadOnlyPrincipals  []string `json:"read-only-principals"`
	ReadWritePrincipals []string `json:"read-write-principals"`
}

func ReadJSON(path string, target any) error {
	f, err := os.Open(path)
	if err != nil {
		return errors.New("cannot open configuration file")
	}
	defer f.Close()
	return decodeJSON(io.LimitReader(f, 4<<20), target)
}

func decodeJSON(r io.Reader, target any) error {
	decoder := json.NewDecoder(r)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return errors.New("invalid configuration JSON")
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return errors.New("configuration must contain one JSON object")
	}
	return nil
}

// snapshot verifies all content before any database connection, then copies only
// attested bytes into a private directory. Migration execution cannot observe a
// later edit to the input package. Neither staged directories nor files may be
// symlinks. Unexpected files, duplicate versions and traversal fail closed.
func snapshot(directory string, binding Binding) (schemaplan.Plan, string, error) {
	var p schemaplan.Plan
	fail := func(message string) (schemaplan.Plan, string, error) { return p, "", errors.New(message) }
	data, readErr := os.ReadFile(filepath.Join(directory, "plan.json"))
	if readErr != nil || len(data) > 4<<20 {
		return fail("cannot read bounded schema plan")
	}
	hash := sha256.Sum256(data)
	if binding.PlanSHA256 != hex.EncodeToString(hash[:]) {
		return fail("schema plan file identity mismatch")
	}
	if err := decodeJSON(bytes.NewReader(data), &p); err != nil {
		return p, "", err
	}
	if p.ContractVersion != schemaplan.ContractVersion || p.Digest != p.ContentDigest() || p.Digest != binding.PlanDigest {
		return fail("schema plan identity mismatch")
	}
	if err := validateBinding(p, binding); err != nil {
		return p, "", err
	}
	root, err := os.OpenRoot(directory)
	if err != nil {
		return p, "", errors.New("cannot open schema package")
	}
	defer root.Close()
	temp, err := os.MkdirTemp("", "postgres-managed-bootstrap-")
	if err != nil {
		return p, "", err
	}
	success := false
	defer func() {
		if !success {
			os.RemoveAll(temp)
		}
	}()
	stages, ledgers := map[string]bool{}, map[string]bool{}
	for _, l := range p.Lineages {
		if !component(l.Stage) || !component(l.Label) || !ledgerName.MatchString(l.Ledger) || stages[l.Stage] || ledgers[l.Ledger] || len(l.Files) == 0 || l.Digest != l.ContentDigest() {
			return fail("invalid or duplicate schema lineage")
		}
		stages[l.Stage] = true
		ledgers[l.Ledger] = true
		source := "sources/" + l.Stage
		for _, path := range []string{"sources", source} {
			info, e := root.Lstat(path)
			if e != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
				return fail("invalid schema source directory")
			}
		}
		entries, e := fs.ReadDir(root.FS(), source)
		if e != nil || len(entries) != len(l.Files) {
			return fail("schema source inventory mismatch")
		}
		if e = os.Mkdir(filepath.Join(temp, l.Stage), 0700); e != nil {
			return p, "", e
		}
		names, versions := map[string]bool{}, map[string]bool{}
		previous := ""
		for _, f := range l.Files {
			match := migrationName.FindStringSubmatch(f.Name)
			if !component(f.Name) || len(match) == 0 || f.Name <= previous || names[f.Name] {
				return fail("invalid or unordered migration inventory")
			}
			previous = f.Name
			names[f.Name] = true
			version, e := strconv.ParseUint(match[1], 10, 64)
			if e != nil {
				return fail("invalid migration version")
			}
			key := fmt.Sprintf("%d.%s", version, match[2])
			if versions[key] {
				return fail("duplicate migration version and direction")
			}
			versions[key] = true
			path := source + "/" + f.Name
			info, e := root.Lstat(path)
			if e != nil || !info.Mode().IsRegular() {
				return fail("migration must be a regular file")
			}
			data, e := root.ReadFile(path)
			if e != nil {
				return fail("cannot read migration")
			}
			hash := sha256.Sum256(data)
			if "sha256:"+hex.EncodeToString(hash[:]) != f.Digest {
				return fail("migration content identity mismatch")
			}
			if e = os.WriteFile(filepath.Join(temp, l.Stage, f.Name), data, 0600); e != nil {
				return p, "", e
			}
		}
	}
	// Ordering itself is attested, but duplicate extension declarations are invalid.
	extensions := map[string]bool{}
	for _, e := range p.Extensions {
		if !identifier(e.Name) || extensions[e.Name] {
			return fail("invalid extension declaration")
		}
		extensions[e.Name] = true
	}
	success = true
	return p, temp, nil
}

func component(s string) bool {
	return s != "" && s != "." && s != ".." && !strings.ContainsAny(s, "/\\\x00")
}
func identifier(s string) bool {
	return strings.TrimSpace(s) != "" && len(s) <= 63 && !strings.ContainsRune(s, 0)
}

func validateBinding(p schemaplan.Plan, b Binding) error {
	if !identifier(p.Database) || !identifier(b.OwnerRole) || !identifier(p.Access.ReadOnlyRole) || !identifier(p.Access.ReadWriteRole) || len(p.Access.Schemas) == 0 {
		return errors.New("database, owner, groups and schemas are required")
	}
	seen := map[string]bool{b.OwnerRole: true}
	for _, group := range []string{p.Access.ReadOnlyRole, p.Access.ReadWriteRole} {
		if seen[group] {
			return errors.New("owner and managed groups must differ")
		}
		seen[group] = true
	}
	for _, roles := range [][]string{p.Access.ReadWriteRoles, b.ReadOnlyPrincipals, b.ReadWritePrincipals} {
		for _, r := range roles {
			if !identifier(r) || seen[r] {
				return errors.New("role bindings must be distinct valid identifiers")
			}
			seen[r] = true
		}
	}
	if len(b.ReadOnlyPrincipals) == 0 || len(b.ReadWritePrincipals) == 0 {
		return errors.New("explicit reader and writer principals are required")
	}
	schemas := append([]string(nil), p.Access.Schemas...)
	sort.Strings(schemas)
	for i, s := range schemas {
		if !identifier(s) || (i > 0 && s == schemas[i-1]) {
			return errors.New("invalid or duplicate runtime schema")
		}
	}
	return nil
}
