package main

import (
	"bytes"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// Every schema, format and contract version marker this repository owns is v1
// and carries the current format. A marker above 1 means a format was renamed
// instead of replaced, so two readers and a label dispatch are about to exist.
// This is the fleet guard, as one expression, run by `go test ./...`:
//
//   - a codefly identifier ending /vN or .vN, N above 1;
//   - a codefly media type ending .vN+, N above 1;
//   - a schema, format, contract, layout, startup-protocol or marker version
//     field set above 1;
//   - an authenticated-vN envelope or a /vN/run route, N above 1.
//
// A line that must state such a label, because a test proves the label is
// refused, ends with the comment `version-guard:allow` and a reason.
var versionMarkerAboveOne = regexp.MustCompile(
	`(codefly(\.dev)?[./][a-z0-9./-]+|robin\.[a-z-]+|runtime\.plan|accounts\.[a-z-]+|saas\.[a-z.]+|[a-z-]+\.input)[/.]v([2-9]|[1-9][0-9]+)\b` +
		`|vnd\.codefly\.[a-z.]+\.v([2-9]|[1-9][0-9]+)\+` +
		`|(?i:\b(schema|format|contract|layout|startup[-_]?protocol|marker)[-_]?version"?\s*[:=]+\s*"?v?([2-9]|[1-9][0-9]+)\b|authenticated-v[2-9]|/v[2-9]/run\b)`)

const versionGuardAllow = "version-guard:allow"

// versionMarkerHits returns every unallowed marker above 1 under root, as
// path:line: text. It reads what the fleet guard reads: no prose, no module
// or lock files, nothing generated or vendored, no release or evidence record.
func versionMarkerHits(root string) ([]string, error) {
	skippedDirectories := map[string]bool{".git": true, "node_modules": true, "vendor": true, "generated": true, "gen": true, "releases": true, "evidence": true, "target": true}
	var hits []string
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		name := entry.Name()
		if entry.IsDir() {
			if skippedDirectories[name] {
				return filepath.SkipDir
			}
			return nil
		}
		if !entry.Type().IsRegular() || name == "go.sum" || name == "go.mod" ||
			strings.HasSuffix(name, ".md") || strings.HasSuffix(name, ".lock") || strings.HasSuffix(name, ".pb.go") || strings.Contains(name, "_pb2") {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if bytes.IndexByte(data[:min(len(data), 8000)], 0) >= 0 {
			return nil
		}
		relative, _ := filepath.Rel(root, path)
		for number, line := range strings.Split(string(data), "\n") {
			if versionMarkerAboveOne.MatchString(line) && !strings.Contains(line, versionGuardAllow) {
				hits = append(hits, fmt.Sprintf("%s:%d: %s", filepath.ToSlash(relative), number+1, strings.TrimSpace(line)))
			}
		}
		return nil
	})
	return hits, err
}

func TestEveryVersionMarkerIsV1(t *testing.T) {
	hits, err := versionMarkerHits(".")
	require.NoError(t, err)
	require.Empty(t, hits, "a version marker above 1: there is one version of each format, v1, and it carries the current format.\n"+
		"Replace the format under its v1 name, refuse the earlier format by its content, and refuse any other label by name.\n%s", strings.Join(hits, "\n"))
}

// The guard is only worth its green if it sees what it is for. Each label is
// assembled here so that this file is not itself a hit.
func TestVersionMarkerGuardSeesAMarkerAboveOne(t *testing.T) {
	above := func(prefix, number, suffix string) string { return prefix + number + suffix }
	root := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(root, "libs", "go", "evidence"), 0o700))
	write := func(name string, lines ...string) {
		require.NoError(t, os.WriteFile(filepath.Join(root, filepath.FromSlash(name)), []byte(strings.Join(lines, "\n")+"\n"), 0o600))
	}
	write("plan.go",
		`const a = "`+above("codefly.dev/postgres-schema-plan/v", "2", "")+`"`,
		`const b = "`+above("codefly.dev/postgres-schema-plan/v", "1", "")+`"`,
		`const c = "`+above("codefly.dev/postgres-workload-attachment/v", "12", "")+`" // refused`,
		`const d = "`+above("codefly.dev/postgres-schema-plan/v", "3", "")+`" // `+versionGuardAllow+` refused by name`,
	)
	write("attachment.json", above(`  "schema_version": "v`, "2", `",`), above(`  "Contract-Version": `, "4", ","), above(`  "schema_version": `, "1", ","))
	write("media.yaml", above("type: application/vnd.codefly.module.v", "2", "+tar"), above("route: POST /v", "2", "/run"), above("envelope: authenticated-v", "2", ""))
	write("notes.md", above("codefly.dev/postgres-schema-plan/v", "2", ""))
	write("go.mod", above("// codefly.dev/postgres-schema-plan/v", "2", ""))
	write("libs/go/evidence/record.json", above(`"contract-version": "codefly.dev/postgres-schema-plan/v`, "2", `"`))
	hits, err := versionMarkerHits(root)
	require.NoError(t, err)
	var where []string
	for _, hit := range hits {
		where = append(where, hit[:strings.Index(hit, ": ")])
	}
	require.ElementsMatch(t, []string{"plan.go:1", "plan.go:3", "attachment.json:1", "attachment.json:2", "media.yaml:1", "media.yaml:2", "media.yaml:3"}, where, strings.Join(hits, "\n"))
}
