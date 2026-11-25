package main

import (
	"context"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	builderv1 "github.com/codefly-dev/core/generated/go/codefly/services/builder/v1"
	"github.com/stretchr/testify/require"
)

// reconcilerManifestTokens name reconciliation control-plane objects and
// repository source bindings. Plugin-owned manifests describe workloads only;
// how they are transported or reconciled is not this plugin's concern, so a
// rendered tree that carries any of these has leaked a transport responsibility.
var reconcilerManifestTokens = []string{
	"argoproj.io/",
	"fluxcd.io/",
	"kind: Application",
	"kind: AppProject",
	"kind: GitRepository",
	"kind: OCIRepository",
	"repoURL",
	"targetRevision",
}

// forbiddenImportSubstrings name Git, GitHub, and reconciler client libraries a
// manifest-only runtime must never link against.
var forbiddenImportSubstrings = []string{
	"argoproj",
	"fluxcd",
	"go-git/go-git",
	"src-d/go-git",
	"libgit2",
	"google/go-github",
	"shurcooL/githubv4",
}

// forbiddenExecBinaries name transport CLIs the runtime must never shell out to.
// A denylist of import paths alone would miss os/exec-based Git or GitHub access.
var forbiddenExecBinaries = map[string]bool{
	"git": true,
	"gh":  true,
}

// forbiddenEndpointLiterals name network endpoints that betray an in-process
// transport client even when it is built on the standard library.
var forbiddenEndpointLiterals = []string{
	"api.github.com",
}

func TestDeploymentTemplatesCarryNoTransportBindings(t *testing.T) {
	require.NoError(t, fs.WalkDir(deploymentFS, ".", func(path string, entry fs.DirEntry, err error) error {
		if err != nil || entry.IsDir() {
			return err
		}
		content, readErr := fs.ReadFile(deploymentFS, path)
		require.NoError(t, readErr)
		assertNoTokens(t, path, string(content), reconcilerManifestTokens)
		return nil
	}))
}

func TestRestrictedRenderCarriesNoTransportBindings(t *testing.T) {
	builder, networkMappings := newDeploymentTestBuilder(t)
	destination := t.TempDir()

	response, err := builder.Deploy(context.Background(), promotableDeploymentRequest(
		destination,
		networkMappings,
		promotablePostgresSecretReferences(),
	))
	require.NoError(t, err)
	require.Equal(t, builderv1.DeploymentStatus_SUCCESS, response.GetState().GetState(), response.GetState().GetMessage())

	require.NoError(t, filepath.WalkDir(destination, func(path string, entry fs.DirEntry, err error) error {
		if err != nil || entry.IsDir() {
			return err
		}
		content, readErr := os.ReadFile(path)
		require.NoError(t, readErr)
		assertNoTokens(t, path, string(content), reconcilerManifestTokens)
		return nil
	}))
}

func TestRuntimeSourceHasNoReconcilerIntegration(t *testing.T) {
	require.NoError(t, filepath.WalkDir(".", func(path string, entry fs.DirEntry, err error) error {
		if err != nil || entry.IsDir() {
			return err
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		source, readErr := os.ReadFile(path)
		require.NoError(t, readErr)
		violations, parseErr := transportViolations(path, source)
		require.NoError(t, parseErr)
		require.Emptyf(t, violations, "%s carries transport integration: %s", path, strings.Join(violations, "; "))
		return nil
	}))
}

// transportViolations parses Go source and reports repository, GitHub, and
// reconciler integration. It inspects imports, os/exec invocations, and string
// literals so a comment or documentation reference to a forbidden term is not
// mistaken for real integration, while shell-outs and endpoint literals that a
// bare import scan would miss are still caught.
func transportViolations(filename string, source []byte) ([]string, error) {
	fileSet := token.NewFileSet()
	file, err := parser.ParseFile(fileSet, filename, source, parser.SkipObjectResolution)
	if err != nil {
		return nil, err
	}

	var violations []string
	for _, imported := range file.Imports {
		path, unquoteErr := strconv.Unquote(imported.Path.Value)
		if unquoteErr != nil {
			continue
		}
		for _, forbidden := range forbiddenImportSubstrings {
			if strings.Contains(path, forbidden) {
				violations = append(violations, fmt.Sprintf("imports %q", path))
			}
		}
	}

	ast.Inspect(file, func(node ast.Node) bool {
		switch typed := node.(type) {
		case *ast.CallExpr:
			if binary, ok := execCommandBinary(typed); ok && forbiddenExecBinaries[binary] {
				violations = append(violations, fmt.Sprintf("shells out to %q", binary))
			}
		case *ast.BasicLit:
			if typed.Kind != token.STRING {
				return true
			}
			value, unquoteErr := strconv.Unquote(typed.Value)
			if unquoteErr != nil {
				return true
			}
			for _, endpoint := range forbiddenEndpointLiterals {
				if strings.Contains(value, endpoint) {
					violations = append(violations, fmt.Sprintf("references %q", endpoint))
				}
			}
		}
		return true
	})

	return violations, nil
}

// execCommandBinary returns the base name of the binary an exec.Command or
// exec.CommandContext call launches, when that name is a string literal.
func execCommandBinary(call *ast.CallExpr) (string, bool) {
	selector, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return "", false
	}
	pkg, ok := selector.X.(*ast.Ident)
	if !ok || pkg.Name != "exec" {
		return "", false
	}
	var nameArg ast.Expr
	switch selector.Sel.Name {
	case "Command":
		if len(call.Args) >= 1 {
			nameArg = call.Args[0]
		}
	case "CommandContext":
		if len(call.Args) >= 2 {
			nameArg = call.Args[1]
		}
	default:
		return "", false
	}
	literal, ok := nameArg.(*ast.BasicLit)
	if !ok || literal.Kind != token.STRING {
		return "", false
	}
	name, err := strconv.Unquote(literal.Value)
	if err != nil {
		return "", false
	}
	return filepath.Base(name), true
}

func TestTransportViolationsDetectsForbiddenIntegration(t *testing.T) {
	cases := []struct {
		name       string
		source     string
		wantMarker string
	}{
		{
			name:   "clean source",
			source: "package p\n\nimport \"fmt\"\n\nfunc F() { fmt.Println(\"ok\") }\n",
		},
		{
			name:   "reconciler named only in a comment",
			source: "package p\n\n// Renders manifests; the fluxcd.io/argoproj reconciler owns transport.\nimport \"fmt\"\n\nvar _ = fmt.Sprint\n",
		},
		{
			name:       "reconciler client import",
			source:     "package p\n\nimport app \"github.com/argoproj/argo-cd/v2/pkg/apis/application/v1alpha1\"\n\nvar _ = app.Application{}\n",
			wantMarker: "argoproj",
		},
		{
			name:       "git shell-out",
			source:     "package p\n\nimport \"os/exec\"\n\nfunc F() { _ = exec.Command(\"git\", \"push\") }\n",
			wantMarker: "git",
		},
		{
			name:       "gh shell-out with context",
			source:     "package p\n\nimport (\n\t\"context\"\n\t\"os/exec\"\n)\n\nfunc F(ctx context.Context) { _ = exec.CommandContext(ctx, \"/usr/bin/gh\", \"pr\", \"create\") }\n",
			wantMarker: "gh",
		},
		{
			name:       "github api endpoint literal",
			source:     "package p\n\nconst endpoint = \"https://api.github.com/repos/o/r\"\n",
			wantMarker: "api.github.com",
		},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			violations, err := transportViolations(testCase.name+".go", []byte(testCase.source))
			require.NoError(t, err)
			if testCase.wantMarker == "" {
				require.Empty(t, violations)
				return
			}
			require.Contains(t, strings.Join(violations, "\n"), testCase.wantMarker)
		})
	}
}

func assertNoTokens(t *testing.T, path, content string, tokens []string) {
	t.Helper()
	for _, token := range tokens {
		require.NotContainsf(t, content, token, "%s carries forbidden transport token %q", path, token)
	}
}
