package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	agenttesting "github.com/codefly-dev/core/agents/testing"
)

func TestDeploymentTemplatesWithMigration(t *testing.T) {
	dir := agenttesting.AssertKustomizeTemplates(t, deploymentFS, DeploymentTemplateParameters{
		WithBootstrap: true,
		ManagedImage:  image.FullName(),
	})
	assertMigrationResource(t, dir, true)
}

func TestDeploymentTemplatesWithoutBootstrap(t *testing.T) {
	dir := agenttesting.AssertKustomizeTemplates(t, deploymentFS, DeploymentTemplateParameters{
		ManagedImage: image.FullName(),
	})
	assertMigrationResource(t, dir, false)
}

func assertMigrationResource(t *testing.T, dir string, expected bool) {
	t.Helper()
	content, err := os.ReadFile(filepath.Join(dir, "base", "kustomization.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Contains(string(content), "- job.yaml"); got != expected {
		t.Fatalf("migration resource present = %t, want %t:\n%s", got, expected, content)
	}
}
