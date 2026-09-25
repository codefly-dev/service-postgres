package main

import (
	"os"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestReleaseDeclaresOnePublisherAndArchiveSBOMs(t *testing.T) {
	read := func(path string, target any) {
		t.Helper()
		payload, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if err := yaml.Unmarshal(payload, target); err != nil {
			t.Fatal(err)
		}
	}
	var manifest struct {
		Release struct{ Owner, Workflow string }
	}
	read("agent.codefly.yaml", &manifest)
	if manifest.Release.Owner != "workflow" || manifest.Release.Workflow != "releaser.yml" {
		t.Fatal("the tag workflow must be the sole artifact publisher")
	}
	var config struct {
		Release struct {
			Prerelease string `yaml:"prerelease"`
		} `yaml:"release"`
		SBOMs []struct {
			Artifacts string
			Documents []string
			Disable   bool
		} `yaml:"sboms"`
	}
	read(".goreleaser.yaml", &config)
	if len(config.SBOMs) != 1 || config.SBOMs[0].Artifacts != "archive" || config.SBOMs[0].Disable || len(config.SBOMs[0].Documents) != 1 || config.SBOMs[0].Documents[0] != "${artifact}.sbom.json" {
		t.Fatal("each published archive must carry its canonical SBOM")
	}
	if config.Release.Prerelease != "auto" {
		t.Fatal("a dev tag must publish as a prerelease, never as Latest")
	}
}
