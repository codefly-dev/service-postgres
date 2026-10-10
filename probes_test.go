package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	agenttesting "github.com/codefly-dev/core/agents/testing"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

// A cell's execution admission refuses any pod whose container declares an
// exec probe or an exec lifecycle hook: both run a command of the delivering
// party's choosing inside a pod that already holds the workload identity. The
// store is probed on its port instead, and nothing it renders execs.
func TestRenderedWorkloadsDeclareNoExecProbeOrHook(t *testing.T) {
	dir := agenttesting.AssertKustomizeTemplates(t, deploymentFS, DeploymentTemplateParameters{
		WithBootstrap:               true,
		ManagedImage:                image.FullName(),
		BootstrapJobName:            "postgres-aaaaaaaaaaaa",
		BootstrapJobDeadlineSeconds: 240,
		ServicePort:                 5432,
	})
	workloads := 0
	err := filepath.WalkDir(dir, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil || entry.IsDir() || !strings.HasSuffix(path, ".yaml") {
			return walkErr
		}
		content, readErr := os.ReadFile(path)
		require.NoError(t, readErr)
		decoder := yaml.NewDecoder(strings.NewReader(string(content)))
		for {
			var document map[string]any
			if decoder.Decode(&document) != nil {
				break
			}
			containers := podContainers(document)
			if containers == nil {
				continue
			}
			workloads++
			for _, container := range containers {
				for _, probe := range []string{"startupProbe", "readinessProbe", "livenessProbe"} {
					if spec, ok := container[probe].(map[string]any); ok {
						require.NotContainsf(t, spec, "exec", "%s: container %v %s execs", path, container["name"], probe)
					}
				}
				if lifecycle, ok := container["lifecycle"].(map[string]any); ok {
					for hook, spec := range lifecycle {
						if handler, ok := spec.(map[string]any); ok {
							require.NotContainsf(t, handler, "exec", "%s: container %v lifecycle %s execs", path, container["name"], hook)
						}
					}
				}
			}
		}
		return nil
	})
	require.NoError(t, err)
	require.NotZero(t, workloads, "the render produced no workload to check")
	statefulSet := readDeploymentFile(t, dir, "base", "stateful-set.yaml")
	require.Equal(t, 3, strings.Count(statefulSet, "tcpSocket:\n              port: postgres"), "startup, readiness and liveness probe the postgres port")
}

// podContainers returns the containers and init containers of a workload's pod
// template, or nil for a document that is not a workload.
func podContainers(document map[string]any) []map[string]any {
	kind, _ := document["kind"].(string)
	var template map[string]any
	switch kind {
	case "Deployment", "StatefulSet", "DaemonSet", "Job":
		spec, _ := document["spec"].(map[string]any)
		template, _ = spec["template"].(map[string]any)
	case "CronJob":
		spec, _ := document["spec"].(map[string]any)
		jobTemplate, _ := spec["jobTemplate"].(map[string]any)
		jobSpec, _ := jobTemplate["spec"].(map[string]any)
		template, _ = jobSpec["template"].(map[string]any)
	default:
		return nil
	}
	podSpec, _ := template["spec"].(map[string]any)
	var containers []map[string]any
	for _, key := range []string{"containers", "initContainers"} {
		list, _ := podSpec[key].([]any)
		for _, item := range list {
			if container, ok := item.(map[string]any); ok {
				containers = append(containers, container)
			}
		}
	}
	return containers
}
