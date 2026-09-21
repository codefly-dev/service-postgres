package main

import (
	"context"
	"fmt"

	agentv0 "github.com/codefly-dev/core/generated/go/codefly/services/agent/v0"
)

// hostResourceRecoveryCapability lets a host require recovery of this agent's
// leaked host resources without recognizing PostgreSQL. What a leaked resource
// looks like, and which one is safe to remove, are facts about the database
// this agent owns, so the rules live here and only the promise is generic.
const hostResourceRecoveryCapability = "host-resource-recovery/v1"

const recoverHostResourcesCommandName = "recover-host-resources"

// hostResourceRecovery counts what one pass removed.
type hostResourceRecovery struct {
	SharedSegments int
	SemaphoreSets  int
}

func (r hostResourceRecovery) empty() bool {
	return r.SharedSegments == 0 && r.SemaphoreSets == 0
}

func (r hostResourceRecovery) summary() string {
	if r.empty() {
		return "no orphaned host resources"
	}
	return fmt.Sprintf("removed %d orphaned shared-memory segment(s) and %d semaphore set(s)",
		r.SharedSegments, r.SemaphoreSets)
}

func recoverHostResourcesCommand() *agentv0.CommandDefinition {
	return &agentv0.CommandDefinition{
		Name:        recoverHostResourcesCommandName,
		Description: "Remove host IPC resources leaked by an interrupted native run of this service",
		Usage:       recoverHostResourcesCommandName,
		Tags:        []string{"recovery"},
		Destructive: true,
	}
}

// runRecoverHostResources returns a cleanup failure rather than reporting it.
// A caller reaching for this command has collection as its whole purpose, so a
// resource left behind has to reach it; the lifecycle paths, where recovery is
// incidental to starting or stopping a database, warn instead.
func runRecoverHostResources(ctx context.Context, _ []string) (string, error) {
	recovered, err := recoverHostResources(ctx)
	if err != nil {
		return "", err
	}
	return recovered.summary(), nil
}
