//go:build !darwin

package main

import "context"

// recoverHostResources is a no-op where this agent's native runtime does not
// leave Darwin System V IPC resources behind.
func recoverHostResources(context.Context) (hostResourceRecovery, error) {
	return hostResourceRecovery{}, nil
}
