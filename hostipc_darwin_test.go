//go:build darwin

package main

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestHostResourceRemovalPlanPreservesLiveControlSegmentAndRemovesOrphans is
// the safety property of the whole feature: the plan reads a host's real IPC
// tables, and everything it names is destroyed without a second look. Each row
// below is a shape the plan must tell apart from a leaked one.
func TestHostResourceRemovalPlanPreservesLiveControlSegmentAndRemovesOrphans(t *testing.T) {
	shared := `
T ID KEY MODE OWNER GROUP CREATOR CGROUP NATTCH SEGSZ CPID LPID
m 90 0x00001000 --rw------- alice staff alice staff 4 56 200 200
m 91 0x00002000 --rw------- alice staff alice staff 0 56 300 300
m 92 0x00003000 --rw------- alice staff alice staff 0 4096 400 400
m 93 0x00004000 --rw------- bob staff bob staff 0 56 500 500
`
	semaphores := `
T ID KEY MODE OWNER GROUP CREATOR CGROUP NSEMS OTIME CTIME
s 10 0x00001001 --ra------- alice staff alice staff 20 10:00:00 10:00:00
s 11 0x00001002 --ra------- alice staff alice staff 20 10:00:00 10:00:00
s 20 0x00002001 --ra------- alice staff alice staff 20 09:00:00 09:00:00
s 21 0x00002002 --ra------- alice staff alice staff 20 09:00:00 09:00:00
s 30 0x00005001 --ra------- alice staff alice staff 20 08:00:00 08:00:00
s 40 0x00006001 --ra------- alice staff alice staff 20 07:00:00 07:00:00
s 41 0x00006002 --ra------- alice staff alice staff 20 07:00:00 07:00:00
s 42 0x00007001 --ra------- alice staff alice staff 20 06:30:00 06:30:00
s 43 0x00007005 --ra------- alice staff alice staff 20 06:30:00 06:30:00
s 44 0x00001003 --ra------- alice staff alice staff 20 10:00:00 10:00:00
s 45 0x00001004 --ra------- alice staff alice staff 20 10:00:00 10:00:00
s 46 0x00009001 --ra------- alice staff alice staff 20 06:00:00 06:00:00
s 47 0x00009002 --ra------- alice staff alice staff 20 06:00:01 06:00:01
s 50 0x00007001 --rw------- alice staff alice staff 20 06:00:00 06:00:00
s 60 0x00008001 --ra------- bob staff bob staff 20 05:00:00 05:00:00
s 61 0x00008002 --ra------- bob staff bob staff 20 05:00:00 05:00:00
`
	sharedIDs, semaphoreIDs, err := postgresIPCRemovalPlan(shared, semaphores, "alice", func(pid int) bool {
		return pid == 200
	})
	require.NoError(t, err)

	// 91 is a dead 56-byte control segment with nothing attached. 90 is alive,
	// 92 is not a control segment, and 93 belongs to another user.
	require.Equal(t, []int{91}, sharedIDs)

	// 20/21 are named by 91's dead base key; 40/41 are two same-CTIME
	// consecutive sets; 42/43 are what a partially cleaned run leaves behind.
	// Everything else is somebody's live database or not PostgreSQL at all:
	// 10/11/44/45 sit inside the live segment's key span, 30 is a lone set,
	// 46/47 were created a second apart, 50 has the wrong mode, 60/61 belong
	// to another user.
	require.Equal(t, []int{20, 21, 40, 41, 42, 43}, semaphoreIDs)
}

// TestHostResourceRemovalPlanRejectsMalformedCandidateRows refuses to guess.
// A row this parser cannot read is a table it does not understand, and
// removing IDs derived from a half-understood table is how live databases get
// destroyed.
func TestHostResourceRemovalPlanRejectsMalformedCandidateRows(t *testing.T) {
	_, _, err := postgresIPCRemovalPlan(
		"m bad 0x1000 --rw------- alice staff alice staff 0 56 300 300",
		"",
		"alice",
		func(int) bool { return false },
	)
	require.Error(t, err, "malformed PostgreSQL control segment was accepted")

	_, _, err = postgresIPCRemovalPlan(
		"",
		"s bad 0x1001 --ra------- alice staff alice staff 20 10:00:00 10:00:00",
		"alice",
		func(int) bool { return false },
	)
	require.Error(t, err, "malformed PostgreSQL semaphore set was accepted")
}

// TestRecoveryVerdictCountsAPeersRemovalAsDone is the concurrency case that
// ipcrm's exit status gets wrong. Two agents planning the same orphans is
// ordinary — one wins, and the loser's ipcrm fails the whole invocation over
// identifiers that are already gone. Reading that as a cleanup failure makes
// `codefly clear` report a failure for work that is complete, so the verdict
// is taken from what survived, not from what ipcrm said.
func TestRecoveryVerdictCountsAPeersRemovalAsDone(t *testing.T) {
	recovery, err := recoveryVerdict(
		[]int{91}, []int{20, 21},
		survivors{},
		errors.New("ipcrm: shmid(91): invalid identifier"),
	)
	require.NoError(t, err, "resources that are gone are recovered, whoever removed them")
	require.Equal(t, hostResourceRecovery{SharedSegments: 1, SemaphoreSets: 2}, recovery)
}

// TestRecoveryVerdictReportsPartialProgressWithTheFailure keeps a real failure
// from erasing the work that succeeded. ipcrm cannot attribute a batch failure
// to individual identifiers, so a caller told only "it failed" would retry
// believing nothing was removed, and an operator reading the log would not
// know which resources are still holding the host.
func TestRecoveryVerdictReportsPartialProgressWithTheFailure(t *testing.T) {
	recovery, err := recoveryVerdict(
		[]int{90, 91}, []int{20, 21, 22},
		survivors{shared: []int{90}, semaphores: []int{22}},
		nil,
	)
	require.Error(t, err)
	require.Contains(t, err.Error(), "shared memory [90]")
	require.Contains(t, err.Error(), "semaphores [22]")
	require.Equal(t, hostResourceRecovery{SharedSegments: 1, SemaphoreSets: 2}, recovery,
		"what was removed is reported even when the pass failed overall")
}

// TestSurvivingIDsReadsPresenceRatherThanTrustingRemoval is what makes the
// verdict possible: whether a resource is still there is a fact about the
// host, readable at any time, unlike ipcrm's one-shot exit status.
func TestSurvivingIDsReadsPresenceRatherThanTrustingRemoval(t *testing.T) {
	shared := `
m 90 0x00001000 --rw------- alice staff alice staff 4 56 200 200
`
	semaphores := `
s 21 0x00002002 --ra------- alice staff alice staff 20 09:00:00 09:00:00
`
	remaining, err := survivingIDs(shared, semaphores, []int{90, 91}, []int{20, 21})
	require.NoError(t, err)
	require.Equal(t, []int{90}, remaining.shared, "91 is absent, so it was removed")
	require.Equal(t, []int{21}, remaining.semaphores, "20 is absent, so it was removed")
}

// TestSurvivingIDsRefusesAnUnreadableTable fails closed. A table this parser
// cannot read would otherwise look like an empty table, which reads as "every
// planned resource is gone" — reporting a successful cleanup that never
// happened and leaving the host broken with nothing to retry it.
func TestSurvivingIDsRefusesAnUnreadableTable(t *testing.T) {
	_, err := survivingIDs(
		"m bad 0x1000 --rw------- alice staff alice staff 0 56 300 300",
		"",
		[]int{91}, nil,
	)
	require.Error(t, err)
}

// TestHostResourceRemovalPlanSparesEverythingWhenNoRunLeaked is the quiet case
// the lifecycle paths hit on every healthy start: one live database, nothing
// to collect. A plan that names anything here would reap a running server.
func TestHostResourceRemovalPlanSparesEverythingWhenNoRunLeaked(t *testing.T) {
	shared := `
m 90 0x00001000 --rw------- alice staff alice staff 4 56 200 200
`
	semaphores := `
s 10 0x00001001 --ra------- alice staff alice staff 20 10:00:00 10:00:00
s 11 0x00001002 --ra------- alice staff alice staff 20 10:00:00 10:00:00
`
	sharedIDs, semaphoreIDs, err := postgresIPCRemovalPlan(shared, semaphores, "alice", func(pid int) bool {
		return pid == 200
	})
	require.NoError(t, err)
	require.Empty(t, sharedIDs)
	require.Empty(t, semaphoreIDs)
}
