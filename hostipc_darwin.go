//go:build darwin

package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"os/user"
	"sort"
	"strconv"
	"strings"
)

const (
	postgresDarwinControlSegmentBytes = 56
	postgresDarwinSemaphoresPerSet    = 20
	postgresDarwinSemaphoreKeySpan    = 1024
	postgresIPCRemovalBatchSize       = 256
)

type postgresSharedMemoryRow struct {
	id          int
	key         uint64
	owner       string
	attachments int
	size        int
	creatorPID  int
}

type postgresSemaphoreRow struct {
	id         int
	key        uint64
	mode       string
	owner      string
	semaphores int
	createdAt  string
}

// recoverHostResources removes only current-user PostgreSQL control segments
// whose creator is dead and semaphore runs that no live PostgreSQL control
// segment owns. PostgreSQL normally removes these resources itself; their
// orphaned shape means an interrupted process group prevented the postmaster
// from executing IPC_RMID.
//
// Safety depends on PostgreSQL's 56-byte control segment and its cluster of
// 20-semaphore sets. A set is removed only when its dead control segment is
// present or at least two same-creation-time sets form a bounded key cluster.
// A lone semaphore set with no matching control segment is never touched.
// Live control segments protect every matching semaphore cluster.
func recoverHostResources(ctx context.Context) (hostResourceRecovery, error) {
	if err := ctx.Err(); err != nil {
		return hostResourceRecovery{}, err
	}
	current, err := user.Current()
	if err != nil {
		return hostResourceRecovery{}, fmt.Errorf("resolve user for PostgreSQL IPC cleanup: %w", err)
	}
	sharedOutput, err := exec.CommandContext(ctx, "ipcs", "-ma").Output()
	if err != nil {
		return hostResourceRecovery{}, fmt.Errorf("list System V shared memory: %w", err)
	}
	semaphoreOutput, err := exec.CommandContext(ctx, "ipcs", "-sa").Output()
	if err != nil {
		return hostResourceRecovery{}, fmt.Errorf("list System V semaphores: %w", err)
	}
	sharedIDs, semaphoreIDs, err := postgresIPCRemovalPlan(
		string(sharedOutput),
		string(semaphoreOutput),
		current.Username,
		processAlive,
	)
	if err != nil {
		return hostResourceRecovery{}, err
	}
	if err := removePostgresIPC(ctx, sharedIDs, semaphoreIDs); err != nil {
		return hostResourceRecovery{}, err
	}
	return hostResourceRecovery{SharedSegments: len(sharedIDs), SemaphoreSets: len(semaphoreIDs)}, nil
}

func postgresIPCRemovalPlan(
	sharedOutput string,
	semaphoreOutput string,
	username string,
	alive func(int) bool,
) ([]int, []int, error) {
	sharedRows, err := parsePostgresSharedMemoryRows(sharedOutput)
	if err != nil {
		return nil, nil, err
	}
	semaphoreRows, err := parsePostgresSemaphoreRows(semaphoreOutput)
	if err != nil {
		return nil, nil, err
	}

	activeBases := make(map[uint64]struct{})
	orphanedBases := make(map[uint64]struct{})
	var sharedIDs []int
	for _, row := range sharedRows {
		if row.owner != username || row.size != postgresDarwinControlSegmentBytes {
			continue
		}
		if row.creatorPID <= 1 {
			continue
		}
		if row.attachments > 0 || alive(row.creatorPID) {
			activeBases[row.key] = struct{}{}
			continue
		}
		orphanedBases[row.key] = struct{}{}
		sharedIDs = append(sharedIDs, row.id)
	}

	candidates := make([]postgresSemaphoreRow, 0, len(semaphoreRows))
	for _, row := range semaphoreRows {
		if row.key > 0 && row.owner == username && row.mode == "--ra-------" && row.semaphores == postgresDarwinSemaphoresPerSet {
			candidates = append(candidates, row)
		}
	}
	sort.Slice(candidates, func(i, j int) bool { return candidates[i].key < candidates[j].key })

	var semaphoreIDs []int
	selected := make(map[int]struct{})
	belongsToActivePostgres := func(key uint64) bool {
		for base := range activeBases {
			if key > base && key-base <= postgresDarwinSemaphoreKeySpan {
				return true
			}
		}
		return false
	}
	for start := 0; start < len(candidates); {
		end := start + 1
		for end < len(candidates) && candidates[end].key == candidates[end-1].key+1 {
			end++
		}
		run := candidates[start:end]
		base := run[0].key - 1
		active := false
		for _, row := range run {
			if belongsToActivePostgres(row.key) {
				active = true
				break
			}
		}
		_, explicitlyOrphaned := orphanedBases[base]
		sameCreation := run[0].createdAt != ""
		for _, row := range run[1:] {
			if row.createdAt != run[0].createdAt {
				sameCreation = false
				break
			}
		}
		// PostgreSQL may allocate a different number of sets as max_connections
		// changes. Two same-creation-time consecutive sets are the minimum safe
		// orphan signature; a dead control segment is stronger and permits one.
		if !active && (explicitlyOrphaned || len(run) >= 2 && sameCreation) {
			for _, row := range run {
				semaphoreIDs = append(semaphoreIDs, row.id)
				selected[row.id] = struct{}{}
			}
		}
		start = end
	}
	// Interrupted or older cleanup may already have removed some sets from a
	// PostgreSQL run, leaving holes between keys. Sets created by one postmaster
	// share a CTIME; cluster those rows within PostgreSQL's bounded key span and
	// require at least two survivors. This heals partial runs without treating a
	// lone same-shaped semaphore from another application as PostgreSQL.
	byCreation := make(map[string][]postgresSemaphoreRow)
	for _, row := range candidates {
		if _, ok := selected[row.id]; ok {
			continue
		}
		byCreation[row.createdAt] = append(byCreation[row.createdAt], row)
	}
	for _, rows := range byCreation {
		sort.Slice(rows, func(i, j int) bool { return rows[i].key < rows[j].key })
		for start := 0; start < len(rows); {
			end := start + 1
			for end < len(rows) && rows[end].key-rows[start].key <= postgresDarwinSemaphoreKeySpan {
				end++
			}
			cluster := rows[start:end]
			active := false
			for _, row := range cluster {
				if belongsToActivePostgres(row.key) {
					active = true
					break
				}
			}
			if !active && len(cluster) >= 2 {
				for _, row := range cluster {
					semaphoreIDs = append(semaphoreIDs, row.id)
					selected[row.id] = struct{}{}
				}
			}
			start = end
		}
	}
	sort.Ints(sharedIDs)
	sort.Ints(semaphoreIDs)
	return sharedIDs, semaphoreIDs, nil
}

func parsePostgresSharedMemoryRows(output string) ([]postgresSharedMemoryRow, error) {
	var rows []postgresSharedMemoryRow
	scanner := bufio.NewScanner(strings.NewReader(output))
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		// Darwin `ipcs -ma` rows are:
		// T ID KEY MODE OWNER GROUP CREATOR CGROUP NATTCH SEGSZ CPID ...
		if len(fields) < 11 || fields[0] != "m" {
			continue
		}
		id, idErr := strconv.Atoi(fields[1])
		key, keyErr := strconv.ParseUint(fields[2], 0, 64)
		attachments, attachmentsErr := strconv.Atoi(fields[8])
		size, sizeErr := strconv.Atoi(fields[9])
		creatorPID, creatorErr := strconv.Atoi(fields[10])
		if idErr != nil || keyErr != nil || attachmentsErr != nil || sizeErr != nil || creatorErr != nil {
			return nil, fmt.Errorf("parse System V shared-memory row %q", scanner.Text())
		}
		rows = append(rows, postgresSharedMemoryRow{
			id: id, key: key, owner: fields[4], attachments: attachments,
			size: size, creatorPID: creatorPID,
		})
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scan System V shared-memory table: %w", err)
	}
	return rows, nil
}

func parsePostgresSemaphoreRows(output string) ([]postgresSemaphoreRow, error) {
	var rows []postgresSemaphoreRow
	scanner := bufio.NewScanner(strings.NewReader(output))
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		// Darwin `ipcs -sa` rows are:
		// T ID KEY MODE OWNER GROUP CREATOR CGROUP NSEMS OTIME CTIME
		if len(fields) < 11 || fields[0] != "s" {
			continue
		}
		id, idErr := strconv.Atoi(fields[1])
		key, keyErr := strconv.ParseUint(fields[2], 0, 64)
		semaphores, semaphoresErr := strconv.Atoi(fields[8])
		if idErr != nil || keyErr != nil || semaphoresErr != nil {
			return nil, fmt.Errorf("parse System V semaphore row %q", scanner.Text())
		}
		rows = append(rows, postgresSemaphoreRow{
			id: id, key: key, mode: fields[3], owner: fields[4], semaphores: semaphores, createdAt: fields[10],
		})
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scan System V semaphore table: %w", err)
	}
	return rows, nil
}

func removePostgresIPC(ctx context.Context, sharedIDs, semaphoreIDs []int) error {
	var operations []string
	for _, id := range sharedIDs {
		operations = append(operations, "-m", strconv.Itoa(id))
	}
	for _, id := range semaphoreIDs {
		operations = append(operations, "-s", strconv.Itoa(id))
	}
	var cleanupErr error
	for len(operations) > 0 {
		count := postgresIPCRemovalBatchSize * 2
		if count > len(operations) {
			count = len(operations)
		}
		batch := operations[:count]
		output, err := exec.CommandContext(ctx, "ipcrm", batch...).CombinedOutput()
		if err != nil {
			cleanupErr = errors.Join(cleanupErr, fmt.Errorf(
				"remove orphaned PostgreSQL IPC resources: %w: %s",
				err,
				strings.TrimSpace(string(output)),
			))
		}
		operations = operations[count:]
	}
	return cleanupErr
}
