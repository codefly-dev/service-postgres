package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	basev0 "github.com/codefly-dev/core/generated/go/codefly/base/v0"
	builderv0 "github.com/codefly-dev/core/generated/go/codefly/services/builder/v0"
	runtimev0 "github.com/codefly-dev/core/generated/go/codefly/services/runtime/v0"
	"github.com/codefly-dev/core/network"
	"github.com/codefly-dev/core/resources"
	"github.com/codefly-dev/core/shared"
	"github.com/stretchr/testify/require"
)

func TestSustainedWALBudgetDocker(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	cacheRoot := t.TempDir()
	t.Setenv(resources.CodeflyHomeEnv, cacheRoot)
	runtime := NewRuntime()
	cleaned := false
	t.Cleanup(func() {
		if !cleaned {
			if err := cleanupWALQualificationRuntime(runtime, cacheRoot); err != nil {
				t.Errorf("cleanup WAL qualification runtime: %v", err)
			}
		}
	})
	startWALQualificationRuntime(t, ctx, runtime)

	db, err := sql.Open("postgres", runtime.connection)
	require.NoError(t, err)
	defer func() { _ = db.Close() }()
	require.NoError(t, qualifySustainedWALBudget(ctx, db, runtime))
	require.NoError(t, db.Close())

	require.NoError(t, cleanupWALQualificationRuntime(runtime, cacheRoot))
	cleaned = true
	_, err = os.Stat(cacheRoot)
	require.ErrorIs(t, err, os.ErrNotExist, "qualification must remove its persistent runtime cache")
}

func startWALQualificationRuntime(t *testing.T, ctx context.Context, runtime *Runtime) {
	t.Helper()
	workspace := &resources.Workspace{Name: "wal-qualification"}
	workspacePath := t.TempDir()
	service := resources.Service{
		Name:    fmt.Sprintf("walq-%d", time.Now().UnixNano()),
		Version: "test",
	}
	require.NoError(t, service.SaveAtDir(ctx, filepath.Join(workspacePath, "mod", service.Name)))
	identity := &basev0.ServiceIdentity{
		Name:                service.Name,
		Module:              "mod",
		Workspace:           workspace.Name,
		WorkspacePath:       workspacePath,
		RelativeToWorkspace: filepath.Join("mod", service.Name),
	}
	builder := NewBuilder()
	_, err := builder.Load(ctx, &builderv0.LoadRequest{
		DisableCatch: true,
		Identity:     identity,
		CreationMode: &builderv0.CreationMode{Communicate: false},
	})
	require.NoError(t, err)
	_, err = builder.Create(ctx, &builderv0.CreateRequest{})
	require.NoError(t, err)

	environment := resources.LocalEnvironment()
	load, err := runtime.Load(ctx, &runtimev0.LoadRequest{
		Identity:     identity,
		Environment:  shared.Must(environment.Proto()),
		DisableCatch: true,
	})
	require.NoError(t, err)
	require.Equal(t, runtimev0.LoadStatus_READY, load.GetStatus().GetState(), load.GetStatus().GetMessage())
	require.NotNil(t, runtime.TcpEndpoint)
	runtime.NoMigration = true

	networkManager, err := network.NewRuntimeManager(ctx, nil)
	require.NoError(t, err)
	networkManager.WithTemporaryPorts()
	networkMappings, err := networkManager.GenerateNetworkMappings(
		ctx,
		environment,
		workspace,
		runtime.Identity,
		runtime.Endpoints,
		resources.NewRuntimeContextContainer(),
	)
	require.NoError(t, err)
	configuration := &basev0.Configuration{
		Origin:         identity.Module + "/" + identity.Name,
		RuntimeContext: resources.NewRuntimeContextFree(),
		Infos: []*basev0.ConfigurationInformation{{
			Name: "postgres",
			ConfigurationValues: []*basev0.ConfigurationValue{
				{Key: "POSTGRES_USER", Value: "postgres"},
				{Key: "POSTGRES_PASSWORD", Value: "owner-password"},
				{Key: "POSTGRES_READ_ONLY_PASSWORD", Value: "read-only-password"},
				{Key: "POSTGRES_READ_WRITE_PASSWORD", Value: "read-write-password"},
			},
		}},
	}
	init, err := runtime.Init(ctx, &runtimev0.InitRequest{
		RuntimeContext:          resources.NewRuntimeContextContainer(),
		Configuration:           configuration,
		ProposedNetworkMappings: networkMappings,
	})
	require.NoError(t, err)
	require.Equal(t, runtimev0.InitStatus_READY, init.GetStatus().GetState(), init.GetStatus().GetMessage())
	start, err := runtime.Start(ctx, &runtimev0.StartRequest{})
	require.NoError(t, err)
	require.Equal(t, runtimev0.StartStatus_STARTED, start.GetStatus().GetState(), start.GetStatus().GetMessage())
}

func qualifySustainedWALBudget(ctx context.Context, db *sql.DB, runtime *Runtime) error {
	var maxWALSize, checkpointTimeout, checkpointWarning, walSegmentSize string
	if err := db.QueryRowContext(ctx, "SHOW max_wal_size").Scan(&maxWALSize); err != nil {
		return err
	}
	if err := db.QueryRowContext(ctx, "SHOW checkpoint_timeout").Scan(&checkpointTimeout); err != nil {
		return err
	}
	if err := db.QueryRowContext(ctx, "SHOW checkpoint_warning").Scan(&checkpointWarning); err != nil {
		return err
	}
	if err := db.QueryRowContext(ctx, "SHOW wal_segment_size").Scan(&walSegmentSize); err != nil {
		return err
	}
	if maxWALSize != "4GB" || checkpointTimeout != "15min" || checkpointWarning != "30s" || walSegmentSize != "16MB" {
		return fmt.Errorf(
			"effective WAL settings = max_wal_size %s, checkpoint_timeout %s, checkpoint_warning %s, wal_segment_size %s",
			maxWALSize,
			checkpointTimeout,
			checkpointWarning,
			walSegmentSize,
		)
	}
	if _, err := db.ExecContext(ctx, "CREATE TABLE wal_budget_qualification (id bigint)"); err != nil {
		return err
	}
	if _, err := db.ExecContext(ctx, "CHECKPOINT"); err != nil {
		return err
	}
	var requestedBefore int64
	if err := db.QueryRowContext(ctx, "SELECT num_requested FROM pg_stat_checkpointer").Scan(&requestedBefore); err != nil {
		return err
	}

	const (
		segmentsPerSecond = 3
		maximumSegments   = 384
	)
	started := time.Now()
	segmentsGenerated := 0
	for segmentsGenerated < maximumSegments {
		batch := segmentsGenerated/segmentsPerSecond + 1
		target := started.Add(time.Duration(batch) * time.Second)
		if wait := time.Until(target); wait > 0 {
			timer := time.NewTimer(wait)
			select {
			case <-ctx.Done():
				timer.Stop()
				return ctx.Err()
			case <-timer.C:
			}
		}
		if _, err := db.ExecContext(ctx, `
			DO $$
			BEGIN
				FOR i IN 1..3 LOOP
					INSERT INTO wal_budget_qualification VALUES (i);
					PERFORM pg_switch_wal();
				END LOOP;
			END
			$$
		`); err != nil {
			return err
		}
		segmentsGenerated += segmentsPerSecond
		var requestedAfter int64
		if err := db.QueryRowContext(ctx, "SELECT num_requested FROM pg_stat_checkpointer").Scan(&requestedAfter); err != nil {
			return err
		}
		if requestedAfter > requestedBefore {
			cadence := time.Since(started)
			if cadence < 30*time.Second {
				return fmt.Errorf("production WAL profile requested its checkpoint after %s", cadence.Round(time.Millisecond))
			}
			logs := runtime.runnerEnvironment.TailLogs(ctx, 10000)
			if err := ctx.Err(); err != nil {
				return err
			}
			if containsCheckpointFrequencyWarning(logs) {
				return errors.New("production WAL profile emitted the checkpoint-frequency warning")
			}
			return nil
		}
	}
	return fmt.Errorf("production WAL profile did not request a WAL-budget checkpoint after %d segment switches", segmentsGenerated)
}

func containsCheckpointFrequencyWarning(logs string) bool {
	return strings.Contains(logs, "checkpoints are occurring too frequently")
}

func cleanupWALQualificationRuntime(runtime *Runtime, cacheRoot string) error {
	cleanupCtx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	var permissionErr, shutdownErr error
	if runtime.runnerEnvironment != nil {
		proc, err := runtime.runnerEnvironment.NewProcess("chmod", "-R", "a+rwX", postgresDataDirectory)
		if err != nil {
			permissionErr = err
		} else {
			permissionErr = proc.Run(cleanupCtx)
		}
		shutdownErr = runtime.runnerEnvironment.Shutdown(cleanupCtx)
	}
	removeErr := os.RemoveAll(cacheRoot)
	return errors.Join(permissionErr, shutdownErr, removeErr)
}
