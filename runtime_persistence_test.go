package main

import (
	"context"
	"errors"
	"testing"
)

type recordingPersistentCacheMounter struct {
	key       string
	target    string
	err       error
	callCount int
}

func (m *recordingPersistentCacheMounter) WithPersistentCacheMount(
	_ context.Context,
	key string,
	target string,
) (string, error) {
	m.callCount++
	m.key = key
	m.target = target
	return "/codefly/runtime-cache/test/postgres-data", m.err
}

func TestMountPersistentPostgresDataUsesCodeflyOwnedScope(t *testing.T) {
	mounter := &recordingPersistentCacheMounter{}

	path, err := mountPersistentPostgresData(context.Background(), mounter)
	if err != nil {
		t.Fatalf("mount persistent postgres data: %v", err)
	}
	if path != "/codefly/runtime-cache/test/postgres-data" {
		t.Fatalf("cache path = %q", path)
	}
	if mounter.callCount != 1 {
		t.Fatalf("mount calls = %d, want 1", mounter.callCount)
	}
	if mounter.key != postgresDataCacheKey {
		t.Fatalf("cache key = %q, want %q", mounter.key, postgresDataCacheKey)
	}
	if mounter.target != postgresDataDirectory {
		t.Fatalf("container target = %q, want %q", mounter.target, postgresDataDirectory)
	}
}

func TestMountPersistentPostgresDataPropagatesFailure(t *testing.T) {
	want := errors.New("cache unavailable")
	mounter := &recordingPersistentCacheMounter{err: want}

	if _, err := mountPersistentPostgresData(context.Background(), mounter); !errors.Is(err, want) {
		t.Fatalf("mount error = %v, want %v", err, want)
	}
}
