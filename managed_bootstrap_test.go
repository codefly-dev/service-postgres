package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	builderv0 "github.com/codefly-dev/core/generated/go/codefly/services/builder/v0"
	"github.com/stretchr/testify/require"
)

func TestExternalIdentityBuildRejectsPasswordBootstrapBeforeWriting(t *testing.T) {
	builder := newBuildTestBuilder(t)
	builder.AuthMode = authModeExternalIdentity
	output := t.TempDir()
	marker := filepath.Join(output, "caller-owned")
	require.NoError(t, os.WriteFile(marker, []byte("preserve"), 0o600))

	response, err := builder.Build(context.Background(), buildRequest(output))
	require.NoError(t, err)
	require.Equal(t, builderv0.BuildStatus_ERROR, response.GetState().GetState(),
		"external-identity must not emit the password-based role bootstrap")
	require.Contains(t, response.GetState().GetMessage(), "external-identity")
	data, err := os.ReadFile(marker)
	require.NoError(t, err)
	require.Equal(t, "preserve", string(data))
	_, err = os.Stat(filepath.Join(builder.Location, "bootstrap"))
	require.True(t, os.IsNotExist(err), "rejection must precede staged output")
}

func TestExternalIdentityBuildWithoutOutputRejectsPasswordBootstrap(t *testing.T) {
	builder := newBuildTestBuilder(t)
	builder.AuthMode = authModeExternalIdentity
	response, err := builder.Build(context.Background(), buildRequest(""))
	require.NoError(t, err)
	require.Equal(t, builderv0.BuildStatus_ERROR, response.GetState().GetState())
	require.Contains(t, response.GetState().GetMessage(), "external-identity")
	_, err = os.Stat(filepath.Join(builder.Location, "builder", "Dockerfile"))
	require.True(t, os.IsNotExist(err))
}

func TestBootstrapBuildRejectsUnknownAuthMode(t *testing.T) {
	builder := newBuildTestBuilder(t)
	builder.AuthMode = "external-identty"
	response, err := builder.Build(context.Background(), buildRequest(t.TempDir()))
	require.NoError(t, err)
	require.Equal(t, builderv0.BuildStatus_ERROR, response.GetState().GetState())
	require.Contains(t, response.GetState().GetMessage(), "unsupported postgres auth mode")
}
