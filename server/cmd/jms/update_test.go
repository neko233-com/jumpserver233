package main

import (
	"bytes"
	"context"
	"testing"

	"github.com/neko233-com/jumpserver233/server/internal/core/updates"
	"github.com/neko233-com/jumpserver233/server/internal/sessionclient"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestUpdateCLIRejectsInvalidArgumentsBeforeNetworking(t *testing.T) {
	factory := func(string, string) *updates.Feed { t.Fatal("invalid input contacted release service"); return nil }
	for _, args := range [][]string{{}, {"install"}, {"check", "--source", "https://evil.example"}, {"download"}, {"download", "--version", "v1.2.3-rc.1", "--out", "file"}, {"download", "--version", "v1.2.3", "--out", "file", "--os", "unknown"}} {
		var out bytes.Buffer
		assert.Error(t, executeUpdate(context.Background(), args, &out, factory))
	}
	c, e := sessionclient.New("http://127.0.0.1:1", "")
	require.NoError(t, e)
	for _, args := range [][]string{{}, {"bad"}, {"policy", "--revision", "1"}, {"policy", "--automatic=true", "--revision", "0"}, {"check-server", "--revision", "1"}, {"status", "--revision", "1"}} {
		var out bytes.Buffer
		assert.Error(t, executeServerUpdate(context.Background(), c, args, &out))
	}
	var out bytes.Buffer
	require.NoError(t, printBuildVersion(&out))
	assert.Contains(t, out.String(), `"version":`)
}

func TestUpdateStagingCLIRequiresExplicitRootAndExactActionArguments(t *testing.T) {
	for _, args := range [][]string{{}, {"stage"}, {"stage", "--root", "x", "--file", "x"}, {"stage-status", "--root", "x"}, {"stage-clean", "--root", "x", "--sha256", "x"}, {"stage-status", "--root", "x", "--file", "x", "--sha256", "x"}, {"stage-clean", "--root", "x", "--os", "unknown"}, {"install", "--root", "x"}} {
		var out bytes.Buffer
		require.Error(t, executeStage(context.Background(), args, &out))
		assert.Empty(t, out.String())
	}
}
