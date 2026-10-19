package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/neko233-com/jumpserver233/server/internal/connector/sshclient"
	"github.com/neko233-com/jumpserver233/server/internal/core/jobs"
	"github.com/neko233-com/jumpserver233/server/internal/sessionclient"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestExecWithoutTTYUsesOnlyAPICredentialAndPreservesRemoteExit(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "Bearer api-only", r.Header.Get("Authorization"))
		assert.Equal(t, "/api/v1/ops/jobs", r.URL.Path)
		var input jobs.Input
		require.NoError(t, json.NewDecoder(r.Body).Decode(&input))
		assert.Equal(t, "printf hello", input.Command)
		assert.Equal(t, "/srv/work/app", input.WorkingDirectory)
		assert.NotEmpty(t, input.RequestID)
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(jobs.Job{ID: "job-one", State: "failed", ErrorCode: "remote_exit", ExecResult: sshclient.ExecResult{Stdout: "hello", Stderr: "problem", ExitCode: 7}})
	}))
	defer server.Close()
	client, err := sessionclient.New(server.URL, "api-only")
	require.NoError(t, err)
	var out, stderr bytes.Buffer
	err = executeCommand(context.Background(), client, []string{"asset", "--directory", "/srv/work/app", "--timeout", "20", "--", "printf", "hello"}, &out, &stderr)
	var remote *remoteExitError
	require.ErrorAs(t, err, &remote)
	assert.Equal(t, 7, remote.Code)
	assert.Equal(t, "hello", out.String())
	assert.Contains(t, stderr.String(), "problem")
}
