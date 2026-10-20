package main

import (
	"bytes"
	"context"
	"encoding/json"
	"github.com/neko233-com/jumpserver233/server/internal/sessionclient"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestFixedPasswordCLIUsesProtectedStdinAndRejectsPlainArguments(t *testing.T) {
	secret := strings.Repeat("Ab2!", 16)
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		var input sessionclient.RotationPlanSaveInput
		require.NoError(t, json.NewDecoder(r.Body).Decode(&input))
		assert.True(t, input.FixedPassword == secret)
		assert.Equal(t, "fixed-cli-request", input.RequestID)
		w.WriteHeader(201)
		_ = json.NewEncoder(w).Encode(sessionclient.RotationPlan{ID: "fixed-cli-plan", SaveRequestID: input.RequestID, RotationPlanInput: input.RotationPlanInput})
	}))
	defer server.Close()
	client, e := sessionclient.New(server.URL, "synthetic-token")
	require.NoError(t, e)
	path := filepath.Join(t.TempDir(), "plan.json")
	require.NoError(t, os.WriteFile(path, []byte(`{"name":"Fixed CLI metadata","kind":"manual","password_mode":"fixed","targets":[{"account_id":"account-a"}]}`), 0600))
	var output bytes.Buffer
	args := []string{"create", "--file", path, "--request-id", "fixed-cli-request", "--fixed-password-file", "-"}
	require.NoError(t, executeRotationPlansInput(context.Background(), client, args, strings.NewReader(secret+"\n"), &output))
	assert.Equal(t, 1, calls)
	assert.NotContains(t, output.String(), secret)
	assert.Contains(t, output.String(), "fixed-cli-request")
	protected := filepath.Join(t.TempDir(), "fixed.jms-secret")
	require.NoError(t, os.WriteFile(protected, []byte(secret+"\n"), 0600))
	fromFile := append([]string(nil), args...)
	fromFile[len(fromFile)-1] = protected
	require.NoError(t, executeRotationPlansInput(context.Background(), client, fromFile, nil, &output))
	assert.Equal(t, 2, calls)
	if runtime.GOOS != "windows" {
		require.NoError(t, os.Chmod(protected, 0644))
		assert.Error(t, executeRotationPlansInput(context.Background(), client, fromFile, nil, &output))
		assert.Equal(t, 2, calls)
	}
	for _, tail := range [][]string{{"--fixed-password", secret}, {"--password", secret}, {"--fixed-password-file", "-", "--extra"}} {
		assert.Error(t, executeRotationPlansInput(context.Background(), client, append([]string{"create", "--file", path}, tail...), strings.NewReader(secret), &output))
	}
	assert.Equal(t, 2, calls)
	require.NoError(t, os.WriteFile(path, []byte(`{"name":"Fixed CLI metadata","kind":"manual","password_mode":"fixed","targets":[{"account_id":"account-a"}],"fixed_password":"must-stay-out-of-metadata-files"}`), 0600))
	assert.Error(t, executeRotationPlansInput(context.Background(), client, args, strings.NewReader(secret), &output))
	assert.Equal(t, 2, calls)
}
