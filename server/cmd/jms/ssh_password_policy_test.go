package main

import (
	"bytes"
	"context"
	"github.com/neko233-com/jumpserver233/server/internal/sessionclient"
	"github.com/stretchr/testify/require"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestSSHPasswordPolicyCLIUsesMetadataAndRejectsUnknownInputs(t *testing.T) {
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		require.Equal(t, "/api/v1/accounts/password-policy", r.URL.Path)
		_, _ = w.Write([]byte(`{"policy":{"revision":2}}`))
	}))
	defer server.Close()
	c, e := sessionclient.New(server.URL, "synthetic-platform")
	require.NoError(t, e)
	var out bytes.Buffer
	require.NoError(t, executeSSHPasswordPolicy(context.Background(), c, []string{"show"}, &out))
	require.Contains(t, out.String(), `"revision":2`)
	file := filepath.Join(t.TempDir(), "policy.json")
	require.NoError(t, os.WriteFile(file, []byte(`{"request_id":"cli-policy","policy":{"revision":1}}`), 0600))
	require.NoError(t, executeSSHPasswordPolicy(context.Background(), c, []string{"set", "--file", file}, &out))
	require.Equal(t, 2, calls)
	require.NoError(t, os.WriteFile(file, []byte(`{"password":"must-not-be-a-policy-input"}`), 0600))
	require.Error(t, executeSSHPasswordPolicy(context.Background(), c, []string{"set", "--file", file}, &out))
	require.Equal(t, 2, calls)
	require.Error(t, executeSSHPasswordPolicy(context.Background(), c, []string{"show", "unexpected"}, &out))
}
