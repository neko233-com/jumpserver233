package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/neko233-com/jumpserver233/server/internal/sessionclient"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAccountImportCLIPreviewsThenCommitsSameFileWithSafeDTOAndPreservesExistingOutput(t *testing.T) {
	dir := t.TempDir()
	source := filepath.Join(dir, "accounts.csv")
	require.NoError(t, os.WriteFile(source, []byte("action,asset_id,username,password\ncreate,asset,user,synthetic-file-secret\n"), 0600))
	calls := 0
	var requestID string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		assert.Equal(t, "Bearer synthetic-token", r.Header.Get("Authorization"))
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/v1/accounts/imports/preview":
			var in sessionclient.AccountImportRequest
			require.NoError(t, json.NewDecoder(r.Body).Decode(&in))
			assert.Contains(t, string(in.Content), "synthetic-file-secret")
			assert.NotEmpty(t, in.RequestID)
			requestID = in.RequestID
			json.NewEncoder(w).Encode(map[string]any{"request_id": in.RequestID, "preview_token": "signed-proof", "rows": []map[string]string{{"username": "user", "password": "synthetic-never-print"}}, "issues": []any{}, "private_key": "synthetic-never-print"})
		case "/api/v1/accounts/imports":
			if r.Method == "GET" {
				w.Write([]byte(`{"results":[],"total":0}`))
				return
			}
			var in sessionclient.AccountImportRequest
			require.NoError(t, json.NewDecoder(r.Body).Decode(&in))
			assert.Equal(t, requestID, in.RequestID)
			assert.Equal(t, "signed-proof", in.PreviewToken)
			json.NewEncoder(w).Encode(map[string]any{"request_id": in.RequestID, "rows": []map[string]string{{"username": "user", "private_key": "synthetic-never-print"}}, "password": "synthetic-never-print"})
		case "/api/v1/accounts/imports/template":
			json.NewEncoder(w).Encode(map[string]any{"content": []byte("action,asset_id,username\n")})
		default:
			w.WriteHeader(404)
		}
	}))
	defer server.Close()
	c, e := sessionclient.New(server.URL, "synthetic-token")
	require.NoError(t, e)
	var out bytes.Buffer
	require.NoError(t, executeManagedAccount(context.Background(), c, []string{"import-preview", "--file", source}, nil, &out))
	assert.NotContains(t, out.String(), "synthetic-never-print")
	assert.NotContains(t, out.String(), "synthetic-file-secret")
	review := filepath.Join(dir, "review.json")
	require.NoError(t, os.WriteFile(review, out.Bytes(), 0600))
	out.Reset()
	require.NoError(t, executeManagedAccount(context.Background(), c, []string{"import-commit", "--file", source, "--preview-file", review}, nil, &out))
	assert.NotContains(t, out.String(), "synthetic-never-print")
	target := filepath.Join(dir, "template.csv")
	require.NoError(t, executeManagedAccount(context.Background(), c, []string{"import-template", "--out", target}, nil, &out))
	assert.Error(t, executeManagedAccount(context.Background(), c, []string{"import-template", "--out", target}, nil, &out))
	raw, e := os.ReadFile(target)
	require.NoError(t, e)
	assert.Equal(t, "action,asset_id,username\n", string(raw))
	before := calls
	for _, args := range [][]string{{"import-commit", "--file", source}, {"imports", "--limit", "101"}, {"import-preview", "--file", source, "--format", "exe"}, {"import-template", "--out", target, "--format", "bad"}} {
		require.Error(t, executeManagedAccount(context.Background(), c, args, nil, &bytes.Buffer{}))
	}
	assert.Equal(t, before, calls)
}
