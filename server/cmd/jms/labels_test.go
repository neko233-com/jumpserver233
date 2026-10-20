package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/neko233-com/jumpserver233/server/internal/sessionclient"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLabelCLIUsesStrictJSONSafeIDsAndCompleteSDKSurface(t *testing.T) {
	id := "label-" + strings.Repeat("a", 32)
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		assert.Equal(t, "Bearer synthetic-token", r.Header.Get("Authorization"))
		assert.NotContains(t, r.URL.Path, "..")
		if r.Method == "DELETE" {
			w.WriteHeader(204)
			return
		}
		if r.URL.Path == "/api/v1/labels/choices" {
			_ = json.NewEncoder(w).Encode([]any{})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"id": id, "results": []any{}, "total": 0, "revision": 1})
	}))
	defer srv.Close()
	c, err := sessionclient.New(srv.URL, "synthetic-token")
	require.NoError(t, err)
	for _, args := range [][]string{{}, {"unknown"}, {"list", "--limit", "101"}, {"list", "--offset", "-1"}, {"save", "../escape", "--file", "-"}, {"delete", id, "--revision", "1"}, {"binding", "asset", "../escape"}, {"binding", "user", "host"}, {"save", "--file", "-"}, {"bind", "asset", "host", "--file", "-"}} {
		var out bytes.Buffer
		err = executeLabels(context.Background(), c, args, strings.NewReader(`{"unknown":true}`), &out)
		require.Error(t, err)
		assert.Empty(t, out.String())
	}
	assert.Zero(t, calls)
	for _, tc := range []struct {
		args  []string
		input string
	}{{[]string{"list", "--search", "Team & Ops"}, ""}, {[]string{"choices"}, ""}, {[]string{"audit"}, ""}, {[]string{"save", "--file", "-"}, `{"name":"Team","value":"Ops","request_id":"cli-label-001"}`}, {[]string{"save", id, "--file", "-"}, `{"name":"Team","revision":1,"request_id":"cli-label-002"}`}, {[]string{"binding", "node", "root"}, ""}, {[]string{"bind", "asset", "host", "--file", "-"}, `{"label_ids":[],"revision":1,"request_id":"cli-bind-001"}`}, {[]string{"delete", id, "--revision", "1", "--request-id", "cli-delete-001"}, ""}} {
		var out bytes.Buffer
		require.NoError(t, executeLabels(context.Background(), c, tc.args, strings.NewReader(tc.input), &out))
		assert.NotEmpty(t, out.String())
	}
	assert.Equal(t, 8, calls)
}
