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

func TestAnnouncementCLIUsesStrictJSONSafeIDsAndCompleteSurface(t *testing.T) {
	id := "notice-" + strings.Repeat("a", 32)
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		assert.Equal(t, "Bearer synthetic-token", r.Header.Get("Authorization"))
		if r.Method == "DELETE" {
			w.WriteHeader(204)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"id": id, "results": []any{}, "total": 0, "unread": 0, "revision": 1})
	}))
	defer srv.Close()
	c, e := sessionclient.New(srv.URL, "synthetic-token")
	require.NoError(t, e)
	for _, args := range [][]string{{}, {"unknown"}, {"list", "--limit", "101"}, {"list", "--offset", "-1"}, {"read", "../escape", "--revision", "1"}, {"read", id}, {"delete", id, "--revision", "1"}, {"save", "--file", "-"}} {
		var out bytes.Buffer
		e := executeAnnouncements(context.Background(), c, args, strings.NewReader(`{"unknown":true}`), &out)
		require.Error(t, e)
		assert.Empty(t, out.String())
	}
	assert.Zero(t, calls)
	input := `{"title":{"en":"Maintenance"},"body":{"en":"Plain content"},"request_id":"cli-notice-001"}`
	for _, args := range [][]string{{"list"}, {"list", "--manage"}, {"audit"}, {"save", "--file", "-"}, {"save", id, "--file", "-"}, {"read", id, "--revision", "1"}, {"delete", id, "--revision", "1", "--request-id", "cli-delete-001"}} {
		var out bytes.Buffer
		require.NoError(t, executeAnnouncements(context.Background(), c, args, strings.NewReader(input), &out))
		assert.NotEmpty(t, out.String())
	}
	assert.Equal(t, 7, calls)
}
