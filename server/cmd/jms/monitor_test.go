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
	"strings"
	"testing"
)

func TestMonitorCLIValidatesIDsStdinAndScopesRequests(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		assert.Equal(t, "Bearer synthetic-monitor-client", r.Header.Get("Authorization"))
		assert.Equal(t, "00000000-0000-0000-0000-000000000002", r.Header.Get("X-JMS-ORG"))
		assert.True(t, strings.HasPrefix(r.URL.Path, "/api/v1/monitoring/"))
		if strings.HasSuffix(r.URL.Path, "/acknowledge") {
			var in struct {
				Revision int    `json:"revision"`
				Comment  string `json:"comment"`
			}
			require.NoError(t, json.NewDecoder(r.Body).Decode(&in))
			assert.Equal(t, 3, in.Revision)
			assert.Equal(t, "Synthetic note", in.Comment)
		}
		if r.URL.Path == "/api/v1/monitoring/alerts" {
			assert.Equal(t, "A & B", r.URL.Query().Get("q"))
		}
		_, _ = w.Write([]byte(`{"id":"monitor-alert-synthetic","password":"synthetic-extra-secret","stdout":"synthetic-output"}`))
	}))
	defer srv.Close()
	c, e := sessionclient.New(srv.URL, "synthetic-monitor-client")
	require.NoError(t, e)
	c, e = c.WithOrganization("00000000-0000-0000-0000-000000000002")
	require.NoError(t, e)
	var out bytes.Buffer
	for _, args := range [][]string{{}, {"unknown"}, {"alert", ".."}, {"alert", "x/y"}, {"rule-delete", "safe"}, {"mute", "safe", "--revision", "1", "--until", "bad"}, {"alerts", "--limit", "201"}, {"acknowledge", "../escape", "--revision", "1"}, {"rule-save", "--file", "-"}} {
		assert.Error(t, executeMonitor(context.Background(), c, args, strings.NewReader(`{"owner":"synthetic-extra"}`), &out))
	}
	assert.Zero(t, calls)
	require.NoError(t, executeMonitor(context.Background(), c, []string{"acknowledge", "monitor-alert-synthetic", "--revision", "3", "--comment", "Synthetic note"}, strings.NewReader(""), &out))
	require.NoError(t, executeMonitor(context.Background(), c, []string{"alerts", "--query", "A & B"}, strings.NewReader(""), &out))
	require.NoError(t, executeMonitor(context.Background(), c, []string{"rule-save", "--file", "-"}, strings.NewReader(`{"name":"Synthetic rule"}`), &out))
	assert.Equal(t, 3, calls)
	assert.NotContains(t, out.String(), "synthetic-extra-secret")
	assert.NotContains(t, out.String(), "synthetic-output")
}
