package main

import (
	"bytes"
	"context"
	"github.com/neko233-com/jumpserver233/server/internal/sessionclient"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestDiscoveryCLIWholeWorkflowTypedOutputAndStrictJSON(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.Method == "DELETE" {
			w.WriteHeader(204)
			return
		}
		if strings.HasSuffix(r.URL.Path, ".csv") {
			_, _ = w.Write([]byte("host,port\n192.0.2.1,22\n"))
			return
		}
		if strings.HasSuffix(r.URL.Path, "/runs") && r.Method == "POST" {
			w.WriteHeader(202)
		}
		_, _ = w.Write([]byte(`{"id":"public-resource","revision":1,"results":[],"total":0,"password":"do-not-emit"}`))
	}))
	defer srv.Close()
	c, e := sessionclient.New(srv.URL, "fixture-token")
	require.NoError(t, e)
	for _, args := range [][]string{{"sources"}, {"policies"}, {"runs"}, {"findings", "--source", "source-1"}, {"audit"}, {"source", "show", "source-1"}, {"source", "save", "--file", "-"}, {"policy", "save", "--file", "-"}, {"run", "start", "--file", "-"}, {"run", "show", "run-1"}, {"run", "cancel", "run-1"}, {"preview", "--file", "-"}, {"import", "--file", "-"}, {"source", "delete", "source-1", "--revision", "1"}, {"policy", "delete", "policy-1", "--revision", "1"}, {"export", "--source", "source-1"}} {
		var out bytes.Buffer
		require.NoError(t, executeAssetDiscovery(context.Background(), c, args, strings.NewReader(`{}`), &out), args)
		assert.NotContains(t, out.String(), "do-not-emit")
	}
	for _, args := range [][]string{{}, {"unknown"}, {"source", "show"}, {"source", "delete", "id"}, {"findings"}, {"audit", "--limit", "501"}, {"run", "start", "unexpected", "--file", "-"}, {"source", "save"}} {
		before := calls
		var out bytes.Buffer
		assert.Error(t, executeAssetDiscovery(context.Background(), c, args, strings.NewReader(`{}`), &out), args)
		assert.Equal(t, before, calls)
	}
	before := calls
	var out bytes.Buffer
	assert.Error(t, executeAssetDiscovery(context.Background(), c, []string{"source", "save", "--file", "-"}, strings.NewReader(`{"unknown":"reject"}`), &out))
	assert.Equal(t, before, calls)
}
