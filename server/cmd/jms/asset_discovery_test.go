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

func TestDiscoveryCLIListSourceFiltersAndPaginationAreApplied(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/policies") {
			_, _ = w.Write([]byte(`{"results":[{"id":"p1","source_id":"s1","migrate_cloud_ssh_address":true},{"id":"p2","source_id":"s2"},{"id":"p3","source_id":"s1","migrate_cloud_ssh_address":true}],"total":3}`))
			return
		}
		_, _ = w.Write([]byte(`{"results":[{"id":"s1"},{"id":"s2"},{"id":"s3"}],"total":3}`))
	}))
	defer srv.Close()
	c, e := sessionclient.New(srv.URL, "fixture-token")
	require.NoError(t, e)
	for _, tc := range []struct {
		args  []string
		ids   []string
		total int
	}{
		{[]string{"policies", "--source", "s1", "--offset", "1", "--limit", "1"}, []string{"p3"}, 2},
		{[]string{"policies", "--source", "missing"}, []string{}, 0},
		{[]string{"policies", "--offset", "1", "--limit", "1"}, []string{"p2"}, 3},
		{[]string{"policies", "--offset", "99", "--limit", "1"}, []string{}, 3},
		{[]string{"sources", "--source", "s2"}, []string{"s2"}, 1},
		{[]string{"sources", "--limit", "2"}, []string{"s1", "s2"}, 3},
	} {
		t.Run(strings.Join(tc.args, " "), func(t *testing.T) {
			var out bytes.Buffer
			require.NoError(t, executeAssetDiscovery(context.Background(), c, tc.args, strings.NewReader(""), &out))
			var page struct {
				Results []map[string]any `json:"results"`
				Total   int              `json:"total"`
			}
			require.NoError(t, json.Unmarshal(out.Bytes(), &page))
			assert.NotNil(t, page.Results)
			assert.Equal(t, tc.total, page.Total)
			ids := []string{}
			for _, row := range page.Results {
				ids = append(ids, row["id"].(string))
			}
			assert.Equal(t, tc.ids, ids)
			if len(ids) == 1 && ids[0] == "p3" {
				assert.Equal(t, true, page.Results[0]["migrate_cloud_ssh_address"])
			}
		})
	}
}
