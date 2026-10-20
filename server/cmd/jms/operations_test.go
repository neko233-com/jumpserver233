package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"github.com/neko233-com/jumpserver233/server/internal/sessionclient"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestOperationsCLIDirectorySurvivesStrictJSONAndSDK(t *testing.T) {
	requests := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var input struct {
			WorkingDirectory string `json:"working_directory"`
		}
		require.NoError(t, json.NewDecoder(r.Body).Decode(&input))
		assert.Equal(t, "/srv/work/deploy", input.WorkingDirectory)
		requests++
		_ = json.NewEncoder(w).Encode(input)
	}))
	defer srv.Close()
	c, err := sessionclient.New(srv.URL, "synthetic-token")
	require.NoError(t, err)
	for _, command := range []string{"create", "template-create"} {
		var out bytes.Buffer
		err := executeOperations(context.Background(), c, []string{command, "--file", "-"}, strings.NewReader(`{"name":"directory","command":"pwd","working_directory":"/srv/work/deploy"}`), &out)
		require.NoError(t, err)
		assert.Contains(t, out.String(), `"working_directory":"/srv/work/deploy"`)
	}
	assert.Equal(t, 2, requests)
}

func TestOperationsCLICompleteCommandSurfaceAndStrictInputs(t *testing.T) {
	id := "plan-" + strings.Repeat("a", 32)
	run := "run-" + strings.Repeat("b", 32)
	template := "template-" + strings.Repeat("c", 32)
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.Method == "DELETE" || strings.HasSuffix(r.URL.Path, "/cancel") {
			w.WriteHeader(204)
			return
		}
		if r.URL.Path == "/api/v1/ops/templates" && r.Method == "GET" {
			fmt.Fprint(w, `[]`)
			return
		}
		fmt.Fprint(w, `{"id":"synthetic","results":[],"occurrences":[],"total":0}`)
	}))
	defer srv.Close()
	c, e := sessionclient.New(srv.URL, "synthetic-token")
	require.NoError(t, e)
	for _, args := range [][]string{{}, {"unknown"}, {"plan"}, {"plan", "../escape"}, {"plans", "--limit", "101"}, {"plans", "--offset", "-1"}, {"create"}, {"preview", "--revision", "1"}, {"enable", id}, {"run", run, "extra"}, {"templates", "--file", "-"}, {"cancel", run, "--limit", "1"}} {
		var out bytes.Buffer
		require.Error(t, executeOperations(context.Background(), c, args, strings.NewReader(`{}`), &out))
		assert.Empty(t, out.String())
	}
	assert.Zero(t, calls)
	for _, raw := range []string{`{"unknown":true}`, `{} {}`, `null`, `{"kind":`, strings.Repeat("x", (64<<10)+1)} {
		var out bytes.Buffer
		require.Error(t, executeOperations(context.Background(), c, []string{"preview", "--file", "-"}, strings.NewReader(raw), &out))
		assert.Empty(t, out.String())
	}
	assert.Zero(t, calls)
	for _, args := range [][]string{
		{"preview", "--file", "-"}, {"create", "--file", "-"}, {"schedule", id, "--file", "-"},
		{"enable", id, "--revision", "2"}, {"disable", id, "--revision", "2"},
		{"plans", "--offset", "0", "--limit", "25"}, {"plan", id}, {"runs"}, {"run", run}, {"events", id}, {"cancel", run},
		{"templates"}, {"template-create", "--file", "-"}, {"template-update", template, "--file", "-"}, {"template-delete", template, "--revision", "2"},
	} {
		var out bytes.Buffer
		require.NoError(t, executeOperations(context.Background(), c, args, strings.NewReader(`{}`), &out), args)
		assert.NotEmpty(t, out.String())
	}
	assert.Equal(t, 15, calls)
	file := filepath.Join(t.TempDir(), "schedule.json")
	require.NoError(t, os.WriteFile(file, []byte(`{"kind":"cron","cron_expression":"* * * * *","timezone":"UTC"}`), 0600))
	var out bytes.Buffer
	require.NoError(t, executeOperations(context.Background(), c, []string{"preview", "--file", file}, nil, &out))
	require.Error(t, executeOperations(context.Background(), c, []string{"preview", "--file", file + "missing"}, nil, &out))
}
