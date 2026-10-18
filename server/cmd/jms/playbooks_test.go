package main

import (
	"bytes"
	"context"
	"fmt"
	"github.com/neko233-com/jumpserver233/server/internal/sessionclient"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestNativePlaybookCLICompleteSurfaceAndBounds(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.Method == "DELETE" {
			w.WriteHeader(204)
			return
		}
		fmt.Fprint(w, `{"results":[],"total":0}`)
	}))
	defer srv.Close()
	c, e := sessionclient.New(srv.URL, "synthetic-token")
	require.NoError(t, e)
	book := "playbook-" + strings.Repeat("a", 32)
	run := "run-" + strings.Repeat("b", 32)
	step := "step-" + strings.Repeat("c", 32)
	plan := "plan-" + strings.Repeat("d", 32)
	for _, args := range [][]string{{"validate", "--file", "-"}, {"playbooks"}, {"playbook", book}, {"playbook-create", "--file", "-"}, {"playbook-update", book, "--file", "-"}, {"playbook-delete", book, "--revision", "1"}, {"playbook-events", book}, {"program", run}, {"step", run, "asset", step}, {"trigger", plan, "--request-id", "unique"}} {
		var out bytes.Buffer
		require.NoError(t, executeOperations(context.Background(), c, args, strings.NewReader(`{}`), &out), args)
		assert.NotEmpty(t, out.String())
	}
	assert.Equal(t, 10, calls)
	for _, args := range [][]string{{"validate"}, {"step", run, "asset"}, {"step", run, "../escape", step}, {"trigger", plan}, {"playbook-delete", book}, {"program", run, "--revision", "1"}} {
		var out bytes.Buffer
		require.Error(t, executeOperations(context.Background(), c, args, strings.NewReader(`{}`), &out), args)
	}
	assert.Equal(t, 10, calls)
	var out bytes.Buffer
	require.Error(t, executeOperations(context.Background(), c, []string{"validate", "--file", "-"}, strings.NewReader(strings.Repeat("x", (512<<10)+1)), &out))
	assert.Equal(t, 10, calls)
}
