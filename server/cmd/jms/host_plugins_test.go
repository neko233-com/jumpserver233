package main

import (
	"bytes"
	"context"
	"encoding/json"
	"github.com/neko233-com/jumpserver233/server/internal/sessionclient"
	"github.com/stretchr/testify/require"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
)

func TestPluginCLIUsesPlatformIdentityStableRequestsAndJSONWithoutMutationRetry(t *testing.T) {
	var posts atomic.Int32
	var fail atomic.Bool
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/v1/assets/asset/host-plugins/banhack233/jobs", func(w http.ResponseWriter, r *http.Request) {
		posts.Add(1)
		require.Equal(t, "Bearer platform-token", r.Header.Get("Authorization"))
		var v sessionclient.PluginRequest
		require.NoError(t, json.NewDecoder(r.Body).Decode(&v))
		require.Equal(t, "stable-plugin-request", v.RequestID)
		require.Equal(t, "install", v.Action)
		if fail.Load() {
			w.WriteHeader(502)
			return
		}
		w.WriteHeader(201)
		_, _ = w.Write([]byte(`{"id":"job-one","state":"succeeded","stdout":"{\"installed\":true}"}`))
	})
	mux.HandleFunc("GET /api/v1/host-plugins", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`[{"id":"banhack233","version":"0.2.3"}]`))
	})
	server := httptest.NewServer(mux)
	defer server.Close()
	client, e := sessionclient.New(server.URL, "platform-token")
	require.NoError(t, e)
	var out bytes.Buffer
	args := []string{"asset", "banhack233", "install", "--request-id", "stable-plugin-request"}
	require.NoError(t, executePlugin(context.Background(), client, args, &out))
	require.Contains(t, out.String(), "job-one")
	require.NotContains(t, out.String(), "platform-token")
	require.EqualValues(t, 1, posts.Load())
	fail.Store(true)
	out.Reset()
	require.Error(t, executePlugin(context.Background(), client, args, &out))
	require.EqualValues(t, 2, posts.Load())
	require.Empty(t, out.String())
	require.NoError(t, executePlugin(context.Background(), client, []string{"catalog"}, &out))
	require.Contains(t, out.String(), "banhack233")
	for _, bad := range [][]string{{}, {"asset"}, {"asset", "banhack233", "install", "--timeout", "0"}, {"asset", "banhack233", "install", "--unknown"}} {
		require.Error(t, executePlugin(context.Background(), client, bad, &out))
	}
	require.EqualValues(t, 2, posts.Load())
}
func TestPluginCLINoWaitReturnsApprovalMetadataWithoutReplaying(t *testing.T) {
	var count atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		count.Add(1)
		w.WriteHeader(202)
		_, _ = w.Write([]byte(`{"review_id":"review-one"}`))
	}))
	defer server.Close()
	client, e := sessionclient.New(server.URL, "token")
	require.NoError(t, e)
	var out bytes.Buffer
	require.NoError(t, executePlugin(context.Background(), client, []string{"asset", "banhack233", "install", "--request-id", "pending-one", "--no-wait"}, &out))
	require.Contains(t, out.String(), "pending_login_review")
	require.Contains(t, out.String(), "pending-one")
	require.EqualValues(t, 1, count.Load())
}

func TestPluginCLIPinsSelectedVersionAndParsesBoundedProtectionPolicy(t *testing.T) {
	var received sessionclient.PluginRequest
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.NoError(t, json.NewDecoder(r.Body).Decode(&received))
		w.WriteHeader(201)
		_, _ = w.Write([]byte(`{"id":"job-test","state":"succeeded","stdout":"{}"}`))
	}))
	defer s.Close()
	c, e := sessionclient.New(s.URL, "platform-only")
	require.NoError(t, e)
	var out bytes.Buffer
	require.NoError(t, executePlugin(context.Background(), c, []string{"asset", "node_exporter", "install", "--version", "1.12.0"}, &out))
	require.Equal(t, "1.12.0", received.Version)
	file := filepath.Join(t.TempDir(), "policy.json")
	require.NoError(t, os.WriteFile(file, []byte(`{"mode":"enforce","ignore_ips":["192.0.2.0/24"]}`), 0600))
	require.NoError(t, executePlugin(context.Background(), c, []string{"asset", "banhack233", "protection_apply", "--policy-file", file}, &out))
	require.Equal(t, "enforce", received.Protection.Mode)
	require.Equal(t, 5, received.Protection.MaxAttempts)
	require.Error(t, executePlugin(context.Background(), c, []string{"asset", "banhack233", "protection_apply"}, &out))
	require.NoError(t, os.WriteFile(file, []byte(`{"mode":"enforce","shell":"id"}`), 0600))
	require.Error(t, executePlugin(context.Background(), c, []string{"asset", "banhack233", "protection_apply", "--policy-file", file}, &out))
}
