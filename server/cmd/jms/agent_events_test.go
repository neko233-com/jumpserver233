package main

import (
	"bytes"
	"context"
	"github.com/neko233-com/jumpserver233/server/internal/sessionclient"
	"github.com/stretchr/testify/require"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestAgentEventCLIHistoryCollectionAndInvalidFlags(t *testing.T) {
	calls := 0
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.Method == "POST" {
			w.WriteHeader(201)
			return
		}
		if r.URL.Path == "/api/v1/assets/asset-a/agent-events/collection" {
			_, _ = w.Write([]byte(`[]`))
		} else {
			require.Equal(t, "/api/v1/audit/agent-events", r.URL.Path)
			require.Equal(t, "12", r.URL.Query().Get("before"))
			_, _ = w.Write([]byte(`{"results":[],"next_before":0}`))
		}
	}))
	defer s.Close()
	c, e := sessionclient.New(s.URL, "synthetic-token")
	require.NoError(t, e)
	var out bytes.Buffer
	require.NoError(t, executeAgentEvents(context.Background(), c, []string{"all", "--before", "12"}, &out))
	require.Contains(t, out.String(), "next_before")
	require.NoError(t, executeAgentEvents(context.Background(), c, []string{"asset-a", "collection", "--enable", "--interval", "300"}, &out))
	before := calls
	for _, args := range [][]string{{}, {"all", "collection", "--enable"}, {"asset-a", "collection", "--enable", "--disable"}, {"asset-a", "--before", "-1"}, {"asset-a", "collection", "--interval", "1"}, {"asset-a", "--unknown"}} {
		require.Error(t, executeAgentEvents(context.Background(), c, args, &out))
	}
	require.Equal(t, before, calls)
}
