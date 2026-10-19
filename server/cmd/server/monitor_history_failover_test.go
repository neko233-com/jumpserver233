package main

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	coreassets "github.com/neko233-com/jumpserver233/server/internal/core/assets"
	"github.com/neko233-com/jumpserver233/server/internal/core/monitorhistory"
	"github.com/neko233-com/jumpserver233/server/internal/storage"
	"github.com/stretchr/testify/require"
)

func TestMonitoringHistoryPersistsAcrossRealPostgresLeaderTakeover(t *testing.T) {
	dbURL := os.Getenv("JMS_TEST_DATABASE_URL")
	if dbURL == "" {
		t.Skip("set JMS_TEST_DATABASE_URL for real monitoring history leader takeover")
	}
	namespace := fmt.Sprintf("monitor-history-ha-%d", time.Now().UnixNano())
	dir := t.TempDir()
	key := []byte("0123456789abcdef0123456789abcdef")
	docs, e := storage.OpenPostgres(context.Background(), dbURL, namespace)
	require.NoError(t, e)
	ctx1, cancel1 := context.WithCancel(context.Background())
	ctx2, cancel2 := context.WithCancel(context.Background())
	done1, done2 := make(chan error, 1), make(chan error, 1)
	started1, started2, finished1 := false, false, false
	t.Cleanup(func() {
		cancel1()
		cancel2()
		if started1 && !finished1 {
			select {
			case e := <-done1:
				require.NoError(t, e)
			case <-time.After(15 * time.Second):
				t.Error("first history node did not stop")
			}
		}
		if started2 {
			select {
			case e := <-done2:
				require.NoError(t, e)
			case <-time.After(15 * time.Second):
				t.Error("second history node did not stop")
			}
		}
		require.NoError(t, docs.Close())
		pool, e := sql.Open("pgx", dbURL)
		require.NoError(t, e)
		defer pool.Close()
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_, e = pool.ExecContext(cleanupCtx, `DELETE FROM jms233_state_documents WHERE namespace=$1`, namespace)
		require.NoError(t, e)
	})
	inventory, e := coreassets.OpenStoreWithDocuments(filepath.Join(dir, "assets.json"), key, docs)
	require.NoError(t, e)
	assets := coreassets.NewService(inventory, nil)
	host, e := assets.Create(coreassets.Input{Name: "Synthetic history failover host", Host: "127.0.0.1", Port: 1, Username: "ops", Password: "synthetic-history-ha-password", HostKeyFingerprint: "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"})
	require.NoError(t, e)
	history, e := monitorhistory.Open(filepath.Join(dir, "monitor-history"), key, docs)
	require.NoError(t, e)
	// Seed a distinctive, closed-minute observation. A new live probe cannot
	// recreate this value or overwrite this earlier minute during takeover.
	at := time.Now().UTC().Add(-2 * time.Minute).Truncate(time.Minute)
	_, e = history.Record(host.ID, monitorhistory.Sample{At: at, Binding: assets.MonitorSources(nil)[0].Binding, State: "online", Values: map[string]float64{"cpu_percent": 73.25}})
	require.NoError(t, e)
	history.Close()
	_, e = os.Stat(filepath.Join(dir, "monitor-history", "meta.json"))
	require.True(t, os.IsNotExist(e), "shared history must not rely on a local metadata copy")
	encoded := base64.StdEncoding.EncodeToString(key)
	first := integrationNodeConfig(t, namespace, dir, encoded, freeAddress(t), freeAddress(t))
	second := integrationNodeConfig(t, namespace, dir, encoded, freeAddress(t), freeAddress(t))
	query := url.Values{"from": {at.Format(time.RFC3339Nano)}, "to": {at.Add(time.Minute).Format(time.RFC3339Nano)}, "step": {"60"}}
	read := func(address string) {
		req, e := http.NewRequest("GET", "http://"+address+"/api/v1/assets/"+host.ID+"/monitor-history?"+query.Encode(), nil)
		require.NoError(t, e)
		req.Header.Set("Authorization", "Bearer "+first.AdminToken)
		response, e := http.DefaultClient.Do(req)
		require.NoError(t, e)
		defer response.Body.Close()
		body, e := io.ReadAll(response.Body)
		require.NoError(t, e)
		require.Equal(t, 200, response.StatusCode, string(body))
		var page monitorhistory.Page
		require.NoError(t, json.Unmarshal(body, &page))
		require.Len(t, page.Results, 1)
		require.Equal(t, at, page.Results[0].LastSample)
		require.Equal(t, 73.25, page.Results[0].Values["cpu_percent"].Mean)
	}
	started1 = true
	go func() { done1 <- runActiveStandby(ctx1, first) }()
	waitForHTTPStatus(t, "http://"+first.ClusterHealthAddr+"/readyz", 200, 20*time.Second)
	read(first.Addr)
	started2 = true
	go func() { done2 <- runActiveStandby(ctx2, second) }()
	waitForHTTPStatus(t, "http://"+second.ClusterHealthAddr+"/readyz", 503, 20*time.Second)
	cancel1()
	select {
	case e := <-done1:
		finished1 = true
		require.NoError(t, e)
	case <-time.After(15 * time.Second):
		t.Fatal("history leader did not stop")
	}
	waitForHTTPStatus(t, "http://"+second.ClusterHealthAddr+"/readyz", 200, 20*time.Second)
	read(second.Addr)
}
