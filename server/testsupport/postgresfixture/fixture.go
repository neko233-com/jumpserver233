// Package postgresfixture describes the disposable, loopback-only QA database.
package postgresfixture

import (
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/neko233-com/jumpserver233/server/internal/connector/postgresclient"
	"github.com/stretchr/testify/require"
)

func Load(t *testing.T) (postgresclient.Target, postgresclient.Credentials) {
	t.Helper()
	endpoint := os.Getenv("JMS_TEST_POSTGRES_FIXTURE_URL")
	if endpoint == "" {
		t.Skip("set JMS_TEST_POSTGRES_FIXTURE_URL for real TLS PostgreSQL query integration")
	}
	client := http.Client{Timeout: 5 * time.Second}
	r, e := client.Get(endpoint)
	require.NoError(t, e)
	defer r.Body.Close()
	require.Equal(t, 200, r.StatusCode)
	var m struct {
		Address    string `json:"address"`
		CA         string `json:"root_ca_pem"`
		ServerName string `json:"server_name"`
		Database   string `json:"database"`
		Username   string `json:"username"`
	}
	require.NoError(t, json.NewDecoder(r.Body).Decode(&m))
	host, port, e := net.SplitHostPort(m.Address)
	require.NoError(t, e)
	n, e := strconv.Atoi(port)
	require.NoError(t, e)
	if override := os.Getenv("JMS_TEST_POSTGRES_NETWORK_ADDR"); override != "" {
		host, port, e = net.SplitHostPort(override)
		require.NoError(t, e)
		n, e = strconv.Atoi(port)
		require.NoError(t, e)
	}
	return postgresclient.Target{Host: host, Port: n, Username: m.Username, Settings: postgresclient.Settings{Database: m.Database, TLSMode: "verify-full", ServerName: m.ServerName, RootCAPEM: m.CA}}, postgresclient.Credentials{Password: "synthetic-postgres-query-233"}
}

// LoadPAM uses only the dedicated disposable account-management authority.
func LoadPAM(t *testing.T) (postgresclient.Target, postgresclient.Credentials) {
	t.Helper()
	target, _ := Load(t)
	target.Username = "pam_admin"
	return target, postgresclient.Credentials{Password: "synthetic-pam-admin-233"}
}

// Keep the gateway fixture loopback-only even when tests run in a separate
// Linux container and the dedicated QA PostgreSQL is on its Docker network.
func LoopbackForward(t *testing.T, address string) string {
	t.Helper()
	listener, e := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, e)
	var mu sync.Mutex
	var wg sync.WaitGroup
	connections := map[net.Conn]bool{}
	closed := false
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			local, e := listener.Accept()
			if e != nil {
				return
			}
			mu.Lock()
			if closed {
				mu.Unlock()
				local.Close()
				return
			}
			connections[local] = true
			wg.Add(1)
			mu.Unlock()
			go func() {
				defer wg.Done()
				defer local.Close()
				remote, e := net.DialTimeout("tcp", address, 3*time.Second)
				if e != nil {
					return
				}
				mu.Lock()
				if closed {
					mu.Unlock()
					remote.Close()
					return
				}
				connections[remote] = true
				mu.Unlock()
				defer remote.Close()
				done := make(chan struct{})
				go func() { _, _ = io.Copy(remote, local); remote.Close(); close(done) }()
				_, _ = io.Copy(local, remote)
				local.Close()
				<-done
				mu.Lock()
				delete(connections, local)
				delete(connections, remote)
				mu.Unlock()
			}()
		}
	}()
	t.Cleanup(func() {
		mu.Lock()
		closed = true
		listener.Close()
		for c := range connections {
			c.Close()
		}
		mu.Unlock()
		wg.Wait()
	})
	return listener.Addr().String()
}
