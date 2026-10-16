package sqlserverfixture

import (
	"encoding/json"
	"github.com/neko233-com/jumpserver233/server/internal/connector/sqlclient"
	"github.com/stretchr/testify/require"
	"net"
	"net/http"
	"os"
	"strconv"
	"testing"
	"time"
)

func Load(t *testing.T) (sqlclient.Target, sqlclient.Credentials) {
	t.Helper()
	url := os.Getenv("JMS_TEST_SQLSERVER_FIXTURE_URL")
	if url == "" {
		t.Skip("set JMS_TEST_SQLSERVER_FIXTURE_URL for real TLS SQL Server integration")
	}
	client := http.Client{Timeout: 5 * time.Second}
	r, e := client.Get(url)
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
	address := m.Address
	if override := os.Getenv("JMS_TEST_SQLSERVER_NETWORK_ADDR"); override != "" {
		address = override
	}
	host, port, e := net.SplitHostPort(address)
	require.NoError(t, e)
	n, e := strconv.Atoi(port)
	require.NoError(t, e)
	return sqlclient.Target{Host: host, Port: n, Username: m.Username, Settings: sqlclient.Settings{Database: m.Database, TLSMode: "verify-full", ServerName: m.ServerName, RootCAPEM: m.CA}}, sqlclient.Credentials{Password: "Synthetic-SQLServer-Query-233!"}
}
