package mysqlfixture

import (
	"encoding/json"
	"github.com/neko233-com/jumpserver233/server/internal/connector/sqlclient"
	"github.com/stretchr/testify/require"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"
)

func LoadPAM(t *testing.T, engine string) (sqlclient.Target, sqlclient.Credentials) {
	t.Helper()
	target, _ := Load(t, engine)
	target.Username = "pam_admin"
	return target, sqlclient.Credentials{Password: "synthetic-pam-admin-233"}
}

func Load(t *testing.T, engine string) (sqlclient.Target, sqlclient.Credentials) {
	t.Helper()
	require.Contains(t, []string{"mysql", "mariadb"}, engine)
	prefix := "JMS_TEST_" + strings.ToUpper(engine)
	url := os.Getenv(prefix + "_FIXTURE_URL")
	if url == "" {
		t.Skip("set " + prefix + "_FIXTURE_URL for real TLS SQL integration")
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
		Protocol   string `json:"protocol"`
	}
	require.NoError(t, json.NewDecoder(r.Body).Decode(&m))
	require.Equal(t, engine, m.Protocol)
	address := m.Address
	if override := os.Getenv(prefix + "_NETWORK_ADDR"); override != "" {
		address = override
	}
	host, port, e := net.SplitHostPort(address)
	require.NoError(t, e)
	n, e := strconv.Atoi(port)
	require.NoError(t, e)
	return sqlclient.Target{Host: host, Port: n, Username: m.Username, Settings: sqlclient.Settings{Database: m.Database, TLSMode: "verify-full", ServerName: m.ServerName, RootCAPEM: m.CA}}, sqlclient.Credentials{Password: "synthetic-mysql-query-233"}
}
