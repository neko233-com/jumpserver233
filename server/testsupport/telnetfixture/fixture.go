package telnetfixture

import (
	"encoding/json"
	"github.com/neko233-com/jumpserver233/server/internal/connector/telnetclient"
	"github.com/stretchr/testify/require"
	"net"
	"net/http"
	"os"
	"strconv"
	"testing"
	"time"
)

const Username = "telnetqa"
const Password = "synthetic-telnet-password-233"

func Load(t *testing.T, plain bool) telnetclient.Target {
	t.Helper()
	url := os.Getenv("JMS_TEST_TELNET_FIXTURE_URL")
	if url == "" {
		t.Skip("set JMS_TEST_TELNET_FIXTURE_URL for native Linux Telnet integration")
	}
	client := http.Client{Timeout: 5 * time.Second}
	r, e := client.Get(url)
	require.NoError(t, e)
	defer r.Body.Close()
	require.Equal(t, 200, r.StatusCode)
	var m struct {
		Address string `json:"address"`
		Plain   string `json:"plaintext_address"`
		CA      string `json:"root_ca_pem"`
		Name    string `json:"server_name"`
	}
	require.NoError(t, json.NewDecoder(r.Body).Decode(&m))
	addr := m.Address
	key := "JMS_TEST_TELNET_NETWORK_ADDR"
	settings := telnetclient.Settings{RootCAPEM: m.CA, ServerName: m.Name}
	if plain {
		addr = m.Plain
		key = "JMS_TEST_TELNET_PLAINTEXT_NETWORK_ADDR"
		settings = telnetclient.Settings{TLSMode: "disable"}
	}
	if v := os.Getenv(key); v != "" {
		addr = v
	}
	host, port, e := net.SplitHostPort(addr)
	require.NoError(t, e)
	n, e := strconv.Atoi(port)
	require.NoError(t, e)
	settings, e = telnetclient.Normalize(settings)
	require.NoError(t, e)
	return telnetclient.Target{Host: host, Port: n, Settings: settings}
}
