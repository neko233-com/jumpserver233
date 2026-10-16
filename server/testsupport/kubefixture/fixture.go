package kubefixture

import (
	"encoding/json"
	"github.com/neko233-com/jumpserver233/server/internal/connector/kubeclient"
	"github.com/stretchr/testify/require"
	"net"
	"net/http"
	"os"
	"strconv"
	"testing"
	"time"
)

func Load(t *testing.T) (kubeclient.Target, string) {
	t.Helper()
	url := os.Getenv("JMS_TEST_KUBERNETES_FIXTURE_URL")
	if url == "" {
		t.Skip("set JMS_TEST_KUBERNETES_FIXTURE_URL for real K3s TLS integration")
	}
	client := http.Client{Timeout: 5 * time.Second}
	r, e := client.Get(url)
	require.NoError(t, e)
	defer r.Body.Close()
	require.Equal(t, 200, r.StatusCode)
	var m struct {
		Address string `json:"address"`
		CA      string `json:"root_ca_pem"`
		Name    string `json:"server_name"`
		Token   string `json:"token"`
	}
	require.NoError(t, json.NewDecoder(r.Body).Decode(&m))
	addr := m.Address
	if v := os.Getenv("JMS_TEST_KUBERNETES_NETWORK_ADDR"); v != "" {
		addr = v
	}
	host, port, e := net.SplitHostPort(addr)
	require.NoError(t, e)
	n, e := strconv.Atoi(port)
	require.NoError(t, e)
	return kubeclient.Target{Host: host, Port: n, Settings: kubeclient.Settings{Namespaces: []string{"jms-qa"}, Shell: []string{"/bin/sh"}, RootCAPEM: m.CA, ServerName: m.Name}}, m.Token
}
