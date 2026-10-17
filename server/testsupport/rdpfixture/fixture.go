package rdpfixture

import (
	"encoding/json"
	"github.com/neko233-com/jumpserver233/server/internal/connector/rdpclient"
	"github.com/stretchr/testify/require"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"
)

const Username = "rdpqa"
const Password = "synthetic-rdp-password-233"

type State struct {
	Copies      int    `json:"copies"`
	Pastes      int    `json:"pastes"`
	PasteFailed bool   `json:"paste_failed"`
	Focus       bool   `json:"focus"`
	Clicks      int    `json:"clicks"`
	Text        string `json:"text"`
	Display     string `json:"display"`
}

func ReadState() (State, error) {
	client := http.Client{Timeout: 3 * time.Second}
	r, e := client.Get(strings.TrimSuffix(os.Getenv("JMS_TEST_RDP_FIXTURE_URL"), "/health") + "/state")
	if e != nil {
		return State{}, e
	}
	defer r.Body.Close()
	var s State
	e = json.NewDecoder(r.Body).Decode(&s)
	return s, e
}

func Load(t *testing.T) rdpclient.Target {
	t.Helper()
	url := os.Getenv("JMS_TEST_RDP_FIXTURE_URL")
	if url == "" {
		t.Skip("set JMS_TEST_RDP_FIXTURE_URL for real xrdp/Xorg integration")
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
	}
	require.NoError(t, json.NewDecoder(r.Body).Decode(&m))
	if v := os.Getenv("JMS_TEST_RDP_NETWORK_ADDR"); v != "" {
		m.Address = v
	}
	host, port, e := net.SplitHostPort(m.Address)
	require.NoError(t, e)
	n, e := strconv.Atoi(port)
	require.NoError(t, e)
	settings, e := rdpclient.Normalize(rdpclient.Settings{Security: "tls", ServerName: m.Name, RootCAPEM: m.CA})
	require.NoError(t, e)
	return rdpclient.Target{Host: host, Port: n, Settings: settings}
}
