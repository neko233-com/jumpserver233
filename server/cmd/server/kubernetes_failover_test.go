package main

import (
	"context"
	"encoding/json"
	"github.com/coder/websocket"
	"github.com/neko233-com/jumpserver233/server/internal/connector/kubeclient"
	"github.com/neko233-com/jumpserver233/server/internal/core/assets"
	"github.com/neko233-com/jumpserver233/server/internal/gateway"
	"github.com/neko233-com/jumpserver233/server/internal/sessionclient"
	"github.com/neko233-com/jumpserver233/server/testsupport/kubefixture"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"os"
	"strings"
	"testing"
	"time"
)

type kubeFailoverProof struct {
	Asset      string
	Old        gateway.CreatedSession
	Connection *websocket.Conn
}

func prepareKubeFailover(t *testing.T, address, token, org string) *kubeFailoverProof {
	if os.Getenv("JMS_TEST_KUBERNETES_FIXTURE_URL") == "" {
		return nil
	}
	target, secret := kubefixture.Load(t)
	var a assets.Asset
	require.NoError(t, json.Unmarshal(databaseHARequest(t, address, "POST", "/api/v1/assets", token, org, "", assets.Input{Name: "Kubernetes HA", Protocol: assets.ProtocolKubernetes, Host: target.Host, Port: target.Port, Username: "qadb", Password: secret, Kubernetes: &target.Settings}, 201), &a))
	client, e := sessionclient.New("http://"+address, token)
	require.NoError(t, e)
	client, e = client.WithOrganization(org)
	require.NoError(t, e)
	ctx, stop := context.WithTimeout(context.Background(), 15*time.Second)
	defer stop()
	session, e := client.CreateSession(ctx, gateway.CreateRequest{AssetID: a.ID, Cols: 80, Rows: 24, Kubernetes: &kubeclient.Selection{Namespace: "jms-qa", Pod: "qa-shell", Container: "main"}})
	require.NoError(t, e)
	conn, e := client.DialTerminal(ctx, session)
	require.NoError(t, e)
	t.Cleanup(func() { conn.CloseNow() })
	return &kubeFailoverProof{a.ID, session, conn}
}
func verifyKubeActiveBeforeFailover(t *testing.T, p *kubeFailoverProof) {
	if p == nil {
		return
	}
	ctx, stop := context.WithTimeout(context.Background(), 5*time.Second)
	defer stop()
	require.NoError(t, p.Connection.Write(ctx, websocket.MessageBinary, []byte("echo __KUBE_HA_STILL_ACTIVE__\n")))
	var output strings.Builder
	for !strings.Contains(output.String(), "\r\n__KUBE_HA_STILL_ACTIVE__\r\n") {
		_, data, e := p.Connection.Read(ctx)
		require.NoError(t, e)
		output.Write(data)
	}
}
func verifyKubeFailover(t *testing.T, address, token, org string, p *kubeFailoverProof) {
	if p == nil {
		return
	}
	client, e := sessionclient.New("http://"+address, token)
	require.NoError(t, e)
	client, e = client.WithOrganization(org)
	require.NoError(t, e)
	ctx, stop := context.WithTimeout(context.Background(), 15*time.Second)
	defer stop()
	for {
		_, _, e := p.Connection.Read(ctx)
		if e != nil {
			break
		}
	}
	conn, e := client.DialTerminal(ctx, p.Old)
	assert.Error(t, e)
	if conn != nil {
		conn.CloseNow()
	}
	var records struct {
		Results []gateway.SessionRecord `json:"results"`
	}
	require.NoError(t, json.Unmarshal(databaseHARequest(t, address, "GET", "/api/v1/sessions", token, org, "", nil, 200), &records))
	found := false
	for _, r := range records.Results {
		if r.SessionID == p.Old.SessionID {
			found = true
			assert.NotEqual(t, "active", r.Status)
			assert.NotEqual(t, "ticket_expired", r.EndReason)
			require.NotNil(t, r.Kubernetes)
			assert.Equal(t, "qa-shell", r.Kubernetes.Pod)
		}
	}
	assert.True(t, found)
	session, e := client.CreateSession(ctx, gateway.CreateRequest{AssetID: p.Asset, Cols: 80, Rows: 24, Kubernetes: &kubeclient.Selection{Namespace: "jms-qa", Pod: "qa-shell", Container: "sidecar"}})
	require.NoError(t, e)
	require.NoError(t, client.CloseSession(ctx, session.SessionID))
	databaseHARequest(t, address, "POST", "/api/v1/assets/"+p.Asset+"/kubernetes/sessions", token, "", "", map[string]any{"namespace": "jms-qa", "pod": "qa-shell", "cols": 80, "rows": 24}, 404)
}
