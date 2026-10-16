package main

import (
	"context"
	"encoding/json"
	"github.com/coder/websocket"
	"github.com/neko233-com/jumpserver233/server/internal/core/assets"
	"github.com/neko233-com/jumpserver233/server/internal/gateway"
	"github.com/neko233-com/jumpserver233/server/internal/sessionclient"
	"github.com/neko233-com/jumpserver233/server/testsupport/telnetfixture"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"os"
	"strings"
	"testing"
	"time"
)

type telnetFailoverProof struct {
	Asset      string
	Old        gateway.CreatedSession
	Connection *websocket.Conn
}

func prepareTelnetFailover(t *testing.T, address, token, org string) *telnetFailoverProof {
	if os.Getenv("JMS_TEST_TELNET_FIXTURE_URL") == "" {
		return nil
	}
	target := telnetfixture.Load(t, false)
	var a assets.Asset
	require.NoError(t, json.Unmarshal(databaseHARequest(t, address, "POST", "/api/v1/assets", token, org, "", assets.Input{Name: "Telnet HA", Protocol: assets.ProtocolTelnet, Host: target.Host, Port: target.Port, Username: telnetfixture.Username, Password: telnetfixture.Password, Telnet: &target.Settings}, 201), &a))
	client, e := sessionclient.New("http://"+address, token)
	require.NoError(t, e)
	client, e = client.WithOrganization(org)
	require.NoError(t, e)
	ctx, stop := context.WithTimeout(context.Background(), 15*time.Second)
	defer stop()
	session, e := client.CreateSession(ctx, gateway.CreateRequest{AssetID: a.ID, Protocol: assets.ProtocolTelnet, Cols: 80, Rows: 24})
	require.NoError(t, e)
	conn, e := client.DialTerminal(ctx, session)
	require.NoError(t, e)
	t.Cleanup(func() { conn.CloseNow() })
	return &telnetFailoverProof{a.ID, session, conn}
}
func verifyTelnetActiveBeforeFailover(t *testing.T, p *telnetFailoverProof) {
	if p == nil {
		return
	}
	ctx, stop := context.WithTimeout(context.Background(), 5*time.Second)
	defer stop()
	require.NoError(t, p.Connection.Write(ctx, websocket.MessageBinary, []byte("echo __TELNET_HA_ACTIVE__\r")))
	var out strings.Builder
	for !strings.Contains(out.String(), "\r\n__TELNET_HA_ACTIVE__\r\n") {
		_, b, e := p.Connection.Read(ctx)
		require.NoError(t, e)
		out.Write(b)
	}
}
func verifyTelnetFailover(t *testing.T, address, token, org string, p *telnetFailoverProof) {
	if p == nil {
		return
	}
	ctx, stop := context.WithTimeout(context.Background(), 15*time.Second)
	defer stop()
	for {
		_, _, e := p.Connection.Read(ctx)
		if e != nil {
			break
		}
	}
	client, e := sessionclient.New("http://"+address, token)
	require.NoError(t, e)
	client, e = client.WithOrganization(org)
	require.NoError(t, e)
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
			assert.Equal(t, "telnet", r.Protocol)
		}
	}
	assert.True(t, found)
	session, e := client.CreateSession(ctx, gateway.CreateRequest{AssetID: p.Asset, Protocol: assets.ProtocolTelnet, Cols: 80, Rows: 24})
	require.NoError(t, e)
	conn, e = client.DialTerminal(ctx, session)
	require.NoError(t, e)
	defer conn.CloseNow()
	require.NoError(t, conn.Write(ctx, websocket.MessageBinary, []byte("echo __TELNET_HA_RECONNECTED__\r")))
	var out strings.Builder
	for !strings.Contains(out.String(), "\r\n__TELNET_HA_RECONNECTED__\r\n") {
		_, b, e := conn.Read(ctx)
		require.NoError(t, e)
		out.Write(b)
	}
	require.NoError(t, client.CloseSession(ctx, session.SessionID))
	databaseHARequest(t, address, "POST", "/api/v1/assets/"+p.Asset+"/telnet/sessions", token, "", "", map[string]any{"cols": 80, "rows": 24}, 404)
}
