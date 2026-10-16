package main

import (
	"bytes"
	"context"
	"encoding/json"
	"github.com/coder/websocket"
	"github.com/neko233-com/jumpserver233/server/internal/core/assets"
	"github.com/neko233-com/jumpserver233/server/internal/desktop"
	"github.com/neko233-com/jumpserver233/server/internal/sessionclient"
	"github.com/neko233-com/jumpserver233/server/testsupport/rdpfixture"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"image/png"
	"io"
	"net/http"
	"os"
	"testing"
	"time"
)

type rdpFailoverProof struct {
	Asset      string
	Old        desktop.Created
	Connection *websocket.Conn
}

func prepareRDPFailover(t *testing.T, address, token, org string) *rdpFailoverProof {
	if os.Getenv("JMS_TEST_RDP_FIXTURE_URL") == "" {
		return nil
	}
	target := rdpfixture.Load(t)
	var a assets.Asset
	require.NoError(t, json.Unmarshal(databaseHARequest(t, address, "POST", "/api/v1/assets", token, org, "", assets.Input{Name: "RDP HA", Protocol: assets.ProtocolRDP, Host: target.Host, Port: target.Port, Username: rdpfixture.Username, Password: rdpfixture.Password, RDP: &target.Settings}, 201), &a))
	c, e := sessionclient.New("http://"+address, token)
	require.NoError(t, e)
	c, e = c.WithOrganization(org)
	require.NoError(t, e)
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	created, e := c.CreateDesktop(ctx, a.ID)
	require.NoError(t, e)
	conn, e := c.DialDesktop(ctx, created)
	require.NoError(t, e)
	t.Cleanup(func() { conn.CloseNow() })
	return &rdpFailoverProof{a.ID, created, conn}
}
func verifyRDPActiveBeforeFailover(t *testing.T, p *rdpFailoverProof) {
	if p == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	for {
		kind, data, e := p.Connection.Read(ctx)
		require.NoError(t, e)
		if kind != websocket.MessageBinary || len(data) < 16 {
			continue
		}
		im, e := png.Decode(bytes.NewReader(data[8:]))
		require.NoError(t, e)
		r, g, b, _ := im.At(60, 430).RGBA()
		if r > 45000 && g < 35000 && b < 35000 {
			return
		}
	}
}
func verifyRDPFailover(t *testing.T, address, token, org string, p *rdpFailoverProof) {
	if p == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	for {
		_, _, e := p.Connection.Read(ctx)
		if e != nil {
			break
		}
	}
	c, e := sessionclient.New("http://"+address, token)
	require.NoError(t, e)
	c, e = c.WithOrganization(org)
	require.NoError(t, e)
	conn, e := c.DialDesktop(ctx, p.Old)
	assert.Error(t, e)
	if conn != nil {
		conn.CloseNow()
	}
	var record desktop.Record
	require.NoError(t, json.Unmarshal(databaseHARequest(t, address, "GET", "/api/v1/desktop-sessions/"+p.Old.ID, token, org, "", nil, 200), &record))
	assert.NotEqual(t, "active", record.Status)
	require.NotEmpty(t, record.Frames)
	req, e := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+address+"/api/v1/desktop-sessions/"+p.Old.ID+"/frames/0", nil)
	require.NoError(t, e)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("X-JMS-ORG", org)
	response, e := http.DefaultClient.Do(req)
	require.NoError(t, e)
	require.Equal(t, 200, response.StatusCode)
	raw, e := io.ReadAll(io.LimitReader(response.Body, 40<<20))
	response.Body.Close()
	require.NoError(t, e)
	_, e = png.Decode(bytes.NewReader(raw))
	require.NoError(t, e)
	created, e := c.CreateDesktop(ctx, p.Asset)
	require.NoError(t, e)
	conn, e = c.DialDesktop(ctx, created)
	require.NoError(t, e)
	defer conn.CloseNow()
	verifyRDPActiveBeforeFailover(t, &rdpFailoverProof{Connection: conn})
	require.NoError(t, c.CloseDesktop(ctx, created.ID))
	databaseHARequest(t, address, "POST", "/api/v1/assets/"+p.Asset+"/rdp/sessions", token, "", "", nil, 404)
	databaseHARequest(t, address, "GET", "/api/v1/desktop-sessions/"+p.Old.ID, token, "", "", nil, 404)
}
