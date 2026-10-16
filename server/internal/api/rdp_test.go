package api

import (
	"context"
	"encoding/json"
	"github.com/coder/websocket"
	"github.com/neko233-com/jumpserver233/server/internal/core/accessreviews"
	"github.com/neko233-com/jumpserver233/server/internal/core/assets"
	coreauth "github.com/neko233-com/jumpserver233/server/internal/core/auth"
	"github.com/neko233-com/jumpserver233/server/internal/core/grants"
	"github.com/neko233-com/jumpserver233/server/internal/desktop"
	"github.com/neko233-com/jumpserver233/server/internal/sessionclient"
	"github.com/neko233-com/jumpserver233/server/testsupport/rdpfixture"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"
)

func TestNativeRDPAPIReviewOwnershipAndRevocation(t *testing.T) {
	target := rdpfixture.Load(t)
	root := t.TempDir()
	auth, e := coreauth.OpenService(filepath.Join(root, "users.json"))
	require.NoError(t, e)
	_, e = auth.Bootstrap("admin", bootstrapPassword)
	require.NoError(t, e)
	owner, e := auth.CreateUser("rdp-owner", "synthetic-rdp-owner-pass-233", coreauth.RoleOperator)
	require.NoError(t, e)
	other, e := auth.CreateUser("rdp-other", "synthetic-rdp-other-pass-233", coreauth.RoleOperator)
	require.NoError(t, e)
	login, e := auth.Authenticate(owner.Username, "synthetic-rdp-owner-pass-233")
	require.NoError(t, e)
	foreign, e := auth.Authenticate(other.Username, "synthetic-rdp-other-pass-233")
	require.NoError(t, e)
	inventory := testAssetService(t)
	reviewRequired := true
	a, e := inventory.Create(assets.Input{Name: "Native RDP", Protocol: assets.ProtocolRDP, Host: target.Host, Port: target.Port, Username: rdpfixture.Username, Password: rdpfixture.Password, RDP: &target.Settings, LoginReviewRequired: &reviewRequired})
	require.NoError(t, e)
	g, e := grants.OpenStore(filepath.Join(root, "grants.json"))
	require.NoError(t, e)
	reviews, e := accessreviews.OpenStore(filepath.Join(root, "reviews.json"))
	require.NoError(t, e)
	b, e := desktop.New(root, make([]byte, 32))
	require.NoError(t, e)
	defer b.CloseAll()
	server := httptest.NewServer(NewRouter("test", Dependencies{Assets: inventory, Auth: auth, Grants: g, AccessReviews: reviews, Desktops: b}))
	defer server.Close()
	client, e := sessionclient.New(server.URL, login.AccessToken)
	require.NoError(t, e)
	foreignClient, e := sessionclient.New(server.URL, foreign.AccessToken)
	require.NoError(t, e)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	view, e := g.Create(grants.Input{UserID: owner.ID, AssetID: a.ID, Account: a.Username, Actions: []string{"view"}}, "admin")
	require.NoError(t, e)
	_, e = client.CreateDesktop(ctx, a.ID)
	require.Error(t, e)
	require.NoError(t, g.Delete(view.ID))
	grant, e := g.Create(grants.Input{UserID: owner.ID, AssetID: a.ID, Account: a.Username, Actions: []string{"connect"}}, "admin")
	require.NoError(t, e)
	sshReview, e := reviews.RequestAction(owner.ID, owner.Username, a.ID, a.Name, a.Username, accessreviews.ActionSSH)
	require.NoError(t, e)
	require.NoError(t, reviews.Resolve(sshReview.ID, "admin", true))
	_, e = client.CreateDesktop(ctx, a.ID)
	var pending *sessionclient.AccessReviewPendingError
	require.ErrorAs(t, e, &pending)
	require.NoError(t, reviews.Resolve(pending.ReviewID, "admin", true))
	created, e := client.CreateDesktop(ctx, a.ID)
	require.NoError(t, e)
	conn, e := client.DialDesktop(ctx, created)
	require.NoError(t, e)
	defer conn.CloseNow()
	for {
		kind, data, e := conn.Read(ctx)
		require.NoError(t, e)
		if kind == websocket.MessageBinary {
			assert.Greater(t, len(data), 16)
			break
		}
	}
	var records struct {
		Results []desktop.Record `json:"results"`
	}
	require.NoError(t, foreignClient.DatabaseRequest(ctx, "GET", "/api/v1/desktop-sessions", "", nil, &records))
	assert.Empty(t, records.Results)
	assert.Error(t, foreignClient.DatabaseRequest(ctx, "GET", "/api/v1/desktop-sessions/"+created.ID, "", nil, &desktop.Record{}))
	assert.Error(t, foreignClient.CloseDesktop(ctx, created.ID))
	require.NoError(t, g.Delete(grant.ID))
	for {
		_, _, e = conn.Read(ctx)
		if e != nil {
			break
		}
	}
	require.Eventually(t, func() bool {
		record, e := b.Get(created.ID, owner.ID, false)
		return e == nil && record.Status == "ended"
	}, time.Second, 5*time.Millisecond)
	record, e := b.Get(created.ID, owner.ID, false)
	require.NoError(t, e)
	assert.NotEmpty(t, record.Frames)
	raw, e := json.Marshal(record)
	require.NoError(t, e)
	assert.NotContains(t, string(raw), rdpfixture.Password)
	_, e = b.Frame(created.ID, other.ID, false, 0)
	assert.ErrorIs(t, e, desktop.ErrNotFound)
	approved, e := reviews.ConsumeApprovedAction(owner.ID, a.ID, a.Username, accessreviews.ActionSSH)
	require.NoError(t, e)
	assert.True(t, approved)
}
