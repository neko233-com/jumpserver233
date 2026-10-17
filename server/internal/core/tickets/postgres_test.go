package tickets

import (
	"context"
	"errors"
	"fmt"
	"github.com/neko233-com/jumpserver233/server/internal/core/grants"
	"github.com/neko233-com/jumpserver233/server/internal/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestTicketPostgresTakeoverRecoversOneGrantBatchAndIsolatesOrganizations(t *testing.T) {
	dsn := os.Getenv("JMS_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("requires PostgreSQL state fixture")
	}
	docs, e := storage.OpenPostgres(context.Background(), dsn, fmt.Sprintf("tickets-%d", time.Now().UnixNano()))
	require.NoError(t, e)
	a, e := docs.Scoped("organization-a")
	require.NoError(t, e)
	b, e := docs.Scoped("organization-b")
	require.NoError(t, e)
	t.Cleanup(func() {
		_ = a.Delete("access-tickets")
		_ = a.Delete("grants")
		_ = b.Delete("access-tickets")
		_ = docs.Close()
	})
	_, f, _ := setup(t)
	native, e := grants.OpenStoreWithDocuments(filepath.Join(t.TempDir(), "grants.json"), a)
	require.NoError(t, e)
	f.grantStore = native
	path := filepath.Join(t.TempDir(), "tickets.json")
	s, e := Open(path, make([]byte, 32), a)
	require.NoError(t, e)
	s.SetRunner(f.runner())
	native.SetTicketGuard(s.GrantGuard)
	p := publish(t, s, 1)
	v := apply(t, s, p, "pg-takeover")
	writes := 0
	s.saveHook = func([]byte) error {
		writes++
		if writes >= 2 {
			return errors.New("synthetic final approval write failure")
		}
		return nil
	}
	v, e = s.Decide(context.Background(), "reviewer-a", v.ID, Decision{Revision: v.Revision, RequestID: "pg-approved", Action: "approve"})
	require.NoError(t, e)
	assert.Equal(t, "issuing", v.State)
	require.Len(t, native.List(), 1)
	assert.False(t, native.Allows("requester", "asset-a", "managed", "connect", time.Now()))
	id := native.List()[0].ID
	s.Close()
	raw, e := a.Load("access-tickets")
	require.NoError(t, e)
	assert.NotContains(t, string(raw), "Synthetic temporary access")
	native, e = grants.OpenStoreWithDocuments(filepath.Join(t.TempDir(), "grants-peer.json"), a)
	require.NoError(t, e)
	f.grantStore = native
	peer, e := Open(path, make([]byte, 32), a)
	require.NoError(t, e)
	defer peer.Close()
	peer.SetRunner(f.runner())
	native.SetTicketGuard(peer.GrantGuard)
	peer.Tick()
	v, e = peer.Get(context.Background(), "requester", v.ID)
	require.NoError(t, e)
	assert.Equal(t, "approved", v.State)
	require.Len(t, native.List(), 1)
	assert.Equal(t, id, native.List()[0].ID)
	assert.True(t, native.Allows("requester", "asset-a", "managed", "connect", time.Now()))
	other, e := Open(path, make([]byte, 32), b)
	require.NoError(t, e)
	defer other.Close()
	other.SetRunner(f.runner())
	_, e = other.Get(context.Background(), "requester", v.ID)
	assert.ErrorIs(t, e, ErrNotFound)
	v, e = peer.Cancel(context.Background(), "requester", v.ID, v.Revision)
	require.NoError(t, e)
	assert.Equal(t, "revoked", v.State)
	assert.Empty(t, native.List())
}
