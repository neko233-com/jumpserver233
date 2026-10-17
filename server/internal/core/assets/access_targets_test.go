package assets

import (
	"context"
	"fmt"
	"github.com/neko233-com/jumpserver233/server/internal/core/nodes"
	"github.com/neko233-com/jumpserver233/server/internal/core/tickets"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"path/filepath"
	"testing"
	"time"
)

func TestAccessTargetBindingTracksConnectionAndPreservesCredentialRotation(t *testing.T) {
	s, store, a, _ := newRotationServiceTest(t)
	ctx := context.Background()
	tree := []nodes.Node{{ID: "node-parent", Name: "Parent", CreatedAt: time.Now(), UpdatedAt: time.Now()}, {ID: "node-child", Name: "Child", ParentID: "node-parent", CreatedAt: time.Now(), UpdatedAt: time.Now()}}
	store.mu.Lock()
	row := store.assets[a.ID]
	row.NodeID = "node-child"
	store.assets[a.ID] = row
	store.mu.Unlock()
	in := []tickets.Target{{Kind: "asset", ID: a.ID, Account: a.Username, Actions: []string{"connect"}}}
	initial, e := s.ResolveAccessTargets(ctx, in, tree)
	require.NoError(t, e)
	require.Len(t, initial, 1)
	assert.Contains(t, initial[0].Nodes, "node-parent")
	store.mu.Lock()
	row = store.assets[a.ID]
	row.CredentialRevision++
	row.PasswordRotatedAt = time.Now()
	row.KeyFingerprint = "changed-credential-fingerprint"
	store.assets[a.ID] = row
	store.mu.Unlock()
	rotated, e := s.ResolveAccessTargets(ctx, in, tree)
	require.NoError(t, e)
	assert.Equal(t, initial[0].Binding, rotated[0].Binding)
	store.mu.Lock()
	row = store.assets[a.ID]
	row.Host = "192.0.2.98"
	store.assets[a.ID] = row
	store.mu.Unlock()
	moved, e := s.ResolveAccessTargets(ctx, in, tree)
	require.NoError(t, e)
	assert.NotEqual(t, initial[0].Binding, moved[0].Binding)
	policy := tickets.Policy{PolicyInput: tickets.PolicyInput{Scopes: []tickets.Scope{{Kind: "node", ID: "node-parent", Accounts: []string{a.Username}, Actions: []string{"connect"}}}}}
	catalog, e := s.AccessCatalog(ctx, policy, tree, "", 0, 25)
	require.NoError(t, e)
	require.Len(t, catalog.Results, 2)
	for _, v := range catalog.Results {
		assert.Contains(t, v.Actions, "view")
		assert.Contains(t, v.Actions, "connect")
	}
	policy.Scopes = append(policy.Scopes, tickets.Scope{Kind: "asset", ID: a.ID, Accounts: []string{a.Username}, Actions: []string{"sftp"}})
	merged, e := s.AccessCatalog(ctx, policy, tree, "", 0, 25)
	require.NoError(t, e)
	for _, v := range merged.Results {
		if v.Kind == "asset" {
			assert.Equal(t, []string{"connect", "sftp", "view"}, v.Actions)
		} else {
			assert.NotContains(t, v.Actions, "sftp")
		}
	}
	empty, e := s.AccessCatalog(ctx, policy, tree, "no-match", 0, 25)
	require.NoError(t, e)
	assert.Zero(t, empty.Total)
	store.mu.Lock()
	row = store.assets[a.ID]
	row.AccountDisabled = true
	store.assets[a.ID] = row
	store.mu.Unlock()
	_, e = s.ResolveAccessTargets(ctx, in, tree)
	assert.ErrorIs(t, e, tickets.ErrNotFound)
	catalog, e = s.AccessCatalog(ctx, policy, tree, "", 0, 25)
	require.NoError(t, e)
	require.Len(t, catalog.Results, 1)
	assert.Equal(t, "node", catalog.Results[0].Kind)
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	_, e = s.ResolveAccessTargets(cancelled, in, tree)
	assert.ErrorIs(t, e, context.Canceled)
}

func BenchmarkAccessCatalogTenThousandAssets(b *testing.B) {
	store, e := OpenStore(filepath.Join(b.TempDir(), "assets.json"), make([]byte, 32))
	if e != nil {
		b.Fatal(e)
	}
	for i := range 10000 {
		id := fmt.Sprintf("asset-%05d", i)
		store.assets[id] = storedAsset{Asset: Asset{ID: id, Name: id, Host: "192.0.2.20", Port: 22, Username: "maintenance", NodeID: "node-root"}}
	}
	s := NewService(store, nil)
	tree := []nodes.Node{{ID: "node-root", Name: "Synthetic node"}}
	p := tickets.Policy{PolicyInput: tickets.PolicyInput{Scopes: []tickets.Scope{{Kind: "node", ID: "node-root", Accounts: []string{"maintenance"}, Actions: []string{"connect"}}}}}
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		page, e := s.AccessCatalog(context.Background(), p, tree, "", 0, 25)
		if e != nil || page.Total != 10001 || len(page.Results) != 25 {
			b.Fatal("invalid bounded catalog")
		}
	}
}
