package assets

import (
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"path/filepath"
	"testing"
)

func TestOrganizationOverviewInventoryStatsNeverDecryptOrProbeAndExcludeSubaccounts(t *testing.T) {
	store, err := OpenStore(filepath.Join(t.TempDir(), "assets.json"), make([]byte, 32))
	require.NoError(t, err)
	store.mu.Lock()
	store.assets["parent"] = storedAsset{Asset: Asset{ID: "parent", Name: "private hostname", Protocol: "ssh"}}
	store.assets["child"] = storedAsset{Asset: Asset{ID: "child", ParentAssetID: "parent", Protocol: "ssh"}}
	store.assets["db"] = storedAsset{Asset: Asset{ID: "db", Protocol: "postgresql"}}
	store.mu.Unlock()
	s := NewService(store, nil)
	s.status["parent"] = MonitorStatus{State: "online"}
	stats := s.InventoryStats()
	assert.Equal(t, 2, stats.Assets)
	assert.Equal(t, 1, stats.SSHAssets)
	assert.Equal(t, 1, stats.Online)
	assert.Equal(t, 1, stats.Unknown)
	assert.Equal(t, map[string]int{"ssh": 1, "postgresql": 1}, stats.Protocols)
}
