package api

import (
	"encoding/json"
	"github.com/neko233-com/jumpserver233/server/internal/core/assets"
	coreauth "github.com/neko233-com/jumpserver233/server/internal/core/auth"
	"github.com/neko233-com/jumpserver233/server/internal/core/commandfilters"
	"github.com/neko233-com/jumpserver233/server/internal/gateway"
	"github.com/neko233-com/jumpserver233/server/internal/terminalwire"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestDirectoryTerminalAPIUsesCurrentWorkspaceAndRejectsPublicProofInput(t *testing.T) {
	inventory := testAssetService(t)
	root := "/srv/work"
	a, e := inventory.Create(assets.Input{Name: "Scoped host", Host: "127.0.0.1", Port: 1, Username: "ops", Password: "synthetic-only", HostKeyFingerprint: validTestFingerprint(), SSHWorkspace: &root})
	require.NoError(t, e)
	filters, e := commandfilters.OpenStore(filepath.Join(t.TempDir(), "rules.json"))
	require.NoError(t, e)
	_, e = filters.Create(commandfilters.Input{Name: "Directory deny", AssetID: a.ID, Account: "ops", Match: "exact", Pattern: "pwd", Action: "deny", DirectoryMatch: "tree", DirectoryPattern: root + "/private"}, "admin")
	require.NoError(t, e)
	policy := terminalDirectoryPolicy(Dependencies{Assets: inventory, CommandFilters: filters}, coreauth.User{ID: "operator"}, a.ID)
	proof := terminalwire.Proof{Root: root, Directory: root + "/private", RootIdentity: strings.Repeat("a", 64), DirectoryIdentity: strings.Repeat("b", 64)}
	assert.False(t, policy("pwd", true, time.Now(), proof).Allowed)
	assert.True(t, policy("pwd", true, time.Now(), terminalwire.Proof{}).DirectoryRequired)
	proof.Directory = root + "/allowed"
	assert.True(t, policy("pwd", true, time.Now(), proof).Allowed)
	proof.Root = "/srv/other"
	proof.Directory = "/srv/other/private"
	assert.True(t, policy("pwd", true, time.Now(), proof).DirectoryRequired)
	var request gateway.CreateRequest
	r := httptest.NewRequest("POST", "/api/v1/sessions", strings.NewReader(`{"asset_id":"asset","cols":80,"rows":24,"directory_command_policy":{"directory":"/forged"}}`))
	assert.Error(t, decodeRequestJSON(httptest.NewRecorder(), r, &request))
	encoded, e := json.Marshal(gateway.CreateRequest{AssetID: a.ID, DirectoryCommandPolicy: policy})
	require.NoError(t, e)
	assert.NotContains(t, string(encoded), "directory_command_policy")
	assert.Nil(t, terminalDirectoryPolicy(Dependencies{}, coreauth.User{}, a.ID))
}
