package api

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"path/filepath"
	"sync"
	"testing"

	"github.com/neko233-com/jumpserver233/server/internal/connector/replaystore"
	"github.com/neko233-com/jumpserver233/server/internal/core/rbac"
	"github.com/neko233-com/jumpserver233/server/internal/core/replayarchive"
	"github.com/neko233-com/jumpserver233/server/internal/gateway"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type replayAPIObjects struct {
	mu   sync.Mutex
	data map[string][]byte
	gets int
}

func (m *replayAPIObjects) Put(ctx context.Context, key string, r io.Reader, size int64, digest string) error {
	data, e := io.ReadAll(r)
	if e != nil {
		return e
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.data[key]; ok {
		return replaystore.ErrExists
	}
	m.data[key] = data
	return nil
}
func (m *replayAPIObjects) Get(ctx context.Context, key string) (io.ReadCloser, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.gets++
	data, ok := m.data[key]
	if !ok {
		return nil, replaystore.ErrNotFound
	}
	return io.NopCloser(bytes.NewReader(bytes.Clone(data))), nil
}
func (m *replayAPIObjects) Close() error { return nil }
func replayAPIEnv(t *testing.T) (*policyTestEnv, *replayAPIObjects, string) {
	t.Helper()
	e := newPolicyEnv(t)
	root := t.TempDir()
	key := make([]byte, 32)
	source, err := replayarchive.NewRecordings(root, key)
	require.NoError(t, err)
	objects := &replayAPIObjects{data: map[string][]byte{}}
	e.d.ReplayArchive, err = replayarchive.Open(filepath.Join(root, "replay-archive.json"), key, nil, source, func(context.Context, replayarchive.Config) (replaystore.Objects, error) { return objects, nil })
	require.NoError(t, err)
	e.d.Sessions = gateway.NewBroker(root, key, func(context.Context, string, int, int) (gateway.AssetInfo, gateway.Terminal, error) {
		return gateway.AssetInfo{ID: e.asset.ID, Name: e.asset.Name, Username: e.asset.Username}, sessionTestTerminal{}, nil
	})
	e.d.Sessions.SetReplayArchive(e.d.ReplayArchive)
	t.Cleanup(func() { e.d.Sessions.CloseAll(); e.d.ReplayArchive.Close() })
	e.router = NewRouter("test", e.d)
	return e, objects, root
}
func TestReplayStorageAPISettingsReceiptsVisibilityRemoteReplayAndEviction(t *testing.T) {
	e, objects, root := replayAPIEnv(t)
	base := "/api/v1/settings/replay-storage"
	ip := "127.0.0.1:12345"
	in := replayarchive.Input{Config: replayarchive.Config{Provider: "s3", Enabled: true, Cloud: &replaystore.CloudConfig{Provider: "s3", Endpoint: "https://replay-api.example.com", Region: "us-east-1", Bucket: "replays", AccessKeyID: "synthetic-api-key", SecretAccessKey: "synthetic-api-secret"}}, RequestID: "api-storage-config-001"}
	assert.Equal(t, 403, e.send(t, "PUT", base, in, e.token, ip).Code)
	response := e.send(t, "PUT", base, in, e.adminToken, ip)
	require.Equal(t, 200, response.Code, response.Body.String())
	assert.NotContains(t, response.Body.String(), "synthetic-api-secret")
	same := e.send(t, "PUT", base, in, e.adminToken, ip)
	assert.JSONEq(t, response.Body.String(), same.Body.String())
	wrong := in
	wrong.RequestID = "api-storage-stale-001"
	assert.Equal(t, 409, e.send(t, "PUT", base, wrong, e.adminToken, ip).Code)
	role, err := e.d.RBAC.SaveRole("", rbac.RoleInput{Name: "Storage operator", Permissions: []string{"replay_storage.view", "replay_storage.archive", "replay_storage.verify", "replay_storage.evict", "replay_storage.audit"}}, e.admin.ID, e.admin.Username)
	require.NoError(t, err)
	_, err = e.d.RBAC.SaveBinding(rbac.BindingInput{SubjectType: "user", SubjectID: e.operator.ID, RoleIDs: []string{role.ID}}, e.admin.ID, e.admin.Username)
	require.NoError(t, err)
	view := e.send(t, "GET", base, nil, e.token, ip)
	require.Equal(t, 200, view.Code)
	assert.NotContains(t, view.Body.String(), "replay-api.example.com")
	assert.NotContains(t, view.Body.String(), "synthetic-api-key")
	create := func(owner string) gateway.CreatedSession {
		session, err := e.d.Sessions.Create(context.Background(), gateway.CreateRequest{AssetID: e.asset.ID, OperatorID: owner, Operator: "operator", Cols: 80, Rows: 24})
		require.NoError(t, err)
		return session
	}
	own, foreign, active := create(e.operator.ID), create(e.admin.ID), create(e.operator.ID)
	require.NoError(t, e.d.Sessions.Close(own.SessionID))
	require.NoError(t, e.d.Sessions.Close(foreign.SessionID))
	path := base + "/records/terminal/" + own.SessionID
	request := map[string]string{"request_id": "api-history-archive-001"}
	queued := e.send(t, "POST", path+"/archive", request, e.token, ip)
	require.Equal(t, 200, queued.Code, queued.Body.String())
	replayed := e.send(t, "POST", path+"/archive", request, e.token, ip)
	assert.JSONEq(t, queued.Body.String(), replayed.Body.String())
	assert.Equal(t, 404, e.send(t, "POST", base+"/records/terminal/"+active.SessionID+"/archive", request, e.token, ip).Code)
	assert.Equal(t, 404, e.send(t, "GET", base+"/records/terminal/"+foreign.SessionID, nil, e.token, ip).Code)
	for range 3 {
		worked, err := e.d.ReplayArchive.ProcessNext(context.Background())
		require.NoError(t, err)
		if !worked {
			break
		}
	}
	list := e.send(t, "GET", base+"/records?limit=1", nil, e.token, ip)
	require.Equal(t, 200, list.Code, list.Body.String())
	var page struct {
		Results []replayarchive.Record `json:"results"`
		Total   int                    `json:"total"`
	}
	require.NoError(t, json.Unmarshal(list.Body.Bytes(), &page))
	require.Len(t, page.Results, 1)
	assert.Equal(t, 1, page.Total)
	assert.Equal(t, own.SessionID, page.Results[0].SessionID)
	assert.NotContains(t, list.Body.String(), "object_key")
	verifyInput := map[string]string{"request_id": "api-storage-verify-001"}
	verified := e.send(t, "POST", path+"/verify", verifyInput, e.token, ip)
	require.Equal(t, 200, verified.Code, verified.Body.String())
	gets := objects.gets
	verifiedAgain := e.send(t, "POST", path+"/verify", verifyInput, e.token, ip)
	assert.JSONEq(t, verified.Body.String(), verifiedAgain.Body.String())
	assert.Equal(t, gets, objects.gets)
	evictInput := map[string]string{"request_id": "api-storage-evict-001"}
	evicted := e.send(t, "POST", path+"/evict", evictInput, e.token, ip)
	require.Equal(t, 200, evicted.Code, evicted.Body.String())
	assert.NoFileExists(t, filepath.Join(root, "sessions", own.SessionID+".json.gz.enc"))
	assert.FileExists(t, filepath.Join(root, "sessions", "index.jsonl"))
	again := e.send(t, "POST", path+"/evict", evictInput, e.token, ip)
	assert.JSONEq(t, evicted.Body.String(), again.Body.String())
	replay := e.send(t, "GET", "/api/v1/sessions/"+own.SessionID+"/replay", nil, e.token, ip)
	assert.Equal(t, 200, replay.Code, replay.Body.String())
	assert.Equal(t, "application/gzip", replay.Header().Get("Content-Type"))
	gets = objects.gets
	assert.Equal(t, 404, e.send(t, "GET", "/api/v1/sessions/"+foreign.SessionID+"/replay", nil, e.token, ip).Code)
	assert.Equal(t, gets, objects.gets)
	audit := e.send(t, "GET", base+"/audit", nil, e.token, ip)
	require.Equal(t, 200, audit.Code)
	assert.NotContains(t, audit.Body.String(), foreign.SessionID)
	assert.Contains(t, audit.Body.String(), "evict")
	assert.Equal(t, 400, e.send(t, "GET", base+"/records?offset=-1", nil, e.token, ip).Code)
	assert.Equal(t, 400, e.send(t, "POST", path+"/verify", map[string]any{"request_id": "api-invalid-001", "raw_url": "forged"}, e.token, ip).Code)
	assert.Zero(t, e.opens.Load())
	assert.Zero(t, e.execs.Load())
	assert.Contains(t, rbac.OrganizationCatalog(), "replay_storage.manage")
}
func TestReplayStorageAPISFTPRequiresIndependentAssetAuthorityAndServerBinding(t *testing.T) {
	e, _, _ := replayAPIEnv(t)
	base := "/api/v1/settings/replay-storage"
	ip := "127.0.0.1:12345"
	in := replayarchive.Input{Config: replayarchive.Config{Provider: "sftp", Enabled: true, SFTPAssetID: e.asset.ID, SFTPDirectory: "archives", SFTPTarget: "forged-client-target"}, RequestID: "api-sftp-storage-001"}
	role, err := e.d.RBAC.SaveRole("", rbac.RoleInput{Name: "Configure storage only", Permissions: []string{"replay_storage.manage", "replay_storage.view"}}, e.admin.ID, e.admin.Username)
	require.NoError(t, err)
	_, err = e.d.RBAC.SaveBinding(rbac.BindingInput{SubjectType: "user", SubjectID: e.operator.ID, RoleIDs: []string{role.ID}}, e.admin.ID, e.admin.Username)
	require.NoError(t, err)
	assert.Equal(t, 403, e.send(t, "PUT", base, in, e.token, ip).Code)
	response := e.send(t, "PUT", base, in, e.adminToken, ip)
	require.Equal(t, 200, response.Code, response.Body.String())
	var config replayarchive.Config
	require.NoError(t, json.Unmarshal(response.Body.Bytes(), &config))
	assert.Len(t, config.SFTPTarget, 64)
	assert.NotEqual(t, in.SFTPTarget, config.SFTPTarget)
	assert.Equal(t, 400, e.send(t, "PUT", base, map[string]any{"provider": "postgres", "enabled": true, "revision": config.Revision, "request_id": "api-unavailable-db-001"}, e.adminToken, ip).Code)
	assert.Zero(t, e.opens.Load())
	assert.Zero(t, e.execs.Load())
}
