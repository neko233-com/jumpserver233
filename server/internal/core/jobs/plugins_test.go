package jobs

import (
	"context"
	"encoding/json"
	"github.com/neko233-com/jumpserver233/server/internal/connector/sshclient"
	"github.com/neko233-com/jumpserver233/server/internal/core/hostplugins"
	"github.com/stretchr/testify/require"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestPluginJobsPersistTypedMetadataAndNeverReplayAfterTakeover(t *testing.T) {
	path := filepath.Join(t.TempDir(), "jobs")
	key := make([]byte, 32)
	var calls atomic.Int32
	normal := func(context.Context, string, string) (sshclient.ExecResult, error) {
		t.Error("typed plugin reached shell executor")
		return sshclient.ExecResult{}, nil
	}
	s, e := Open(path, key, nil, normal)
	require.NoError(t, e)
	s.SetExecutionGuard(func(Job) error { return nil })
	s.SetPluginExecutor(func(ctx context.Context, j Job) (sshclient.ExecResult, error) {
		calls.Add(1)
		<-ctx.Done()
		return sshclient.ExecResult{}, ctx.Err()
	})
	op := hostplugins.Operation{Plugin: "banhack233", Version: "0.2.3", Action: "install", Binding: strings.Repeat("a", 64)}
	in := Input{AssetID: "host", Plugin: &op, Command: op.Command(), RequestID: "once"}
	raw, e := json.Marshal(in)
	require.NoError(t, e)
	var encoded map[string]any
	require.NoError(t, json.Unmarshal(raw, &encoded))
	require.NotContains(t, encoded, "plugin")
	j, e := s.Submit(in, "owner", "owner", "host", "ops", "allow", "")
	require.NoError(t, e)
	require.Eventually(t, func() bool { return calls.Load() == 1 }, time.Second, time.Millisecond*5)
	s.Abandon()
	recovered, e := Open(path, key, nil, normal)
	require.NoError(t, e)
	defer recovered.Close()
	old, e := recovered.Get(j.ID)
	require.NoError(t, e)
	require.Equal(t, "interrupted", old.State)
	require.Equal(t, op, *old.Plugin)
	again, e := recovered.Submit(in, "owner", "owner", "host", "ops", "allow", "")
	require.NoError(t, e)
	require.Equal(t, j.ID, again.ID)
	require.Equal(t, "interrupted", again.State)
	require.EqualValues(t, 1, calls.Load())
	invalid := in
	invalid.Command = "id"
	_, e = Validate(invalid)
	require.ErrorIs(t, e, ErrInvalid)
	sameCommand := in
	sameCommand.Plugin = nil
	_, e = recovered.Submit(sameCommand, "owner", "owner", "host", "ops", "allow", "")
	require.ErrorIs(t, e, ErrConflict)
}

func TestProtectionJobOwnsDeepPolicySnapshotsAndBindsRequestDeduplication(t *testing.T) {
	s, e := Open(filepath.Join(t.TempDir(), "jobs"), make([]byte, 32), nil, func(context.Context, string, string) (sshclient.ExecResult, error) {
		return sshclient.ExecResult{}, nil
	})
	require.NoError(t, e)
	defer s.Close()
	p, e := (hostplugins.ProtectionPolicy{Mode: "enforce", IgnoreIPs: []string{"192.0.2.1"}}).Normalize()
	require.NoError(t, e)
	o := hostplugins.Operation{Plugin: "banhack233", Version: "0.2.3", Action: "protection_apply", Binding: strings.Repeat("f", 64), Protection: &p}
	in := Input{AssetID: "host", Plugin: &o, Command: o.Command(), RequestID: "policy-once"}
	j, e := s.Submit(in, "owner", "owner", "host", "root", "review", "")
	require.NoError(t, e)
	p.IgnoreIPs[0] = "198.51.100.1"
	j.Plugin.Protection.IgnoreIPs[0] = "203.0.113.1"
	stored, e := s.Get(j.ID)
	require.NoError(t, e)
	require.Equal(t, "192.0.2.1", stored.Plugin.Protection.IgnoreIPs[0])
	stored.Plugin.Protection.IgnoreIPs[0] = "203.0.113.2"
	again, e := s.Get(j.ID)
	require.NoError(t, e)
	require.Equal(t, "192.0.2.1", again.Plugin.Protection.IgnoreIPs[0])
	in.Command = o.Command()
	_, e = s.Submit(in, "owner", "owner", "host", "root", "review", "")
	require.ErrorIs(t, e, ErrConflict)
}
