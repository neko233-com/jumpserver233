package jobs

import (
	"context"
	"encoding/json"
	"github.com/neko233-com/jumpserver233/server/internal/connector/sshclient"
	"github.com/neko233-com/jumpserver233/server/internal/core/playbooks"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestNativeStepMetadataControlsMultilineAndRequiresExecutionGuard(t *testing.T) {
	meta := &playbooks.Execution{RunID: "run-" + strings.Repeat("a", 32), StepID: "step-" + strings.Repeat("b", 32), ProgramID: strings.Repeat("c", 64)}
	in := Input{AssetID: "asset", Command: "set -e\nprintf '\tready'", TimeoutSeconds: 5, RequestID: "step-one", PlaybookStep: meta}
	_, e := Validate(in)
	require.NoError(t, e)
	plain := in
	plain.PlaybookStep = nil
	_, e = Validate(plain)
	assert.ErrorIs(t, e, ErrInvalid)
	for _, bad := range []string{"\x00", "\r", "\x1b"} {
		badInput := in
		badInput.Command = "id" + bad + "argument"
		_, e = Validate(badInput)
		assert.ErrorIs(t, e, ErrInvalid)
	}
	var public Input
	require.NoError(t, json.Unmarshal([]byte(`{"asset_id":"asset","command":"id","playbook_step":{"run_id":"forged"}}`), &public))
	assert.Nil(t, public.PlaybookStep)
	public.Command, public.WorkingDirectory = in.Command, "/srv/work/deploy"
	_, e = Validate(public)
	assert.ErrorIs(t, e, ErrInvalid, "public JSON cannot grant multiline workflow authority")
	withDirectory := in
	withDirectory.WorkingDirectory = "/srv/work/deploy"
	_, e = Validate(withDirectory)
	require.NoError(t, e, "trusted workflow steps can select an execution directory")
	var calls atomic.Int32
	s, e := Open(filepath.Join(t.TempDir(), "jobs.json"), make([]byte, 32), nil, func(context.Context, string, string) (sshclient.ExecResult, error) {
		calls.Add(1)
		return sshclient.ExecResult{ExitCode: 0}, nil
	})
	require.NoError(t, e)
	defer s.Close()
	j, e := s.Submit(in, "owner", "owner", "asset", "qa", "allow", "")
	require.NoError(t, e)
	require.Eventually(t, func() bool { j, _ = s.Get(j.ID); return j.State != "running" }, time.Second, time.Millisecond)
	assert.Zero(t, calls.Load())
	assert.Equal(t, "failed", j.State)
	s.SetExecutionGuard(func(Job) error { return nil })
	in.RequestID = "step-two"
	j, e = s.Submit(in, "owner", "owner", "asset", "qa", "allow", "")
	require.NoError(t, e)
	require.Eventually(t, func() bool { j, _ = s.Get(j.ID); return j.State == "succeeded" }, time.Second, time.Millisecond)
	assert.Equal(t, int32(1), calls.Load())
	j.PlaybookStep.StepID = "mutated"
	found, e := s.Get(j.ID)
	require.NoError(t, e)
	assert.Equal(t, meta.StepID, found.PlaybookStep.StepID)
	replay, ok, e := s.FindRequest("owner", in)
	require.NoError(t, e)
	assert.True(t, ok)
	assert.Equal(t, j.ID, replay.ID)
	restored, e := Open(s.path, make([]byte, 32), nil, s.exec)
	require.NoError(t, e)
	defer restored.Close()
	saved, e := restored.Get(j.ID)
	require.NoError(t, e)
	assert.Equal(t, meta, saved.PlaybookStep)
}
