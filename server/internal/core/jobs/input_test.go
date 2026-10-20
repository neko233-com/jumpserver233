package jobs

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/neko233-com/jumpserver233/server/internal/connector/sshclient"
	"github.com/neko233-com/jumpserver233/server/internal/core/playbooks"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func privateInput() Input {
	return Input{AssetID: "host", Command: "cat", Stdin: []byte("synthetic private stdin"), TimeoutSeconds: 60, RequestID: "private-stdin", PlaybookStep: &playbooks.Execution{RunID: "run-" + strings.Repeat("1", 32), StepID: "step-" + strings.Repeat("2", 32), ProgramID: strings.Repeat("3", 64)}}
}

func TestTypedStdinIsEphemeralAuditsOnlyKeyedDigestAndDeduplicates(t *testing.T) {
	in := privateInput()
	var executions, gates atomic.Int32
	s, err := Open(filepath.Join(t.TempDir(), "jobs.json"), make([]byte, 32), nil, func(ctx context.Context, _, command string) (sshclient.ExecResult, error) {
		executions.Add(1)
		assert.Equal(t, "cat", command)
		assert.Equal(t, in.Stdin, sshclient.ExecInput(ctx))
		return sshclient.ExecResult{ExitCode: 0}, nil
	})
	require.NoError(t, err)
	defer s.Close()
	s.SetExecutionGuard(func(Job) error { return nil })
	gate := func() error { gates.Add(1); return nil }
	j, err := s.SubmitWithGate(in, "owner", "Owner", "Host", "ops", "review", "", gate)
	require.NoError(t, err)
	_, err = s.SubmitWithGate(in, "owner", "Owner", "Host", "ops", "review", "", gate)
	require.NoError(t, err)
	assert.EqualValues(t, 1, gates.Load())
	changed := in
	changed.Stdin = []byte("changed private stdin")
	_, err = s.SubmitWithGate(changed, "owner", "Owner", "Host", "ops", "review", "", gate)
	assert.ErrorIs(t, err, ErrConflict)
	assert.EqualValues(t, 1, gates.Load())
	raw, err := os.ReadFile(s.path)
	require.NoError(t, err)
	var box envelope
	require.NoError(t, json.Unmarshal(raw, &box))
	plain, err := s.aead.Open(nil, box.Nonce, box.Ciphertext, []byte("jms233/ssh-jobs/v7"))
	require.NoError(t, err)
	for _, value := range []string{string(in.Stdin), base64.StdEncoding.EncodeToString(in.Stdin)} {
		assert.NotContains(t, string(plain), value)
	}
	public, err := json.Marshal(j)
	require.NoError(t, err)
	assert.NotContains(t, string(public), string(in.Stdin))
	assert.Len(t, j.InputDigest, 64)
	_, err = s.Review(j.ID, "Reviewer", true)
	require.NoError(t, err)
	waitJob(t, s, j.ID, "succeeded")
	assert.EqualValues(t, 1, executions.Load())
}

func TestRestartCannotExecuteAPendingReviewWhosePrivateInputWasNotPersisted(t *testing.T) {
	file := filepath.Join(t.TempDir(), "jobs.json")
	s, err := Open(file, make([]byte, 32), nil, historyExecutor)
	require.NoError(t, err)
	in := privateInput()
	j, err := s.Submit(in, "owner", "Owner", "Host", "ops", "review", "")
	require.NoError(t, err)
	s.Close()
	peer, err := Open(file, make([]byte, 32), nil, historyExecutor)
	require.NoError(t, err)
	defer peer.Close()
	loaded, err := peer.Get(j.ID)
	require.NoError(t, err)
	assert.Equal(t, "interrupted", loaded.State)
	_, err = peer.Review(j.ID, "Reviewer", true)
	assert.ErrorIs(t, err, ErrConflict)
	_, found, err := peer.FindRequest("owner", in)
	require.NoError(t, err)
	assert.True(t, found)
	in.PlaybookStep = nil
	_, err = Validate(in)
	assert.ErrorIs(t, err, ErrInvalid, "public ordinary commands cannot supply opaque stdin")
}
