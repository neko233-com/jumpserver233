package loginaudit

import (
	"context"
	"errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func openTest(t *testing.T) (*Store, string) {
	t.Helper()
	dir := t.TempDir()
	s, e := Open(dir, make([]byte, 32), nil)
	require.NoError(t, e)
	t.Cleanup(s.Close)
	return s, dir
}
func input() Input {
	return Input{Method: "local", Stage: "session", Outcome: "succeeded", UserID: "synthetic-user", Username: "synthetic.operator", SourceIP: "192.0.2.1", Client: "browser", Reason: "session_issued"}
}
func TestSegmentCommitIndexFailureRecoveryAndEncryptedMetadata(t *testing.T) {
	s, dir := openTest(t)
	r, e := s.Append(input())
	require.NoError(t, e)
	s.saveHook = func(key string, _ []byte) error {
		if key == "index" {
			return errors.New("synthetic index fault")
		}
		return nil
	}
	_, e = s.Append(input())
	require.Error(t, e)
	assert.Equal(t, uint64(1), s.Health().LastSequence)
	s.Close()
	peer, e := Open(dir, make([]byte, 32), nil)
	require.NoError(t, e)
	defer peer.Close()
	p, e := peer.List(Filter{Limit: 100}, nil)
	require.NoError(t, e)
	require.Len(t, p.Results, 1)
	assert.Equal(t, r.ID, p.Results[0].ID)
	_, e = peer.Append(input())
	require.NoError(t, e)
	assert.Equal(t, uint64(2), peer.Health().LastSequence)
	raw, e := os.ReadFile(filepath.Join(dir, "segment-000000000000.json"))
	require.NoError(t, e)
	assert.NotContains(t, string(raw), "synthetic.operator")
	assert.NotContains(t, string(raw), "192.0.2.1")
	_, e = Open(dir, append([]byte{1}, make([]byte, 31)...), nil)
	require.ErrorIs(t, e, ErrInvalid)
}
func TestSuccessNewSourceAndFailedAggregationAreDurable(t *testing.T) {
	s, dir := openTest(t)
	clock := time.Now().UTC()
	s.now = func() time.Time { return clock }
	r, e := s.Append(input())
	require.NoError(t, e)
	assert.Equal(t, "platform_login_succeeded", r.Notification)
	in := input()
	in.SourceIP = "198.51.100.1"
	clock = clock.Add(time.Second)
	r, e = s.Append(in)
	require.NoError(t, e)
	assert.Equal(t, "platform_login_new_source", r.Notification)
	bad := Input{Method: "local", Stage: "primary", Outcome: "failed", Reason: "credentials_rejected", SourceIP: "203.0.113.1", AttemptedName: "unverified"}
	for i := 0; i < 5; i++ {
		clock = clock.Add(time.Second)
		r, e = s.Append(bad)
		require.NoError(t, e)
		if i < 4 {
			assert.Empty(t, r.Notification)
		} else {
			assert.Equal(t, "platform_login_failures", r.Notification)
		}
	}
	s.Close()
	peer, e := Open(dir, make([]byte, 32), nil)
	require.NoError(t, e)
	defer peer.Close()
	peer.now = func() time.Time { return clock }
	r, e = peer.Append(bad)
	require.NoError(t, e)
	assert.Empty(t, r.Notification)
	b, e := peer.NotificationFeed(context.Background(), "", time.Time{}, 100)
	require.NoError(t, e)
	assert.Len(t, b.Events, 3)
	for _, event := range b.Events {
		assert.Empty(t, event.Name)
		assert.NotContains(t, event.Name, "unverified")
	}
}
func TestIdentityVisibilityFiltersAndInvalidInput(t *testing.T) {
	s, _ := openTest(t)
	mine, e := s.Append(input())
	require.NoError(t, e)
	in := input()
	in.UserID = "other-user"
	_, e = s.Append(in)
	require.NoError(t, e)
	p, e := s.List(Filter{Limit: 25}, func(r Record) bool { return r.UserID == mine.UserID })
	require.NoError(t, e)
	assert.Equal(t, 1, p.Total)
	p, e = s.List(Filter{Limit: 25, Outcome: "challenge"}, nil)
	require.NoError(t, e)
	assert.Zero(t, p.Total)
	_, e = s.List(Filter{Limit: 201}, nil)
	assert.ErrorIs(t, e, ErrInvalid)
	for _, bad := range []Input{{}, {Method: "local", Stage: "primary", Outcome: "failed", SourceIP: "https://secret.example"}} {
		_, e = s.Append(bad)
		assert.ErrorIs(t, e, ErrInvalid)
	}
	in = input()
	in.ID = mine.ID
	r, e := s.Append(in)
	require.NoError(t, e)
	assert.Equal(t, mine.ID, r.ID)
	assert.Equal(t, uint64(2), s.Health().LastSequence)
	s.Close()
	_, e = s.Append(input())
	assert.ErrorIs(t, e, ErrClosed)
}
