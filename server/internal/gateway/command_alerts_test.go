package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/neko233-com/jumpserver233/server/internal/core/commandalerts"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCommandAlertsPublishSanitizedMetadataAfterAuditAndPropagateFailure(t *testing.T) {
	dir := t.TempDir()
	key := make([]byte, 32)
	s, e := commandalerts.Open(filepath.Join(dir, "alerts"), key, nil)
	require.NoError(t, e)
	defer s.Close()
	b := NewBroker(dir, key, nil)
	session := &activeSession{id: "synthetic-session-1", operatorID: "owner", operator: "Owner", asset: AssetInfo{ID: "asset", Name: "Synthetic\nhost", Username: "ops"}}
	b.SetCommandAlerts(s.Publish)
	for _, outcome := range []string{"allowed", "blocked", "pending", "approved", "denied", "timed_out", "cancelled"} {
		in := commandSubmission{Command: "echo synthetic-private-command", SubmittedAt: time.Now().UTC(), Outcome: outcome, ActorID: "sharer", Actor: "Synthetic\nsharer", RuleName: "Synthetic policy"}
		if outcome != "blocked" && outcome != "allowed" {
			in.ReviewID = "_synthetic-review-1"
		}
		require.NoError(t, b.appendCommand(session.id, in, session))
	}
	batch, e := s.NotificationFeed(context.Background(), "", time.Time{}, 100)
	require.NoError(t, e)
	require.Len(t, batch.Events, 6)
	for _, event := range batch.Events {
		record, e := s.Get(event.ResourceID)
		require.NoError(t, e)
		assert.Equal(t, "sharer", record.ActorID)
		assert.Equal(t, "owner", record.OwnerID)
		assert.Equal(t, "Synthetic host", record.AssetName)
		raw, _ := json.Marshal(record)
		assert.NotContains(t, string(raw), "synthetic-private-command")
	}
	b.SetCommandAlerts(func(commandalerts.Record) error { return errors.New("synthetic metadata failure") })
	require.ErrorContains(t, b.appendCommand(session.id, commandSubmission{Command: "echo fail", Outcome: "denied", SubmittedAt: time.Now().UTC()}, session), "synthetic metadata failure")
	require.NoError(t, b.appendCommand(session.id, commandSubmission{Command: "echo allowed", Outcome: "allowed", SubmittedAt: time.Now().UTC()}, session))
	records, total, e := b.readCommands(session.id, 0, 100)
	require.NoError(t, e)
	assert.Equal(t, 9, total)
	require.Len(t, records, 9)
	assert.Equal(t, "command_denied", commandAlertState(commandSubmission{Outcome: "denied"}))
	assert.Equal(t, "command_denied", commandAlertState(commandSubmission{Outcome: "blocked", Supported: true, Command: "synthetic"}))
}
func TestCommandAlertFailureStopsPreparedInputBeforeAnyForwarding(t *testing.T) {
	for _, review := range []bool{false, true} {
		t.Run(map[bool]string{false: "policy deny", true: "review"}[review], func(t *testing.T) {
			b := NewBroker(t.TempDir(), make([]byte, 32), nil)
			s := &activeSession{id: "synthetic-session-1", operatorID: "owner", operator: "Owner", asset: AssetInfo{ID: "asset", Name: "host", Username: "ops"}, commands: newCommandCapture(), commandPolicy: func(string, bool, time.Time) CommandPolicyDecision {
				return CommandPolicyDecision{RequireReview: review, RuleName: "Synthetic"}
			}}
			b.sessions[s.id] = s
			s.commands.ObserveOutput([]byte("ops@qa:~$ "))
			b.SetCommandAlerts(func(commandalerts.Record) error { return errors.New("synthetic durable alert failure") })
			forwarded, e := b.prepareTerminalInput(context.Background(), nil, s, []byte("echo synthetic-private-command\r"))
			require.ErrorContains(t, e, "synthetic durable alert failure")
			assert.Empty(t, forwarded)
			assert.Nil(t, s.pendingReview)
		})
	}
}
func TestCommandReviewSnapshotCanonicalIDAndLiveVisibility(t *testing.T) {
	b := NewBroker(t.TempDir(), make([]byte, 32), nil)
	now := time.Now().UTC()
	pending := &pendingCommandReview{request: CommandReview{ID: "_review", AssetName: "host", Command: "private command", ActorID: "sharer", RequestedAt: now, ExpiresAt: now.Add(time.Minute)}}
	s := &activeSession{id: "session", operatorID: "owner", pendingReview: pending}
	b.sessions[s.id] = s
	batch, e := b.NotificationFeed(context.Background(), "", time.Time{}, 1)
	require.NoError(t, e)
	require.Len(t, batch.Events, 1)
	event := batch.Events[0]
	assert.Equal(t, "command-review-_review", event.ResourceID)
	assert.Equal(t, "sharer", event.OwnerID)
	assert.True(t, b.NotificationPending(event.ResourceID))
	raw, _ := json.Marshal(event)
	assert.NotContains(t, string(raw), "private command")
	pending.resolving = true
	assert.False(t, b.NotificationPending(event.ResourceID))
	batch, e = b.NotificationFeed(context.Background(), event.ID, time.Time{}, 1)
	require.NoError(t, e)
	assert.Empty(t, batch.Events)
	assert.False(t, batch.Gap)
	assert.Empty(t, batch.Cursor)
	pending.resolving = false
	pending.request.ExpiresAt = now.Add(-time.Second)
	assert.False(t, b.NotificationPending(event.ResourceID))
}
