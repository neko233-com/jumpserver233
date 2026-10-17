package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/neko233-com/jumpserver233/server/internal/core/sessionpolicy"
	"github.com/neko233-com/jumpserver233/server/internal/core/sessionshares"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func sharedFixture(t *testing.T, mode string, policy func(AssetInfo) CommandPolicy) (*Broker, CreatedSession, *websocket.Conn, *websocket.Conn, SharedSession, sessionshares.Created, context.Context) {
	t.Helper()
	b, s, owner, base, ctx := monitorFixture(t)
	b.SetSessionPolicy(func() sessionpolicy.Settings { return sessionpolicy.Settings{Sharing: true} })
	c, e := b.CreateShare(ctx, s.SessionID, sessionshares.Actor{ID: "owner", Name: "operator"}, sessionshares.Input{Mode: mode, Minutes: 10, AllowedUsers: []string{"peer"}}, func() error { return nil })
	require.NoError(t, e)
	j, e := b.JoinShare(ctx, c.ID, c.Code, sessionshares.Actor{ID: "peer", Name: "collaborator"}, func(context.Context, AssetInfo) error { return nil }, policy)
	require.NoError(t, e)
	peer, _, e := websocket.Dial(ctx, base+j.WebSocketURL, &websocket.DialOptions{Subprotocols: []string{ShareSubprotocol, TicketSubprotocol(j.Ticket)}})
	require.NoError(t, e)
	t.Cleanup(func() { peer.CloseNow() })
	_, data, e := peer.Read(ctx)
	require.NoError(t, e)
	assert.Contains(t, string(data), "share_state")
	return b, s, owner, peer, j, c, ctx
}
func readShareUntil(t *testing.T, ctx context.Context, c *websocket.Conn, contains string) []byte {
	t.Helper()
	for i := 0; i < 20; i++ {
		_, data, e := c.Read(ctx)
		require.NoError(t, e)
		if strings.Contains(string(data), contains) {
			return data
		}
	}
	t.Fatal("shared output not observed")
	return nil
}
func TestSharedReadOnlyHasNoInputPathAndClosingKeepsPrimary(t *testing.T) {
	b, s, owner, peer, _, created, ctx := sharedFixture(t, sessionshares.ReadOnly, nil)
	require.NoError(t, owner.Write(ctx, websocket.MessageBinary, []byte("visible output")))
	readShareUntil(t, ctx, peer, "visible output")
	require.NoError(t, peer.Write(ctx, websocket.MessageBinary, []byte("must not execute\r")))
	_, _, e := peer.Read(ctx)
	require.Error(t, e)
	require.NoError(t, owner.Write(ctx, websocket.MessageBinary, []byte("owner continues")))
	readShareUntil(t, ctx, owner, "owner continues")
	_, e = b.JoinShare(ctx, created.ID, created.Code, sessionshares.Actor{ID: "stranger", Name: "other"}, func(context.Context, AssetInfo) error { return nil }, nil)
	assert.ErrorIs(t, e, sessionshares.ErrDenied)
	events, _, e := b.ListShareEvents(s.SessionID, "owner", false, 0, 100)
	require.NoError(t, e)
	raw, e := json.Marshal(events)
	require.NoError(t, e)
	assert.NotContains(t, string(raw), created.Code)
	assert.NotContains(t, string(raw), "visible output")
}
func TestSharedWriterControlCommandActorAndKick(t *testing.T) {
	b, s, owner, peer, joined, created, ctx := sharedFixture(t, sessionshares.ReadWrite, nil)
	require.NoError(t, b.ChangeShareControl(ctx, s.SessionID, joined.Member.Actor, joined.Member.ID))
	b.mu.Lock()
	live := b.sessions[s.SessionID]
	b.mu.Unlock()
	live.commands.ObserveOutput([]byte("ops@qa:~$ "))
	require.NoError(t, owner.Write(ctx, websocket.MessageBinary, []byte("must wait")))
	readShareUntil(t, ctx, owner, "share_control_required")
	require.NoError(t, peer.Write(ctx, websocket.MessageBinary, []byte("echo collaboration\r")))
	readShareUntil(t, ctx, peer, "echo collaboration")
	require.Eventually(t, func() bool {
		rows, _, e := b.ListCommands(s.SessionID, 0, 100)
		return e == nil && len(rows) == 1 && rows[0].ActorID == "peer" && rows[0].Actor == "collaborator"
	}, time.Second, time.Millisecond)
	require.NoError(t, b.KickShareMember(joined.Member.ID, sessionshares.Actor{ID: "owner", Name: "operator"}))
	for {
		_, _, e := peer.Read(ctx)
		if e != nil {
			break
		}
	}
	assert.Equal(t, joined.Member.ID, b.shares.Controller(s.SessionID), "owner input must remain paused until explicit reclaim")
	require.NoError(t, b.ChangeShareControl(ctx, s.SessionID, sessionshares.Actor{ID: "owner", Name: "operator"}, ""))
	require.NoError(t, owner.Write(ctx, websocket.MessageBinary, []byte("owner resumes")))
	readShareUntil(t, ctx, owner, "owner resumes")
	require.NoError(t, b.RevokeShare(created.ID, sessionshares.Actor{ID: "owner", Name: "operator"}))
}
func TestSharedPendingReviewRejectsRevokedParticipant(t *testing.T) {
	b, s, owner, peer, j, _, ctx := sharedFixture(t, sessionshares.ReadWrite, func(AssetInfo) CommandPolicy {
		return func(string, bool, time.Time) CommandPolicyDecision {
			return CommandPolicyDecision{RequireReview: true, RuleName: "peer review"}
		}
	})
	require.NoError(t, b.ChangeShareControl(ctx, s.SessionID, j.Member.Actor, j.Member.ID))
	b.mu.Lock()
	live := b.sessions[s.SessionID]
	b.mu.Unlock()
	live.commands.ObserveOutput([]byte("ops@qa:~$ "))
	require.NoError(t, peer.Write(ctx, websocket.MessageBinary, []byte("echo pending\r")))
	readShareUntil(t, ctx, peer, "command_review_pending")
	reviews := b.ListPendingCommandReviews()
	require.Len(t, reviews, 1)
	assert.Equal(t, "peer", reviews[0].ActorID)
	assert.ErrorIs(t, b.ChangeShareControl(ctx, s.SessionID, sessionshares.Actor{ID: "owner", Name: "operator"}, ""), ErrCommandReviewInProgress)
	require.NoError(t, b.KickShareMember(j.Member.ID, sessionshares.Actor{ID: "owner", Name: "operator"}))
	e := b.ResolveCommandReview(reviews[0].ID, "reviewer", true)
	if e != nil {
		assert.True(t, errors.Is(e, ErrCommandReviewNotFound) || errors.Is(e, ErrCommandReviewInProgress))
	}
	readShareUntil(t, ctx, owner, "command_review_denied")
	rows, _, e := b.ListCommands(s.SessionID, 0, 100)
	require.NoError(t, e)
	require.Len(t, rows, 2)
	assert.True(t, rows[0].Outcome == "denied" || rows[1].Outcome == "denied")
	for _, row := range rows {
		assert.NotEqual(t, "approved", row.Outcome)
		assert.Equal(t, "peer", row.ActorID)
	}
}
func TestGlobalSharingDisableDisconnectsPeerWithoutPrimary(t *testing.T) {
	b, s, owner, peer, _, _, ctx := sharedFixture(t, sessionshares.ReadOnly, nil)
	var enabled atomic.Bool
	enabled.Store(true)
	b.SetSessionPolicy(func() sessionpolicy.Settings { return sessionpolicy.Settings{Sharing: enabled.Load()} })
	enabled.Store(false)
	_, _, e := peer.Read(ctx)
	require.Error(t, e)
	require.NoError(t, owner.Write(ctx, websocket.MessageBinary, []byte("primary remains")))
	readShareUntil(t, ctx, owner, "primary remains")
	_, e = b.CreateShare(ctx, s.SessionID, sessionshares.Actor{ID: "owner", Name: "operator"}, sessionshares.Input{Mode: sessionshares.ReadOnly, Minutes: 1, AllowedUsers: []string{"peer"}}, func() error { return nil })
	assert.ErrorIs(t, e, sessionshares.ErrDenied)
}

func TestSharingReplaysBoundedHistoryAndPreservesLegacyTerminalProtocol(t *testing.T) {
	b, s, owner, base, ctx := monitorFixtureWithCapabilities(t, false)
	b.SetSessionPolicy(func() sessionpolicy.Settings { return sessionpolicy.Settings{Sharing: true} })
	require.NoError(t, owner.Write(ctx, websocket.MessageBinary, []byte("existing terminal prompt $ ")))
	readShareUntil(t, ctx, owner, "existing terminal prompt")
	c, e := b.CreateShare(ctx, s.SessionID, sessionshares.Actor{ID: "owner", Name: "owner"}, sessionshares.Input{Mode: sessionshares.ReadWrite, Minutes: 5, AllowedUsers: []string{"peer"}}, func() error { return nil })
	require.NoError(t, e)
	j, e := b.JoinShare(ctx, c.ID, c.Code, sessionshares.Actor{ID: "peer", Name: "peer"}, func(context.Context, AssetInfo) error { return nil }, nil)
	require.NoError(t, e)
	assert.ErrorIs(t, b.ChangeShareControl(ctx, s.SessionID, j.Member.Actor, j.Member.ID), sessionshares.ErrDenied, "a pending ticket cannot take control")
	peer, _, e := websocket.Dial(ctx, base+j.WebSocketURL, &websocket.DialOptions{Subprotocols: []string{ShareSubprotocol, TicketSubprotocol(j.Ticket)}})
	require.NoError(t, e)
	defer peer.CloseNow()
	readShareUntil(t, ctx, peer, "existing terminal prompt")
	require.NoError(t, b.ChangeShareControl(ctx, s.SessionID, j.Member.Actor, j.Member.ID))
	require.NoError(t, peer.Write(ctx, websocket.MessageBinary, []byte("peer output")))
	kind, data, e := owner.Read(ctx)
	require.NoError(t, e)
	assert.Equal(t, websocket.MessageBinary, kind, "v1 clients without the capability must not receive new control frames")
	assert.Equal(t, "peer output", string(data))
	b.mu.Lock()
	live := b.sessions[s.SessionID]
	b.mu.Unlock()
	for i := 0; i < 10; i++ {
		b.publishShareOutput(live, bytes.Repeat([]byte("x"), 16*1024))
	}
	b.mu.Lock()
	assert.Len(t, live.shareHistory, maxShareHistory)
	b.mu.Unlock()
}

func TestSharedReviewDetectsOwnerRuleChangesWithStableParticipantRule(t *testing.T) {
	b, s, owner, peer, j, _, ctx := sharedFixture(t, sessionshares.ReadWrite, func(AssetInfo) CommandPolicy {
		return func(string, bool, time.Time) CommandPolicyDecision {
			return CommandPolicyDecision{RequireReview: true, RuleName: "participant-review"}
		}
	})
	var changed atomic.Bool
	b.mu.Lock()
	live := b.sessions[s.SessionID]
	live.commandPolicy = func(string, bool, time.Time) CommandPolicyDecision {
		name := "owner-review-old"
		if changed.Load() {
			name = "owner-review-new"
		}
		return CommandPolicyDecision{RequireReview: true, RuleName: name}
	}
	b.mu.Unlock()
	require.NoError(t, b.ChangeShareControl(ctx, s.SessionID, j.Member.Actor, j.Member.ID))
	live.commands.ObserveOutput([]byte("ops@qa:~$ "))
	require.NoError(t, peer.Write(ctx, websocket.MessageBinary, []byte("echo pending\r")))
	readShareUntil(t, ctx, peer, "command_review_pending")
	reviews := b.ListPendingCommandReviews()
	require.Len(t, reviews, 1)
	changed.Store(true)
	require.NoError(t, b.ResolveCommandReview(reviews[0].ID, "reviewer", true))
	readShareUntil(t, ctx, owner, "command_review_denied")
}

func TestRevokingSharedWriterUnblocksStalledRemoteInput(t *testing.T) {
	terminal := &stalledTerminal{entered: make(chan struct{}), closed: make(chan struct{})}
	b, s, _, base, ctx := monitorFixtureTerminal(t, true, terminal)
	b.SetSessionPolicy(func() sessionpolicy.Settings { return sessionpolicy.Settings{Sharing: true} })
	owner := sessionshares.Actor{ID: "owner", Name: "operator"}
	c, e := b.CreateShare(ctx, s.SessionID, owner, sessionshares.Input{Mode: sessionshares.ReadWrite, Minutes: 5, AllowedUsers: []string{"peer"}}, func() error { return nil })
	require.NoError(t, e)
	j, e := b.JoinShare(ctx, c.ID, c.Code, sessionshares.Actor{ID: "peer", Name: "peer"}, func(context.Context, AssetInfo) error { return nil }, nil)
	require.NoError(t, e)
	peer, _, e := websocket.Dial(ctx, base+j.WebSocketURL, &websocket.DialOptions{Subprotocols: []string{ShareSubprotocol, TicketSubprotocol(j.Ticket)}})
	require.NoError(t, e)
	defer peer.CloseNow()
	readShareUntil(t, ctx, peer, "share_state")
	require.NoError(t, b.ChangeShareControl(ctx, s.SessionID, j.Member.Actor, j.Member.ID))
	require.NoError(t, peer.Write(ctx, websocket.MessageBinary, []byte("blocked remote input")))
	select {
	case <-terminal.entered:
	case <-ctx.Done():
		t.Fatal("shared input never reached the remote writer")
	}
	require.NoError(t, b.KickShareMember(j.Member.ID, owner))
	select {
	case <-terminal.closed:
	case <-time.After(2 * time.Second):
		t.Fatal("revoked input remained blocked in the remote writer")
	}
	require.Eventually(t, func() bool {
		b.mu.Lock()
		defer b.mu.Unlock()
		return b.sessions[s.SessionID] == nil
	}, time.Second, time.Millisecond)
}

func TestSharedSlowConsumerHasBoundedQueueAndCannotBlockPrimary(t *testing.T) {
	b, s, owner, _, ctx := monitorFixture(t)
	b.mu.Lock()
	live := b.sessions[s.SessionID]
	p := &sharePeer{session: live, used: true, output: make(chan []byte, 32), done: make(chan struct{})}
	live.sharePeers = map[*sharePeer]struct{}{p: {}}
	b.shareTickets[p.hash] = p
	b.mu.Unlock()
	for i := 0; i < 33; i++ {
		b.publishShareOutput(live, []byte("bounded output"))
	}
	select {
	case <-p.done:
	default:
		t.Fatal("slow shared consumer exceeded its bounded queue")
	}
	assert.Len(t, p.output, 32)
	b.mu.Lock()
	assert.Empty(t, live.sharePeers)
	assert.Empty(t, b.shareTickets)
	b.mu.Unlock()
	require.NoError(t, owner.Write(ctx, websocket.MessageBinary, []byte("primary continues")))
	readShareUntil(t, ctx, owner, "primary continues")
}
