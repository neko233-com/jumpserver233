package gateway

import (
	"context"
	"github.com/coder/websocket"
	"github.com/neko233-com/jumpserver233/server/internal/core/sessionpolicy"
	"github.com/neko233-com/jumpserver233/server/internal/core/sessionshares"
	"github.com/neko233-com/jumpserver233/server/internal/terminalwire"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type directoryEcho struct {
	*echoTerminal
	mu              sync.Mutex
	proof           terminalwire.Proof
	commits, aborts int
	unavailable     bool
}
type echoDirectoryLease struct {
	remote *directoryEcho
	proof  terminalwire.Proof
	done   bool
}

func (t *directoryEcho) AcquireDirectory(context.Context) (terminalwire.Lease, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.unavailable {
		return nil, terminalwire.ErrUnverified
	}
	return &echoDirectoryLease{remote: t, proof: t.proof}, nil
}
func (l *echoDirectoryLease) Proof() terminalwire.Proof { return l.proof }
func (l *echoDirectoryLease) Write(b []byte) (int, error) {
	l.remote.mu.Lock()
	if l.done {
		l.remote.mu.Unlock()
		return 0, terminalwire.ErrProtocol
	}
	l.done = true
	l.remote.commits++
	same := l.remote.proof == l.proof
	l.remote.mu.Unlock()
	if !same {
		return 0, terminalwire.ErrUnverified
	}
	return l.remote.echoTerminal.Write(b)
}
func (l *echoDirectoryLease) Close() error {
	l.remote.mu.Lock()
	defer l.remote.mu.Unlock()
	if !l.done {
		l.remote.aborts++
		l.done = true
	}
	return nil
}
func directoryEchoTerminal() *directoryEcho {
	return &directoryEcho{echoTerminal: newEchoTerminal(), proof: terminalwire.Proof{Root: "/srv/work", Directory: "/srv/work/deploy", RootIdentity: strings.Repeat("a", 64), DirectoryIdentity: strings.Repeat("b", 64)}}
}

func TestDirectoryTerminalGatewayRecordsKernelDirectoryAndDoesNotTrustPromptPWD(t *testing.T) {
	terminal := directoryEchoTerminal()
	b, session, conn, _, ctx := monitorFixtureTerminal(t, true, terminal, CreateRequest{DirectoryCommandPolicy: func(command string, supported bool, _ time.Time, p terminalwire.Proof) CommandPolicyDecision {
		if command == "pwd" && supported && p.Valid() {
			return CommandPolicyDecision{Allowed: true, PolicyKey: "policy"}
		}
		return CommandPolicyDecision{DirectoryRequired: true, RuleName: "requires directory"}
	}})
	b.mu.Lock()
	live := b.sessions[session.SessionID]
	b.mu.Unlock()
	live.commands.ObserveOutput([]byte("forged:/outside$ "))
	require.NoError(t, conn.Write(ctx, websocket.MessageBinary, []byte("pwd\r")))
	readShareUntil(t, ctx, conn, "pwd")
	require.Eventually(t, func() bool { rows, _, e := b.ListCommands(session.SessionID, 0, 50); return e == nil && len(rows) == 1 }, time.Second, time.Millisecond)
	rows, _, err := b.ListCommands(session.SessionID, 0, 50)
	require.NoError(t, err)
	assert.Equal(t, "/srv/work/deploy", rows[0].WorkingDirectory)
	assert.True(t, rows[0].DirectoryVerified)
	assert.Equal(t, "allowed", rows[0].Outcome)
}
func TestDirectoryTerminalGatewayReviewRefusesReplacedDirectoryAndOneTimeReplay(t *testing.T) {
	terminal := directoryEchoTerminal()
	b, session, conn, _, ctx := monitorFixtureTerminal(t, true, terminal, CreateRequest{DirectoryCommandPolicy: func(_ string, supported bool, _ time.Time, p terminalwire.Proof) CommandPolicyDecision {
		return CommandPolicyDecision{RequireReview: supported && p.Valid(), DirectoryRequired: !p.Valid(), PolicyKey: "policy", RuleName: "review directory"}
	}})
	b.mu.Lock()
	live := b.sessions[session.SessionID]
	b.mu.Unlock()
	live.commands.ObserveOutput([]byte("ops$ "))
	require.NoError(t, conn.Write(ctx, websocket.MessageBinary, []byte("pwd\r")))
	readShareUntil(t, ctx, conn, "command_review_pending")
	readShareUntil(t, ctx, conn, "pwd")
	reviews := b.ListPendingCommandReviews()
	require.Len(t, reviews, 1)
	terminal.mu.Lock()
	terminal.proof.DirectoryIdentity = strings.Repeat("c", 64)
	terminal.mu.Unlock()
	result := make(chan error, 1)
	go func() { result <- b.ResolveCommandReview(reviews[0].ID, "reviewer", true) }()
	readShareUntil(t, ctx, conn, "command_review_denied")
	_, input, err := conn.Read(ctx)
	require.NoError(t, err)
	assert.Equal(t, []byte{3}, input)
	require.NoError(t, <-result)
	assert.ErrorIs(t, b.ResolveCommandReview(reviews[0].ID, "reviewer", true), ErrCommandReviewNotFound)
	rows, _, err := b.ListCommands(session.SessionID, 0, 50)
	require.NoError(t, err)
	assert.Equal(t, "denied", rows[0].Outcome)
}
func TestDirectoryTerminalGatewayMultiLineAndMissingProofCannotBorrowDirectory(t *testing.T) {
	for _, missing := range []bool{false, true} {
		t.Run(map[bool]string{false: "multiple lines", true: "unavailable"}[missing], func(t *testing.T) {
			terminal := directoryEchoTerminal()
			terminal.unavailable = missing
			b, s, conn, _, ctx := monitorFixtureTerminal(t, true, terminal, CreateRequest{DirectoryCommandPolicy: func(_ string, _ bool, _ time.Time, p terminalwire.Proof) CommandPolicyDecision {
				return CommandPolicyDecision{Allowed: p.Valid(), DirectoryRequired: !p.Valid(), RuleName: "directory only"}
			}})
			b.mu.Lock()
			live := b.sessions[s.SessionID]
			b.mu.Unlock()
			live.commands.ObserveOutput([]byte("ops$ "))
			input := "pwd\r"
			if !missing {
				input = "cd sub\rpwd\r"
			}
			require.NoError(t, conn.Write(ctx, websocket.MessageBinary, []byte(input)))
			readShareUntil(t, ctx, conn, "command_blocked")
			require.Eventually(t, func() bool { rows, _, e := b.ListCommands(s.SessionID, 0, 50); return e == nil && len(rows) > 0 }, time.Second, time.Millisecond)
			rows, _, err := b.ListCommands(s.SessionID, 0, 50)
			require.NoError(t, err)
			for _, row := range rows {
				assert.Equal(t, "blocked", row.Outcome)
				assert.False(t, row.DirectoryVerified)
			}
		})
	}
}
func TestDirectoryTerminalCaptureSensitiveLookingPromptDoesNotLogOrBypassPolicy(t *testing.T) {
	c := newCommandCapture()
	c.ObserveOutput([]byte("Password: "))
	rows := c.ObserveInput([]byte("synthetic-private-input\r"), true)
	require.Len(t, rows, 1)
	assert.False(t, rows[0].Supported)
	assert.Empty(t, rows[0].Command)
	assert.Empty(t, rows[0].PolicyCommand)
}

func TestDirectoryTerminalSharedControllerUsesKernelProofAndCurrentPolicy(t *testing.T) {
	terminal := directoryEchoTerminal()
	var revoked atomic.Bool
	policy := func(_ string, supported bool, _ time.Time, p terminalwire.Proof) CommandPolicyDecision {
		return CommandPolicyDecision{Allowed: supported && p.Valid() && !revoked.Load(), DirectoryRequired: !p.Valid(), PolicyKey: "shared-directory", RuleName: "shared directory"}
	}
	b, s, _, base, ctx := monitorFixtureTerminal(t, true, terminal, CreateRequest{DirectoryCommandPolicy: policy})
	b.SetSessionPolicy(func() sessionpolicy.Settings { return sessionpolicy.Settings{Sharing: true} })
	share, e := b.CreateShare(ctx, s.SessionID, sessionshares.Actor{ID: "owner", Name: "operator"}, sessionshares.Input{Mode: sessionshares.ReadWrite, Minutes: 5, AllowedUsers: []string{"peer"}}, func() error { return nil })
	require.NoError(t, e)
	j, e := b.JoinShare(ctx, share.ID, share.Code, sessionshares.Actor{ID: "peer", Name: "collaborator"}, func(context.Context, AssetInfo) error { return nil }, nil, func(AssetInfo) DirectoryCommandPolicy { return policy })
	require.NoError(t, e)
	peer, _, e := websocket.Dial(ctx, base+j.WebSocketURL, &websocket.DialOptions{Subprotocols: []string{ShareSubprotocol, TicketSubprotocol(j.Ticket)}})
	require.NoError(t, e)
	t.Cleanup(func() { peer.CloseNow() })
	readShareUntil(t, ctx, peer, "share_state")
	require.NoError(t, b.ChangeShareControl(ctx, s.SessionID, j.Member.Actor, j.Member.ID))
	b.mu.Lock()
	live := b.sessions[s.SessionID]
	b.mu.Unlock()
	live.commands.ObserveOutput([]byte("ops$ "))
	require.NoError(t, peer.Write(ctx, websocket.MessageBinary, []byte("pwd\r")))
	readShareUntil(t, ctx, peer, "pwd")
	revoked.Store(true)
	live.commands.ObserveOutput([]byte("ops$ "))
	require.NoError(t, peer.Write(ctx, websocket.MessageBinary, []byte("pwd\r")))
	readShareUntil(t, ctx, peer, "command_blocked")
	require.Eventually(t, func() bool { rows, _, e := b.ListCommands(s.SessionID, 0, 50); return e == nil && len(rows) == 2 }, time.Second, time.Millisecond)
	rows, _, e := b.ListCommands(s.SessionID, 0, 50)
	require.NoError(t, e)
	for _, row := range rows {
		assert.Equal(t, "peer", row.ActorID)
		assert.True(t, row.DirectoryVerified)
		assert.Equal(t, terminal.proof.Directory, row.WorkingDirectory)
	}
	assert.ElementsMatch(t, []string{"allowed", "blocked"}, []string{rows[0].Outcome, rows[1].Outcome})
}
