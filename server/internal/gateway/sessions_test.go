package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/neko233-com/jumpserver233/server/internal/recorder"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type echoTerminal struct {
	reader  *io.PipeReader
	writer  *io.PipeWriter
	closed  sync.Once
	resized chan [2]int
}

func TestTerminalCloseReason(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want string
	}{
		{name: "nil", want: "disconnected"},
		{name: "ssh eof", err: io.EOF, want: "disconnected"},
		{name: "normal websocket close", err: websocket.CloseError{Code: websocket.StatusNormalClosure}, want: "disconnected"},
		{name: "going away websocket close", err: websocket.CloseError{Code: websocket.StatusGoingAway}, want: "disconnected"},
		{name: "unexpected error", err: errors.New("synthetic read failure"), want: "terminal_io_error"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := terminalCloseReason(test.err); got != test.want {
				t.Fatalf("terminalCloseReason(%v) = %q, want %q", test.err, got, test.want)
			}
		})
	}
}

func TestCloseAllJoinsAnAlreadyClosingSessionUntilAuditCompletes(t *testing.T) {
	terminal := newEchoTerminal()
	broker := NewBroker(t.TempDir(), []byte("0123456789abcdef0123456789abcdef"), func(context.Context, string, int, int) (AssetInfo, Terminal, error) {
		return AssetInfo{ID: "qa", Name: "qa", Username: "ops"}, terminal, nil
	})
	t.Cleanup(broker.CloseAll)
	created, err := broker.Create(context.Background(), CreateRequest{AssetID: "qa", Cols: 80, Rows: 24})
	require.NoError(t, err)
	broker.auditMu.Lock()
	closed := make(chan struct{})
	go func() { _ = broker.Close(created.SessionID); close(closed) }()
	func() {
		defer broker.auditMu.Unlock()
		require.Eventually(t, func() bool {
			broker.mu.Lock()
			defer broker.mu.Unlock()
			session := broker.sessions[created.SessionID]
			return session != nil && session.closing
		}, 5*time.Second, time.Millisecond)
		joined := make(chan struct{})
		go func() { broker.CloseAll(); close(joined) }()
		select {
		case <-joined:
			t.Error("CloseAll returned before the final audit could be written")
		default:
		}
	}()
	select {
	case <-closed:
	case <-time.After(5 * time.Second):
		t.Fatal("session close did not complete")
	}
	broker.CloseAll()
	broker.mu.Lock()
	assert.Empty(t, broker.sessions)
	broker.mu.Unlock()
}

func newEchoTerminal() *echoTerminal {
	reader, writer := io.Pipe()
	return &echoTerminal{reader: reader, writer: writer, resized: make(chan [2]int, 4)}
}

func (t *echoTerminal) Read(p []byte) (int, error)  { return t.reader.Read(p) }
func (t *echoTerminal) Write(p []byte) (int, error) { return t.writer.Write(p) }
func (t *echoTerminal) Resize(cols, rows int) error {
	t.resized <- [2]int{cols, rows}
	return nil
}
func (t *echoTerminal) Close() error {
	var result error
	t.closed.Do(func() {
		result = errors.Join(t.writer.Close(), t.reader.Close())
	})
	return result
}

func TestBrokerServesAuditedSSHWebSocketAndConsumesTicketOnce(t *testing.T) {
	dataDir := t.TempDir()
	vaultKey := []byte("0123456789abcdef0123456789abcdef")
	var terminal *echoTerminal
	broker := NewBroker(dataDir, vaultKey, func(_ context.Context, assetID string, _, _ int) (AssetInfo, Terminal, error) {
		if assetID != "asset-01" {
			return AssetInfo{}, nil, errors.New("unexpected asset")
		}
		terminal = newEchoTerminal()
		return AssetInfo{ID: assetID, Name: "test-host", Username: "ops"}, terminal, nil
	})
	t.Cleanup(broker.CloseAll)
	mux := http.NewServeMux()
	mux.HandleFunc("GET /ws/api/v1/sessions/{sessionID}/terminal", broker.ServeTerminal)
	server := httptest.NewServer(mux)
	defer server.Close()

	session, err := broker.Create(context.Background(), CreateRequest{AssetID: "asset-01", Cols: 90, Rows: 28})
	if err != nil {
		t.Fatalf("create session: %v", err)
	}
	endpoint := "ws" + strings.TrimPrefix(server.URL, "http") + session.WebSocketURL
	protocols := []string{TerminalSubprotocol, TicketSubprotocol(session.Ticket)}
	conn, response, err := websocket.Dial(context.Background(), endpoint, &websocket.DialOptions{Subprotocols: protocols})
	if err != nil {
		if response != nil {
			_ = response.Body.Close()
		}
		t.Fatalf("connect terminal websocket: %v", err)
	}
	defer conn.CloseNow()
	if got := conn.Subprotocol(); got != TerminalSubprotocol {
		t.Fatalf("negotiated subprotocol = %q", got)
	}
	promptWritten := make(chan error, 1)
	go func() {
		_, writeErr := terminal.writer.Write([]byte("ops@test-host:~$ "))
		promptWritten <- writeErr
	}()
	promptCtx, promptCancel := context.WithTimeout(context.Background(), 2*time.Second)
	_, prompt, promptErr := conn.Read(promptCtx)
	promptCancel()
	if promptErr != nil || string(prompt) != "ops@test-host:~$ " {
		t.Fatalf("read synthetic shell prompt = %q, %v", prompt, promptErr)
	}
	if err := <-promptWritten; err != nil {
		t.Fatalf("write synthetic shell prompt: %v", err)
	}

	if err := conn.Write(context.Background(), websocket.MessageText, []byte(`{"type":"resize","cols":100,"rows":32}`)); err != nil {
		t.Fatalf("send resize: %v", err)
	}
	select {
	case got := <-terminal.resized:
		if got != [2]int{100, 32} {
			t.Fatalf("resized to %v, want [100 32]", got)
		}
	case <-time.After(time.Second):
		t.Fatal("SSH PTY did not receive resize")
	}
	if err := conn.Write(context.Background(), websocket.MessageBinary, []byte("echo me\r")); err != nil {
		t.Fatalf("send terminal input: %v", err)
	}
	readCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	type frame struct {
		typ  websocket.MessageType
		data []byte
		err  error
	}
	frames := make(chan frame, 1)
	go func() {
		typ, data, readErr := conn.Read(readCtx)
		frames <- frame{typ: typ, data: data, err: readErr}
	}()
	select {
	case result := <-frames:
		if result.err != nil {
			t.Fatalf("read terminal output: %v", result.err)
		}
		if result.typ != websocket.MessageBinary || string(result.data) != "echo me\r" {
			t.Fatalf("terminal output = (%v, %q)", result.typ, result.data)
		}
	case <-readCtx.Done():
		t.Fatal("timed out waiting for terminal output")
	}

	second, rejectedResponse, secondErr := websocket.Dial(context.Background(), endpoint, &websocket.DialOptions{Subprotocols: protocols})
	if secondErr == nil {
		_ = second.CloseNow()
		t.Fatal("a consumed terminal ticket opened a second websocket")
	}
	if rejectedResponse != nil {
		_ = rejectedResponse.Body.Close()
		if rejectedResponse.StatusCode != http.StatusUnauthorized {
			t.Fatalf("second websocket status = %d, want 401", rejectedResponse.StatusCode)
		}
	}

	_ = conn.Close(websocket.StatusNormalClosure, "done")
	deadline := time.Now().Add(2 * time.Second)
	active := true
	for time.Now().Before(deadline) {
		broker.mu.Lock()
		_, active = broker.sessions[session.SessionID]
		broker.mu.Unlock()
		if !active {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	broker.mu.Lock()
	_, active = broker.sessions[session.SessionID]
	broker.mu.Unlock()
	if active {
		t.Fatal("session stayed active after websocket close")
	}
	if _, err := os.Stat(filepath.Join(dataDir, "sessions", session.SessionID+".json.gz.enc")); err != nil {
		t.Fatalf("encrypted recording was not saved: %v", err)
	}
	auditPath := filepath.Join(dataDir, "sessions", "index.jsonl")
	var audit []byte
	for time.Now().Before(deadline) {
		audit, err = os.ReadFile(auditPath)
		if err == nil && strings.Count(string(audit), "\n") >= 2 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err != nil {
		t.Fatal(err)
	}
	var events []map[string]any
	for _, line := range strings.Split(strings.TrimSpace(string(audit)), "\n") {
		var event map[string]any
		if err := json.Unmarshal([]byte(line), &event); err != nil {
			t.Fatalf("decode audit line: %v", err)
		}
		events = append(events, event)
	}
	if len(events) != 2 || events[0]["event"] != "started" || events[1]["event"] != "ended" {
		t.Fatalf("session audit = %#v", events)
	}
	commands, commandTotal, err := broker.ListCommands(session.SessionID, 0, 10)
	if err != nil || commandTotal != 1 || len(commands) != 1 || commands[0].Command != "echo me" {
		t.Fatalf("command audit = %#v, total=%d, err=%v", commands, commandTotal, err)
	}
	commandIndex, err := os.ReadFile(filepath.Join(dataDir, "sessions", "commands.jsonl"))
	if err != nil {
		t.Fatalf("read encrypted command index: %v", err)
	}
	if strings.Contains(string(commandIndex), "echo me") {
		t.Fatalf("command audit index contains plaintext: %s", commandIndex)
	}
	replay, err := recorder.OpenReplay(filepath.Join(dataDir, "sessions", session.SessionID+".json.gz.enc"), session.SessionID, vaultKey)
	if err != nil {
		t.Fatalf("open session replay: %v", err)
	}
	replayData, err := io.ReadAll(replay)
	closeErr := replay.Close()
	if err != nil || closeErr != nil {
		t.Fatalf("read replay: read=%v close=%v", err, closeErr)
	}
	if !strings.Contains(string(replayData), `"i","echo me\r"`) || !strings.Contains(string(replayData), `"o","echo me\r"`) {
		t.Fatalf("replay does not contain terminal input and output: %s", replayData)
	}
}

func TestBrokerBlocksCommandBeforeForwardingAndAuditsDecision(t *testing.T) {
	dataDir := t.TempDir()
	vaultKey := []byte("0123456789abcdef0123456789abcdef")
	terminal := newEchoTerminal()
	broker := NewBroker(dataDir, vaultKey, func(_ context.Context, assetID string, _, _ int) (AssetInfo, Terminal, error) {
		return AssetInfo{ID: assetID, Name: "test-host", Username: "ops"}, terminal, nil
	})
	t.Cleanup(broker.CloseAll)
	mux := http.NewServeMux()
	mux.HandleFunc("GET /ws/api/v1/sessions/{sessionID}/terminal", broker.ServeTerminal)
	server := httptest.NewServer(mux)
	defer server.Close()
	policy := func(command string, supported bool, _ time.Time) CommandPolicyDecision {
		if !supported {
			return CommandPolicyDecision{Allowed: false, RuleName: "unknown input"}
		}
		if strings.Contains(command, "blocked") {
			return CommandPolicyDecision{Allowed: false, RuleName: "deny blocked word"}
		}
		return CommandPolicyDecision{Allowed: true}
	}
	session, err := broker.Create(context.Background(), CreateRequest{AssetID: "asset-01", Cols: 80, Rows: 24, CommandPolicy: policy})
	if err != nil {
		t.Fatalf("create session: %v", err)
	}
	endpoint := "ws" + strings.TrimPrefix(server.URL, "http") + session.WebSocketURL
	conn, response, err := websocket.Dial(context.Background(), endpoint, &websocket.DialOptions{Subprotocols: []string{TerminalSubprotocol, TicketSubprotocol(session.Ticket)}})
	if err != nil {
		if response != nil {
			_ = response.Body.Close()
		}
		t.Fatalf("connect terminal websocket: %v", err)
	}
	defer conn.CloseNow()
	readFrame := func() (websocket.MessageType, []byte) {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		typ, data, readErr := conn.Read(ctx)
		if readErr != nil {
			t.Fatalf("read terminal frame: %v", readErr)
		}
		return typ, data
	}
	promptCount := 0
	writePrompt := func() {
		t.Helper()
		prompt := "ops@test-host:~$ "
		if promptCount > 0 {
			prompt = "\r\n" + prompt
		}
		promptCount++
		written := make(chan error, 1)
		go func() {
			_, writeErr := terminal.writer.Write([]byte(prompt))
			written <- writeErr
		}()
		if typ, data := readFrame(); typ != websocket.MessageBinary || string(data) != prompt {
			t.Fatalf("shell prompt frame = (%v, %q)", typ, data)
		}
		if writeErr := <-written; writeErr != nil {
			t.Fatalf("write shell prompt: %v", writeErr)
		}
	}
	writePrompt()
	if err := conn.Write(context.Background(), websocket.MessageBinary, []byte("echo blocked\r")); err != nil {
		t.Fatalf("send blocked command: %v", err)
	}
	typ, notice := readFrame()
	if typ != websocket.MessageText || !strings.Contains(string(notice), `"type":"command_blocked"`) || !strings.Contains(string(notice), "deny blocked word") {
		t.Fatalf("blocked command notice = (%v, %q)", typ, notice)
	}
	typ, forwarded := readFrame()
	if typ != websocket.MessageBinary || string(forwarded) != "echo blocked\x03\r" {
		t.Fatalf("blocked input forwarded to PTY = (%v, %q)", typ, forwarded)
	}

	writePrompt()
	if err := conn.Write(context.Background(), websocket.MessageBinary, []byte("echo allowed\r")); err != nil {
		t.Fatalf("send allowed command: %v", err)
	}
	typ, forwarded = readFrame()
	if typ != websocket.MessageBinary || string(forwarded) != "echo allowed\r" {
		t.Fatalf("allowed input forwarded to PTY = (%v, %q)", typ, forwarded)
	}
	_ = conn.Close(websocket.StatusNormalClosure, "done")
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		broker.mu.Lock()
		_, active := broker.sessions[session.SessionID]
		broker.mu.Unlock()
		if !active {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	commands, total, err := broker.ListCommands(session.SessionID, 0, 10)
	if err != nil || total != 2 || len(commands) != 2 {
		t.Fatalf("command audit = %#v, total=%d, err=%v", commands, total, err)
	}
	seenBlocked, seenAllowed := false, false
	for _, command := range commands {
		if command.Command == "echo blocked" && command.Outcome == "blocked" && command.RuleName == "deny blocked word" {
			seenBlocked = true
		}
		if command.Command == "echo allowed" && command.Outcome == "allowed" {
			seenAllowed = true
		}
	}
	if !seenBlocked || !seenAllowed {
		t.Fatalf("command audit omitted allow/deny outcomes: %#v", commands)
	}
}

func TestBrokerHoldsReviewedCommandUntilApprovalAndAuditsResolution(t *testing.T) {
	dataDir := t.TempDir()
	vaultKey := []byte("0123456789abcdef0123456789abcdef")
	terminal := newEchoTerminal()
	broker := NewBroker(dataDir, vaultKey, func(_ context.Context, assetID string, _, _ int) (AssetInfo, Terminal, error) {
		return AssetInfo{ID: assetID, Name: "review-host", Username: "ops"}, terminal, nil
	})
	t.Cleanup(broker.CloseAll)
	mux := http.NewServeMux()
	mux.HandleFunc("GET /ws/api/v1/sessions/{sessionID}/terminal", broker.ServeTerminal)
	server := httptest.NewServer(mux)
	defer server.Close()
	policy := func(command string, supported bool, _ time.Time) CommandPolicyDecision {
		if supported && strings.Contains(command, "reviewed") {
			return CommandPolicyDecision{RequireReview: true, RuleName: "review deployment"}
		}
		return CommandPolicyDecision{Allowed: true}
	}
	session, err := broker.Create(context.Background(), CreateRequest{AssetID: "asset-review", Cols: 80, Rows: 24, OperatorID: "operator-1", Operator: "alice", CommandPolicy: policy})
	if err != nil {
		t.Fatalf("create session: %v", err)
	}
	endpoint := "ws" + strings.TrimPrefix(server.URL, "http") + session.WebSocketURL
	conn, response, err := websocket.Dial(context.Background(), endpoint, &websocket.DialOptions{Subprotocols: []string{TerminalSubprotocol, TicketSubprotocol(session.Ticket)}})
	if err != nil {
		if response != nil {
			_ = response.Body.Close()
		}
		t.Fatalf("connect terminal websocket: %v", err)
	}
	defer conn.CloseNow()
	readFrame := func() (websocket.MessageType, []byte) {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		typ, data, readErr := conn.Read(ctx)
		if readErr != nil {
			t.Fatalf("read terminal frame: %v", readErr)
		}
		return typ, data
	}
	writeOutput := func(data string) {
		t.Helper()
		written := make(chan error, 1)
		go func() {
			_, writeErr := terminal.writer.Write([]byte(data))
			written <- writeErr
		}()
		if typ, got := readFrame(); typ != websocket.MessageBinary || string(got) != data {
			t.Fatalf("terminal output = (%v, %q), want %q", typ, got, data)
		}
		if writeErr := <-written; writeErr != nil {
			t.Fatalf("write terminal output: %v", writeErr)
		}
	}
	writeOutput("ops@review-host:~$ ")
	if err := conn.Write(context.Background(), websocket.MessageBinary, []byte("echo reviewed deployment\r")); err != nil {
		t.Fatalf("send reviewed command: %v", err)
	}
	typ, notice := readFrame()
	if typ != websocket.MessageText || !strings.Contains(string(notice), `"type":"command_review_pending"`) {
		t.Fatalf("pending command notice = (%v, %q)", typ, notice)
	}
	if typ, output := readFrame(); typ != websocket.MessageBinary || string(output) != "echo reviewed deployment" {
		t.Fatalf("unapproved command text output = (%v, %q)", typ, output)
	}
	reviews := broker.ListPendingCommandReviews()
	if len(reviews) != 1 || reviews[0].Command != "echo reviewed deployment" || reviews[0].Operator != "alice" {
		t.Fatalf("pending reviews = %#v", reviews)
	}
	restartedBroker := NewBroker(dataDir, vaultKey, nil)
	restartedCommands, restartedTotal, err := restartedBroker.ListCommands(session.SessionID, 0, 10)
	if err != nil || restartedTotal != 1 || len(restartedCommands) != 1 || restartedCommands[0].Outcome != "cancelled" {
		t.Fatalf("orphaned review after restart = %#v, total=%d, err=%v", restartedCommands, restartedTotal, err)
	}
	if err := conn.Write(context.Background(), websocket.MessageBinary, []byte("echo reviewed again\r")); err != nil {
		t.Fatalf("send input while waiting for review: %v", err)
	}
	time.Sleep(75 * time.Millisecond)
	if err := broker.ResolveCommandReview(reviews[0].ID, "reviewer-1", true); err != nil {
		t.Fatalf("approve command review: %v", err)
	}
	typ, notice = readFrame()
	if typ != websocket.MessageText || !strings.Contains(string(notice), `"type":"command_review_approved"`) {
		t.Fatalf("approval notice = (%v, %q)", typ, notice)
	}
	if typ, forwarded := readFrame(); typ != websocket.MessageBinary || string(forwarded) != "\r" {
		t.Fatalf("approved Enter forwarded to PTY = (%v, %q)", typ, forwarded)
	}
	if got := broker.ListPendingCommandReviews(); len(got) != 0 {
		t.Fatalf("pending reviews after approval = %#v", got)
	}

	writeOutput("\r\nops@review-host:~$ ")
	if err := conn.Write(context.Background(), websocket.MessageBinary, []byte("echo reviewed denial\r")); err != nil {
		t.Fatalf("send command for denial: %v", err)
	}
	typ, notice = readFrame()
	if typ != websocket.MessageText || !strings.Contains(string(notice), `"type":"command_review_pending"`) {
		t.Fatalf("denial pending notice = (%v, %q)", typ, notice)
	}
	if typ, output := readFrame(); typ != websocket.MessageBinary || string(output) != "echo reviewed denial" {
		t.Fatalf("denied command text output = (%v, %q)", typ, output)
	}
	reviews = broker.ListPendingCommandReviews()
	if len(reviews) != 1 {
		t.Fatalf("pending reviews before denial = %#v", reviews)
	}
	if err := broker.ResolveCommandReview(reviews[0].ID, "reviewer-1", false); err != nil {
		t.Fatalf("deny command review: %v", err)
	}
	typ, notice = readFrame()
	if typ != websocket.MessageText || !strings.Contains(string(notice), `"type":"command_review_denied"`) {
		t.Fatalf("denial notice = (%v, %q)", typ, notice)
	}
	if typ, forwarded := readFrame(); typ != websocket.MessageBinary || string(forwarded) != "\x03" {
		t.Fatalf("denied command clear input = (%v, %q)", typ, forwarded)
	}
	writeOutput("\r\nops@review-host:~$ ")
	if err := conn.Write(context.Background(), websocket.MessageBinary, []byte("echo reviewed timeout\r")); err != nil {
		t.Fatalf("send command for timeout: %v", err)
	}
	typ, notice = readFrame()
	if typ != websocket.MessageText || !strings.Contains(string(notice), `"type":"command_review_pending"`) {
		t.Fatalf("timeout pending notice = (%v, %q)", typ, notice)
	}
	if typ, output := readFrame(); typ != websocket.MessageBinary || string(output) != "echo reviewed timeout" {
		t.Fatalf("timed-out command text output = (%v, %q)", typ, output)
	}
	broker.mu.Lock()
	timeoutReview := broker.sessions[session.SessionID].pendingReview
	timeoutReview.request.ExpiresAt = time.Now().UTC().Add(-time.Second)
	timeoutReviewID := timeoutReview.request.ID
	broker.mu.Unlock()
	if err := broker.ResolveCommandReview(timeoutReviewID, "reviewer-1", false); !errors.Is(err, ErrCommandReviewExpired) {
		t.Fatalf("resolve expired command review = %v, want ErrCommandReviewExpired", err)
	}
	typ, notice = readFrame()
	if typ != websocket.MessageText || !strings.Contains(string(notice), `"type":"command_review_timed_out"`) {
		t.Fatalf("timeout notice = (%v, %q)", typ, notice)
	}
	if typ, forwarded := readFrame(); typ != websocket.MessageBinary || string(forwarded) != "\x03" {
		t.Fatalf("timed-out command clear input = (%v, %q)", typ, forwarded)
	}
	commands, total, err := broker.ListCommands(session.SessionID, 0, 10)
	if err != nil || total != 6 || len(commands) != 6 {
		t.Fatalf("command review audit = %#v, total=%d, err=%v", commands, total, err)
	}
	seenPending, seenApproved, seenDenied, seenTimedOut := false, false, false, false
	for _, command := range commands {
		if command.ReviewID == "" {
			continue
		}
		if command.Command == "echo reviewed deployment" && command.Outcome == "pending" {
			seenPending = true
		}
		if command.Command == "echo reviewed deployment" && command.Outcome == "approved" && command.ReviewedBy == "reviewer-1" {
			seenApproved = true
		}
		if command.Command == "echo reviewed denial" && command.Outcome == "denied" && command.ReviewedBy == "reviewer-1" {
			seenDenied = true
		}
		if command.Command == "echo reviewed timeout" && command.Outcome == "timed_out" && command.ReviewedBy == "system" {
			seenTimedOut = true
		}
	}
	if !seenPending || !seenApproved || !seenDenied || !seenTimedOut {
		t.Fatalf("command review outcomes missing: %#v", commands)
	}
}

func TestBrokerRejectsInvalidSessionDimensions(t *testing.T) {
	broker := NewBroker(t.TempDir(), []byte("0123456789abcdef0123456789abcdef"), func(context.Context, string, int, int) (AssetInfo, Terminal, error) {
		t.Fatal("open called for invalid request")
		return AssetInfo{}, nil, nil
	})
	if _, err := broker.Create(context.Background(), CreateRequest{AssetID: "asset-01", Cols: 1, Rows: 24}); !errors.Is(err, ErrInvalidSessionRequest) {
		t.Fatalf("Create() error = %v, want invalid request", err)
	}
}

func TestSessionAuditListsCompletedInterruptedAndReplayableSessions(t *testing.T) {
	dataDir := t.TempDir()
	vaultKey := []byte("0123456789abcdef0123456789abcdef")
	open := func(_ context.Context, assetID string, _, _ int) (AssetInfo, Terminal, error) {
		return AssetInfo{ID: assetID, Name: "test-host", Username: "ops", GatewayIDs: []string{"outer", "inner"}}, newEchoTerminal(), nil
	}
	broker := NewBroker(dataDir, vaultKey, open)
	completed, err := broker.Create(context.Background(), CreateRequest{
		AssetID: "asset-01", Cols: 80, Rows: 24, OperatorID: "user-operator", Operator: "alice",
	})
	if err != nil {
		t.Fatalf("create completed session: %v", err)
	}
	if err := broker.Close(completed.SessionID); err != nil {
		t.Fatalf("close session: %v", err)
	}

	rows, total, activeTotal, err := broker.ListSessions(0, 10)
	if err != nil {
		t.Fatalf("list sessions: %v", err)
	}
	if total != 1 || activeTotal != 0 || len(rows) != 1 {
		t.Fatalf("list sessions = (%d, %d rows), want (1, 1)", total, len(rows))
	}
	if rows[0].SessionID != completed.SessionID || rows[0].AssetName != "test-host" || rows[0].Username != "ops" || rows[0].OperatorID != "user-operator" || rows[0].Operator != "alice" || rows[0].Status != "ended" || !rows[0].ReplayAvailable || rows[0].EndedAt == nil {
		t.Fatalf("completed session summary = %#v", rows[0])
	}
	assert.Equal(t, []string{"outer", "inner"}, rows[0].GatewayIDs)
	audit, err := os.ReadFile(filepath.Join(dataDir, "sessions", "index.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(audit), `"operator_id":"user-operator"`) || !strings.Contains(string(audit), `"operator":"alice"`) {
		t.Fatalf("session audit omitted authenticated operator: %s", audit)
	}
	replay, err := broker.OpenReplay(completed.SessionID)
	if err != nil {
		t.Fatalf("open completed replay: %v", err)
	}
	if _, err := io.ReadAll(replay); err != nil {
		t.Fatalf("read completed replay: %v", err)
	}
	if err := replay.Close(); err != nil {
		t.Fatalf("close completed replay: %v", err)
	}

	active, err := broker.Create(context.Background(), CreateRequest{AssetID: "asset-02", Cols: 80, Rows: 24})
	if err != nil {
		t.Fatalf("create active session: %v", err)
	}
	defer broker.CloseAll()
	if _, err := broker.OpenReplay(active.SessionID); !errors.Is(err, ErrReplayUnavailable) {
		t.Fatalf("open active session replay error = %v, want replay unavailable", err)
	}
	rows, total, activeTotal, err = broker.ListSessions(0, 10)
	if err != nil {
		t.Fatalf("list active session: %v", err)
	}
	if total != 2 || activeTotal != 1 || rows[0].SessionID != active.SessionID || rows[0].Status != "active" || rows[1].Status != "ended" {
		t.Fatalf("active/completed session summaries = %#v", rows)
	}

	restartedBroker := NewBroker(dataDir, vaultKey, nil)
	rows, total, activeTotal, err = restartedBroker.ListSessions(0, 10)
	if err != nil {
		t.Fatalf("list session after restart: %v", err)
	}
	if total != 2 || activeTotal != 0 || rows[0].Status != "interrupted" || rows[0].ReplayAvailable {
		t.Fatalf("restart session summary = %#v", rows[0])
	}
}

func TestOperatorSessionAccessIsScopedToTheAuthenticatedOwner(t *testing.T) {
	broker := NewBroker(t.TempDir(), []byte("0123456789abcdef0123456789abcdef"), func(_ context.Context, assetID string, _, _ int) (AssetInfo, Terminal, error) {
		return AssetInfo{ID: assetID, Name: assetID, Username: "deploy"}, newEchoTerminal(), nil
	})
	defer broker.CloseAll()
	create := func(assetID, operatorID, operator string) CreatedSession {
		t.Helper()
		session, err := broker.Create(context.Background(), CreateRequest{AssetID: assetID, Cols: 80, Rows: 24, OperatorID: operatorID, Operator: operator})
		if err != nil {
			t.Fatalf("create %s session: %v", operator, err)
		}
		return session
	}

	aliceReplay := create("alice-recording", "user-alice", "alice")
	if err := broker.Close(aliceReplay.SessionID); err != nil {
		t.Fatal(err)
	}
	bobReplay := create("bob-recording", "user-bob", "bob")
	if err := broker.Close(bobReplay.SessionID); err != nil {
		t.Fatal(err)
	}
	aliceActive := create("alice-active", "user-alice", "alice")
	bobActive := create("bob-active", "user-bob", "bob")

	rows, total, activeTotal, err := broker.ListSessionsForOperator("user-alice", 0, 10)
	if err != nil || total != 2 || activeTotal != 1 || len(rows) != 2 {
		t.Fatalf("alice session list = (%d, %d active, %d rows), err %v", total, activeTotal, len(rows), err)
	}
	for _, row := range rows {
		if row.OperatorID != "user-alice" {
			t.Fatalf("alice session list leaked another operator: %#v", row)
		}
	}
	emptyRows, emptyTotal, _, err := broker.ListSessionsForOperator("", 0, 10)
	if err != nil || emptyTotal != 0 || len(emptyRows) != 0 {
		t.Fatalf("empty operator filter returned sessions: (%d, %d rows), err %v", emptyTotal, len(emptyRows), err)
	}

	replay, err := broker.OpenReplayForOperator(aliceReplay.SessionID, "user-alice")
	if err != nil {
		t.Fatalf("open owner's replay: %v", err)
	}
	_ = replay.Close()
	if _, err := broker.OpenReplayForOperator(bobReplay.SessionID, "user-alice"); !errors.Is(err, ErrSessionNotFound) {
		t.Fatalf("open another operator's replay error = %v, want not found", err)
	}
	if err := broker.CloseForOperator(bobActive.SessionID, "user-alice"); !errors.Is(err, ErrSessionNotFound) {
		t.Fatalf("stop another operator's session error = %v, want not found", err)
	}
	if err := broker.CloseForOperator(aliceActive.SessionID, "user-alice"); err != nil {
		t.Fatalf("stop owner's session: %v", err)
	}

	rows, total, activeTotal, err = broker.ListSessions(0, 10)
	if err != nil || total != 4 || activeTotal != 1 || len(rows) != 4 {
		t.Fatalf("administrator session list = (%d, %d active, %d rows), err %v", total, activeTotal, len(rows), err)
	}
}

func TestOpenReplayRejectsInvalidOrUnknownSessionIDs(t *testing.T) {
	broker := NewBroker(t.TempDir(), []byte("0123456789abcdef0123456789abcdef"), nil)
	for _, id := range []string{"../secrets", "unknown-session-id-123"} {
		if _, err := broker.OpenReplay(id); !errors.Is(err, ErrSessionNotFound) {
			t.Errorf("OpenReplay(%q) error = %v, want session not found", id, err)
		}
	}
}
