package gateway

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/coder/websocket"
	"github.com/neko233-com/jumpserver233/server/internal/connector/kubeclient"
	"github.com/neko233-com/jumpserver233/server/internal/core/sessionpolicy"
	"github.com/neko233-com/jumpserver233/server/internal/core/sessionshares"
	"github.com/neko233-com/jumpserver233/server/internal/recorder"
)

const (
	TerminalSubprotocol    = "jms233-terminal-v1"
	ticketProtocolPrefix   = "jms233-ticket."
	terminalTicketLifetime = 30 * time.Second
	terminalReadLimit      = 64 * 1024
)

// AssetInfo is the non-secret inventory data displayed for a terminal session.
type AssetInfo struct {
	Protocol   string
	Kubernetes *KubernetesSession

	GatewayIDs []string
	ID         string
	Name       string
	Host       string
	Port       int
	Username   string
}

// Terminal is an interactive server-side PTY. Implementations must not expose
// the SSH credential used to establish the connection.
type Terminal interface {
	io.ReadWriteCloser
	Resize(cols, rows int) error
}

// OpenFunc obtains an asset's server-side credential and returns a connected
// terminal without returning any credential material to the gateway.
type OpenFunc func(context.Context, string, int, int) (AssetInfo, Terminal, error)

type CreateRequest struct {
	Protocol   string                `json:"protocol,omitempty"`
	Open       OpenFunc              `json:"-"`
	Kubernetes *kubeclient.Selection `json:"kubernetes,omitempty"`

	AccessPolicy  func(context.Context) error `json:"-"`
	AssetID       string                      `json:"asset_id"`
	Cols          int                         `json:"cols"`
	Rows          int                         `json:"rows"`
	OperatorID    string                      `json:"-"`
	Operator      string                      `json:"-"`
	CommandPolicy CommandPolicy               `json:"-"`
}

type CommandPolicyDecision struct {
	PolicyKey     string
	Allowed       bool
	RequireReview bool
	RuleName      string
}

type CommandPolicy func(command string, supported bool, at time.Time) CommandPolicyDecision

type CreatedSession struct {
	Watermark    string    `json:"watermark,omitempty"`
	SessionID    string    `json:"session_id"`
	AssetName    string    `json:"asset_name"`
	WebSocketURL string    `json:"websocket_url"`
	Ticket       string    `json:"ticket"`
	ExpiresAt    time.Time `json:"expires_at"`
}

// SessionRecord is the safe operator-facing summary retained in the session
// audit index. It never includes SSH credentials or terminal contents.
type KubernetesSession struct {
	Namespace string `json:"namespace"`
	Pod       string `json:"pod"`
	Container string `json:"container"`
	PodUID    string `json:"pod_uid"`
}

type SessionRecord struct {
	Watermark  string             `json:"watermark,omitempty"`
	Protocol   string             `json:"protocol,omitempty"`
	Kubernetes *KubernetesSession `json:"kubernetes,omitempty"`

	GatewayIDs      []string   `json:"gateway_ids,omitempty"`
	SessionID       string     `json:"session_id"`
	AssetID         string     `json:"asset_id"`
	AssetName       string     `json:"asset_name"`
	OperatorID      string     `json:"operator_id,omitempty"`
	Operator        string     `json:"operator,omitempty"`
	Username        string     `json:"username"`
	StartedAt       time.Time  `json:"started_at"`
	EndedAt         *time.Time `json:"ended_at,omitempty"`
	Status          string     `json:"status"`
	EndReason       string     `json:"end_reason,omitempty"`
	ReplayAvailable bool       `json:"replay_available"`
}

type activeSession struct {
	accessPolicy   func(context.Context) error
	accessContext  context.Context
	id             string
	asset          AssetInfo
	operatorID     string
	operator       string
	terminal       Terminal
	terminalSocket *websocket.Conn
	recorder       *recorder.Asciinema
	commands       *commandCapture
	commandPolicy  CommandPolicy
	startedAt      time.Time
	lastInput      time.Time // guarded by Broker.mu; remote output is not user activity
	watermark      string
	ticketHash     [32]byte
	ticketExpiry   time.Time
	ticketTimer    *time.Timer
	closeOnce      sync.Once
	closing        bool // guarded by Broker.mu; retained in sessions until final audit completes
	writeMu        sync.Mutex
	inputMu        sync.Mutex
	pendingReview  *pendingCommandReview
	monitors       map[*sessionMonitor]struct{} // guarded by Broker.mu
	sharePeers     map[*sharePeer]struct{}      // guarded by Broker.mu
	shareHistory   []byte                       // bounded output tail, guarded by Broker.mu
	shareNotices   bool                         // immutable after terminal attachment; negotiated v1 extension
	cols, rows     int                          // guarded by Broker.mu
}

// Broker owns live SSH PTYs, short-lived single-use WebSocket tickets, and
// asciinema session recordings.
type Broker struct {
	open           OpenFunc
	dataDir        string
	vaultKey       []byte
	mu             sync.Mutex
	sessions       map[string]*activeSession
	monitors       map[[32]byte]*sessionMonitor
	shares         *sessionshares.Store
	shareTickets   map[[32]byte]*sharePeer
	sessionPolicy  func() sessionpolicy.Settings
	auditMu        sync.Mutex
	auditPath      string
	commandAuditMu sync.Mutex
	commandPath    string
}

func NewBroker(dataDir string, vaultKey []byte, open OpenFunc) *Broker {
	b := &Broker{
		open:         open,
		dataDir:      dataDir,
		vaultKey:     append([]byte(nil), vaultKey...),
		sessions:     make(map[string]*activeSession),
		monitors:     make(map[[32]byte]*sessionMonitor),
		shareTickets: make(map[[32]byte]*sharePeer),
		auditPath:    filepath.Join(dataDir, "sessions", "index.jsonl"),
		commandPath:  filepath.Join(dataDir, "sessions", "commands.jsonl"),
	}
	b.shares = sessionshares.New(b.appendShareAudit)
	return b
}

func (b *Broker) Create(ctx context.Context, request CreateRequest) (CreatedSession, error) {
	open := request.Open
	if open == nil {
		open = b.open
	}
	if open == nil {
		return CreatedSession{}, errors.New("SSH terminal connector is unavailable")
	}
	if strings.TrimSpace(request.AssetID) == "" || request.Cols < 2 || request.Cols > 500 || request.Rows < 2 || request.Rows > 500 {
		return CreatedSession{}, fmt.Errorf("%w: asset ID and terminal dimensions are required", ErrInvalidSessionRequest)
	}
	setupCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	if request.AccessPolicy != nil && request.AccessPolicy(setupCtx) != nil {
		return CreatedSession{}, errSessionPolicyDenied
	}
	asset, terminal, err := open(setupCtx, request.AssetID, request.Cols, request.Rows)
	if err != nil {
		return CreatedSession{}, err
	}
	if request.AccessPolicy != nil && request.AccessPolicy(setupCtx) != nil {
		_ = terminal.Close()
		return CreatedSession{}, errSessionPolicyDenied
	}
	startedAt := time.Now().UTC()
	sessionID, err := randomToken(18)
	if err != nil {
		_ = terminal.Close()
		return CreatedSession{}, fmt.Errorf("create session ID: %w", err)
	}
	ticket, err := randomToken(32)
	if err != nil {
		_ = terminal.Close()
		return CreatedSession{}, fmt.Errorf("create terminal ticket: %w", err)
	}
	recordingPath := filepath.Join(b.dataDir, "sessions", sessionID+".json.gz.enc")
	watermark := ""
	if b.securitySettings().Watermark {
		watermark = sessionpolicy.Label(request.OperatorID, sessionID, startedAt)
	}
	sessionRecorder, err := recorder.NewAsciinema(recordingPath, sessionID, asset.ID, request.Cols, request.Rows, startedAt, b.vaultKey, watermark)
	if err != nil {
		_ = terminal.Close()
		return CreatedSession{}, err
	}
	session := &activeSession{
		id:            sessionID,
		asset:         asset,
		operatorID:    request.OperatorID,
		operator:      request.Operator,
		terminal:      terminal,
		recorder:      sessionRecorder,
		commands:      newCommandCapture(),
		commandPolicy: request.CommandPolicy,
		accessPolicy:  request.AccessPolicy,
		accessContext: context.WithoutCancel(ctx),
		startedAt:     startedAt,
		lastInput:     startedAt,
		watermark:     watermark,
		ticketHash:    sha256.Sum256([]byte(ticket)),
		ticketExpiry:  startedAt.Add(terminalTicketLifetime),
		monitors:      make(map[*sessionMonitor]struct{}),
		cols:          request.Cols,
		rows:          request.Rows,
	}
	if err := b.appendAudit(session, "started", ""); err != nil {
		_ = terminal.Close()
		_ = sessionRecorder.Close()
		_ = os.Remove(recordingPath)
		return CreatedSession{}, err
	}
	b.mu.Lock()
	b.sessions[sessionID] = session
	session.ticketTimer = time.AfterFunc(terminalTicketLifetime, func() { b.closeExpiredSession(session) })
	b.mu.Unlock()
	return CreatedSession{
		Watermark:    watermark,
		SessionID:    sessionID,
		AssetName:    asset.Name,
		WebSocketURL: "/ws/api/v1/sessions/" + sessionID + "/terminal",
		Ticket:       ticket,
		ExpiresAt:    session.ticketExpiry,
	}, nil
}

func (b *Broker) Close(id string) error {
	b.mu.Lock()
	session := b.sessions[id]
	b.mu.Unlock()
	if session == nil {
		return ErrSessionNotFound
	}
	b.closeSession(session, "closed_by_client")
	return nil
}

// CloseForOperator closes a live session only when the authenticated operator
// owns it. Missing and foreign sessions deliberately share the same error.
func (b *Broker) CloseForOperator(id, operatorID string) error {
	if err := b.requireSessionOperator(id, operatorID); err != nil {
		return err
	}
	return b.Close(id)
}

// ListSessions returns the newest session records first. Sessions with a
// start record but no end record after a process restart are marked interrupted.
func (b *Broker) ListSessions(offset, limit int) ([]SessionRecord, int, int, error) {
	return b.listSessions(nil, offset, limit)
}

// ListSessionsForOperator returns only sessions created with this authenticated
// operator identity. It never treats an empty identity as an unfiltered query.
func (b *Broker) ListSessionsForOperator(operatorID string, offset, limit int) ([]SessionRecord, int, int, error) {
	operatorID = strings.TrimSpace(operatorID)
	if operatorID == "" {
		return []SessionRecord{}, 0, 0, nil
	}
	return b.listSessions(&operatorID, offset, limit)
}

func (b *Broker) listSessions(operatorID *string, offset, limit int) ([]SessionRecord, int, int, error) {
	if offset < 0 || limit < 1 || limit > 200 {
		return nil, 0, 0, fmt.Errorf("session pagination is out of range")
	}
	records, err := b.readSessionRecords()
	if err != nil {
		return nil, 0, 0, err
	}
	activeIDs := make(map[string]struct{})
	b.mu.Lock()
	for id := range b.sessions {
		activeIDs[id] = struct{}{}
	}
	b.mu.Unlock()
	visible := make([]SessionRecord, 0, len(records))
	for _, record := range records {
		if operatorID != nil && record.OperatorID != *operatorID {
			continue
		}
		if _, ok := activeIDs[record.SessionID]; ok {
			record.Status = "active"
		} else if record.Status == "started" {
			record.Status = "interrupted"
		}
		visible = append(visible, record)
	}
	activeTotal := 0
	for _, record := range visible {
		if record.Status == "active" {
			activeTotal++
		}
	}
	sort.Slice(visible, func(i, j int) bool { return visible[i].StartedAt.After(visible[j].StartedAt) })
	total := len(visible)
	if offset >= total {
		return []SessionRecord{}, total, activeTotal, nil
	}
	end := offset + limit
	if end > total {
		end = total
	}
	return visible[offset:end], total, activeTotal, nil
}

// OpenReplay returns a completed session's asciinema stream. Session IDs are
// validated before being used to form a recording path, and only an ended
// session from the audit index can be replayed.
func (b *Broker) OpenReplay(id string) (io.ReadCloser, error) {
	if !validSessionID(id) {
		return nil, ErrSessionNotFound
	}
	records, err := b.readSessionRecords()
	if err != nil {
		return nil, err
	}
	for _, record := range records {
		if record.SessionID != id {
			continue
		}
		if record.Status != "ended" || !record.ReplayAvailable {
			return nil, ErrReplayUnavailable
		}
		return recorder.OpenReplay(filepath.Join(b.dataDir, "sessions", id+".json.gz.enc"), id, b.vaultKey)
	}
	return nil, ErrSessionNotFound
}

// OpenReplayForOperator returns a replay only when its authenticated operator
// owns the session. Missing and foreign sessions deliberately share one error.
func (b *Broker) OpenReplayForOperator(id, operatorID string) (io.ReadCloser, error) {
	if err := b.requireSessionOperator(id, operatorID); err != nil {
		return nil, err
	}
	return b.OpenReplay(id)
}

func (b *Broker) requireSessionOperator(id, operatorID string) error {
	operatorID = strings.TrimSpace(operatorID)
	if !validSessionID(id) || operatorID == "" {
		return ErrSessionNotFound
	}
	records, err := b.readSessionRecords()
	if err != nil {
		return err
	}
	for _, record := range records {
		if record.SessionID == id && record.OperatorID == operatorID {
			return nil
		}
	}
	return ErrSessionNotFound
}

func (b *Broker) readSessionRecords() ([]SessionRecord, error) {
	b.auditMu.Lock()
	defer b.auditMu.Unlock()
	file, err := os.Open(b.auditPath)
	if errors.Is(err, os.ErrNotExist) {
		return []SessionRecord{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("open session audit index: %w", err)
	}
	defer file.Close()

	byID := make(map[string]SessionRecord)
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	for scanner.Scan() {
		var event struct {
			Watermark  string             `json:"watermark,omitempty"`
			Protocol   string             `json:"protocol,omitempty"`
			Kubernetes *KubernetesSession `json:"kubernetes,omitempty"`
			SessionID  string             `json:"session_id"`
			AssetID    string             `json:"asset_id"`
			AssetName  string             `json:"asset_name"`
			GatewayIDs []string           `json:"gateway_ids,omitempty"`
			OperatorID string             `json:"operator_id"`
			Operator   string             `json:"operator"`
			Username   string             `json:"username"`
			Event      string             `json:"event"`
			Reason     string             `json:"reason"`
			At         time.Time          `json:"at"`
		}
		if err := json.Unmarshal(scanner.Bytes(), &event); err != nil || !validSessionID(event.SessionID) {
			continue
		}
		record := byID[event.SessionID]
		if event.Event == "started" {
			record = SessionRecord{Watermark: event.Watermark, Protocol: event.Protocol, Kubernetes: event.Kubernetes,
				SessionID:  event.SessionID,
				AssetID:    event.AssetID,
				AssetName:  event.AssetName,
				GatewayIDs: append([]string(nil), event.GatewayIDs...),
				OperatorID: event.OperatorID,
				Operator:   event.Operator,
				Username:   event.Username,
				StartedAt:  event.At,
				Status:     "started",
			}
		} else if event.Event == "ended" && record.SessionID != "" {
			endedAt := event.At
			record.EndedAt = &endedAt
			record.Status = "ended"
			record.EndReason = event.Reason
		}
		if record.SessionID != "" {
			byID[event.SessionID] = record
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read session audit index: %w", err)
	}
	records := make([]SessionRecord, 0, len(byID))
	for id, record := range byID {
		if record.Status == "ended" {
			_, err := os.Stat(filepath.Join(b.dataDir, "sessions", id+".json.gz.enc"))
			record.ReplayAvailable = err == nil
		}
		records = append(records, record)
	}
	return records, nil
}

func validSessionID(id string) bool {
	if len(id) < 16 || len(id) > 128 {
		return false
	}
	for _, char := range id {
		if (char < 'a' || char > 'z') && (char < 'A' || char > 'Z') && (char < '0' || char > '9') && char != '-' && char != '_' {
			return false
		}
	}
	return true
}

func (b *Broker) CloseAll() {
	b.mu.Lock()
	sessions := make([]*activeSession, 0, len(b.sessions))
	for _, session := range b.sessions {
		sessions = append(sessions, session)
	}
	b.mu.Unlock()
	for _, session := range sessions {
		b.closeSession(session, "server_shutdown")
	}
}

func (b *Broker) ServeTerminal(w http.ResponseWriter, r *http.Request) {
	sessionID := r.PathValue("sessionID")
	ticket := ticketFromProtocols(r.Header.Values("Sec-WebSocket-Protocol"))
	session, ok := b.consumeTicket(sessionID, ticket)
	if !ok {
		http.Error(w, "terminal ticket is invalid or expired", http.StatusUnauthorized)
		return
	}
	if session.accessPolicy != nil && session.accessPolicy(r.Context()) != nil {
		b.closeSession(session, "access_policy_denied")
		http.Error(w, "access policy denied", http.StatusForbidden)
		return
	}
	conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{Subprotocols: []string{TerminalSubprotocol}})
	if err != nil {
		b.closeSession(session, "websocket_handshake_failed")
		return
	}
	b.mu.Lock()
	if b.sessions[sessionID] != session || session.closing {
		b.mu.Unlock()
		_ = conn.Close(websocket.StatusGoingAway, "session closed")
		return
	}
	session.terminalSocket = conn
	session.shareNotices = acceptsShareControl(r.Header.Values("Sec-WebSocket-Protocol"))
	session.accessContext = context.WithoutCancel(r.Context())
	b.mu.Unlock()
	conn.SetReadLimit(terminalReadLimit)
	ctx, cancel := context.WithCancel(r.Context())
	done := make(chan error, 3)
	go func() { done <- b.writeTerminal(ctx, conn, session) }()
	go func() { done <- b.readTerminal(ctx, conn, session) }()
	go func() {
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		checks := 0
		for {
			select {
			case <-ctx.Done():
				done <- ctx.Err()
				return
			case <-ticker.C:
				if err := b.sessionLimit(session); err != nil {
					done <- err
					return
				}
				checks++
				if checks%10 == 0 && session.accessPolicy != nil && session.accessPolicy(ctx) != nil {
					done <- errSessionPolicyDenied
					return
				}
			}
		}
	}()
	firstErr := <-done
	cancel()
	_ = conn.CloseNow()
	b.closeSession(session, terminalCloseReason(firstErr))
	<-done
	<-done
}

var ErrSessionAccessDenied = errors.New("terminal access policy denied")
var errSessionPolicyDenied = ErrSessionAccessDenied

func terminalCloseReason(err error) string {
	if errors.Is(err, errSessionIdle) {
		return "idle_timeout"
	}
	if errors.Is(err, errSessionDuration) {
		return "duration_limit"
	}
	if errors.Is(err, errSessionPolicyDenied) {
		return "access_policy_denied"
	}
	if err == nil || errors.Is(err, io.EOF) {
		return "disconnected"
	}
	switch websocket.CloseStatus(err) {
	case websocket.StatusNormalClosure, websocket.StatusGoingAway:
		return "disconnected"
	default:
		return "terminal_io_error"
	}
}

func (b *Broker) writeTerminal(ctx context.Context, conn *websocket.Conn, session *activeSession) error {
	buffer := make([]byte, 16*1024)
	for {
		count, err := session.terminal.Read(buffer)
		if count > 0 {
			data := append([]byte(nil), buffer[:count]...)
			session.commands.ObserveOutput(data)
			if recordErr := session.recorder.Record('o', data); recordErr != nil {
				return recordErr
			}
			b.publishMonitorOutput(session, data)
			b.publishShareOutput(session, data)
			if writeErr := session.writeWebSocket(ctx, conn, websocket.MessageBinary, data); writeErr != nil {
				return writeErr
			}
		}
		if err != nil {
			return err
		}
	}
}

func (b *Broker) readTerminal(ctx context.Context, conn *websocket.Conn, session *activeSession) error {
	for {
		messageType, data, err := conn.Read(ctx)
		if err != nil {
			return err
		}
		if session.accessPolicy != nil && session.accessPolicy(ctx) != nil {
			return errSessionPolicyDenied
		}
		if err := b.sessionLimit(session); err != nil {
			return err
		}
		switch messageType {
		case websocket.MessageBinary:
			if len(data) == 0 {
				continue
			}
			session.inputMu.Lock()
			if b.shares.Controller(session.id) != "" {
				session.inputMu.Unlock()
				if !session.shareNotices {
					continue
				}
				if err := session.writeWebSocket(ctx, conn, websocket.MessageText, []byte(`{"type":"share_control_required"}`)); err != nil {
					return err
				}
				continue
			}
			forward, err := b.prepareTerminalInput(ctx, conn, session, data)
			if err != nil {
				session.inputMu.Unlock()
				return err
			}
			if len(forward) == 0 {
				session.inputMu.Unlock()
				continue
			}
			if err := session.recorder.Record('i', forward); err != nil {
				session.inputMu.Unlock()
				return err
			}
			if err := writeAll(session.terminal, forward); err != nil {
				session.inputMu.Unlock()
				return err
			}
			b.touchSession(session)
			session.inputMu.Unlock()
		case websocket.MessageText:
			var control struct {
				Type string `json:"type"`
				Cols int    `json:"cols"`
				Rows int    `json:"rows"`
			}
			if err := json.Unmarshal(data, &control); err != nil {
				return fmt.Errorf("decode terminal control: %w", err)
			}
			switch control.Type {
			case "resize":
				if control.Cols < 2 || control.Cols > 500 || control.Rows < 2 || control.Rows > 500 {
					return ErrInvalidSessionRequest
				}
				if err := session.terminal.Resize(control.Cols, control.Rows); err != nil {
					return err
				}
				b.mu.Lock()
				session.cols, session.rows = control.Cols, control.Rows
				b.mu.Unlock()
			case "close":
				return io.EOF
			default:
				return fmt.Errorf("unsupported terminal control message")
			}
		default:
			return fmt.Errorf("unsupported WebSocket message type")
		}
	}
}

func (b *Broker) prepareTerminalInput(ctx context.Context, conn *websocket.Conn, session *activeSession, data []byte, identities ...inputIdentity) ([]byte, error) {
	identity := inputIdentity{ID: session.operatorID, Name: session.operator}
	if len(identities) > 0 {
		identity = identities[0]
	}
	b.mu.Lock()
	hasPendingReview := session.pendingReview != nil
	b.mu.Unlock()
	if hasPendingReview {
		return nil, nil
	}
	submissions := session.commands.ObserveInput(data)
	blockedOffsets := make([]int, 0, len(submissions))
	reviewOffset := -1
	for _, submission := range submissions {
		submission.ActorID, submission.Actor = identity.ID, identity.Name
		decision := decideInputPolicy(session, identity, submission)
		submission.PolicyKey = decision.PolicyKey
		if decision.Allowed {
			if submission.Supported && submission.Command != "" {
				submission.Outcome = "allowed"
				if err := b.appendCommand(session.id, submission); err != nil {
					return nil, err
				}
			}
			continue
		}
		if decision.RequireReview && submission.Supported && submission.Command != "" {
			if _, err := b.createCommandReview(ctx, conn, session, submission, decision.RuleName, identity); err != nil {
				return nil, err
			}
			reviewOffset = submission.Offset
			break
		}
		submission.Outcome = "blocked"
		submission.RuleName = decision.RuleName
		if err := b.appendCommand(session.id, submission); err != nil {
			return nil, err
		}
		blockedOffsets = append(blockedOffsets, submission.Offset)
		message, err := json.Marshal(struct {
			Type     string `json:"type"`
			RuleName string `json:"rule_name,omitempty"`
		}{Type: "command_blocked", RuleName: decision.RuleName})
		if err != nil {
			return nil, fmt.Errorf("encode command filter notice: %w", err)
		}
		if err := session.writeWebSocket(ctx, conn, websocket.MessageText, message); err != nil {
			return nil, err
		}
	}
	if len(blockedOffsets) == 0 && reviewOffset < 0 {
		return data, nil
	}
	limit := len(data)
	if reviewOffset >= 0 {
		if reviewOffset >= len(data) {
			return nil, fmt.Errorf("command review returned an invalid input offset")
		}
		limit = reviewOffset
	}
	forward := make([]byte, 0, limit+len(blockedOffsets))
	previous := 0
	for _, offset := range blockedOffsets {
		if offset < previous || offset >= limit {
			return nil, fmt.Errorf("command filter returned an invalid input offset")
		}
		forward = append(forward, data[previous:offset]...)
		forward = append(forward, 0x03) // Ctrl+C clears the remote shell's pending command line.
		previous = offset
	}
	forward = append(forward, data[previous:limit]...)
	return forward, nil
}

func (s *activeSession) writeWebSocket(ctx context.Context, conn *websocket.Conn, messageType websocket.MessageType, data []byte) error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	return conn.Write(ctx, messageType, data)
}

func (b *Broker) consumeTicket(id, ticket string) (*activeSession, bool) {
	if ticket == "" {
		return nil, false
	}
	b.mu.Lock()
	session := b.sessions[id]
	if session == nil || session.ticketTimer == nil || time.Now().After(session.ticketExpiry) {
		b.mu.Unlock()
		return nil, false
	}
	providedHash := sha256.Sum256([]byte(ticket))
	if subtle.ConstantTimeCompare(providedHash[:], session.ticketHash[:]) != 1 {
		b.mu.Unlock()
		return nil, false
	}
	session.ticketHash = [32]byte{}
	session.ticketTimer.Stop()
	session.ticketTimer = nil
	b.mu.Unlock()
	return session, true
}

func (b *Broker) closeSession(session *activeSession, reason string) {
	session.closeOnce.Do(func() {
		b.mu.Lock()
		session.closing = true
		for peer := range session.sharePeers {
			b.stopSharePeerLocked(peer)
		}
		b.shares.CloseSession(session.id)
		for monitor := range session.monitors {
			b.stopMonitorLocked(monitor)
		}
		session.terminalSocket = nil
		pendingReview := session.pendingReview
		session.pendingReview = nil
		if pendingReview != nil && pendingReview.timer != nil {
			pendingReview.timer.Stop()
		}
		if session.ticketTimer != nil {
			session.ticketTimer.Stop()
			session.ticketTimer = nil
		}
		session.ticketHash = [32]byte{}
		b.mu.Unlock()
		// A remote that stops reading can block PTY input. Closing the transport
		// first releases that write so expiry/admin termination can join it.
		_ = session.terminal.Close()
		session.inputMu.Lock()
		if pendingReview != nil {
			submission := pendingReview.submission
			submission.SubmittedAt = time.Now().UTC()
			submission.Outcome = "cancelled"
			submission.ReviewedBy = "system"
			_ = b.appendCommand(session.id, submission)
		}
		session.inputMu.Unlock()
		_ = session.recorder.Close()
		session.commands.Close()
		_ = b.appendAudit(session, "ended", reason)
		// CloseAll must still see closing sessions so it can join closeOnce and
		// wait for recording/audit writes before storage is released.
		b.mu.Lock()
		delete(b.sessions, session.id)
		b.mu.Unlock()
	})
}

func (b *Broker) closeExpiredSession(session *activeSession) {
	b.mu.Lock()
	expired := session.ticketTimer != nil && !time.Now().Before(session.ticketExpiry)
	if expired {
		session.ticketTimer = nil
		session.ticketHash = [32]byte{}
	}
	b.mu.Unlock()
	if expired {
		b.closeSession(session, "ticket_expired")
	}
}

func (b *Broker) appendAudit(session *activeSession, event, reason string) error {
	record := struct {
		Watermark  string             `json:"watermark,omitempty"`
		Protocol   string             `json:"protocol,omitempty"`
		Kubernetes *KubernetesSession `json:"kubernetes,omitempty"`
		SessionID  string             `json:"session_id"`
		AssetID    string             `json:"asset_id"`
		AssetName  string             `json:"asset_name"`
		GatewayIDs []string           `json:"gateway_ids,omitempty"`
		OperatorID string             `json:"operator_id,omitempty"`
		Operator   string             `json:"operator,omitempty"`
		Username   string             `json:"username"`
		Event      string             `json:"event"`
		Reason     string             `json:"reason,omitempty"`
		At         time.Time          `json:"at"`
	}{
		Watermark: session.watermark,
		Protocol:  session.asset.Protocol, Kubernetes: session.asset.Kubernetes,
		SessionID:  session.id,
		AssetID:    session.asset.ID,
		AssetName:  session.asset.Name,
		GatewayIDs: append([]string(nil), session.asset.GatewayIDs...),
		OperatorID: session.operatorID,
		Operator:   session.operator,
		Username:   session.asset.Username,
		Event:      event,
		Reason:     reason,
		At:         time.Now().UTC(),
	}
	return b.appendSessionAudit(record)
}

func (b *Broker) appendSessionAudit(record any) error {
	b.auditMu.Lock()
	defer b.auditMu.Unlock()
	return b.appendAuditFileLocked(b.auditPath, record)
}
func (b *Broker) appendAuditFile(path string, record any) error {
	b.auditMu.Lock()
	defer b.auditMu.Unlock()
	return b.appendAuditFileLocked(path, record)
}
func (b *Broker) appendAuditFileLocked(path string, record any) error {
	encoded, err := json.Marshal(record)
	if err != nil {
		return fmt.Errorf("encode session audit event: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("create session audit directory: %w", err)
	}
	file, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("open session audit index: %w", err)
	}
	if _, err := file.Write(append(encoded, '\n')); err != nil {
		_ = file.Close()
		return fmt.Errorf("write session audit index: %w", err)
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return fmt.Errorf("sync session audit index: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close session audit index: %w", err)
	}
	return nil
}

var ErrSessionNotFound = errors.New("terminal session not found")
var ErrReplayUnavailable = errors.New("terminal session replay is unavailable")
var ErrInvalidSessionRequest = errors.New("invalid terminal session request")

func randomToken(size int) (string, error) {
	data := make([]byte, size)
	if _, err := rand.Read(data); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(data), nil
}

func TicketSubprotocol(ticket string) string {
	return ticketProtocolPrefix + ticket
}

func ticketFromProtocols(values []string) string {
	for _, value := range values {
		for _, protocol := range strings.Split(value, ",") {
			protocol = strings.TrimSpace(protocol)
			if strings.HasPrefix(protocol, ticketProtocolPrefix) {
				return strings.TrimPrefix(protocol, ticketProtocolPrefix)
			}
		}
	}
	return ""
}

func writeAll(writer io.Writer, data []byte) error {
	for len(data) > 0 {
		count, err := writer.Write(data)
		if err != nil {
			return err
		}
		if count == 0 {
			return io.ErrShortWrite
		}
		data = data[count:]
	}
	return nil
}
