package gateway

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/coder/websocket"
	"github.com/neko233-com/jumpserver233/server/internal/core/sessionshares"
)

const ShareSubprotocol = "jms233-share-v1"
const ShareControlCapability = "jms233-share-control-v1"

func acceptsShareControl(values []string) bool {
	for _, value := range values {
		for _, protocol := range strings.Split(value, ",") {
			if strings.TrimSpace(protocol) == ShareControlCapability {
				return true
			}
		}
	}
	return false
}

const maxShareHistory = 64 * 1024

type inputIdentity struct {
	MemberID        string
	ID, Name        string
	Policy          CommandPolicy
	DirectoryPolicy DirectoryCommandPolicy
	Guard           func(context.Context) error
}

func decideInputPolicy(s *activeSession, actor inputIdentity, submission commandSubmission) CommandPolicyDecision {
	result := CommandPolicyDecision{Allowed: true}
	decisions := []CommandPolicyDecision{}
	for i, policy := range []CommandPolicy{s.commandPolicy, actor.Policy} {
		directoryPolicy := s.directoryPolicy
		if i == 1 {
			directoryPolicy = actor.DirectoryPolicy
		}
		if policy == nil && directoryPolicy == nil {
			continue
		}
		var v CommandPolicyDecision
		if directoryPolicy != nil {
			v = directoryPolicy(submission.PolicyCommand, submission.Supported, submission.SubmittedAt, submission.Directory)
		} else {
			v = policy(submission.PolicyCommand, submission.Supported, submission.SubmittedAt)
		}
		decisions = append(decisions, v)
		if !v.Allowed && !v.RequireReview {
			return v
		}
		if v.RequireReview {
			result = v
		} else if !result.RequireReview {
			result.PolicyKey = v.PolicyKey
		}
	}
	if actor.Policy != nil || actor.DirectoryPolicy != nil || submission.Directory.Valid() {
		raw, _ := json.Marshal(struct {
			Decisions []CommandPolicyDecision
			Directory any
		}{decisions, submission.Directory})
		digest := sha256.Sum256(raw)
		result.PolicyKey = hex.EncodeToString(digest[:])
	}
	return result
}

type sharePeer struct {
	session         *activeSession
	member          sessionshares.Member
	guard           func(context.Context, AssetInfo) error
	policy          CommandPolicy
	directoryPolicy DirectoryCommandPolicy
	hash            [32]byte
	expires         time.Time
	timer           *time.Timer
	used            bool
	output          chan []byte
	history         []byte
	done            chan struct{}
	once            sync.Once
	inflight        atomic.Bool
}
type SharedSession struct {
	CreatedSession
	Member sessionshares.Member `json:"member"`
}
type ShareState struct {
	Usernames  map[string]string      `json:"usernames,omitempty"`
	Enabled    bool                   `json:"enabled"`
	Shares     []sessionshares.Share  `json:"shares"`
	Members    []sessionshares.Member `json:"members"`
	Controller string                 `json:"controller"`
}

func (b *Broker) ownedLiveSession(id, ownerID string) (*activeSession, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	s := b.sessions[id]
	if s == nil || s.closing || s.terminalSocket == nil || s.operatorID != ownerID {
		return nil, ErrSessionNotFound
	}
	return s, nil
}
func (b *Broker) ShareAsset(id, ownerID string) (AssetInfo, error) {
	s, e := b.ownedLiveSession(id, ownerID)
	if e != nil {
		return AssetInfo{}, e
	}
	return s.asset, nil
}
func (b *Broker) CreateShare(ctx context.Context, id string, owner sessionshares.Actor, in sessionshares.Input, authorize func() error) (sessionshares.Created, error) {
	s, e := b.ownedLiveSession(id, owner.ID)
	if e != nil {
		return sessionshares.Created{}, e
	}
	if !b.securitySettings().Sharing || authorize == nil || authorize() != nil {
		return sessionshares.Created{}, sessionshares.ErrDenied
	}
	in.SessionID = id
	in.Authorize = func() error {
		if authorize() != nil {
			return sessionshares.ErrDenied
		}
		if s.accessPolicy != nil {
			return s.accessPolicy(s.accessContext)
		}
		return nil
	}
	created, e := b.shares.Create(in, owner)
	if e != nil {
		return created, e
	}
	if _, e = b.ownedLiveSession(id, owner.ID); e != nil {
		_ = b.shares.Revoke(created.ID, owner)
		return sessionshares.Created{}, e
	}
	return created, nil
}
func (b *Broker) ShareState(id, ownerID string) (ShareState, error) {
	if _, e := b.ownedLiveSession(id, ownerID); e != nil {
		return ShareState{}, e
	}
	return ShareState{Enabled: b.securitySettings().Sharing, Shares: b.shares.List(id, ownerID), Members: b.shares.Members(id, ownerID), Controller: b.shares.Controller(id)}, nil
}
func (b *Broker) RevokeShare(id string, owner sessionshares.Actor) error {
	e := b.shares.Revoke(id, owner)
	if e == nil || errors.Is(e, sessionshares.ErrAudit) {
		b.mu.Lock()
		for _, p := range b.shareTickets {
			if p.member.ShareID == id {
				b.stopSharePeerLocked(p)
			}
		}
		b.mu.Unlock()
	}
	return e
}
func (b *Broker) KickShareMember(id string, owner sessionshares.Actor) error {
	e := b.shares.Kick(id, owner)
	if e == nil || errors.Is(e, sessionshares.ErrAudit) {
		b.mu.Lock()
		for _, p := range b.shareTickets {
			if p.member.ID == id {
				b.stopSharePeerLocked(p)
			}
		}
		b.mu.Unlock()
	}
	return e
}
func (b *Broker) JoinShare(ctx context.Context, id, code string, actor sessionshares.Actor, guard func(context.Context, AssetInfo) error, policy func(AssetInfo) CommandPolicy, directoryPolicies ...func(AssetInfo) DirectoryCommandPolicy) (SharedSession, error) {
	if !b.securitySettings().Sharing || guard == nil || len(directoryPolicies) > 1 {
		return SharedSession{}, sessionshares.ErrDenied
	}
	m, e := b.shares.Join(id, code, actor)
	if e != nil {
		return SharedSession{}, e
	}
	keep := false
	defer func() {
		if !keep {
			_ = b.shares.Leave(m.ID, actor.ID)
		}
	}()
	b.mu.Lock()
	s := b.sessions[m.SessionID]
	valid := s != nil && !s.closing && s.terminalSocket != nil
	b.mu.Unlock()
	if !valid || guard(ctx, s.asset) != nil || b.sessionLimit(s) != nil {
		return SharedSession{}, sessionshares.ErrDenied
	}
	ticket, e := randomToken(32)
	if e != nil {
		return SharedSession{}, e
	}
	p := &sharePeer{session: s, member: m, guard: guard, hash: sha256.Sum256([]byte(ticket)), expires: time.Now().Add(terminalTicketLifetime), output: make(chan []byte, 32), done: make(chan struct{})}
	if policy != nil {
		p.policy = policy(s.asset)
	}
	if len(directoryPolicies) == 1 && directoryPolicies[0] != nil {
		p.directoryPolicy = directoryPolicies[0](s.asset)
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if s.closing || s.terminalSocket == nil {
		return SharedSession{}, sessionshares.ErrDenied
	}
	if s.sharePeers == nil {
		s.sharePeers = map[*sharePeer]struct{}{}
	}
	s.sharePeers[p] = struct{}{}
	b.shareTickets[p.hash] = p
	p.timer = time.AfterFunc(terminalTicketLifetime, func() {
		b.mu.Lock()
		unused := !p.used
		if unused {
			b.stopSharePeerLocked(p)
		}
		b.mu.Unlock()
		if unused {
			_ = b.shares.Leave(m.ID, actor.ID)
		}
	})
	keep = true
	return SharedSession{CreatedSession: CreatedSession{SessionID: s.id, AssetName: s.asset.Name, Watermark: s.watermark, Ticket: ticket, ExpiresAt: p.expires, WebSocketURL: "/ws/api/v1/sessions/" + s.id + "/share"}, Member: m}, nil
}
func (b *Broker) stopSharePeerLocked(p *sharePeer) {
	p.once.Do(func() {
		delete(p.session.sharePeers, p)
		delete(b.shareTickets, p.hash)
		if p.timer != nil {
			p.timer.Stop()
		}
		close(p.done)
	})
}
func (b *Broker) publishShareOutput(s *activeSession, data []byte) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if len(data) >= maxShareHistory {
		s.shareHistory = append(s.shareHistory[:0], data[len(data)-maxShareHistory:]...)
	} else {
		if extra := len(s.shareHistory) + len(data) - maxShareHistory; extra > 0 {
			copy(s.shareHistory, s.shareHistory[extra:])
			s.shareHistory = s.shareHistory[:len(s.shareHistory)-extra]
		}
		s.shareHistory = append(s.shareHistory, data...)
	}
	for p := range s.sharePeers {
		if !p.used {
			continue
		}
		select {
		case p.output <- data:
		default:
			b.stopSharePeerLocked(p)
		}
	}
}
func (b *Broker) shareAccess(ctx context.Context, p *sharePeer) error {
	if ctx.Err() != nil {
		return sessionshares.ErrDenied
	}
	if !b.securitySettings().Sharing {
		return sessionshares.ErrDenied
	}
	if _, e := b.shares.Member(p.member.ID, p.member.Actor.ID); e != nil {
		return e
	}
	if p.session.accessPolicy != nil && p.session.accessPolicy(p.session.accessContext) != nil {
		return sessionshares.ErrDenied
	}
	if b.sessionLimit(p.session) != nil {
		return sessionshares.ErrDenied
	}
	return p.guard(ctx, p.session.asset)
}

// Control changes and complete input frames share inputMu. The PTY and its
// existing input remain intact; submission uses the current writer's identity.
func (b *Broker) ChangeShareControl(ctx context.Context, sessionID string, actor sessionshares.Actor, memberID string) error {
	b.mu.Lock()
	s := b.sessions[sessionID]
	b.mu.Unlock()
	if s == nil {
		return ErrSessionNotFound
	}
	s.inputMu.Lock()
	b.mu.Lock()
	closed := s.closing
	pending := s.pendingReview != nil
	b.mu.Unlock()
	if closed || pending {
		s.inputMu.Unlock()
		return ErrCommandReviewInProgress
	}
	var e error
	before := b.shares.Controller(sessionID)
	if memberID == "" {
		if s.operatorID != actor.ID {
			s.inputMu.Unlock()
			return sessionshares.ErrDenied
		}
		e = b.shares.Reclaim(sessionID, actor)
	} else {
		m, err := b.shares.Member(memberID, actor.ID)
		b.mu.Lock()
		var peer *sharePeer
		for p := range s.sharePeers {
			if p.member.ID == memberID && p.used {
				peer = p
				break
			}
		}
		b.mu.Unlock()
		if err != nil || m.SessionID != sessionID || peer == nil || b.shareAccess(ctx, peer) != nil {
			s.inputMu.Unlock()
			return sessionshares.ErrDenied
		}
		e = b.shares.TakeControl(memberID, actor.ID)
	}
	if e != nil || before == b.shares.Controller(sessionID) {
		s.inputMu.Unlock()
		return e
	}
	if s.accessPolicy != nil && s.accessPolicy(s.accessContext) != nil {
		s.inputMu.Unlock()
		b.closeSession(s, "access_policy_denied")
		return ErrSessionAccessDenied
	}
	if e = b.sessionLimit(s); e != nil {
		s.inputMu.Unlock()
		b.closeSession(s, terminalCloseReason(e))
		return e
	}
	s.inputMu.Unlock()
	{
		b.mu.Lock()
		conn := s.terminalSocket
		b.mu.Unlock()
		if conn != nil && s.shareNotices {
			raw, _ := json.Marshal(map[string]string{"type": "share_controller", "controller": b.shares.Controller(sessionID)})
			noticeCtx, stop := context.WithTimeout(ctx, 2*time.Second)
			_ = s.writeWebSocket(noticeCtx, conn, websocket.MessageText, raw)
			stop()
		}
	}
	return e
}
func (b *Broker) readShare(ctx context.Context, conn *websocket.Conn, p *sharePeer) error {
	for {
		kind, data, e := conn.Read(ctx)
		if e != nil {
			return e
		}
		if e = b.shareAccess(ctx, p); e != nil {
			return e
		}
		if kind == websocket.MessageText {
			var control struct {
				Type string `json:"type"`
			}
			if json.Unmarshal(data, &control) != nil || control.Type != "take_control" {
				return sessionshares.ErrDenied
			}
			if e = b.ChangeShareControl(ctx, p.session.id, p.member.Actor, p.member.ID); e != nil {
				if errors.Is(e, ErrCommandReviewInProgress) {
					deadline, stop := context.WithTimeout(ctx, 2*time.Second)
					writeErr := conn.Write(deadline, websocket.MessageText, []byte(`{"type":"share_control_busy"}`))
					stop()
					if writeErr != nil {
						return writeErr
					}
					continue
				}
				return e
			}
			continue
		}
		if kind != websocket.MessageBinary || p.member.Mode != sessionshares.ReadWrite {
			return sessionshares.ErrDenied
		}
		if len(data) == 0 {
			continue
		}
		s := p.session
		s.inputMu.Lock()
		if b.shares.Controller(s.id) != p.member.ID {
			s.inputMu.Unlock()
			deadline, stop := context.WithTimeout(ctx, 2*time.Second)
			e := conn.Write(deadline, websocket.MessageText, []byte(`{"type":"share_control_required"}`))
			stop()
			if e != nil {
				return e
			}
			continue
		}
		if b.shareAccess(ctx, p) != nil {
			s.inputMu.Unlock()
			return sessionshares.ErrDenied
		}
		identity := inputIdentity{MemberID: p.member.ID, ID: p.member.Actor.ID, Name: p.member.Actor.Name, Policy: p.policy, DirectoryPolicy: p.directoryPolicy, Guard: func(context.Context) error { return b.shareAccess(ctx, p) }}
		p.inflight.Store(true)
		stop := context.AfterFunc(ctx, func() {
			timer := time.NewTimer(100 * time.Millisecond)
			defer timer.Stop()
			<-timer.C
			if p.inflight.Load() {
				b.closeSession(s, "share_input_cancelled")
			}
		})
		e = b.writeTerminalInput(ctx, conn, s, data, identity)
		p.inflight.Store(false)
		stop()
		s.inputMu.Unlock()
		if e != nil {
			if !errors.Is(e, sessionshares.ErrDenied) {
				b.closeSession(s, "share_input_failed")
			}
			return e
		}
	}
}
func (b *Broker) ServeShare(w http.ResponseWriter, r *http.Request) {
	hash := sha256.Sum256([]byte(ticketFromProtocols(r.Header.Values("Sec-WebSocket-Protocol"))))
	b.mu.Lock()
	p := b.shareTickets[hash]
	valid := p != nil && !p.used && time.Now().Before(p.expires) && p.session.id == r.PathValue("sessionID") && !p.session.closing
	if valid {
		p.used = true
		p.history = append([]byte(nil), p.session.shareHistory...)
		p.timer.Stop()
	}
	b.mu.Unlock()
	if !valid {
		http.Error(w, "share ticket is invalid", 401)
		return
	}
	defer func() {
		b.mu.Lock()
		b.stopSharePeerLocked(p)
		b.mu.Unlock()
		_ = b.shares.Leave(p.member.ID, p.member.Actor.ID)
		b.cancelSharedReview(p)
	}()
	if b.shareAccess(r.Context(), p) != nil {
		http.Error(w, "share access denied", 403)
		return
	}
	conn, e := websocket.Accept(w, r, &websocket.AcceptOptions{Subprotocols: []string{ShareSubprotocol}})
	if e != nil {
		return
	}
	defer conn.CloseNow()
	conn.SetReadLimit(64 * 1024)
	if b.appendShareAudit(sessionshares.Event{Kind: "share_connected", SessionID: p.member.SessionID, ShareID: p.member.ShareID, MemberID: p.member.ID, Actor: p.member.Actor, Mode: p.member.Mode, At: time.Now().UTC()}) != nil {
		return
	}
	defer func() {
		_ = b.appendShareAudit(sessionshares.Event{Kind: "share_disconnected", SessionID: p.member.SessionID, ShareID: p.member.ShareID, MemberID: p.member.ID, Actor: p.member.Actor, At: time.Now().UTC()})
	}()
	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()
	go func() { _ = b.readShare(ctx, conn, p); cancel() }()
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	write := func(kind websocket.MessageType, data []byte) error {
		if e := b.shareAccess(ctx, p); e != nil {
			return e
		}
		select {
		case <-p.done:
			return sessionshares.ErrDenied
		default:
		}
		deadline, stop := context.WithTimeout(ctx, 5*time.Second)
		defer stop()
		return conn.Write(deadline, kind, data)
	}
	state := func() error {
		b.mu.Lock()
		cols, rows := p.session.cols, p.session.rows
		pending := p.session.pendingReview != nil
		b.mu.Unlock()
		data, _ := json.Marshal(map[string]any{"type": "share_state", "member_id": p.member.ID, "controller": b.shares.Controller(p.session.id), "mode": p.member.Mode, "review_pending": pending, "cols": cols, "rows": rows})
		return write(websocket.MessageText, data)
	}
	if state() != nil {
		return
	}
	if len(p.history) > 0 {
		if write(websocket.MessageBinary, p.history) != nil {
			return
		}
		p.history = nil
	}
	for {
		select {
		case <-ctx.Done():
			return
		case <-p.done:
			return
		case <-ticker.C:
			if state() != nil {
				return
			}
		case data := <-p.output:
			if write(websocket.MessageBinary, data) != nil {
				return
			}
		}
	}
}

func (b *Broker) cancelSharedReview(p *sharePeer) {
	b.mu.Lock()
	pending := p.session.pendingReview
	id := ""
	if pending != nil && pending.identity.MemberID == p.member.ID {
		id = pending.request.ID
	}
	b.mu.Unlock()
	if id == "" {
		return
	}
	stop := time.AfterFunc(5*time.Second, func() { b.closeSession(p.session, "share_review_cancel_failed") })
	defer stop.Stop()
	_ = b.ResolveCommandReview(id, "system", false)
}
