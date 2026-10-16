package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/coder/websocket"
)

const commandReviewLifetime = 5 * time.Minute

var (
	ErrCommandReviewNotFound   = errors.New("command review not found")
	ErrCommandReviewInProgress = errors.New("command review is already being resolved")
	ErrCommandReviewExpired    = errors.New("command review expired")
)

type CommandReview struct {
	ID          string    `json:"id"`
	SessionID   string    `json:"session_id"`
	AssetID     string    `json:"asset_id"`
	AssetName   string    `json:"asset_name"`
	Operator    string    `json:"operator"`
	Account     string    `json:"account"`
	Command     string    `json:"command"`
	RuleName    string    `json:"rule_name"`
	RequestedAt time.Time `json:"requested_at"`
	ExpiresAt   time.Time `json:"expires_at"`
}

type pendingCommandReview struct {
	request    CommandReview
	submission commandSubmission
	timer      *time.Timer
	resolving  bool
}

func (b *Broker) createCommandReview(ctx context.Context, conn *websocket.Conn, session *activeSession, submission commandSubmission, ruleName string) (CommandReview, error) {
	id, err := randomToken(18)
	if err != nil {
		return CommandReview{}, fmt.Errorf("create command review ID: %w", err)
	}
	now := time.Now().UTC()
	review := CommandReview{
		ID: id, SessionID: session.id, AssetID: session.asset.ID,
		AssetName: session.asset.Name, Operator: session.operator,
		Account: session.asset.Username, Command: submission.Command,
		RuleName: ruleName, RequestedAt: now, ExpiresAt: now.Add(commandReviewLifetime),
	}
	submission.Outcome = "pending"
	submission.RuleName = ruleName
	submission.ReviewID = id
	if err := b.appendCommand(session.id, submission); err != nil {
		return CommandReview{}, err
	}
	pending := &pendingCommandReview{request: review, submission: submission}
	b.mu.Lock()
	if b.sessions[session.id] != session || session.pendingReview != nil {
		b.mu.Unlock()
		submission.SubmittedAt = time.Now().UTC()
		submission.Outcome = "cancelled"
		submission.ReviewedBy = "system"
		_ = b.appendCommand(session.id, submission)
		return CommandReview{}, ErrCommandReviewInProgress
	}
	session.pendingReview = pending
	pending.timer = time.AfterFunc(commandReviewLifetime, func() {
		_ = b.resolveCommandReview(id, "system", false, true)
	})
	b.mu.Unlock()
	message, err := json.Marshal(struct {
		Type      string    `json:"type"`
		ReviewID  string    `json:"review_id"`
		RuleName  string    `json:"rule_name"`
		ExpiresAt time.Time `json:"expires_at"`
	}{Type: "command_review_pending", ReviewID: review.ID, RuleName: review.RuleName, ExpiresAt: review.ExpiresAt})
	if err != nil {
		return CommandReview{}, fmt.Errorf("encode command review notice: %w", err)
	}
	if err := session.writeWebSocket(ctx, conn, websocket.MessageText, message); err != nil {
		return CommandReview{}, err
	}
	return review, nil
}

func (b *Broker) ListPendingCommandReviews() []CommandReview {
	now := time.Now().UTC()
	b.mu.Lock()
	reviews := make([]CommandReview, 0)
	for _, session := range b.sessions {
		pending := session.pendingReview
		if pending == nil || pending.resolving || !now.Before(pending.request.ExpiresAt) {
			continue
		}
		reviews = append(reviews, pending.request)
	}
	b.mu.Unlock()
	sort.Slice(reviews, func(i, j int) bool { return reviews[i].RequestedAt.After(reviews[j].RequestedAt) })
	return reviews
}

func (b *Broker) ResolveCommandReview(id, reviewer string, approve bool) error {
	return b.resolveCommandReview(id, reviewer, approve, false)
}

func (b *Broker) resolveCommandReview(id, reviewer string, approve, automatic bool) error {
	id = strings.TrimSpace(id)
	reviewer = strings.TrimSpace(reviewer)
	if !validSessionID(id) || (!automatic && reviewer == "") {
		return ErrCommandReviewNotFound
	}
	b.mu.Lock()
	var session *activeSession
	var pending *pendingCommandReview
	for _, candidate := range b.sessions {
		if candidate.pendingReview != nil && candidate.pendingReview.request.ID == id {
			session = candidate
			pending = candidate.pendingReview
			break
		}
	}
	if pending == nil {
		b.mu.Unlock()
		return ErrCommandReviewNotFound
	}
	if pending.resolving {
		b.mu.Unlock()
		return ErrCommandReviewInProgress
	}
	if pending.timer != nil {
		pending.timer.Stop()
	}
	expired := automatic || !time.Now().UTC().Before(pending.request.ExpiresAt)
	if expired {
		approve = false
		reviewer = "system"
	}
	pending.resolving = true
	b.mu.Unlock()

	outcome := "denied"
	input := []byte{0x03}
	noticeType := "command_review_denied"
	if expired {
		outcome = "timed_out"
		noticeType = "command_review_timed_out"
	} else if approve {
		outcome = "approved"
		input = []byte{'\r'}
		noticeType = "command_review_approved"
	}

	session.inputMu.Lock()
	b.mu.Lock()
	active := b.sessions[session.id] == session && session.pendingReview == pending
	conn := session.terminalSocket
	b.mu.Unlock()
	if !active || conn == nil {
		session.inputMu.Unlock()
		return ErrCommandReviewNotFound
	}
	submission := pending.submission
	submission.SubmittedAt = time.Now().UTC()
	submission.Outcome = outcome
	submission.ReviewedBy = reviewer
	if err := b.appendCommand(session.id, submission); err != nil {
		session.inputMu.Unlock()
		b.closeSession(session, "command_review_audit_failed")
		return err
	}
	notice, err := json.Marshal(struct {
		Type     string `json:"type"`
		RuleName string `json:"rule_name"`
	}{Type: noticeType, RuleName: pending.request.RuleName})
	if err != nil {
		session.inputMu.Unlock()
		b.closeSession(session, "command_review_notice_failed")
		return fmt.Errorf("encode command review result: %w", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	writeErr := session.writeWebSocket(ctx, conn, websocket.MessageText, notice)
	cancel()
	if writeErr != nil {
		session.inputMu.Unlock()
		b.closeSession(session, "command_review_notice_failed")
		return writeErr
	}
	if err := session.recorder.Record('i', input); err != nil {
		session.inputMu.Unlock()
		b.closeSession(session, "command_review_recording_failed")
		return err
	}
	if err := writeAll(session.terminal, input); err != nil {
		session.inputMu.Unlock()
		b.closeSession(session, "command_review_write_failed")
		return err
	}
	b.mu.Lock()
	if session.pendingReview == pending {
		session.pendingReview = nil
	}
	b.mu.Unlock()
	session.inputMu.Unlock()
	if expired && !automatic {
		return ErrCommandReviewExpired
	}
	return nil
}
