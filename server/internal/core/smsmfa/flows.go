package smsmfa

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"math/big"
	"net"
	"slices"
	"time"

	"github.com/neko233-com/jumpserver233/server/internal/core/auth"
	"github.com/neko233-com/jumpserver233/server/internal/workgate"
)

type BeginInput struct {
	UserID, Proof, AuthSource, SourceIP, IdentityStamp string
	Generation                                         int
	ExpiresAt                                          time.Time
	Browser, Secure                                    bool
}
type Status struct {
	Active        bool      `json:"active"`
	Purpose       string    `json:"purpose"`
	MaskedPhone   string    `json:"masked_phone"`
	DeliveryState string    `json:"delivery_state"`
	ExpiresAt     time.Time `json:"expires_at"`
	RetryAt       time.Time `json:"retry_at,omitzero"`
	NeedsPhone    bool      `json:"needs_phone"`
}
type Verified struct {
	UserID, Phone, Proof, AuthSource, Kind string
	Generation                             int
	Browser, Secure                        bool
}

func randomValue() (string, error) {
	var b [32]byte
	if _, e := rand.Read(b[:]); e != nil {
		return "", e
	}
	return base64.RawURLEncoding.EncodeToString(b[:]), nil
}
func publicFlow(f flow) Status {
	retry := time.Time{}
	if !f.SentAt.IsZero() {
		retry = f.SentAt.Add(time.Minute)
	}
	return Status{Active: true, Purpose: f.Kind, MaskedPhone: MaskedPhone(f.Phone), DeliveryState: f.DeliveryState, ExpiresAt: f.ExpiresAt, RetryAt: retry, NeedsPhone: f.Phone == ""}
}
func (s *Service) operation(ctx context.Context) (context.Context, func(), error) {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil, nil, ErrUnavailable
	}
	s.wg.Add(1)
	s.mu.Unlock()
	ctx, cancel := context.WithTimeout(ctx, 25*time.Second)
	stop := context.AfterFunc(s.life, cancel)
	ctx, release, e := workgate.FromContext(ctx).Enter(ctx, "sms_mfa")
	if e != nil {
		stop()
		cancel()
		s.wg.Done()
		return nil, nil, e
	}
	select {
	case s.slots <- struct{}{}:
	case <-ctx.Done():
		release()
		stop()
		cancel()
		s.wg.Done()
		return nil, nil, ctx.Err()
	default:
		release()
		stop()
		cancel()
		s.wg.Done()
		return nil, nil, ErrCapacity
	}
	return ctx, func() { <-s.slots; release(); stop(); cancel(); s.wg.Done() }, nil
}
func (s *Service) currentLocked(f flow) bool {
	if s.closed || !s.data.Config.Enabled || s.data.Config.Revision != f.Revision || s.transport.MFARevision() != f.TransportRevision || !s.now().Before(f.ExpiresAt) || s.auth.SMSIdentityStamp(f.UserID) != f.IdentityStamp {
		return false
	}
	phone, generation, e := s.auth.SMSContact(f.UserID)
	if e != nil || generation != f.Generation {
		return false
	}
	if f.Kind == "login" || f.Kind == "disable" {
		if phone != f.Phone {
			return false
		}
	}
	if f.Kind == "login" || f.Kind == "login-enroll" {
		return s.auth.ValidateLoginProof(f.Proof, f.UserID) == nil
	}
	return true
}
func (s *Service) findLocked(ticket, ip string) (string, flow, error) {
	if ticket == "" || len(ticket) > 128 || net.ParseIP(ip) == nil {
		return "", flow{}, ErrFlow
	}
	id := digest(ticket)
	f, ok := s.data.Flows[id]
	if !ok || f.SourceIP != ip || f.Attempts >= 5 || !s.currentLocked(f) {
		return "", flow{}, ErrFlow
	}
	return id, f, nil
}
func (s *Service) Status(ticket, ip string) (Status, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, f, e := s.findLocked(ticket, ip)
	if e != nil {
		return Status{}, e
	}
	return publicFlow(f), nil
}
func (s *Service) AuditSubject(ticket, ip string) (string, string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, f, e := s.findLocked(ticket, ip)
	if e != nil {
		return "", ""
	}
	return f.UserID, f.AuthSource
}
func (s *Service) clean(next *state) {
	now := s.now()
	for id, f := range next.Flows {
		if !now.Before(f.ExpiresAt) {
			delete(next.Flows, id)
		}
	}
	for key, times := range next.Rates {
		recent := times[:0]
		for _, at := range times {
			if at.After(now.Add(-time.Hour)) {
				recent = append(recent, at)
			}
		}
		if len(recent) == 0 {
			delete(next.Rates, key)
		} else {
			next.Rates[key] = recent
		}
	}
}
func (s *Service) BeginLogin(ctx context.Context, in BeginInput) (string, Status, error) {
	if s.auth.ValidateLoginProof(in.Proof, in.UserID) != nil {
		return "", Status{}, ErrFlow
	}
	phone, generation, e := s.auth.SMSContact(in.UserID)
	if e != nil {
		return "", Status{}, ErrFlow
	}
	in.Generation = generation
	in.IdentityStamp = s.auth.SMSIdentityStamp(in.UserID)
	kind := "login"
	if phone == "" {
		kind = "login-enroll"
	}
	return s.begin(ctx, in, kind, phone)
}
func (s *Service) BeginBinding(ctx context.Context, user auth.User, identityStamp, phone, ip string, secure bool) (string, Status, error) {
	if phone != "" && !phonePattern.MatchString(phone) || !validHash(identityStamp) {
		return "", Status{}, ErrInvalid
	}
	current, generation, e := s.auth.SMSContact(user.ID)
	if e != nil || user.AuthGeneration != generation {
		return "", Status{}, ErrFlow
	}
	kind := "enroll"
	if phone == "" {
		if current == "" {
			return "", Status{}, ErrInvalid
		}
		kind = "disable"
		phone = current
	}
	source := user.Source
	if source == "" {
		source = "local"
	}
	return s.begin(ctx, BeginInput{UserID: user.ID, AuthSource: source, SourceIP: ip, IdentityStamp: identityStamp, Generation: generation, Browser: true, Secure: secure}, kind, phone)
}
func (s *Service) begin(ctx context.Context, in BeginInput, kind, phone string) (string, Status, error) {
	ctx, done, e := s.operation(ctx)
	if e != nil {
		return "", Status{}, e
	}
	defer done()
	if !idPattern.MatchString(in.UserID) || net.ParseIP(in.SourceIP) == nil || !text(in.AuthSource, 32) || len(in.Proof) > 8192 {
		return "", Status{}, ErrInvalid
	}
	ticket, e := randomValue()
	if e != nil {
		return "", Status{}, e
	}
	_, generation, e := s.auth.SMSContact(in.UserID)
	if e != nil {
		return "", Status{}, ErrFlow
	}
	s.mu.Lock()
	if !s.data.Config.Enabled {
		s.mu.Unlock()
		return "", Status{}, ErrDisabled
	}
	transportRevision := s.transport.MFARevision()
	if transportRevision == 0 {
		s.mu.Unlock()
		return "", Status{}, ErrUnavailable
	}
	next := clone(s.data)
	s.clean(&next)
	if len(next.Flows) >= 1000 {
		s.mu.Unlock()
		return "", Status{}, ErrCapacity
	}
	expires := s.now().Add(5 * time.Minute)
	if !in.ExpiresAt.IsZero() && in.ExpiresAt.Before(expires) {
		expires = in.ExpiresAt
	}
	f := flow{UserID: in.UserID, IdentityStamp: in.IdentityStamp, Generation: in.Generation, AuthSource: in.AuthSource, SourceIP: in.SourceIP, Phone: phone, Proof: in.Proof, Kind: kind, Revision: s.data.Config.Revision, TransportRevision: transportRevision, ExpiresAt: expires, Browser: in.Browser, Secure: in.Secure, Requests: map[string]sendReceipt{}, DeliveryState: "unbound"}
	if generation != in.Generation || !s.currentLocked(f) {
		s.mu.Unlock()
		return "", Status{}, ErrFlow
	}
	id := digest(ticket)
	next.Flows[id] = f
	s.addAudit(&next, in.UserID, in.UserID, "flow_started")
	e = s.commit(next)
	s.mu.Unlock()
	if e != nil {
		return "", Status{}, e
	}
	if phone == "" {
		return ticket, publicFlow(f), nil
	}
	status, e := s.send(ctx, ticket, in.SourceIP, "initial", "")
	if e == ErrRate {
		status, e = s.Status(ticket, in.SourceIP)
	}
	return ticket, status, e
}
func (s *Service) BindLoginPhone(ctx context.Context, ticket, ip, phone, requestID string) (Status, error) {
	if !phonePattern.MatchString(phone) {
		return Status{}, ErrInvalid
	}
	ctx, done, e := s.operation(ctx)
	if e != nil {
		return Status{}, e
	}
	defer done()
	return s.send(ctx, ticket, ip, requestID, phone)
}
func (s *Service) Resend(ctx context.Context, ticket, ip, requestID string) (Status, error) {
	ctx, done, e := s.operation(ctx)
	if e != nil {
		return Status{}, e
	}
	defer done()
	return s.send(ctx, ticket, ip, requestID, "")
}
func (s *Service) send(ctx context.Context, ticket, ip, requestID, bindPhone string) (Status, error) {
	if !idPattern.MatchString(requestID) {
		return Status{}, ErrInvalid
	}
	codeNumber, e := rand.Int(rand.Reader, big.NewInt(1_000_000))
	if e != nil {
		return Status{}, e
	}
	code := fmt.Sprintf("%06d", codeNumber.Int64())
	nonce, e := randomValue()
	if e != nil {
		return Status{}, e
	}
	delivery, e := randomValue()
	if e != nil {
		return Status{}, e
	}
	delivery = "sms-mfa-" + delivery
	s.mu.Lock()
	id, f, e := s.findLocked(ticket, ip)
	if e != nil {
		s.mu.Unlock()
		return Status{}, e
	}
	if previous, seen := f.Requests[requestID]; seen {
		s.mu.Unlock()
		if previous.Hash != digest(bindPhone) {
			return Status{}, ErrConflict
		}
		return publicFlow(f), nil
	}
	if len(f.Requests) >= 32 {
		s.mu.Unlock()
		return Status{}, ErrCapacity
	}
	if f.DeliveryState == "sending" {
		s.mu.Unlock()
		return Status{}, ErrConflict
	}
	if bindPhone != "" {
		if f.Kind != "login-enroll" || f.Phone != "" && f.Phone != bindPhone {
			s.mu.Unlock()
			return Status{}, ErrFlow
		}
		f.Phone = bindPhone
	}
	if f.Phone == "" {
		s.mu.Unlock()
		return Status{}, ErrFlow
	}
	now := s.now().UTC()
	if !f.SentAt.IsZero() && now.Before(f.SentAt.Add(time.Minute)) {
		s.mu.Unlock()
		return Status{}, ErrRate
	}
	next := clone(s.data)
	s.clean(&next)
	keys := []string{digest("user:" + f.UserID), digest("phone:" + f.Phone), digest("ip:" + f.SourceIP)}
	for dimension, key := range keys {
		recent := next.Rates[key]
		limit := 6
		if dimension == 2 {
			limit = 120
		}
		if len(recent) >= limit || dimension < 2 && len(recent) > 0 && now.Before(recent[len(recent)-1].Add(time.Minute)) {
			s.mu.Unlock()
			return Status{}, ErrRate
		}
		if len(recent) == 0 && len(next.Rates) >= 20000 {
			s.mu.Unlock()
			return Status{}, ErrCapacity
		}
		next.Rates[key] = append(recent, now)
	}
	f.Nonce = nonce
	f.CodeHash = digest(id + "\x00" + nonce + "\x00" + code)
	f.Delivery = delivery
	f.DeliveryState = "sending"
	f.SentAt = now
	f.Attempts = 0
	if f.Requests == nil {
		f.Requests = map[string]sendReceipt{}
	}
	f.Requests[requestID] = sendReceipt{At: now, Hash: digest(bindPhone)}
	next.Flows[id] = f
	s.addAudit(&next, f.UserID, f.UserID, "code_requested")
	e = s.commit(next)
	s.mu.Unlock()
	if e != nil {
		return Status{}, e
	}
	check := func() error {
		s.mu.Lock()
		defer s.mu.Unlock()
		current, ok := s.data.Flows[id]
		if !ok || current.Delivery != delivery || !s.currentLocked(current) {
			return ErrFlow
		}
		return ctx.Err()
	}
	outcome := s.transport.SendMFA(ctx, f.TransportRevision, f.Phone, delivery, code, check)
	s.mu.Lock()
	defer s.mu.Unlock()
	current, ok := s.data.Flows[id]
	if !ok || current.Delivery != delivery || !s.currentLocked(current) {
		return Status{}, ErrFlow
	}
	switch outcome.State {
	case "sent", "uncertain":
		current.DeliveryState = outcome.State
	default:
		current.DeliveryState = "failed"
		current.CodeHash = ""
	}
	next = clone(s.data)
	next.Flows[id] = current
	s.addAudit(&next, current.UserID, current.UserID, "code_"+current.DeliveryState)
	if e = s.commit(next); e != nil {
		return Status{}, e
	}
	return publicFlow(current), nil
}

// Finish persists one-time consumption before invoking the trusted action. The
// callback may resume a login proof or bind a phone, but must not call Service.
// stamp returns the current identity/config stamp while this operation is held.
func (s *Service) Finish(ctx context.Context, ticket, ip, code string, apply func(Verified, func() string) error) error {
	ctx, done, e := s.operation(ctx)
	if e != nil {
		return e
	}
	defer done()
	if apply == nil {
		return ErrInvalid
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	id, f, e := s.findLocked(ticket, ip)
	if e != nil {
		return e
	}
	if f.DeliveryState == "sending" {
		return ErrConflict
	}
	if !slices.Contains([]string{"sent", "uncertain"}, f.DeliveryState) || f.CodeHash == "" {
		return ErrFlow
	}
	if e = ctx.Err(); e != nil {
		return e
	}
	want := digest(id + "\x00" + f.Nonce + "\x00" + code)
	validCode := len(code) == 6
	for _, digit := range code {
		if digit < '0' || digit > '9' {
			validCode = false
		}
	}
	next := clone(s.data)
	if !validCode || subtle.ConstantTimeCompare([]byte(want), []byte(f.CodeHash)) != 1 {
		f.Attempts++
		if f.Attempts >= 5 {
			delete(next.Flows, id)
		} else {
			next.Flows[id] = f
		}
		s.addAudit(&next, f.UserID, f.UserID, "code_rejected")
		if e = s.commit(next); e != nil {
			return e
		}
		return ErrRejected
	}
	delete(next.Flows, id)
	s.addAudit(&next, f.UserID, f.UserID, "code_verified")
	if e = s.commit(next); e != nil {
		return e
	}
	if e := apply(Verified{f.UserID, f.Phone, f.Proof, f.AuthSource, f.Kind, f.Generation, f.Browser, f.Secure}, func() string { return s.stampLocked(f.UserID) }); e != nil {
		return e
	}
	next = clone(s.data)
	if f.Kind == "login-enroll" {
		s.addAudit(&next, f.UserID, f.UserID, "binding_updated")
	}
	action := "factor_completed"
	if f.Kind == "enroll" || f.Kind == "disable" {
		action = "binding_updated"
	}
	s.addAudit(&next, f.UserID, f.UserID, action)
	return s.commit(next)
}
func (s *Service) Cancel(ticket, ip string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	id, f, e := s.findLocked(ticket, ip)
	if e != nil {
		return nil
	}
	next := clone(s.data)
	delete(next.Flows, id)
	s.addAudit(&next, f.UserID, f.UserID, "cancelled")
	return s.commit(next)
}
