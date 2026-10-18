package radiuslogin

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/neko233-com/jumpserver233/server/internal/connector/radiusclient"
)

type flow struct {
	Kind        string    `json:"kind"`
	State       string    `json:"state"`
	UserID      string    `json:"user_id,omitempty"`
	Username    string    `json:"username"`
	RemoteName  string    `json:"remote_name"`
	SourceIP    string    `json:"source_ip"`
	AuthSource  string    `json:"auth_source,omitempty"`
	Proof       string    `json:"proof,omitempty"`
	Revision    int       `json:"revision"`
	Attempts    int       `json:"attempts"`
	Round       int       `json:"round"`
	RemoteState []byte    `json:"remote_state,omitempty"`
	ExpiresAt   time.Time `json:"expires_at"`
	Browser     bool      `json:"browser"`
	Secure      bool      `json:"secure"`
}
type FlowStatus struct {
	Kind      string    `json:"kind"`
	State     string    `json:"state"`
	Round     int       `json:"round"`
	Attempts  int       `json:"attempts"`
	ExpiresAt time.Time `json:"expires_at"`
}
type FactorInput struct {
	UserID, Username, RemoteName, SourceIP, AuthSource, Proof string
	ExpiresAt                                                 time.Time
	Browser, Secure                                           bool
}
type VerifiedFactor struct {
	UserID, Proof, Stamp, AuthSource string
	Browser, Secure                  bool
}
type PrimaryResult struct {
	Challenge bool
	Status    FlowStatus
	Identity  Identity
	Ticket    string
}

func publicFlow(f flow) FlowStatus {
	return FlowStatus{Kind: f.Kind, State: f.State, Round: f.Round, Attempts: f.Attempts, ExpiresAt: f.ExpiresAt}
}
func policyStamp(c Config) string {
	sum := sha256.Sum256([]byte("jms233/radius/factor/" + c.Realm + "/" + strconv.Itoa(c.Revision)))
	return hex.EncodeToString(sum[:])
}
func validateFlow(f flow) error {
	if f.Kind != "primary" && f.Kind != "factor" || f.Revision < 1 || !validRemote(f.RemoteName) || len(f.Username) > 128 || f.Attempts < 0 || f.Attempts > 5 || f.Round < 0 || f.Round > 4 || len(f.RemoteState) > 253 || len(f.Proof) > 8192 || f.ExpiresAt.IsZero() {
		return ErrInvalid
	}
	if _, e := netip.ParseAddr(f.SourceIP); e != nil {
		return ErrInvalid
	}
	switch f.State {
	case "pending", "verifying", "consumed", "rejected", "interrupted", "cancelled":
	default:
		return ErrInvalid
	}
	if f.Kind == "factor" && (!validID(f.UserID) || len(f.AuthSource) > 32) {
		return ErrInvalid
	}
	return nil
}
func flowHash(ticket string) string {
	sum := sha256.Sum256([]byte(ticket))
	return hex.EncodeToString(sum[:])
}
func (s *Service) findLocked(ticket, source, kind string) (string, flow, error) {
	if len(ticket) != 43 {
		return "", flow{}, ErrFlow
	}
	id := flowHash(ticket)
	f, ok := s.data.Flows[id]
	if !ok || f.SourceIP != source || f.Kind != kind || f.Revision != s.data.Config.Revision || !s.now().Before(f.ExpiresAt) {
		return "", flow{}, ErrFlow
	}
	return id, f, nil
}
func (s *Service) Status(ticket, source, kind string) (FlowStatus, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, f, e := s.findLocked(ticket, source, kind)
	return publicFlow(f), e
}
func (s *Service) begin(f flow) (string, FlowStatus, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return "", FlowStatus{}, ErrDisabled
	}
	if f.Kind == "primary" && !s.data.Config.Enabled || f.Kind == "factor" && s.data.Config.FactorPolicy == "disabled" {
		return "", FlowStatus{}, ErrDisabled
	}
	next := cloneState(s.data)
	now := s.now().UTC()
	for id, old := range next.Flows {
		if !now.Before(old.ExpiresAt) {
			delete(next.Flows, id)
		}
	}
	if len(next.Flows) >= MaxFlows {
		return "", FlowStatus{}, ErrCapacity
	}
	live := 0
	for _, old := range next.Flows {
		if old.UserID == f.UserID && old.RemoteName == f.RemoteName && (old.State == "pending" || old.State == "verifying") {
			live++
		}
	}
	if live >= 5 {
		return "", FlowStatus{}, ErrCapacity
	}
	if f.ExpiresAt.IsZero() || f.ExpiresAt.After(now.Add(5*time.Minute)) {
		f.ExpiresAt = now.Add(5 * time.Minute)
	}
	if !f.ExpiresAt.After(now) {
		return "", FlowStatus{}, ErrFlow
	}
	f.State = "pending"
	f.Revision = next.Config.Revision
	if validateFlow(f) != nil {
		return "", FlowStatus{}, ErrInvalid
	}
	var raw [32]byte
	if _, e := rand.Read(raw[:]); e != nil {
		return "", FlowStatus{}, e
	}
	ticket := base64.RawURLEncoding.EncodeToString(raw[:])
	next.Flows[flowHash(ticket)] = f
	if e := s.persist(next); e != nil {
		return "", FlowStatus{}, e
	}
	s.data = next
	return ticket, publicFlow(f), nil
}
func (s *Service) BeginFactor(in FactorInput) (string, FlowStatus, error) {
	if in.Proof == "" || in.UserID == "" {
		return "", FlowStatus{}, ErrInvalid
	}
	return s.begin(flow{Kind: "factor", UserID: in.UserID, Username: in.Username, RemoteName: in.RemoteName, SourceIP: in.SourceIP, AuthSource: in.AuthSource, Proof: in.Proof, ExpiresAt: in.ExpiresAt, Browser: in.Browser, Secure: in.Secure})
}
func (s *Service) StartPrimary(ctx context.Context, username, password, source string) (PrimaryResult, error) {
	if !validRemote(username) || len(password) > 128 {
		return PrimaryResult{}, ErrRejected
	}
	ticket, _, e := s.begin(flow{Kind: "primary", Username: username, RemoteName: username, SourceIP: source, AuthSource: "radius"})
	if e != nil {
		return PrimaryResult{}, e
	}
	reply, f, e := s.step(ctx, ticket, source, "primary", password)
	if e != nil {
		return PrimaryResult{}, e
	}
	out := PrimaryResult{Challenge: reply.Code == radiusclient.AccessChallenge, Status: publicFlow(f), Ticket: ticket}
	if !out.Challenge {
		c := s.Snapshot()
		if c.Revision != f.Revision {
			return PrimaryResult{}, ErrConflict
		}
		out.Identity = Identity{Issuer: issuer(c.Config), Subject: f.RemoteName, Provision: c.ProvisionNew, Revision: f.Revision}
	}
	return out, nil
}
func (s *Service) AnswerPrimary(ctx context.Context, ticket, source, response string) (PrimaryResult, error) {
	reply, f, e := s.step(ctx, ticket, source, "primary", response)
	if e != nil {
		return PrimaryResult{}, e
	}
	out := PrimaryResult{Challenge: reply.Code == radiusclient.AccessChallenge, Status: publicFlow(f), Ticket: ticket}
	if !out.Challenge {
		c := s.Snapshot()
		if c.Revision != f.Revision {
			return PrimaryResult{}, ErrConflict
		}
		out.Identity = Identity{Issuer: issuer(c.Config), Subject: f.RemoteName, Provision: c.ProvisionNew, Revision: f.Revision}
	}
	return out, nil
}
func (s *Service) VerifyFactor(ctx context.Context, ticket, source, response string) (VerifiedFactor, FlowStatus, error) {
	reply, f, e := s.step(ctx, ticket, source, "factor", response)
	if e != nil {
		return VerifiedFactor{}, publicFlow(f), e
	}
	if reply.Code == radiusclient.AccessChallenge {
		return VerifiedFactor{}, publicFlow(f), nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.data.Config.Revision != f.Revision {
		return VerifiedFactor{}, FlowStatus{}, ErrConflict
	}
	return VerifiedFactor{UserID: f.UserID, Proof: f.Proof, Stamp: policyStamp(s.data.Config), AuthSource: f.AuthSource, Browser: f.Browser, Secure: f.Secure}, publicFlow(f), nil
}
func (s *Service) step(ctx context.Context, ticket, source, kind, response string) (radiusclient.Reply, flow, error) {
	if len(response) > 128 || strings.ContainsRune(response, 0) {
		return radiusclient.Reply{}, flow{}, ErrRejected
	}
	s.mu.Lock()
	id, f, e := s.findLocked(ticket, source, kind)
	if e != nil {
		s.mu.Unlock()
		return radiusclient.Reply{}, flow{}, e
	}
	if f.State == "verifying" {
		s.mu.Unlock()
		return radiusclient.Reply{}, f, ErrBusy
	}
	if s.closed || f.State != "pending" || f.Attempts >= 5 || f.Round >= 4 {
		s.mu.Unlock()
		return radiusclient.Reply{}, f, ErrFlow
	}
	c, secret := s.data.Config.Primary, s.data.PrimarySecrets
	if kind == "factor" {
		c, secret = s.data.Config.Factor, s.data.FactorSecrets
	}
	next := cloneState(s.data)
	f.State = "verifying"
	f.Attempts++
	next.Flows[id] = f
	if e = s.persist(next); e != nil {
		s.mu.Unlock()
		return radiusclient.Reply{}, f, e
	}
	s.data = next
	s.mu.Unlock()
	reply, exchangeError := s.exchange(ctx, c, secret, radiusclient.Request{Username: f.RemoteName, Password: response, State: f.RemoteState})
	s.mu.Lock()
	defer s.mu.Unlock()
	current, ok := s.data.Flows[id]
	if s.closed || !ok || current.State != "verifying" || s.data.Config.Revision != f.Revision || !s.now().Before(f.ExpiresAt) {
		return radiusclient.Reply{}, f, ErrFlow
	}
	next = cloneState(s.data)
	switch {
	case exchangeError != nil:
		current.State = "interrupted"
	case reply.Code == radiusclient.AccessReject:
		current.State = "rejected"
	case reply.Code == radiusclient.AccessChallenge:
		current.State = "pending"
		current.Round++
		current.RemoteState = append([]byte(nil), reply.State...)
		if current.Round >= 4 || current.Attempts >= 5 {
			current.State = "rejected"
		}
	case reply.Code == radiusclient.AccessAccept:
		current.State = "consumed"
	default:
		current.State = "interrupted"
		exchangeError = radiusclient.ErrProtocol
	}
	// The durable one-use consumption precedes any session-resume callback.
	returned := current
	if current.State != "pending" {
		current.Proof = ""
		current.RemoteState = nil
	}
	next.Flows[id] = current
	if e = s.persist(next); e != nil {
		return radiusclient.Reply{}, flow{}, e
	}
	s.data = next
	if exchangeError != nil {
		return radiusclient.Reply{}, returned, exchangeError
	}
	if returned.State == "rejected" {
		return radiusclient.Reply{}, returned, ErrRejected
	}
	return reply, returned, nil
}
func (s *Service) Cancel(ticket, source, kind string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	id, f, e := s.findLocked(ticket, source, kind)
	if e != nil {
		return e
	}
	if f.State == "consumed" {
		return ErrFlow
	}
	f.State = "cancelled"
	f.Proof = ""
	f.RemoteState = nil
	next := cloneState(s.data)
	next.Flows[id] = f
	if e = s.persist(next); e != nil {
		return e
	}
	s.data = next
	return nil
}
func Rejected(e error) bool {
	return errors.Is(e, ErrRejected) || errors.Is(e, radiusclient.ErrCredentials)
}
