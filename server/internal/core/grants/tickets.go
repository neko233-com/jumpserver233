package grants

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"regexp"
	"slices"
	"sort"
	"strings"
	"time"
)

var (
	ErrTicketConflict = errors.New("ticket grant intent changed")
	ErrTicketRevoked  = errors.New("ticket grant issuance was revoked")
	ErrTicketCapacity = errors.New("ticket grant receipt capacity reached")
)

const maxTicketBatches = 5000

var ticketIDPattern = regexp.MustCompile(`^ticket-[0-9a-f]{32}$`)

type ticketBatch struct {
	TicketID  string    `json:"ticket_id"`
	Digest    string    `json:"digest"`
	InputHash string    `json:"input_hash,omitempty"`
	GrantIDs  []string  `json:"grant_ids"`
	Revoked   bool      `json:"revoked"`
	ExpiresAt time.Time `json:"expires_at"`
	CreatedAt time.Time `json:"created_at"`
}

// TicketReceipt contains metadata only. Missing grants are never reissued.
type TicketReceipt struct {
	State     string
	GrantIDs  []string
	ExpiresAt time.Time
	Digest    string
}

// SetTicketGuard is installed before serving requests. A source grant stays
// unusable until its workflow is durably approved. The callback must not call
// this grant store, because authorization already holds the store read lock.
func (s *Store) SetTicketGuard(guard func(Grant, time.Time) bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ticketGuard = guard
}

func digestValid(v string) bool {
	if len(v) != 64 {
		return false
	}
	_, e := hex.DecodeString(v)
	return e == nil
}
func (s *Store) decodeRecords(data []byte, out *[]Grant) error {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) > 0 && trimmed[0] == '{' {
		var box struct {
			Format  int                    `json:"format"`
			Grants  []Grant                `json:"grants"`
			Tickets map[string]ticketBatch `json:"ticket_receipts"`
		}
		d := json.NewDecoder(bytes.NewReader(data))
		d.DisallowUnknownFields()
		if d.Decode(&box) != nil || d.Decode(new(any)) != io.EOF || box.Format != 2 || box.Grants == nil || box.Tickets == nil {
			return ErrInvalidInput
		}
		*out = box.Grants
		s.tickets = box.Tickets
		return nil
	}
	if e := json.Unmarshal(data, out); e != nil {
		return e
	}
	for _, g := range *out {
		if g.SourceTicketID != "" {
			return ErrInvalidInput
		}
	}
	return nil
}
func (s *Store) encodeRecords(rows []Grant, indent bool) ([]byte, error) {
	var value any = rows
	if len(s.tickets) > 0 {
		value = struct {
			Format  int                    `json:"format"`
			Grants  []Grant                `json:"grants"`
			Tickets map[string]ticketBatch `json:"ticket_receipts"`
		}{2, rows, s.tickets}
	}
	if indent {
		return json.MarshalIndent(value, "", "  ")
	}
	return json.Marshal(value)
}
func (s *Store) validateTickets() error {
	if len(s.tickets) > maxTicketBatches {
		return ErrInvalidInput
	}
	owned := map[string]string{}
	for id, r := range s.tickets {
		if id != r.TicketID || !ticketIDPattern.MatchString(id) || !digestValid(r.Digest) || r.ExpiresAt.IsZero() || r.CreatedAt.IsZero() || len(r.GrantIDs) > 50 || (!r.Revoked && (len(r.GrantIDs) == 0 || !digestValid(r.InputHash))) {
			return ErrInvalidInput
		}
		for _, grant := range r.GrantIDs {
			if grant == "" || owned[grant] != "" {
				return ErrInvalidInput
			}
			owned[grant] = id
		}
	}
	for id, g := range s.grants {
		if g.SourceTicketID != "" && (owned[id] != g.SourceTicketID || s.tickets[g.SourceTicketID].Revoked) {
			return ErrInvalidInput
		}
	}
	return nil
}
func normalizedTicketInputs(inputs []Input) ([]Input, string, error) {
	if len(inputs) < 1 || len(inputs) > 50 {
		return nil, "", ErrInvalidInput
	}
	out := make([]Input, len(inputs))
	seen := map[string]bool{}
	for i, v := range inputs {
		v.UserID = strings.TrimSpace(v.UserID)
		v.AssetID = strings.TrimSpace(v.AssetID)
		v.NodeID = strings.TrimSpace(v.NodeID)
		v.Account = strings.TrimSpace(v.Account)
		var e error
		v.Actions, e = normalizeActions(v.Actions)
		if e != nil {
			return nil, "", e
		}
		if v.GroupID != "" || v.UserID == "" || v.StartsAt == nil || v.EndsAt == nil || validateGrant(v.UserID, "", v.AssetID, v.NodeID, v.Account, v.Actions, v.StartsAt, v.EndsAt) != nil {
			return nil, "", ErrInvalidInput
		}
		start, end := v.StartsAt.UTC(), v.EndsAt.UTC()
		v.StartsAt = &start
		v.EndsAt = &end
		key := v.AssetID + "\x00" + v.NodeID + "\x00" + v.Account
		if seen[key] {
			return nil, "", ErrInvalidInput
		}
		seen[key] = true
		out[i] = v
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		return a.AssetID+"\x00"+a.NodeID+"\x00"+a.Account < b.AssetID+"\x00"+b.NodeID+"\x00"+b.Account
	})
	raw, _ := json.Marshal(out)
	sum := sha256.Sum256(raw)
	return out, hex.EncodeToString(sum[:]), nil
}
func (s *Store) ticketReceiptLocked(r ticketBatch) TicketReceipt {
	state := "issued"
	inputs := []Input{}
	if r.Revoked {
		state = "revoked"
	} else {
		for _, id := range r.GrantIDs {
			g, ok := s.grants[id]
			if !ok {
				state = "missing"
				continue
			}
			if g.SourceTicketID != r.TicketID {
				state = "changed"
				continue
			}
			inputs = append(inputs, Input{UserID: g.UserID, AssetID: g.AssetID, NodeID: g.NodeID, Account: g.Account, Actions: g.Actions, StartsAt: g.StartsAt, EndsAt: g.EndsAt})
		}
		if state == "issued" {
			_, hash, e := normalizedTicketInputs(inputs)
			if e != nil || hash != r.InputHash {
				state = "changed"
			}
		}
	}
	return TicketReceipt{State: state, GrantIDs: slices.Clone(r.GrantIDs), ExpiresAt: r.ExpiresAt, Digest: r.Digest}
}
func (s *Store) TicketReceipt(id string) (TicketReceipt, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	r, ok := s.tickets[id]
	if !ok {
		return TicketReceipt{}, ErrNotFound
	}
	return s.ticketReceiptLocked(r), nil
}

// IssueTicket writes the entire grant batch and its immutable receipt in one
// document. A response retry never recreates grants removed by an administrator.
func (s *Store) IssueTicket(id, digest string, inputs []Input, createdBy string) (TicketReceipt, error) {
	if !ticketIDPattern.MatchString(id) || !digestValid(digest) || strings.TrimSpace(createdBy) == "" || len(createdBy) > 128 {
		return TicketReceipt{}, ErrInvalidInput
	}
	rows, hash, e := normalizedTicketInputs(inputs)
	if e != nil {
		return TicketReceipt{}, e
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if prior, ok := s.tickets[id]; ok {
		if prior.Digest != digest || prior.InputHash != "" && prior.InputHash != hash {
			return TicketReceipt{}, ErrTicketConflict
		}
		receipt := s.ticketReceiptLocked(prior)
		if prior.Revoked {
			return receipt, ErrTicketRevoked
		}
		return receipt, nil
	}
	now := time.Now().UTC()
	for _, v := range rows {
		if !v.EndsAt.After(now) {
			return TicketReceipt{}, ErrInvalidInput
		}
	}
	if len(s.tickets) >= maxTicketBatches {
		return TicketReceipt{}, ErrTicketCapacity
	}
	ids := make([]string, 0, len(rows))
	end := time.Time{}
	for _, v := range rows {
		var raw [16]byte
		if _, e = rand.Read(raw[:]); e != nil {
			for _, id := range ids {
				delete(s.grants, id)
			}
			return TicketReceipt{}, e
		}
		grantID := "grant-" + hex.EncodeToString(raw[:])
		ids = append(ids, grantID)
		s.grants[grantID] = Grant{ID: grantID, SourceTicketID: id, UserID: v.UserID, AssetID: v.AssetID, NodeID: v.NodeID, Account: v.Account, Actions: v.Actions, StartsAt: cloneTime(v.StartsAt), EndsAt: cloneTime(v.EndsAt), CreatedAt: now, CreatedBy: createdBy}
		if v.EndsAt.After(end) {
			end = *v.EndsAt
		}
	}
	receipt := ticketBatch{TicketID: id, Digest: digest, InputHash: hash, GrantIDs: ids, ExpiresAt: end, CreatedAt: now}
	s.tickets[id] = receipt
	if e = s.persistLocked(); e != nil {
		delete(s.tickets, id)
		for _, id := range ids {
			delete(s.grants, id)
		}
		return TicketReceipt{}, e
	}
	return s.ticketReceiptLocked(receipt), nil
}

// RevokeTicket commits a tombstone even when issuance never completed, fencing
// an old issuer that retries after a cancellation or active-node takeover.
func (s *Store) RevokeTicket(id, digest string, expires time.Time) (TicketReceipt, error) {
	if !ticketIDPattern.MatchString(id) || !digestValid(digest) || expires.IsZero() {
		return TicketReceipt{}, ErrInvalidInput
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	prior, ok := s.tickets[id]
	if ok && prior.Digest != digest {
		return TicketReceipt{}, ErrTicketConflict
	}
	if ok && prior.Revoked {
		return s.ticketReceiptLocked(prior), nil
	}
	if !ok {
		if len(s.tickets) >= maxTicketBatches {
			return TicketReceipt{}, ErrTicketCapacity
		}
		prior = ticketBatch{TicketID: id, Digest: digest, ExpiresAt: expires, CreatedAt: time.Now().UTC(), GrantIDs: []string{}}
	}
	removed := map[string]Grant{}
	for _, grantID := range prior.GrantIDs {
		if g, found := s.grants[grantID]; found {
			if g.SourceTicketID != id {
				return TicketReceipt{}, ErrTicketConflict
			}
			removed[grantID] = g
		}
	}
	next := prior
	next.Revoked = true
	s.tickets[id] = next
	for grantID := range removed {
		delete(s.grants, grantID)
	}
	if e := s.persistLocked(); e != nil {
		if ok {
			s.tickets[id] = prior
		} else {
			delete(s.tickets, id)
		}
		for id, g := range removed {
			s.grants[id] = g
		}
		return TicketReceipt{}, e
	}
	return s.ticketReceiptLocked(next), nil
}

// Retain revocation receipts for at least 180 days after both expiry and their
// creation. Current or unrevoked batches are never removed by maintenance.
func (s *Store) PruneTicketReceipts(at time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	cutoff := at.Add(-180 * 24 * time.Hour)
	removed := map[string]ticketBatch{}
	for id, r := range s.tickets {
		if r.Revoked && r.ExpiresAt.Before(cutoff) && r.CreatedAt.Before(cutoff) {
			removed[id] = r
			delete(s.tickets, id)
		}
	}
	if len(removed) == 0 {
		return nil
	}
	if e := s.persistLocked(); e != nil {
		for id, r := range removed {
			s.tickets[id] = r
		}
		return e
	}
	return nil
}
