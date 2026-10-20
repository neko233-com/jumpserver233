package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

var (
	ErrPasswordPolicy       = fmt.Errorf("%w: configured policy", ErrInvalidPassword)
	ErrPasswordHistory      = errors.New("password was used recently")
	ErrPasswordChallenge    = errors.New("password change challenge invalid or expired")
	ErrCredentialPermission = errors.New("credential recovery permission required")
)

type PasswordPolicy struct {
	Revision        int  `json:"revision"`
	MinLength       int  `json:"min_length"`
	AdminMinLength  int  `json:"admin_min_length"`
	RequireUpper    bool `json:"require_upper"`
	RequireLower    bool `json:"require_lower"`
	RequireDigit    bool `json:"require_digit"`
	RequireSpecial  bool `json:"require_special"`
	HistoryCount    int  `json:"history_count"`
	MaxAgeDays      int  `json:"max_age_days"`
	AdminMaxAgeDays int  `json:"admin_max_age_days"`
}
type PasswordPolicyEvent struct {
	ID       string         `json:"id"`
	At       time.Time      `json:"at"`
	ActorID  string         `json:"actor_id"`
	Actor    string         `json:"actor"`
	Before   PasswordPolicy `json:"before"`
	After    PasswordPolicy `json:"after"`
	Affected int            `json:"affected"`
}
type passwordHistory struct {
	Fingerprint []byte `json:"fingerprint,omitempty"`
	Salt        []byte `json:"salt,omitempty"`
	Hash        []byte `json:"hash,omitempty"`
}
type passwordPending struct {
	Hash           []byte    `json:"hash"`
	Proof          string    `json:"proof"`
	SourceHash     []byte    `json:"source_hash"`
	Expires        time.Time `json:"expires"`
	PolicyRevision int       `json:"policy_revision"`
}
type PasswordChallenge struct {
	Token     string
	User      User
	Proof     string
	ExpiresAt time.Time
	Policy    PasswordPolicy
}

func defaultPasswordPolicy() PasswordPolicy {
	return PasswordPolicy{Revision: 1, MinLength: 12, AdminMinLength: 12}
}
func validPasswordPolicy(p PasswordPolicy) bool {
	return p.Revision >= 1 && p.MinLength >= 12 && p.MinLength <= 128 && p.AdminMinLength >= 12 && p.AdminMinLength <= 128 && p.HistoryCount >= 0 && p.HistoryCount <= 24 && p.MaxAgeDays >= 0 && p.MaxAgeDays <= 36500 && p.AdminMaxAgeDays >= 0 && p.AdminMaxAgeDays <= 36500
}
func (p PasswordPolicy) check(password, role string) error {
	length := p.MinLength
	if role == RoleAdmin {
		length = p.AdminMinLength
	}
	if len(password) < length || len(password) > 256 || !utf8.ValidString(password) || strings.IndexFunc(password, unicode.IsControl) >= 0 {
		return ErrPasswordPolicy
	}
	upper, lower, digit, special := false, false, false, false
	for _, c := range password {
		upper = upper || unicode.IsUpper(c)
		lower = lower || unicode.IsLower(c)
		digit = digit || unicode.IsDigit(c)
		special = special || unicode.IsPunct(c) || unicode.IsSymbol(c)
	}
	if p.RequireUpper && !upper || p.RequireLower && !lower || p.RequireDigit && !digit || p.RequireSpecial && !special {
		return ErrPasswordPolicy
	}
	return nil
}
func (s *Service) PasswordPolicy() PasswordPolicy {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.passwordPolicy
}
func (s *Service) PasswordPolicyAudit(offset, limit int) ([]PasswordPolicyEvent, int, error) {
	if offset < 0 || limit < 1 || limit > 100 {
		return nil, 0, ErrUserState
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := append([]PasswordPolicyEvent{}, s.passwordPolicyEvents...)
	slices.Reverse(out)
	n := len(out)
	offset = min(offset, n)
	return out[offset:min(offset+limit, n)], n, nil
}
func (s *Service) checkUserActorLocked(a UserActor) error {
	if a.ID == "admin-token" {
		return nil
	}
	_, u, ok := s.storedUserByIDLocked(a.ID)
	if !ok || !s.credentialUsableLocked(u) || u.AuthGeneration != a.AuthGeneration {
		return ErrInvalidCredentials
	}
	return nil
}
func clearUserCapabilities(r *storedUser) {
	r.AuthGeneration++
	r.AccessKeys = nil
	r.PermanentTokens = nil
	r.PendingMFASecretCiphertext = nil
	r.PendingMFAExpiresAt = nil
	r.MFASetupChallengeHash = nil
	r.MFASetupChallengeExpiresAt = nil
	r.MFASetupPasskeyID = ""
	r.PasswordPending = nil
}
func (s *Service) SavePasswordPolicy(in PasswordPolicy, a UserActor) (PasswordPolicy, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if e := s.checkUserActorLocked(a); e != nil {
		return PasswordPolicy{}, e
	}
	if in.Revision != s.passwordPolicy.Revision {
		return PasswordPolicy{}, ErrUserRevision
	}
	if !validPasswordPolicy(in) {
		return PasswordPolicy{}, ErrPasswordPolicy
	}
	if s.aead == nil && (in.HistoryCount > 0 || in.MaxAgeDays > 0 || in.AdminMaxAgeDays > 0) {
		return PasswordPolicy{}, ErrMFAKeyUnavailable
	}
	if in == s.passwordPolicy {
		return s.passwordPolicy, nil
	}
	oldPolicy := s.passwordPolicy
	oldUsers := s.users
	oldEvents := s.passwordPolicyEvents
	next := make(map[string]storedUser, len(s.users))
	affected := 0
	for name, r := range s.users {
		if r.Source == "" {
			clearUserCapabilities(&r)
			r.Revision = userRevision(r.User) + 1
			affected++
			if len(r.PasswordHistory) > in.HistoryCount {
				r.PasswordHistory = slices.Clone(r.PasswordHistory[len(r.PasswordHistory)-in.HistoryCount:])
			}
		}
		next[name] = r
	}
	in.Revision++
	now := s.now().UTC()
	var id [16]byte
	if _, e := rand.Read(id[:]); e != nil {
		return PasswordPolicy{}, e
	}
	events := slices.Clone(oldEvents)
	events = append(events, PasswordPolicyEvent{ID: "password-policy-" + hex.EncodeToString(id[:]), At: now, ActorID: a.ID, Actor: a.Name, Before: oldPolicy, After: in, Affected: affected})
	events = slices.DeleteFunc(events, func(e PasswordPolicyEvent) bool { return e.At.Before(now.AddDate(0, -6, 0)) })
	if len(events) > 1000 {
		events = events[len(events)-1000:]
	}
	s.users = next
	s.passwordPolicy = in
	s.passwordPolicyEvents = events
	if e := s.persistLocked(); e != nil {
		s.users = oldUsers
		s.passwordPolicy = oldPolicy
		s.passwordPolicyEvents = oldEvents
		return PasswordPolicy{}, e
	}
	s.fenceSessionsLocked("", "")
	return in, nil
}
func (s *Service) passwordExpiresLocked(r storedUser) time.Time {
	if r.Source != "" {
		return time.Time{}
	}
	days := s.passwordPolicy.MaxAgeDays
	if r.Role == RoleAdmin {
		days = s.passwordPolicy.AdminMaxAgeDays
	}
	if days == 0 {
		return time.Time{}
	}
	changed := r.PasswordChangedAt
	if changed.IsZero() {
		changed = r.CreatedAt
	}
	return changed.Add(time.Duration(days) * 24 * time.Hour)
}
func (s *Service) passwordRequiredLocked(r storedUser) bool {
	if r.Source != "" {
		return false
	}
	expires := s.passwordExpiresLocked(r)
	return r.PasswordResetRequired || !expires.IsZero() && !s.now().Before(expires)
}
func (s *Service) credentialUsableLocked(r storedUser) bool {
	return s.externalAllowedLocked(r) && !s.passwordRequiredLocked(r)
}
func (s *Service) PasswordChangeRequired(id string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	_, r, ok := s.storedUserByIDLocked(id)
	return ok && s.passwordRequiredLocked(r)
}
func (s *Service) passwordFingerprint(id, password string) []byte {
	if len(s.passwordPepper) == 0 {
		return nil
	}
	m := hmac.New(sha256.New, s.passwordPepper)
	m.Write([]byte(id))
	m.Write([]byte{0})
	m.Write([]byte(password))
	return m.Sum(nil)
}
func (s *Service) preparePassword(r storedUser, p PasswordPolicy, password string, checkCurrent bool) ([]byte, []byte, []byte, error) {
	if e := p.check(password, r.Role); e != nil {
		return nil, nil, nil, e
	}
	if checkCurrent {
		hash, e := s.derivePassword(password, r.PasswordSalt)
		if e != nil {
			return nil, nil, nil, e
		}
		if subtle.ConstantTimeCompare(hash, r.PasswordHash) == 1 {
			return nil, nil, nil, ErrPasswordUnchanged
		}
	}
	fingerprint := s.passwordFingerprint(r.ID, password)
	if p.HistoryCount > 0 {
		if len(fingerprint) != sha256.Size {
			return nil, nil, nil, ErrMFAKeyUnavailable
		}
		history := r.PasswordHistory
		start := max(0, len(history)-p.HistoryCount)
		for _, h := range history[start:] {
			if len(h.Fingerprint) > 0 {
				if subtle.ConstantTimeCompare(fingerprint, h.Fingerprint) == 1 {
					return nil, nil, nil, ErrPasswordHistory
				}
			} else {
				hash, e := s.derivePassword(password, h.Salt)
				if e != nil {
					return nil, nil, nil, e
				}
				if subtle.ConstantTimeCompare(hash, h.Hash) == 1 {
					return nil, nil, nil, ErrPasswordHistory
				}
			}
		}
	}
	salt := make([]byte, 16)
	if _, e := rand.Read(salt); e != nil {
		return nil, nil, nil, e
	}
	hash, e := s.derivePassword(password, salt)
	return salt, hash, fingerprint, e
}
func (s *Service) replacePasswordLocked(r storedUser, salt, hash, fingerprint []byte) storedUser {
	if s.passwordPolicy.HistoryCount > 0 {
		h := passwordHistory{Fingerprint: slices.Clone(r.PasswordFingerprint)}
		if len(h.Fingerprint) == 0 {
			h.Salt = slices.Clone(r.PasswordSalt)
			h.Hash = slices.Clone(r.PasswordHash)
		}
		history := append(slices.Clone(r.PasswordHistory), h)
		r.PasswordHistory = history[max(0, len(history)-s.passwordPolicy.HistoryCount):]
	} else {
		r.PasswordHistory = nil
	}
	r.PasswordSalt = salt
	r.PasswordHash = hash
	r.PasswordFingerprint = fingerprint
	r.PasswordChangedAt = s.now().UTC()
	r.PasswordResetRequired = false
	return r
}
func (s *Service) appendCredentialEventLocked(previous, current storedUser, a UserActor, action string, fields []string) error {
	var id [16]byte
	if _, e := rand.Read(id[:]); e != nil {
		return e
	}
	now := s.now().UTC()
	s.userEvents = append(slices.Clone(s.userEvents), UserEvent{ID: "user-event-" + hex.EncodeToString(id[:]), At: now, UserID: current.ID, Username: current.Username, ActorID: a.ID, Actor: a.Name, Action: action, Revision: current.Revision, AuthGeneration: current.AuthGeneration, Fields: fields, Before: userState(previous.User, now), After: userState(current.User, now)})
	s.userEvents = slices.DeleteFunc(s.userEvents, func(e UserEvent) bool { return e.At.Before(now.AddDate(0, -6, 0)) })
	if len(s.userEvents) > 5000 {
		s.userEvents = s.userEvents[len(s.userEvents)-5000:]
	}
	return nil
}
func (s *Service) fenceSessionsLocked(keepToken, keepID string) {
	if len(keepToken) > 128 {
		keepToken = ""
	}
	keep := sha256.Sum256([]byte(keepToken))
	records := map[string]storedUser{}
	for _, r := range s.users {
		records[r.ID] = r
	}
	for token, session := range s.sessions {
		r, ok := records[session.user.ID]
		if !ok || session.user.AuthGeneration != r.AuthGeneration {
			if keepToken != "" && token == keep && session.user.ID == keepID && ok {
				session.user = r.User
				session.credentialStamp = loginCredentialStamp(r)
				s.sessions[token] = session
			} else {
				delete(s.sessions, token)
			}
		}
	}
	_ = s.persistSessionsLocked()
}
func (s *Service) changePassword(userID, currentToken, currentPassword, newPassword string) error {
	if len(currentPassword) > 256 {
		return ErrInvalidCredentials
	}
	s.mu.RLock()
	name, snapshot, ok := s.storedUserByIDLocked(userID)
	policy := s.passwordPolicy
	s.mu.RUnlock()
	if !ok {
		return ErrUserNotFound
	}
	if snapshot.Source != "" {
		return ErrExternalIdentity
	}
	currentHash, e := s.derivePassword(currentPassword, snapshot.PasswordSalt)
	if e != nil {
		return e
	}
	if subtle.ConstantTimeCompare(currentHash, snapshot.PasswordHash) != 1 {
		return ErrInvalidCredentials
	}
	if currentPassword == newPassword {
		return ErrPasswordUnchanged
	}
	salt, hash, fp, e := s.preparePassword(snapshot, policy, newPassword, false)
	if e != nil {
		return e
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.users[name]
	if !ok || !s.credentialUsableLocked(r) || r.AuthGeneration != snapshot.AuthGeneration || subtle.ConstantTimeCompare(r.PasswordHash, snapshot.PasswordHash) != 1 {
		return ErrPasswordChanged
	}
	if policy.Revision != s.passwordPolicy.Revision {
		return ErrUserRevision
	}
	previous := r
	oldEvents := s.userEvents
	r = s.replacePasswordLocked(r, salt, hash, fp)
	keys, tokens := r.AccessKeys, r.PermanentTokens
	clearUserCapabilities(&r)
	r.AccessKeys = keys
	r.PermanentTokens = tokens
	r.Revision = userRevision(r.User) + 1
	if e = s.appendCredentialEventLocked(previous, r, UserActor{ID: r.ID, Name: r.Username}, "password_change", []string{"password"}); e != nil {
		return e
	}
	s.users[name] = r
	if e = s.persistLocked(); e != nil {
		s.users[name] = previous
		s.userEvents = oldEvents
		return e
	}
	s.fenceSessionsLocked(currentToken, userID)
	return nil
}
func (s *Service) ResetCredentials(id string, revision int, kind, password string, force bool, a UserActor) (ManagedUser, error) {
	if !a.ManageCredentials {
		return ManagedUser{}, ErrCredentialPermission
	}
	if kind != "password_reset" && kind != "mfa_reset" {
		return ManagedUser{}, ErrUserState
	}
	if kind == "mfa_reset" && (password != "" || force) {
		return ManagedUser{}, ErrUserState
	}
	s.mu.RLock()
	_, snapshot, ok := s.storedUserByIDLocked(id)
	policy := s.passwordPolicy
	actorError := s.checkUserActorLocked(a)
	s.mu.RUnlock()
	if actorError != nil {
		return ManagedUser{}, actorError
	}
	if !ok {
		return ManagedUser{}, ErrUserNotFound
	}
	if snapshot.Role == RoleAdmin && !a.ManageAdministrators {
		return ManagedUser{}, ErrUserAdmin
	}
	if snapshot.ID == a.ID {
		return ManagedUser{}, ErrUserSelf
	}
	if !snapshot.ArchivedAt.IsZero() {
		return ManagedUser{}, ErrUserState
	}
	if revision != userRevision(snapshot.User) {
		return ManagedUser{}, ErrUserRevision
	}
	if s.aead == nil {
		return ManagedUser{}, ErrMFAKeyUnavailable
	}
	if kind == "password_reset" && snapshot.Source != "" {
		return ManagedUser{}, ErrExternalIdentity
	}
	var salt, hash, fp []byte
	var e error
	if kind == "password_reset" {
		salt, hash, fp, e = s.preparePassword(snapshot, policy, password, true)
		if e != nil {
			return ManagedUser{}, e
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if e = s.checkUserActorLocked(a); e != nil {
		return ManagedUser{}, e
	}
	name, r, ok := s.storedUserByIDLocked(id)
	if !ok {
		return ManagedUser{}, ErrUserNotFound
	}
	if !r.ArchivedAt.IsZero() {
		return ManagedUser{}, ErrUserState
	}
	if r.Role == RoleAdmin && !a.ManageAdministrators {
		return ManagedUser{}, ErrUserAdmin
	}
	if r.ID == a.ID {
		return ManagedUser{}, ErrUserSelf
	}
	if revision != userRevision(r.User) || r.AuthGeneration != snapshot.AuthGeneration || policy.Revision != s.passwordPolicy.Revision {
		return ManagedUser{}, ErrUserRevision
	}
	previous := r
	oldEvents := s.userEvents
	fields := []string{"mfa"}
	if kind == "password_reset" {
		r = s.replacePasswordLocked(r, salt, hash, fp)
		r.PasswordResetRequired = force
		fields = []string{"password", "password_reset_required"}
	} else {
		r.MFAEnabled = false
		r.SMSMFAEnabled = false
		r.SMSPhoneCiphertext = nil
		r.MFASecretCiphertext = nil
		r.MFALastAcceptedStep = 0
		r.MFARecoveryCodeHashes = nil
	}
	clearUserCapabilities(&r)
	r.Revision = userRevision(r.User) + 1
	if e = s.appendCredentialEventLocked(previous, r, a, kind, fields); e != nil {
		return ManagedUser{}, e
	}
	s.users[name] = r
	if e = s.persistLocked(); e != nil {
		s.users[name] = previous
		s.userEvents = oldEvents
		return ManagedUser{}, e
	}
	s.fenceSessionsLocked("", "")
	return s.managedPasswordUserLocked(r), nil
}
func (s *Service) BeginPasswordChange(token, source string) (PasswordChallenge, error) {
	if len(source) > 128 {
		return PasswordChallenge{}, ErrPasswordChallenge
	}
	proof, e := s.QuarantineLogin(token)
	if e != nil {
		return PasswordChallenge{}, e
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	data, r, e := s.openLoginProofLocked(proof.Proof)
	if e != nil || !s.passwordRequiredLocked(r) {
		return PasswordChallenge{}, ErrPasswordChallenge
	}
	name := r.Username
	var raw [32]byte
	if _, e = rand.Read(raw[:]); e != nil {
		return PasswordChallenge{}, e
	}
	ticket := base64.RawURLEncoding.EncodeToString(raw[:])
	h := sha256.Sum256([]byte(ticket))
	ip := sha256.Sum256([]byte(source))
	previous := r
	r.PasswordPending = &passwordPending{Hash: h[:], Proof: proof.Proof, SourceHash: ip[:], Expires: data.ExpiresAt, PolicyRevision: s.passwordPolicy.Revision}
	s.users[name] = r
	if e = s.persistLocked(); e != nil {
		s.users[name] = previous
		return PasswordChallenge{}, e
	}
	return PasswordChallenge{Token: ticket, User: r.User, Proof: proof.Proof, ExpiresAt: data.ExpiresAt, Policy: s.passwordPolicy}, nil
}
func (s *Service) passwordPendingLocked(token, source string) (storedUser, error) {
	if token == "" || len(token) > 128 || len(source) > 128 {
		return storedUser{}, ErrPasswordChallenge
	}
	h := sha256.Sum256([]byte(token))
	ip := sha256.Sum256([]byte(source))
	for _, r := range s.users {
		p := r.PasswordPending
		if p == nil || subtle.ConstantTimeCompare(p.Hash, h[:]) != 1 {
			continue
		}
		if subtle.ConstantTimeCompare(p.SourceHash, ip[:]) != 1 || !s.now().Before(p.Expires) || p.PolicyRevision != s.passwordPolicy.Revision || !s.passwordRequiredLocked(r) {
			return storedUser{}, ErrPasswordChallenge
		}
		if _, _, e := s.openLoginProofLocked(p.Proof); e != nil {
			return storedUser{}, ErrPasswordChallenge
		}
		return r, nil
	}
	return storedUser{}, ErrPasswordChallenge
}
func (s *Service) PasswordChangePending(token, source string) (PasswordChallenge, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	r, e := s.passwordPendingLocked(token, source)
	if e != nil {
		return PasswordChallenge{}, e
	}
	return PasswordChallenge{User: r.User, Proof: r.PasswordPending.Proof, ExpiresAt: r.PasswordPending.Expires, Policy: s.passwordPolicy}, nil
}
func (s *Service) CompletePasswordChange(token, source, password string) error {
	s.mu.RLock()
	snapshot, e := s.passwordPendingLocked(token, source)
	policy := s.passwordPolicy
	s.mu.RUnlock()
	if e != nil {
		return e
	}
	salt, hash, fp, e := s.preparePassword(snapshot, policy, password, true)
	if e != nil {
		return e
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	r, e := s.passwordPendingLocked(token, source)
	if e != nil {
		return e
	}
	if r.AuthGeneration != snapshot.AuthGeneration || policy.Revision != s.passwordPolicy.Revision {
		return ErrPasswordChallenge
	}
	previous := r
	oldEvents := s.userEvents
	r = s.replacePasswordLocked(r, salt, hash, fp)
	clearUserCapabilities(&r)
	r.Revision = userRevision(r.User) + 1
	if e = s.appendCredentialEventLocked(previous, r, UserActor{ID: r.ID, Name: r.Username}, "password_change", []string{"password"}); e != nil {
		return e
	}
	s.users[r.Username] = r
	if e = s.persistLocked(); e != nil {
		s.users[r.Username] = previous
		s.userEvents = oldEvents
		return e
	}
	s.fenceSessionsLocked("", "")
	return nil
}
func (s *Service) CancelPasswordChange(token, source string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, e := s.passwordPendingLocked(token, source)
	if e != nil {
		return e
	}
	previous := r
	r.PasswordPending = nil
	s.users[r.Username] = r
	if e = s.persistLocked(); e != nil {
		s.users[r.Username] = previous
	}
	return e
}
func validPasswordRecord(r storedUser) bool {
	if !r.PasswordChangedAt.IsZero() && (r.PasswordChangedAt.Year() < 1970 || r.PasswordChangedAt.Year() > 9999) {
		return false
	}
	if len(r.PasswordFingerprint) != 0 && len(r.PasswordFingerprint) != sha256.Size || len(r.PasswordHistory) > 24 {
		return false
	}
	for _, h := range r.PasswordHistory {
		if len(h.Fingerprint) == sha256.Size {
			if len(h.Salt) != 0 || len(h.Hash) != 0 {
				return false
			}
		} else if len(h.Fingerprint) != 0 || len(h.Salt) != 16 || len(h.Hash) != passwordSize {
			return false
		}
	}
	p := r.PasswordPending
	return p == nil || len(p.Hash) == 32 && len(p.SourceHash) == 32 && len(p.Proof) > 0 && len(p.Proof) <= 8192 && !p.Expires.IsZero() && p.PolicyRevision >= 1
}

func (s *Service) passwordStoreMarker() []byte {
	if len(s.passwordPepper) == 0 {
		return s.passwordMarker
	}
	m := hmac.New(sha256.New, s.passwordPepper)
	m.Write([]byte("jms233/password-history/store/v1"))
	return m.Sum(nil)
}
func (s *Service) managedPasswordUserLocked(r storedUser) ManagedUser {
	out := managedUser(r.User, s.now())
	out.PasswordChangeRequired = s.passwordRequiredLocked(r)
	out.PasswordExpiresAt = s.passwordExpiresLocked(r)
	return out
}
func validPasswordPolicyEvents(events []PasswordPolicyEvent) bool {
	seen := map[string]bool{}
	for _, e := range events {
		if e.ID == "" || seen[e.ID] || e.At.IsZero() || e.ActorID == "" || !validPasswordPolicy(e.Before) || !validPasswordPolicy(e.After) || e.After.Revision != e.Before.Revision+1 || e.Affected < 0 {
			return false
		}
		seen[e.ID] = true
	}
	return true
}
