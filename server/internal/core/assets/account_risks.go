package assets

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/neko233-com/jumpserver233/server/internal/core/accountrisks"
)

// CollectAccountRisks decrypts each current password once inside the vault.
// Commit receives account metadata and opaque internal markers, never secrets.
func (s *Service) CollectAccountRisks(ctx context.Context, p accountrisks.Policy, now time.Time, used map[string]time.Time, known map[string]accountrisks.Usage, commit func(accountrisks.Snapshot) error) error {
	if p.Validate() != nil || commit == nil {
		return accountrisks.ErrInvalid
	}
	s.store.mu.RLock()
	defer s.store.mu.RUnlock()
	snapshot := accountrisks.Snapshot{Accounts: []accountrisks.Observation{}, Groups: map[string][]accountrisks.Member{}}
	type member struct {
		index    int
		identity string
	}
	groups := map[string][]member{}
	ids := make([]string, 0, len(s.store.assets))
	for id := range s.store.assets {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		r := s.store.assets[id]
		a := r.Asset
		if !IsSSH(a) || !p.IncludeDisabled && a.AccountDisabled {
			continue
		}
		if len(snapshot.Accounts) >= accountrisks.MaxAccounts {
			return accountrisks.ErrCapacity
		}
		parent := s.store.assets[ResourceID(a)]
		ref := accountrisks.Ref{AssetID: ResourceID(a), AccountID: a.ID, AssetName: parent.Name, Username: a.Username}
		kind := credentialType(a.CredentialType)
		rotated := r.PasswordRotatedAt
		if kind == CredentialSSHKey {
			rotated = a.KeyRotatedAt
		}
		if rotated.IsZero() {
			rotated = a.CreatedAt
		}
		o := accountrisks.Observation{Ref: ref, CredentialType: kind, Active: !a.AccountDisabled, CreatedAt: a.CreatedAt, RotatedAt: rotated, LastUsedAt: used[a.ID], SourceVersion: accountVersion(a),
			Binding: s.store.importMAC("account-risk-binding", struct {
				Identity string
				Revision uint64
				Kind     string
			}{passwordIdentity(a), a.CredentialRevision, kind}), Checks: []accountrisks.Check{}}
		o.Identity = s.store.importMAC("account-risk-identity", passwordIdentity(a))
		if u := known[a.ID]; u.Identity == o.Identity && u.At.After(o.LastUsedAt) {
			o.LastUsedAt = u.At
		}
		add := func(k, severity string, reasons ...string) {
			if p.Has(k) {
				o.Checks = append(o.Checks, accountrisks.Check{Kind: k, Severity: severity, Reasons: reasons})
			}
		}
		if kind == CredentialPassword && (p.Has("weak_password") || p.Has("duplicate_password")) {
			plain, e := s.store.aead.Open(nil, r.Credential.Nonce, r.Credential.Ciphertext, credentialAAD(a.ID, a.CredentialType, ""))
			if e != nil {
				return e
			}
			reasons := weakAccountPassword(string(plain), a.Username, p.MinPasswordLength)
			if len(reasons) > 0 {
				add("weak_password", "high", reasons...)
			}
			if p.Has("duplicate_password") {
				h := hmac.New(sha256.New, s.store.importKey)
				h.Write([]byte("account-risk/password/v1\x00"))
				h.Write(plain)
				group := hex.EncodeToString(h.Sum(nil))
				groups[group] = append(groups[group], member{len(snapshot.Accounts), passwordIdentity(a)})
			}
			clear(plain)
		} else if kind == CredentialSSHKey && p.Has("reused_key") && a.KeyFingerprint != "" {
			h := sha256.Sum256([]byte("account-risk/key/v1\x00" + a.KeyFingerprint))
			group := hex.EncodeToString(h[:])
			groups[group] = append(groups[group], member{len(snapshot.Accounts), passwordIdentity(a)})
		}
		if now.Sub(rotated) >= time.Duration(p.MaxCredentialAgeDays)*24*time.Hour {
			add("stale_credential", "high", "rotation_age")
		}
		lastUse := o.LastUsedAt
		if lastUse.Before(a.CreatedAt) {
			lastUse = a.CreatedAt
		}
		if lastUse.Before(rotated) {
			lastUse = rotated
		}
		if now.Sub(lastUse) >= time.Duration(p.UnusedAccountDays)*24*time.Hour {
			add("unused_account", "medium", "platform_usage_age")
		}
		if kind == CredentialPassword && a.PasswordRotationDisabled || kind == CredentialSSHKey && !a.KeyRotationEnabled {
			add("rotation_disabled", "medium", "automatic_rotation_off")
		}
		if r.PendingRotation != nil || r.PendingKeyChange != nil || remoteAccountPending(a) {
			add("pending_credential", "high", "credential_recovery")
		}
		snapshot.Accounts = append(snapshot.Accounts, o)
	}
	for id, members := range groups {
		identities := map[string]bool{}
		for _, m := range members {
			identities[m.identity] = true
		}
		if len(identities) < 2 {
			continue
		}
		refs := make([]accountrisks.Member, 0, len(members))
		for _, m := range members {
			refs = append(refs, accountrisks.Member{Ref: snapshot.Accounts[m.index].Ref, Identity: snapshot.Accounts[m.index].Identity})
			o := &snapshot.Accounts[m.index]
			kind, severity := "duplicate_password", "high"
			if o.CredentialType == CredentialSSHKey {
				kind, severity = "reused_key", "medium"
			}
			o.Checks = append(o.Checks, accountrisks.Check{Kind: kind, Severity: severity, Reasons: []string{"different_remote_identities"}, GroupID: id})
		}
		snapshot.Groups[id] = refs
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return commit(snapshot)
}
func weakAccountPassword(password, username string, minLength int) []string {
	out := []string{}
	if utf8.RuneCountInString(password) < minLength {
		out = append(out, "short")
	}
	fold := strings.ToLower(strings.TrimSpace(password))
	common := map[string]bool{"password": true, "password1": true, "password123": true, "password123!": true, "123456": true, "12345678": true, "123456789": true, "qwerty": true, "admin": true, "admin123": true, "root": true, "letmein": true, "welcome": true, "changeme": true, "default": true}
	if common[fold] {
		out = append(out, "common")
	}
	user := strings.ToLower(username)
	if user != "" && (fold == user || fold == user+"123" || fold == user+"123!" || fold == user+"2026") {
		out = append(out, "username")
	}
	unique := map[rune]bool{}
	for _, c := range fold {
		unique[c] = true
	}
	if len(fold) > 0 && len(unique) <= 2 {
		out = append(out, "repeated")
	}
	if len(fold) >= 4 && (strings.Contains("01234567890123456789", fold) || strings.Contains("abcdefghijklmnopqrstuvwxyz", fold) || strings.Contains("qwertyuiopasdfghjklzxcvbnm", fold)) {
		out = append(out, "sequence")
	}
	return out
}

// AccountRiskVersions is a lightweight current-source view for redacting stale
// findings and rejecting reviews after credential or target changes.
func (s *Service) AccountRiskVersions() map[string]string {
	s.store.mu.RLock()
	defer s.store.mu.RUnlock()
	out := map[string]string{}
	for id, r := range s.store.assets {
		if IsSSH(r.Asset) {
			out[id] = accountVersion(r.Asset)
		}
	}
	return out
}

// WithAccountRiskVersion keeps a credential/target version stable through review
// publication, using the same vault -> risk-store lock order as scan commits.
func (s *Service) WithAccountRiskVersion(id, version string, apply func() error) error {
	s.store.mu.RLock()
	defer s.store.mu.RUnlock()
	r, ok := s.store.assets[id]
	if !ok || !IsSSH(r.Asset) || accountVersion(r.Asset) != version {
		return accountrisks.ErrConflict
	}
	return apply()
}
