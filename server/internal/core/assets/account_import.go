package assets

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/neko233-com/jumpserver233/server/internal/connector/sshclient"
)

const maxAccountImportReceipts = 256

var ErrAccountImportConflict = errors.New("account import changed")
var ErrAccountImportExpired = errors.New("account import preview expired")
var ErrAccountImportCapacity = errors.New("account import receipt capacity reached")

type AccountImportSummary struct {
	AccountHost        string `json:"account_host,omitempty"`
	PrincipalID        string `json:"principal_id,omitempty"`
	Line               int    `json:"line"`
	Action             string `json:"action"`
	AssetID            string `json:"asset_id"`
	AssetName          string `json:"asset_name"`
	AccountID          string `json:"account_id"`
	Username           string `json:"username"`
	CredentialType     string `json:"credential_type"`
	KeyFingerprint     string `json:"key_fingerprint,omitempty"`
	Active             bool   `json:"active"`
	CredentialReplaced bool   `json:"credential_replaced"`
	RotationChanged    bool   `json:"rotation_changed"`
	Version            string `json:"version,omitempty"`
}
type AccountImportPreview struct {
	RequestID string                 `json:"request_id"`
	Rows      []AccountImportSummary `json:"rows"`
	Issues    []AccountImportIssue   `json:"issues"`
	Token     string                 `json:"preview_token,omitempty"`
	ExpiresAt time.Time              `json:"expires_at,omitzero"`
	Committed bool                   `json:"committed"`
}
type AccountImportReceipt struct {
	RequestID string                 `json:"request_id"`
	Actor     AccountActor           `json:"actor"`
	CreatedAt time.Time              `json:"created_at"`
	Rows      []AccountImportSummary `json:"rows"`
}
type accountImportRecord struct {
	AccountImportReceipt
	Scope          string `json:"scope"`
	InputDigest    string `json:"input_digest"`
	SnapshotDigest string `json:"snapshot_digest"`
}
type accountImportToken struct {
	ActorID        string `json:"actor"`
	Scope          string `json:"scope"`
	RequestID      string `json:"request_id"`
	InputDigest    string `json:"input"`
	SnapshotDigest string `json:"snapshot"`
	Expires        int64  `json:"expires"`
}
type importPrepared struct {
	summary     AccountImportSummary
	asset       Asset
	current     *storedAsset
	replacement *sshclient.Credentials
}
type accountImportPlan struct {
	rows     []importPrepared
	issues   []AccountImportIssue
	snapshot string
}

func accountImportKey(key []byte) []byte {
	h := hmac.New(sha256.New, key)
	_, _ = h.Write([]byte("jms233/account-import/v1/key"))
	return h.Sum(nil)
}
func (s *Store) importMAC(label string, v any) string {
	raw, _ := json.Marshal(v)
	h := hmac.New(sha256.New, s.importKey)
	_, _ = h.Write([]byte(label + "\x00"))
	_, _ = h.Write(raw)
	return hex.EncodeToString(h.Sum(nil))
}
func (s *Store) signImportToken(v accountImportToken) string {
	raw, _ := json.Marshal(v)
	return base64.RawURLEncoding.EncodeToString(raw) + "." + s.importMAC("preview", v)
}
func (s *Store) importInputDigest(rows []AccountImportRow, actor, scope, request string) string {
	return s.importMAC("input", struct {
		Actor, Scope, Request string
		Rows                  []AccountImportRow
	}{actor, scope, request, rows})
}
func (s *Store) decodeImportToken(token string) (accountImportToken, error) {
	var v accountImportToken
	parts := strings.Split(token, ".")
	if len(token) > 2048 || len(parts) != 2 {
		return v, ErrAccountImportConflict
	}
	raw, e := base64.RawURLEncoding.DecodeString(parts[0])
	if e != nil {
		return v, ErrAccountImportConflict
	}
	d := json.NewDecoder(strings.NewReader(string(raw)))
	d.DisallowUnknownFields()
	if d.Decode(&v) != nil || d.Decode(new(any)) != io.EOF || !hmac.Equal([]byte(s.importMAC("preview", v)), []byte(parts[1])) {
		return accountImportToken{}, ErrAccountImportConflict
	}
	return v, nil
}
func importReceiptCopy(v AccountImportReceipt) AccountImportReceipt {
	v.Rows = append([]AccountImportSummary(nil), v.Rows...)
	return v
}
func (s *Store) importRecordLocked(actor, scope, id, digest string) (*accountImportRecord, error) {
	for _, v := range s.imports {
		if v.RequestID == id && v.Actor.ID == actor && v.Scope == scope {
			if v.InputDigest != digest {
				return nil, ErrAccountImportConflict
			}
			return &v, nil
		}
	}
	return nil, nil
}
func validateImportRecords(records []accountImportRecord) error {
	if len(records) > maxAccountImportReceipts {
		return ErrInvalidInput
	}
	seen := map[string]bool{}
	for _, r := range records {
		key := r.Actor.ID + "\x00" + r.Scope + "\x00" + r.RequestID
		if seen[key] || !keyRequestPattern.MatchString(r.RequestID) || !validAccountActor(r.Actor) || r.CreatedAt.IsZero() || r.Scope == "" || !accountText(r.Scope, 128) || len(r.Rows) == 0 || len(r.Rows) > MaxAccountImportRows || !validImportDigest(r.InputDigest) || !validImportDigest(r.SnapshotDigest) {
			return ErrInvalidInput
		}
		seen[key] = true
		lines, accounts := map[int]bool{}, map[string]bool{}
		for _, row := range r.Rows {
			if row.Line < 1 || row.Line > 1_048_576 || lines[row.Line] || accounts[row.AccountID] || row.AssetID == "" || row.AccountID == "" || row.Username == "" || row.Action != "create" && row.Action != "update" || !validImportDigest(row.Version) || !accountText(row.Username, 128) || !accountText(row.AssetName, 480) || row.CredentialType != CredentialPassword && row.CredentialType != CredentialSSHKey {
				return ErrInvalidInput
			}
			lines[row.Line], accounts[row.AccountID] = true, true
		}
	}
	return nil
}
func validImportDigest(v string) bool {
	if len(v) != 64 {
		return false
	}
	for _, c := range v {
		if c < '0' || c > '9' && c < 'a' || c > 'f' {
			return false
		}
	}
	return true
}

// The API holds its access publication read lock across authorization and these
// calls. The coordinator and store locks freeze credentials for one atomic write.
func (s *Service) PreviewAccountImport(ctx context.Context, rows []AccountImportRow, actor AccountActor, scope, requestID string) (AccountImportPreview, error) {
	out := AccountImportPreview{RequestID: requestID, Rows: []AccountImportSummary{}, Issues: []AccountImportIssue{}}
	if !validAccountActor(actor) || scope == "" || !accountText(scope, 128) || !keyRequestPattern.MatchString(requestID) || len(rows) == 0 || len(rows) > MaxAccountImportRows {
		return out, ErrInvalidInput
	}
	if c := s.passwordCoordinator; c != nil {
		c.mu.Lock()
		defer c.mu.Unlock()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.store.mu.Lock()
	defer s.store.mu.Unlock()
	digest := s.store.importInputDigest(rows, actor.ID, scope, requestID)
	existing, e := s.store.importRecordLocked(actor.ID, scope, requestID, digest)
	if e != nil {
		return out, e
	}
	snapshot := ""
	if existing != nil {
		out.Rows = append(out.Rows, existing.Rows...)
		out.Committed = true
		snapshot = existing.SnapshotDigest
	} else {
		plan := s.prepareAccountImportLocked(ctx, rows, actor, requestID)
		out.Issues = plan.issues
		retained := 0
		for _, r := range s.store.imports {
			if r.CreatedAt.After(time.Now().UTC().Add(-24 * time.Hour)) {
				retained++
			}
		}
		if retained >= maxAccountImportReceipts {
			out.Issues = append(out.Issues, AccountImportIssue{Code: "receipt_capacity"})
		}
		for _, r := range plan.rows {
			out.Rows = append(out.Rows, r.summary)
		}
		snapshot = plan.snapshot
	}
	if len(out.Issues) == 0 {
		out.ExpiresAt = time.Now().UTC().Add(15 * time.Minute)
		out.Token = s.store.signImportToken(accountImportToken{actor.ID, scope, requestID, digest, snapshot, out.ExpiresAt.Unix()})
	}
	return out, nil
}

func (s *Service) prepareAccountImportLocked(ctx context.Context, rows []AccountImportRow, actor AccountActor, requestID string) accountImportPlan {
	plan := accountImportPlan{issues: []AccountImportIssue{}}
	index := map[string]string{}
	for id, r := range s.store.assets {
		index[accountNameKey(r.Asset)] = id
	}
	seen := map[string]bool{}
	versions := []string{}
	type credentialResult struct {
		kind, pin string
		value     *sshclient.Credentials
		err       error
	}
	credentials := map[[32]byte]credentialResult{}
	for _, row := range rows {
		issue := func(field, code string) { plan.issues = append(plan.issues, AccountImportIssue{row.Line, field, code}) }
		if row.Line < 1 || row.Line > 1_048_576 {
			issue("", "fields")
			continue
		}
		if ctx.Err() != nil {
			issue("", "cancelled")
			break
		}
		parent, ok := s.store.assets[row.AssetID]
		if !ok || parent.ParentAssetID != "" || !ManagedAccountsSupported(parent.Asset) {
			issue("asset_id", "asset_unavailable")
			continue
		}
		in := row.Input
		in.Username = strings.TrimSpace(in.Username)
		candidate := inheritAccount(parent.Asset, Asset{Username: in.Username, PAM: clonePAM(in.PAM)})
		key := accountNameKey(candidate)
		if seen[key] {
			issue("username", "duplicate")
			continue
		}
		seen[key] = true
		if row.Action != "create" && row.Action != "update" {
			issue("action", "action")
			continue
		}
		id, exists := index[key]
		if !exists && row.Action == "update" && in.Username == parent.Username {
			id, exists = parent.ID, true
		}
		if !exists && in.PAM != nil && in.PAM.Principal.Host != "" {
			if fallback, ok := index[row.AssetID+"\x00"+in.Username]; ok {
				if row.Action == "update" {
					id, exists = fallback, true
				} else {
					issue("username", "pin_default_first")
					continue
				}
			}
		}
		var current *storedAsset
		var a Asset
		if row.Action == "create" {
			if exists {
				issue("username", "exists")
				continue
			}
			sum := sha256.Sum256([]byte(actor.ID + "\x00" + requestID + "\x00" + key))
			id = "account-" + row.AssetID + "-" + hex.EncodeToString(sum[:16])
			if _, exists := s.store.assets[id]; exists {
				issue("username", "conflict")
				continue
			}
			a = inheritAccount(parent.Asset, Asset{ID: id, ParentAssetID: row.AssetID, Username: in.Username, AccountName: in.Username, CredentialRevision: 1})
			if in.Version != "" && in.Version != accountVersion(parent.Asset) {
				issue("version", "conflict")
				continue
			}
		} else {
			if !exists {
				issue("username", "not_found")
				continue
			}
			v := s.store.assets[id]
			current = &v
			a = cloneAsset(v.Asset)
			if remoteAccountPending(a) || v.PendingRotation != nil || v.PendingKeyChange != nil || s.rotationRunning[id] {
				issue("username", "pending")
				continue
			}
			if a.RemoteAccount != nil && a.RemoteAccount.State == "disabled" && in.Active != nil && *in.Active {
				issue("active", "pending")
				continue
			}
			if in.Version != "" && in.Version != accountVersion(a) {
				issue("version", "conflict")
				continue
			}
			if len(v.AccountAudit) >= maxAccountAudit {
				issue("username", "capacity")
				continue
			}
		}
		if in.DiscoveryID != nil || normalizeAccountInput(&a, in) != nil {
			issue("username", "fields")
			continue
		}
		ci := Input{CredentialType: in.CredentialType, Password: in.Password, PrivateKey: in.PrivateKey, PrivateKeyPassphrase: in.PrivateKeyPassphrase, KeyRotationEnabled: in.KeyRotationEnabled}
		var previous *Asset
		if current != nil {
			previous = &current.Asset
		}
		var result credentialResult
		if ci.Password != "" || ci.PrivateKey != "" {
			kind := ci.CredentialType
			if kind == "" {
				kind = CredentialPassword
				if previous != nil {
					kind = credentialType(previous.CredentialType)
				}
			}
			raw, _ := json.Marshal(struct{ Kind, Password, Key, Passphrase string }{kind, ci.Password, ci.PrivateKey, ci.PrivateKeyPassphrase})
			digest := sha256.Sum256(raw)
			var found bool
			result, found = credentials[digest]
			if !found {
				result.kind, result.pin, result.value, result.err = inputCredential(ci, previous)
				credentials[digest] = result
			}
		} else {
			result.kind, result.pin, result.value, result.err = inputCredential(ci, previous)
		}
		kind, pin, credential, e := result.kind, result.pin, result.value, result.err
		if e != nil {
			issue("credential_type", "credential")
			continue
		}
		a.CredentialType, a.KeyFingerprint = kind, pin
		if applyKeyRotationPolicy(&a, ci, previous) != nil {
			issue("key_rotation_enabled", "rotation")
			continue
		}
		if s.passwordCoordinator != nil && (s.passwordCoordinator.blocked(s.passwordScope, id) || s.passwordCoordinator.sharedKeyMutation(a) || s.passwordCoordinator.ops[passwordIdentity(a)] != nil) {
			issue("username", "pending")
			continue
		}
		summary := AccountImportSummary{Line: row.Line, Action: row.Action, AssetID: row.AssetID, AssetName: parent.Name, AccountID: id, Username: a.Username, CredentialType: kind, KeyFingerprint: pin, Active: !a.AccountDisabled, CredentialReplaced: credential != nil}
		if a.PAM != nil {
			summary.AccountHost = a.PAM.Principal.Host
			summary.PrincipalID = a.PAM.Principal.ID
		}
		if current != nil {
			summary.Version = accountVersion(current.Asset)
			summary.RotationChanged = in.PasswordRotationEnabled != nil && *in.PasswordRotationEnabled != !current.PasswordRotationDisabled || in.KeyRotationEnabled != nil && *in.KeyRotationEnabled != current.KeyRotationEnabled
		} else {
			summary.RotationChanged = in.PasswordRotationEnabled != nil && !*in.PasswordRotationEnabled || in.KeyRotationEnabled != nil && *in.KeyRotationEnabled
		}
		versions = append(versions, row.AssetID+":"+accountVersion(parent.Asset)+":"+id+":"+summary.Version)
		plan.rows = append(plan.rows, importPrepared{summary, a, current, credential})
	}
	plan.snapshot = s.store.importMAC("snapshot", versions)
	if len(plan.issues) == 0 {
		if e := s.validateAccountImportAliasesLocked(plan.rows); e != nil {
			plan.issues = append(plan.issues, AccountImportIssue{Code: importIssueCode(e)})
		}
	}
	return plan
}

func importIssueCode(e error) string {
	switch {
	case errors.Is(e, ErrRemoteAccountPending), errors.Is(e, ErrRotationPending), errors.Is(e, ErrSSHKeyPending):
		return "pending"
	case errors.Is(e, ErrSharedCredentialConflict):
		return "shared_conflict"
	default:
		return "unavailable"
	}
}

// Resolve aliases against the final batch, including aliases in other stores.
// No password or private key enters the preview or receipt.
func (s *Service) validateAccountImportAliasesLocked(rows []importPrepared) error {
	type alias struct {
		store  *Store
		record storedAsset
		staged *importPrepared
	}
	type cacheKey struct {
		store *Store
		id    string
	}
	group := func(a Asset) string {
		if !IsSSH(a) || WindowsPAM(a) {
			return passwordIdentity(a)
		}
		return a.HostKeyFingerprint + "\x00" + a.Username
	}
	targets := map[string]bool{}
	final := map[string]*importPrepared{}
	for i := range rows {
		targets[group(rows[i].asset)] = true
		final[rows[i].asset.ID] = &rows[i]
	}
	stores := map[string]*Store{s.passwordScope: s.store}
	if c := s.passwordCoordinator; c != nil {
		stores = c.stores
	}
	aliases := map[string][]alias{}
	add := func(store *Store, r storedAsset) {
		var staged *importPrepared
		if store == s.store {
			if p := final[r.ID]; p != nil {
				staged = p
				r.Asset = p.asset
			}
		}
		if SupportsPasswordRotation(r.Asset) && targets[group(r.Asset)] {
			aliases[group(r.Asset)] = append(aliases[group(r.Asset)], alias{store, r, staged})
		}
	}
	for _, store := range stores {
		if store == s.store {
			for _, r := range store.assets {
				add(store, r)
			}
		} else {
			store.mu.RLock()
			for _, r := range store.assets {
				add(store, r)
			}
			store.mu.RUnlock()
		}
	}
	for i := range rows {
		if rows[i].current == nil {
			add(s.store, storedAsset{Asset: rows[i].asset})
		}
	}
	passwords := map[cacheKey]string{}
	password := func(v alias) (string, error) {
		key := cacheKey{v.store, v.record.ID}
		if value, ok := passwords[key]; ok {
			return value, nil
		}
		if v.staged != nil && v.staged.replacement != nil {
			passwords[key] = v.staged.replacement.Password
			return v.staged.replacement.Password, nil
		}
		plain, e := v.store.aead.Open(nil, v.record.Credential.Nonce, v.record.Credential.Ciphertext, credentialAAD(v.record.ID, v.record.CredentialType, ""))
		if e != nil {
			return "", e
		}
		value := string(plain)
		passwords[key] = value
		return value, nil
	}
	for i := range rows {
		candidate := &rows[i]
		source := storedAsset{Asset: candidate.asset}
		if candidate.current != nil {
			source = *candidate.current
		}
		self := alias{s.store, source, candidate}
		for _, other := range aliases[group(candidate.asset)] {
			if other.store == s.store && other.record.ID == candidate.asset.ID {
				continue
			}
			if remoteAccountPending(other.record.Asset) {
				return ErrRemoteAccountPending
			}
			if credentialType(candidate.asset.CredentialType) != CredentialPassword || credentialType(other.record.CredentialType) != CredentialPassword || passwordIdentity(candidate.asset) != passwordIdentity(other.record.Asset) {
				continue
			}
			if other.record.PendingRotation != nil || other.record.PendingKeyChange != nil {
				return ErrRotationPending
			}
			left, e := password(self)
			if e != nil {
				return e
			}
			right, e := password(other)
			if e != nil || !samePassword(left, right) {
				return ErrSharedCredentialConflict
			}
		}
	}
	return nil
}

func (s *Service) CommitAccountImport(ctx context.Context, rows []AccountImportRow, actor AccountActor, scope, requestID, token string) (AccountImportReceipt, error) {
	var empty AccountImportReceipt
	if !validAccountActor(actor) || len(rows) == 0 || len(rows) > MaxAccountImportRows || !keyRequestPattern.MatchString(requestID) {
		return empty, ErrInvalidInput
	}
	proof, e := s.store.decodeImportToken(token)
	if e != nil || proof.ActorID != actor.ID || proof.Scope != scope || proof.RequestID != requestID || proof.InputDigest != s.store.importInputDigest(rows, actor.ID, scope, requestID) {
		return empty, ErrAccountImportConflict
	}
	if c := s.passwordCoordinator; c != nil {
		c.mu.Lock()
		defer c.mu.Unlock()
		defer c.refreshSharedLocked()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.store.mu.Lock()
	defer s.store.mu.Unlock()
	old, e := s.store.importRecordLocked(actor.ID, scope, requestID, proof.InputDigest)
	if e != nil {
		return empty, e
	}
	if old != nil {
		if old.SnapshotDigest != proof.SnapshotDigest {
			return empty, ErrAccountImportConflict
		}
		return importReceiptCopy(old.AccountImportReceipt), nil
	}
	now := time.Now().UTC()
	if proof.Expires <= now.Unix() || proof.Expires > now.Add(16*time.Minute).Unix() {
		return empty, ErrAccountImportExpired
	}
	plan := s.prepareAccountImportLocked(ctx, rows, actor, requestID)
	if len(plan.issues) != 0 || plan.snapshot != proof.SnapshotDigest {
		return empty, ErrAccountImportConflict
	}
	receipts := make([]accountImportRecord, 0, len(s.store.imports)+1)
	for _, r := range s.store.imports {
		if r.CreatedAt.After(now.Add(-24 * time.Hour)) {
			receipts = append(receipts, r)
		}
	}
	if len(receipts) >= maxAccountImportReceipts {
		return empty, ErrAccountImportCapacity
	}
	next := make(map[string]storedAsset, len(s.store.assets)+len(rows))
	for id, v := range s.store.assets {
		next[id] = v
	}
	receipt := AccountImportReceipt{RequestID: requestID, Actor: actor, CreatedAt: now, Rows: make([]AccountImportSummary, 0, len(rows))}
	for _, prepared := range plan.rows {
		if ctx.Err() != nil {
			return empty, ctx.Err()
		}
		a := cloneAsset(prepared.asset)
		a.UpdatedAt = now
		r := storedAsset{Asset: a, PasswordRotatedAt: now}
		before := ""
		if prepared.current != nil {
			r = *prepared.current
			r.CredentialBackups = append([]credentialBackup(nil), r.CredentialBackups...)
			a.CreatedAt = r.CreatedAt
			before = accountVersion(r.Asset)
		} else {
			a.CreatedAt = now
			a.PasswordRotatedAt = now
		}
		if prepared.replacement != nil {
			if prepared.current != nil {
				if _, e = s.store.snapshotCredentialLocked(a.ID, &r, now, true); e != nil {
					return empty, e
				}
				a.CredentialRevision, e = nextCredentialRevision(r.Asset)
				if e != nil {
					return empty, e
				}
			}
			r.Credential, e = s.store.sealCredentials(&a, *prepared.replacement)
			if e != nil {
				return empty, e
			}
			r.PasswordRotatedAt = now
			a.PasswordRotatedAt = now
			if a.CredentialType == CredentialSSHKey {
				a.KeyRotatedAt = now
			} else {
				a.KeyRotatedAt = time.Time{}
				a.KeyRotationEnabled = false
			}
			r.RotationLastAttemptAt = time.Time{}
			r.RotationState = "scheduled"
			r.RotationErrorCode = ""
		}
		r.Asset = a
		event := newAccountAudit("import_"+prepared.summary.Action, actor, a, before, accountVersion(a))
		event.ImportID = requestID
		r.AccountAudit = append(append([]AccountAudit(nil), r.AccountAudit...), event)
		next[a.ID] = r
		summary := prepared.summary
		summary.Version = accountVersion(a)
		receipt.Rows = append(receipt.Rows, summary)
	}
	previous, previousImports := s.store.assets, s.store.imports
	s.store.assets = next
	s.store.imports = append(receipts, accountImportRecord{receipt, scope, proof.InputDigest, proof.SnapshotDigest})
	rollback := func() { s.store.assets = previous; s.store.imports = previousImports }
	if e = s.store.materializeAccountsLocked(); e != nil {
		rollback()
		return empty, e
	}
	if e = s.store.validateGatewaysLocked(); e != nil {
		rollback()
		return empty, e
	}
	if e = s.store.persistLocked(); e != nil {
		rollback()
		return empty, e
	}
	for _, r := range receipt.Rows {
		delete(s.rotationStatus, r.AccountID)
		delete(s.status, r.AccountID)
		delete(s.last, r.AccountID)
	}
	return importReceiptCopy(receipt), nil
}

func (s *Service) AccountImportReceipts(owner string) []AccountImportReceipt {
	s.store.mu.RLock()
	defer s.store.mu.RUnlock()
	out := []AccountImportReceipt{}
	for _, v := range s.store.imports {
		if owner == "" || v.Actor.ID == owner {
			out = append(out, importReceiptCopy(v.AccountImportReceipt))
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	return out
}

type AccountImportHistory struct {
	RequestID string       `json:"request_id"`
	Actor     AccountActor `json:"actor"`
	CreatedAt time.Time    `json:"created_at"`
	Count     int          `json:"count"`
	Created   int          `json:"created"`
	Updated   int          `json:"updated"`
	AssetIDs  []string     `json:"-"`
}

func (s *Service) AccountImportHistory(owner string) []AccountImportHistory {
	s.store.mu.RLock()
	defer s.store.mu.RUnlock()
	out := []AccountImportHistory{}
	for _, v := range s.store.imports {
		if owner != "" && v.Actor.ID != owner {
			continue
		}
		h := AccountImportHistory{RequestID: v.RequestID, Actor: v.Actor, CreatedAt: v.CreatedAt, Count: len(v.Rows)}
		seen := map[string]bool{}
		for _, row := range v.Rows {
			if row.Action == "create" {
				h.Created++
			} else {
				h.Updated++
			}
			if !seen[row.AssetID] {
				seen[row.AssetID] = true
				h.AssetIDs = append(h.AssetIDs, row.AssetID)
			}
		}
		out = append(out, h)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	return out
}
func (s *Service) AccountImportReceipt(owner, requestID string) (AccountImportReceipt, bool) {
	s.store.mu.RLock()
	defer s.store.mu.RUnlock()
	for _, v := range s.store.imports {
		if v.Actor.ID == owner && v.RequestID == requestID {
			return importReceiptCopy(v.AccountImportReceipt), true
		}
	}
	return AccountImportReceipt{}, false
}
