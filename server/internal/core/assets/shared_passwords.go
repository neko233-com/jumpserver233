package assets

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"github.com/neko233-com/jumpserver233/server/internal/core/credentialpolicy"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/neko233-com/jumpserver233/server/internal/connector/sshclient"
	"github.com/neko233-com/jumpserver233/server/internal/storage"
)

var ErrSharedCredentialConflict = errors.New("shared SSH account credentials conflict")

// PasswordCoordinator is owned by the active server, including in single-active
// HA. It serializes credential mutations and journals a cross-store decision
// before changing a remote password. It never grants access between stores.
type PasswordCoordinator struct {
	mu           sync.Mutex
	path         string
	documents    *storage.Documents
	aead         cipher.AEAD
	stores       map[string]*Store
	services     map[string]*Service
	op           *sharedPasswordOperation
	ops          map[string]*sharedPasswordOperation
	lastRecovery map[string]time.Time
	shared       atomic.Pointer[map[passwordParticipant]bool]
	pendingView  atomic.Pointer[map[passwordParticipant]bool]
	running      sync.Map
	ownerContext context.Context
	keys         sharedKeyState
}
type passwordParticipant struct {
	Scope   string `json:"scope"`
	AssetID string `json:"asset_id"`
}
type sharedPasswordOperation struct {
	Planned      *plannedPasswordIntent `json:"planned,omitempty"`
	ID           string                 `json:"id"`
	Identity     string                 `json:"identity"`
	Phase        string                 `json:"phase"`
	Participants []passwordParticipant  `json:"participants"`
	Old          encryptedSecret        `json:"old"`
	Next         encryptedSecret        `json:"next"`
	StartedAt    time.Time              `json:"started_at"`
	CommittedAt  time.Time              `json:"committed_at,omitempty"`
	Actor        string                 `json:"actor,omitempty"`
	Trigger      string                 `json:"trigger"`
	Source       passwordParticipant    `json:"source"`
	BackupID     string                 `json:"backup_id,omitempty"`
}

func OpenPasswordCoordinator(path string, key []byte, documents *storage.Documents) (*PasswordCoordinator, error) {
	if len(key) != 32 {
		return nil, errors.New("vault key must be 32 bytes")
	}
	block, e := aes.NewCipher(key)
	if e != nil {
		return nil, e
	}
	aead, e := cipher.NewGCM(block)
	if e != nil {
		return nil, e
	}
	c := &PasswordCoordinator{path: path, documents: documents, aead: aead, stores: map[string]*Store{}, services: map[string]*Service{}, ops: map[string]*sharedPasswordOperation{}, lastRecovery: map[string]time.Time{}}
	var raw []byte
	if documents != nil {
		raw, e = documents.LoadOrImport("shared-passwords", path)
	} else {
		raw, e = os.ReadFile(path)
		if errors.Is(e, os.ErrNotExist) {
			e = nil
		}
	}
	if e != nil {
		return nil, e
	}
	if len(raw) > 0 && string(raw) != "null" {
		if json.Unmarshal(raw, &c.ops) != nil || c.ops == nil || len(c.ops) > 10000 {
			return nil, errors.New("invalid shared password journal")
		}
		for identity, o := range c.ops {
			if o == nil || o.Identity != identity {
				return nil, errors.New("invalid shared password journal")
			}
			c.op = o
			if len(o.ID) != 32 || len(o.Identity) != 64 || o.StartedAt.IsZero() || len(o.Participants) < 2 || len(o.Participants) > 10000 || !validSharedPhase(o.Phase) || (o.Phase == "commit" && o.CommittedAt.IsZero()) || len(o.Actor) > 128 {
				return nil, errors.New("invalid shared password journal")
			}
			seen := map[passwordParticipant]bool{}
			for _, p := range o.Participants {
				if p.Scope == "" || len(p.Scope) > 64 || p.AssetID == "" || len(p.AssetID) > 128 || seen[p] {
					return nil, errors.New("invalid shared password participant")
				}
				seen[p] = true
			}
			if !seen[o.Source] || (o.Trigger != "automatic" && o.Trigger != "manual" && o.Trigger != "restore" && o.Trigger != "planned") || (o.BackupID != "" && !validCredentialBackupID(o.BackupID)) || o.Planned != nil && (!validPlannedPassword(o.Planned) || o.Trigger != "planned" || o.Actor != o.Planned.Actor.ID) || o.Trigger == "planned" && o.Planned == nil {
				return nil, errors.New("invalid shared password source")
			}
			if _, e = c.secret(o.Old, "old"); e != nil {
				return nil, errors.New("shared password journal cannot be decrypted")
			}
			if _, e = c.secret(o.Next, "next"); e != nil {
				return nil, errors.New("shared password journal cannot be decrypted")
			}
		}
	}
	c.op = nil
	if e = c.openSharedKeys(); e != nil {
		return nil, e
	}
	c.refreshPendingView()
	return c, nil
}
func (c *PasswordCoordinator) refreshPendingView() {
	view := map[passwordParticipant]bool{}
	for _, op := range c.ops {
		for _, p := range op.Participants {
			view[p] = true
		}
	}
	c.pendingView.Store(&view)
}
func (c *PasswordCoordinator) hasPendingCredential(scope, id string) bool {
	p := passwordParticipant{scope, id}
	if view := c.pendingView.Load(); view != nil && (*view)[p] {
		return true
	}
	if view := c.keys.view.Load(); view != nil {
		if _, ok := (*view)[p]; ok {
			return true
		}
	}
	return false
}

// Credential requests must be able to stop waiting behind another host's SSH
// operation. In particular, a timed-out plan step must release its access locks.
func (c *PasswordCoordinator) lockCredentialContext(ctx context.Context) error {
	if e := ctx.Err(); e != nil {
		return e
	}
	if c.mu.TryLock() {
		return nil
	}
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			if c.mu.TryLock() {
				return nil
			}
		}
	}
}
func validSharedPhase(p string) bool {
	return p == "prepare" || p == "verify" || p == "commit" || p == "abort"
}

// BindOwner is configured before schedulers or API handlers start. Losing the
// active node's context cancels remote mutations as well as background work.
func (c *PasswordCoordinator) BindOwner(ctx context.Context) { c.ownerContext = ctx }
func passwordIdentity(a Asset) string {
	host := strings.TrimSuffix(strings.ToLower(a.Host), ".")
	if ip := net.ParseIP(host); ip != nil {
		host = ip.String()
	}
	raw, _ := json.Marshal([]string{host, strconv.Itoa(a.Port), a.HostKeyFingerprint, a.Username})
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}
func samePassword(a, b string) bool {
	x, y := sha256.Sum256([]byte(a)), sha256.Sum256([]byte(b))
	return subtle.ConstantTimeCompare(x[:], y[:]) == 1
}

// Register includes disabled and archived organizations. Those stores still
// receive verified passwords, but no work is scheduled on their behalf.
func (c *PasswordCoordinator) Register(scope string, store *Store) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if scope == "" || store == nil || len(scope) > 64 {
		return ErrInvalidInput
	}
	if old := c.stores[scope]; old != nil && old != store {
		return errors.New("organization asset store already registered")
	}
	c.stores[scope] = store
	c.refreshSharedLocked()
	return nil
}
func (c *PasswordCoordinator) refreshSharedLocked() {
	defer c.refreshSharedKeyCounts()
	counts := map[string]int{}
	for _, st := range c.stores {
		for _, a := range st.List() {
			if IsSSH(a) && credentialType(a.CredentialType) == CredentialPassword {
				counts[passwordIdentity(a)]++
			}
		}
	}
	values := map[passwordParticipant]bool{}
	for scope, st := range c.stores {
		for _, a := range st.List() {
			if IsSSH(a) && credentialType(a.CredentialType) == CredentialPassword && counts[passwordIdentity(a)] > 1 {
				values[passwordParticipant{scope, a.ID}] = true
			}
		}
	}
	c.shared.Store(&values)
}
func (s *Service) sharedPassword(id string) bool {
	c := s.passwordCoordinator
	if c == nil {
		return false
	}
	values := c.shared.Load()
	return values != nil && (*values)[passwordParticipant{s.passwordScope, id}]
}
func (c *PasswordCoordinator) Store(scope string) *Store {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.stores[scope]
}
func (s *Service) CoordinatePasswords(c *PasswordCoordinator, scope string) error {
	if e := c.Register(scope, s.store); e != nil {
		return e
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	s.passwordCoordinator, s.passwordScope = c, scope
	c.services[scope] = s
	return nil
}
func (c *PasswordCoordinator) participants(identity string) []passwordParticipant {
	out := []passwordParticipant{}
	for scope, store := range c.stores {
		for _, a := range store.List() {
			if IsSSH(a) && credentialType(a.CredentialType) == CredentialPassword && passwordIdentity(a) == identity {
				out = append(out, passwordParticipant{scope, a.ID})
			}
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Scope == out[j].Scope {
			return out[i].AssetID < out[j].AssetID
		}
		return out[i].Scope < out[j].Scope
	})
	return out
}

// The caller holds c.mu until its inventory mutation has persisted.
func (c *PasswordCoordinator) validateMutation(scope string, a Asset, replacement *sshclient.Credentials) error {
	for storeScope, store := range c.stores {
		for _, other := range store.List() {
			if remoteAccountPending(other) && other.HostKeyFingerprint == a.HostKeyFingerprint && other.Username == a.Username && !(storeScope == scope && other.ID == a.ID) {
				return ErrRemoteAccountPending
			}
		}
	}
	if !IsSSH(a) {
		return nil
	}
	identity := passwordIdentity(a)
	if c.sharedKeyMutation(a) {
		return ErrSSHKeyPending
	}
	if c.ops[identity] != nil {
		return ErrRotationPending
	}
	if credentialType(a.CredentialType) != CredentialPassword {
		return nil
	}
	var password string
	if replacement != nil {
		password = replacement.Password
	} else {
		var e error
		password, e = c.stores[scope].Password(a.ID)
		if e != nil {
			return e
		}
	}
	for _, p := range c.participants(identity) {
		if p.Scope == scope && p.AssetID == a.ID {
			continue
		}
		store := c.stores[p.Scope]
		if store.HasPendingPasswordRotation(p.AssetID) || store.HasPendingSSHKeyChange(p.AssetID) {
			return ErrRotationPending
		}
		other, e := store.Password(p.AssetID)
		if e != nil || !samePassword(password, other) {
			return ErrSharedCredentialConflict
		}
	}
	return nil
}
func (c *PasswordCoordinator) blocked(scope, id string) bool {
	if c.keyOperation(passwordParticipant{scope, id}) != nil {
		return true
	}
	for _, o := range c.ops {
		for _, p := range o.Participants {
			if p.Scope == scope && p.AssetID == id {
				return true
			}
		}
	}
	return false
}
func (c *PasswordCoordinator) seal(v, label string) (encryptedSecret, error) {
	n := make([]byte, c.aead.NonceSize())
	if _, e := rand.Read(n); e != nil {
		return encryptedSecret{}, e
	}
	return encryptedSecret{Nonce: n, Ciphertext: c.aead.Seal(nil, n, []byte(v), []byte("jms233/shared-password/v1/"+c.op.ID+"/"+label))}, nil
}
func (c *PasswordCoordinator) secret(v encryptedSecret, label string) (string, error) {
	if len(v.Nonce) != c.aead.NonceSize() {
		return "", ErrInvalidInput
	}
	p, e := c.aead.Open(nil, v.Nonce, v.Ciphertext, []byte("jms233/shared-password/v1/"+c.op.ID+"/"+label))
	if e != nil || len(p) == 0 {
		return "", ErrInvalidInput
	}
	return string(p), nil
}
func (c *PasswordCoordinator) persist() (err error) {
	defer func() {
		if err == nil {
			c.refreshPendingView()
		}
	}()
	raw, e := json.Marshal(c.ops)
	if e != nil {
		return e
	}
	if c.documents != nil {
		return c.documents.Save("shared-passwords", raw)
	}
	if e = os.MkdirAll(filepath.Dir(c.path), 0700); e != nil {
		return e
	}
	f, e := os.CreateTemp(filepath.Dir(c.path), ".shared-passwords-*")
	if e != nil {
		return e
	}
	defer os.Remove(f.Name())
	if e = f.Chmod(0600); e != nil {
		f.Close()
		return e
	}
	if _, e = f.Write(raw); e != nil {
		f.Close()
		return e
	}
	if e = f.Sync(); e != nil {
		f.Close()
		return e
	}
	if e = f.Close(); e != nil {
		return e
	}
	return os.Rename(f.Name(), c.path)
}
func (c *PasswordCoordinator) phase(p string) error {
	old := c.op.Phase
	c.op.Phase = p
	if e := c.persist(); e != nil {
		c.op.Phase = old
		return e
	}
	return nil
}
func (c *PasswordCoordinator) clear() error {
	old := c.op
	delete(c.ops, old.Identity)
	c.op = nil
	if e := c.persist(); e != nil {
		c.op = old
		c.ops[old.Identity] = old
		return e
	}
	return nil
}

func (c *PasswordCoordinator) rotate(ctx context.Context, s *Service, id, trigger, actor, backupID string) error {
	if e := c.lockCredentialContext(ctx); e != nil {
		return e
	}
	defer c.mu.Unlock()
	ctx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	if c.ownerContext != nil {
		stop := context.AfterFunc(c.ownerContext, cancel)
		defer stop()
		if c.ownerContext.Err() != nil {
			return c.ownerContext.Err()
		}
	}
	if e := ctx.Err(); e != nil {
		return e
	}
	a, e := s.Get(id)
	if e != nil {
		return e
	}
	if e = s.guardManagedRotation(ctx, id); e != nil {
		return e
	}
	if !IsSSH(a) {
		return ErrUnsupportedProtocol
	}
	if c.sharedKeyMutation(a) {
		return ErrSSHKeyPending
	}
	if c.ops[passwordIdentity(a)] != nil {
		return ErrRotationPending
	}
	ps := c.participants(passwordIdentity(a))
	if c.certificateParticipant(passwordIdentity(a)) {
		return ErrCredentialType
	}
	if len(ps) < 2 || credentialType(a.CredentialType) != CredentialPassword {
		return s.rotatePasswordToLocal(ctx, id, trigger, actor, backupID)
	}
	if len(ps) > 10000 || len(c.ops) >= 10000 {
		return ErrSharedCredentialConflict
	}
	now := time.Now().UTC()
	if trigger == "automatic" && (baseRotationStatus(a, now).State != "due" || s.rotationAttemptCoolingDown(id, now)) {
		return errRotationNotDue
	}
	old, e := s.store.Password(id)
	if e != nil {
		return e
	}
	for _, p := range ps {
		st := c.stores[p.Scope]
		if service := c.services[p.Scope]; service != nil {
			service.mu.RLock()
			busy := service.rotationRunning[p.AssetID]
			service.mu.RUnlock()
			if busy {
				return ErrRotationInProgress
			}
		}
		if st.HasPendingPasswordRotation(p.AssetID) || st.HasPendingSSHKeyChange(p.AssetID) {
			return ErrRotationPending
		}
		v, e := st.Password(p.AssetID)
		if e != nil || !samePassword(old, v) {
			return ErrSharedCredentialConflict
		}
	}
	for _, p := range ps {
		c.running.Store(p, true)
	}
	defer func() {
		for _, p := range ps {
			c.running.Delete(p)
		}
	}()
	next := ""
	if backupID != "" {
		next, e = s.store.CredentialBackupPassword(id, backupID)
	} else {
		policies := make([]credentialpolicy.Rules, 0, len(ps))
		for _, p := range ps {
			policies = append(policies, c.stores[p.Scope].passwordRules())
		}
		if plan := planPasswordRules(ctx); !plan.IsZero() {
			policies = append(policies, plan)
		}
		var merged credentialpolicy.Rules
		merged, e = credentialpolicy.Merge(policies...)
		if e != nil {
			return errors.Join(ErrSharedCredentialConflict, e)
		}
		next, e = selectRotationPassword(ctx, merged)
		if errors.Is(e, credentialpolicy.ErrConflict) {
			return errors.Join(ErrSharedCredentialConflict, e)
		}
	}
	if e != nil {
		return e
	}
	opID := make([]byte, 16)
	if _, e = rand.Read(opID); e != nil {
		return e
	}
	c.op = &sharedPasswordOperation{ID: hex.EncodeToString(opID), Identity: passwordIdentity(a), Phase: "prepare", Participants: ps, StartedAt: now, Trigger: trigger, Actor: actor, Source: passwordParticipant{s.passwordScope, id}, BackupID: backupID, Planned: plannedPassword(ctx)}
	c.op.Old, e = c.seal(old, "old")
	if e == nil {
		c.op.Next, e = c.seal(next, "next")
	}
	if e != nil {
		c.op = nil
		return e
	}
	c.ops[c.op.Identity] = c.op
	if e = c.persist(); e != nil {
		delete(c.ops, c.op.Identity)
		c.op = nil
		return ErrPasswordRotationFailed
	}
	for _, p := range ps {
		st := c.stores[p.Scope]
		pa, _ := c.asset(p)
		if e = st.RecordPasswordRotationAttempt(p.AssetID, now, "rotating"); e == nil {
			e = c.audit(p, pa, "shared_started", "", "")
		}
		if e == nil {
			if p == c.op.Source && c.op.Planned != nil {
				e = st.beginPasswordRotation(p.AssetID, next, now, "", "", "", c.op.Planned)
			} else {
				e = st.BeginPasswordRotation(p.AssetID, next, now)
			}
		}
		if e != nil {
			_ = c.finish("abort")
			return ErrPasswordRotationFailed
		}
	}
	if e = c.phase("verify"); e != nil {
		_ = c.finish("abort")
		return ErrPasswordRotationFailed
	}
	_, target, current, e := s.store.connection(id)
	if e == nil {
		e = s.changeManagedPassword(ctx, a, target, current, next)
	}
	// Even a successful remote command must authenticate the new credential.
	// An ambiguous command result follows the same durable recovery path.
	if c.verify(ctx, next) == nil {
		c.op.CommittedAt = time.Now().UTC()
		return c.finish("commit")
	}
	if c.verify(ctx, old) == nil {
		_ = c.finish("abort")
		return ErrPasswordRotationFailed
	}
	c.lastRecovery[c.op.Identity] = time.Now().UTC()
	for _, p := range ps {
		st := c.stores[p.Scope]
		_ = st.SetPasswordRotationResult(p.AssetID, "recovery_required", "shared_password_recovery_required")
		c.invalidate(p)
	}
	return ErrPasswordRotationFailed
}
func (c *PasswordCoordinator) asset(p passwordParticipant) (Asset, error) {
	st := c.stores[p.Scope]
	if st == nil {
		return Asset{}, ErrNotFound
	}
	for _, a := range st.List() {
		if a.ID == p.AssetID {
			return a, nil
		}
	}
	return Asset{}, ErrNotFound
}
func (c *PasswordCoordinator) invalidate(p passwordParticipant) {
	if s := c.services[p.Scope]; s != nil {
		s.mu.Lock()
		delete(s.rotationStatus, p.AssetID)
		s.mu.Unlock()
	}
}
func (c *PasswordCoordinator) audit(p passwordParticipant, a Asset, event, result, code string) error {
	// Only local asset metadata is written to an organization's audit.
	s := c.services[p.Scope]
	if s == nil {
		s = &Service{store: c.stores[p.Scope]}
	}
	actor, backup := "", ""
	if p == c.op.Source {
		actor, backup = c.op.Actor, c.op.BackupID
	}
	return s.appendRotationAuditDetails(a, event, c.op.Trigger, result, code, actor, backup, c.op.ID)
}
func (c *PasswordCoordinator) verify(ctx context.Context, password string) error {
	ctx, cancel := context.WithTimeout(ctx, 16*time.Second)
	defer cancel()
	seen := map[string]bool{}
	attempts := 0
	for _, p := range c.op.Participants {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		_, target, _, e := c.stores[p.Scope].connection(p.AssetID)
		if e != nil {
			continue
		}
		route := net.JoinHostPort(target.Host, strconv.Itoa(target.Port))
		for _, hop := range target.Gateways {
			route += "/" + net.JoinHostPort(hop.Target.Host, strconv.Itoa(hop.Target.Port)) + "/" + hop.Target.HostKeyFingerprint
		}
		if seen[route] {
			continue
		}
		seen[route] = true
		attempts++
		if attempts > 3 {
			break
		}
		verify := PasswordVerifyFunc(sshclient.VerifyPassword)
		if s := c.services[p.Scope]; s != nil {
			verify = s.verifyPassword
		}
		if verify(ctx, target, sshclient.Credentials{Password: password}, 8*time.Second) == nil {
			return nil
		}
	}
	return ErrPasswordRotationFailed
}
func (c *PasswordCoordinator) finish(decision string) error {
	if e := c.phase(decision); e != nil {
		return ErrPasswordRotationFailed
	}
	next, e := c.secret(c.op.Next, "next")
	if e != nil {
		return ErrPasswordRotationFailed
	}
	for _, p := range c.op.Participants {
		st := c.stores[p.Scope]
		if st == nil {
			return ErrPasswordRotationFailed
		}
		a, e := c.asset(p)
		if e != nil || passwordIdentity(a) != c.op.Identity {
			return ErrPasswordRotationFailed
		}
		if decision == "commit" {
			if st.HasPendingPasswordRotation(p.AssetID) {
				v, e := st.PendingPassword(p.AssetID)
				if e != nil || !samePassword(v, next) {
					return ErrPasswordRotationFailed
				}
				if st.CommitPasswordRotation(p.AssetID, c.op.CommittedAt) != nil {
					return ErrPasswordRotationFailed
				}
			} else {
				v, e := st.Password(p.AssetID)
				if e != nil || !samePassword(v, next) {
					return ErrPasswordRotationFailed
				}
			}
		} else {
			if st.HasPendingPasswordRotation(p.AssetID) {
				v, e := st.PendingPassword(p.AssetID)
				if e != nil || !samePassword(v, next) {
					return ErrPasswordRotationFailed
				}
				if st.AbortPasswordRotation(p.AssetID) != nil {
					return ErrPasswordRotationFailed
				}
			}
			if st.SetPasswordRotationResult(p.AssetID, "failed", "shared_password_rotation_aborted") != nil {
				return ErrPasswordRotationFailed
			}
		}
		c.invalidate(p)
	}
	for _, p := range c.op.Participants {
		a, _ := c.asset(p)
		if c.audit(p, a, "shared_completed", decision, "") != nil {
			return ErrPasswordRotationFailed
		}
	}
	if c.clear() != nil {
		return ErrPasswordRotationFailed
	}
	return nil
}

// Recover must run after all organizations (including archived ones) register.
// A durable commit decision needs no second remote password change.
func (c *PasswordCoordinator) Recover(ctx context.Context) {
	c.mu.Lock()
	defer c.mu.Unlock()
	identities := make([]string, 0, len(c.ops))
	for id := range c.ops {
		identities = append(identities, id)
	}
	sort.Strings(identities)
	for _, identity := range identities {
		c.recoverOperation(ctx, identity)
	}
}
func (c *PasswordCoordinator) recoverOperation(ctx context.Context, identity string) {
	c.op = c.ops[identity]
	if c.op == nil || ctx.Err() != nil || (!c.lastRecovery[identity].IsZero() && time.Since(c.lastRecovery[identity]) < rotationRetryInterval) {
		return
	}
	c.lastRecovery[identity] = time.Now().UTC()
	for _, p := range c.op.Participants {
		a, e := c.asset(p)
		if e != nil || passwordIdentity(a) != c.op.Identity {
			return
		}
	}
	switch c.op.Phase {
	case "prepare", "abort":
		_ = c.finish("abort")
	case "commit":
		_ = c.finish("commit")
	case "verify":
		next, e := c.secret(c.op.Next, "next")
		if e != nil {
			return
		}
		old, e := c.secret(c.op.Old, "old")
		if e != nil {
			return
		}
		if c.verify(ctx, next) == nil {
			c.op.CommittedAt = time.Now().UTC()
			_ = c.finish("commit")
		} else if c.verify(ctx, old) == nil {
			_ = c.finish("abort")
		}
	}
}
