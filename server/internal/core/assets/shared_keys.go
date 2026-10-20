package assets

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/neko233-com/jumpserver233/server/internal/connector/sshclient"
	xssh "golang.org/x/crypto/ssh"
)

type sharedKeyParticipant struct {
	passwordParticipant
	Revision  uint64 `json:"revision"`
	RequestID string `json:"request_id"`
}
type sharedKeyOperation struct {
	PromotionStarted bool                   `json:"promotion_started,omitempty"`
	ID               string                 `json:"id"`
	Identity         string                 `json:"identity"`
	OldFingerprint   string                 `json:"old_fingerprint"`
	NewFingerprint   string                 `json:"new_fingerprint"`
	Source           passwordParticipant    `json:"source"`
	Participants     []sharedKeyParticipant `json:"participants"`
	Phase            string                 `json:"phase"`
}
type sharedKeyView struct {
	CanCancel   bool
	Phase       string
	OperationID string
	RequestID   string
	Revision    uint64
}
type sharedKeyState struct {
	ops      map[string]*sharedKeyOperation
	view     atomic.Pointer[map[passwordParticipant]sharedKeyView]
	shared   atomic.Pointer[map[passwordParticipant]bool]
	attempts map[string]time.Time
	running  sync.Map
}

func (c *PasswordCoordinator) keyService(scope string) *Service {
	if s := c.services[scope]; s != nil {
		return s
	}
	st := c.stores[scope]
	if st == nil {
		return nil
	}
	s := NewService(st, nil)
	s.passwordCoordinator = c
	s.passwordScope = scope
	return s
}

func (c *PasswordCoordinator) openSharedKeys() error {
	c.keys.ops = map[string]*sharedKeyOperation{}
	c.keys.attempts = map[string]time.Time{}
	var raw []byte
	var e error
	if c.documents != nil {
		raw, e = c.documents.LoadOrImport("shared-keys", c.keyJournalPath())
	} else {
		raw, e = os.ReadFile(c.keyJournalPath())
		if errors.Is(e, os.ErrNotExist) {
			e = nil
		}
	}
	if e != nil {
		return e
	}
	if len(raw) == 0 {
		return nil
	}
	var envelope encryptedSecret
	if json.Unmarshal(raw, &envelope) != nil || len(envelope.Nonce) != c.aead.NonceSize() {
		return ErrInvalidInput
	}
	plain, e := c.aead.Open(nil, envelope.Nonce, envelope.Ciphertext, []byte("jms233/shared-keys/v1"))
	if e != nil {
		return errors.New("shared SSH key journal cannot be decrypted")
	}
	if json.Unmarshal(plain, &c.keys.ops) != nil || c.keys.ops == nil || len(c.keys.ops) > 10000 {
		return ErrInvalidInput
	}
	for id, o := range c.keys.ops {
		if o == nil || id != o.ID || !sshclient.ValidKeyOperationID(id) || len(o.Identity) != 64 || !validFingerprint(o.OldFingerprint) || !validFingerprint(o.NewFingerprint) || o.OldFingerprint == o.NewFingerprint || len(o.Participants) < 2 || len(o.Participants) > 10000 || !validSharedKeyPhase(o.Phase) {
			return ErrInvalidInput
		}
		seen := map[passwordParticipant]bool{}
		for _, p := range o.Participants {
			if p.Scope == "" || len(p.Scope) > 64 || p.AssetID == "" || len(p.AssetID) > 128 || p.Revision == 0 || p.Revision == math.MaxUint64 || !keyRequestPattern.MatchString(p.RequestID) || seen[p.passwordParticipant] {
				return ErrInvalidInput
			}
			seen[p.passwordParticipant] = true
		}
		if !seen[o.Source] {
			return ErrInvalidInput
		}
	}
	c.refreshKeyViews()
	return nil
}
func validSharedKeyPhase(p string) bool {
	return p == "prepare" || p == "active" || p == "promote" || p == "cleanup" || p == "finish" || p == "cancel_finish"
}
func (c *PasswordCoordinator) keyJournalPath() string {
	return filepath.Join(filepath.Dir(c.path), "shared-keys.json")
}
func (c *PasswordCoordinator) saveSharedKeys() error {
	plain, e := json.Marshal(c.keys.ops)
	if e != nil {
		return e
	}
	nonce := make([]byte, c.aead.NonceSize())
	if _, e = rand.Read(nonce); e != nil {
		return e
	}
	raw, e := json.Marshal(encryptedSecret{Nonce: nonce, Ciphertext: c.aead.Seal(nil, nonce, plain, []byte("jms233/shared-keys/v1"))})
	if e != nil {
		return e
	}
	if c.documents != nil {
		e = c.documents.Save("shared-keys", raw)
	} else {
		path := c.keyJournalPath()
		if e = os.MkdirAll(filepath.Dir(path), 0700); e != nil {
			return e
		}
		f, openError := os.CreateTemp(filepath.Dir(path), ".shared-keys-*")
		if openError != nil {
			return openError
		}
		defer os.Remove(f.Name())
		e = f.Chmod(0600)
		if e == nil {
			_, e = f.Write(raw)
		}
		if e == nil {
			e = f.Sync()
		}
		closeError := f.Close()
		if e == nil {
			e = closeError
		}
		if e == nil {
			e = os.Rename(f.Name(), path)
		}
	}
	if e == nil {
		c.refreshKeyViews()
	}
	return e
}
func (c *PasswordCoordinator) refreshKeyViews() {
	view := map[passwordParticipant]sharedKeyView{}
	for _, o := range c.keys.ops {
		for _, p := range o.Participants {
			view[p.passwordParticipant] = sharedKeyView{Phase: o.Phase, OperationID: o.ID, RequestID: p.RequestID, Revision: p.Revision, CanCancel: !o.PromotionStarted && (o.Phase == "prepare" || o.Phase == "active")}
		}
	}
	c.keys.view.Store(&view)
}
func (c *PasswordCoordinator) refreshSharedKeyCounts() {
	counts := map[string]int{}
	for _, st := range c.stores {
		for _, a := range st.List() {
			if a.CredentialType == CredentialSSHKey {
				counts[passwordIdentity(a)+"/"+a.KeyFingerprint]++
			}
		}
	}
	shared := map[passwordParticipant]bool{}
	for scope, st := range c.stores {
		for _, a := range st.List() {
			if a.CredentialType == CredentialSSHKey && counts[passwordIdentity(a)+"/"+a.KeyFingerprint] > 1 {
				shared[passwordParticipant{scope, a.ID}] = true
			}
		}
	}
	c.keys.shared.Store(&shared)
}
func (s *Service) sharedKeyView(id string) (bool, sharedKeyView) {
	c := s.passwordCoordinator
	if c == nil {
		return false, sharedKeyView{}
	}
	p := passwordParticipant{s.passwordScope, id}
	v := sharedKeyView{}
	if view := c.keys.view.Load(); view != nil {
		v = (*view)[p]
	}
	shared := v.OperationID != ""
	if counts := c.keys.shared.Load(); counts != nil {
		shared = shared || (*counts)[p]
	}
	return shared, v
}
func (c *PasswordCoordinator) keyOperation(p passwordParticipant) *sharedKeyOperation {
	for _, o := range c.keys.ops {
		for _, m := range o.Participants {
			if m.passwordParticipant == p {
				return o
			}
		}
	}
	return nil
}
func (c *PasswordCoordinator) sharedKeyMutation(a Asset) bool {
	for _, o := range c.keys.ops {
		if passwordIdentity(a) == o.Identity {
			return true
		}
	}
	return false
}

// withKeyChange holds the same mutation boundary as password rotation and asset
// edits. Remote work is cancelled when the active node loses ownership.
func (c *PasswordCoordinator) withKeyChange(ctx context.Context, s *Service, id string, cancelOperation bool, run func(context.Context) (ListItem, error)) (ListItem, error) {
	if e := c.lockCredentialContext(ctx); e != nil {
		return ListItem{}, e
	}
	defer c.mu.Unlock()
	if !cancelOperation {
		a, e := s.Get(id)
		if e != nil {
			return ListItem{}, e
		}
		if c.certificateParticipant(passwordIdentity(a)) {
			return ListItem{}, ErrCredentialType
		}
		if e := s.guardManagedRotation(ctx, id); e != nil {
			return ListItem{}, e
		}
	}
	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	if c.ownerContext != nil {
		stop := context.AfterFunc(c.ownerContext, cancel)
		defer stop()
		if e := c.ownerContext.Err(); e != nil {
			return ListItem{}, e
		}
	}
	for _, o := range c.ops {
		for _, p := range o.Participants {
			if p.Scope == s.passwordScope && p.AssetID == id {
				return ListItem{}, ErrRotationPending
			}
		}
	}
	if o := c.keyOperation(passwordParticipant{s.passwordScope, id}); o != nil {
		if o.Phase == "finish" || o.Phase == "cancel_finish" {
			if e := c.finishSharedKeyOperation(o, o.Phase == "cancel_finish"); e != nil {
				return ListItem{}, e
			}
		} else if cancelOperation && (o.PromotionStarted || o.Phase == "promote" || o.Phase == "cleanup") {
			return ListItem{}, ErrSSHKeyCommitted
		}
		if o.Phase == "prepare" && !s.store.HasPendingSSHKeyChange(id) {
			return ListItem{}, ErrSSHKeyPending
		}
	}
	defer c.refreshSharedKeyCounts()
	return run(ctx)
}

// stageSharedKey uses the coordinator's operation but the participant's own
// revision, audit identity and encryption key. It never exposes key material.
func (st *Store) stageSharedKey(id string, m sharedKeyParticipant, parent pendingKeyChange, data keyChangeData) error {
	st.mu.Lock()
	defer st.mu.Unlock()
	record, ok := st.assets[id]
	if !ok {
		return ErrNotFound
	}
	if record.PendingKeyChange != nil {
		p, d, e := st.openKeyChange(record)
		if e != nil {
			return e
		}
		if p.OperationID != parent.OperationID || p.ExpectedRevision != m.Revision || d.NewFingerprint != data.NewFingerprint {
			return ErrSSHKeyPending
		}
		return nil
	}
	if record.PendingRotation != nil {
		return ErrRotationPending
	}
	if record.CredentialType != CredentialSSHKey || record.KeyFingerprint != data.OldFingerprint || record.CredentialRevision != m.Revision {
		return ErrCredentialChanged
	}
	if _, e := nextCredentialRevision(record.Asset); e != nil {
		return e
	}
	old, e := st.aead.Open(nil, record.Credential.Nonce, record.Credential.Ciphertext, credentialAAD(id, record.CredentialType, ""))
	if e != nil {
		return ErrSharedCredentialConflict
	}
	// OpenSSH PEM check integers are randomized when normalizing a key. Prove
	// possession of the same signing key instead of comparing serialized bytes.
	local, localError := xssh.ParsePrivateKey(old)
	origin, originError := xssh.ParsePrivateKey(data.Old.PrivateKey)
	if localError != nil || originError != nil || !bytes.Equal(local.PublicKey().Marshal(), origin.PublicKey().Marshal()) {
		return ErrSharedCredentialConflict
	}
	proof := []byte("jms233/shared-key-proof/" + parent.OperationID)
	signature, e := local.Sign(rand.Reader, proof)
	if e != nil || origin.PublicKey().Verify(proof, signature) != nil {
		return ErrSharedCredentialConflict
	}
	data.Old = sshclient.Credentials{PrivateKey: old}
	p := pendingKeyChange{OperationID: parent.OperationID, RequestID: m.RequestID, ExpectedRevision: m.Revision, Phase: "install", StartedAt: parent.StartedAt}
	data.Actor = "system/shared-key-rotation"
	if e = st.sealKeyChange(id, &p, data); e != nil {
		return e
	}
	previous := record
	record.PendingKeyChange = &p
	record.KeyLastAttemptAt = time.Now().UTC()
	record.KeyLastError = ""
	st.assets[id] = record
	if e = st.persistLocked(); e != nil {
		st.assets[id] = previous
	}
	return e
}
func (c *PasswordCoordinator) prepareSharedKey(ctx context.Context, s *Service, id string, p pendingKeyChange, data keyChangeData) error {
	if data.OldType != CredentialSSHKey {
		return nil
	}
	member := passwordParticipant{s.passwordScope, id}
	o := c.keyOperation(member)
	if o == nil {
		a, e := s.Get(id)
		if e != nil {
			return e
		}
		members := []sharedKeyParticipant{{passwordParticipant: member, Revision: p.ExpectedRevision, RequestID: p.RequestID}}
		for scope, st := range c.stores {
			for _, other := range st.List() {
				if other.CredentialType == CredentialSSHKey && other.KeyFingerprint == data.OldFingerprint && passwordIdentity(other) == passwordIdentity(a) {
					q := passwordParticipant{scope, other.ID}
					if q == member {
						continue
					}
					if _, e := nextCredentialRevision(other); e != nil {
						return e
					}
					request := "shared-" + strings.TrimPrefix(p.OperationID, "kr-")
					if st.HasPendingSSHKeyChange(other.ID) || st.HasPendingPasswordRotation(other.ID) {
						return ErrSSHKeyPending
					}
					if service := c.services[scope]; service != nil && q != member {
						service.mu.RLock()
						busy := service.rotationRunning[other.ID]
						service.mu.RUnlock()
						if busy {
							return ErrRotationInProgress
						}
					}
					members = append(members, sharedKeyParticipant{passwordParticipant: q, Revision: other.CredentialRevision, RequestID: request})
				}
			}
		}
		if len(members) < 2 {
			return nil
		}
		if len(members) > 10000 || len(c.keys.ops) >= 10000 {
			return ErrSharedCredentialConflict
		}
		sort.Slice(members, func(i, j int) bool {
			a, b := members[i].passwordParticipant, members[j].passwordParticipant
			if a == member {
				return false
			}
			if b == member {
				return true
			}
			if a.Scope == b.Scope {
				return a.AssetID < b.AssetID
			}
			return a.Scope < b.Scope
		})
		o = &sharedKeyOperation{ID: p.OperationID, Identity: passwordIdentity(a), OldFingerprint: data.OldFingerprint, NewFingerprint: data.NewFingerprint, Source: member, Participants: members, Phase: "prepare", PromotionStarted: p.Phase == "cleanup"}
		c.keys.ops[o.ID] = o
		if e = c.saveSharedKeys(); e != nil {
			delete(c.keys.ops, o.ID)
			return e
		}
	}
	if o.ID != p.OperationID || o.NewFingerprint != data.NewFingerprint {
		return ErrSSHKeyPending
	}
	if o.Phase != "prepare" {
		return nil
	}
	for _, m := range o.Participants {
		if e := ctx.Err(); e != nil {
			return e
		}
		if m.passwordParticipant == o.Source {
			continue
		}
		st := c.stores[m.Scope]
		if st == nil {
			return ErrNotFound
		}
		if e := st.stageSharedKey(m.AssetID, m, p, data); e != nil {
			return e
		}
	}
	phase := "active"
	if o.PromotionStarted {
		phase = "promote"
	}
	return c.sharedKeyPhase(o, phase)
}
func (c *PasswordCoordinator) sharedKeyPhase(o *sharedKeyOperation, phase string) error {
	old := o.Phase
	o.Phase = phase
	if e := c.saveSharedKeys(); e != nil {
		o.Phase = old
		return e
	}
	return nil
}
func (s *Service) promoteKeyChange(ctx context.Context, id, operationID string, data keyChangeData) error {
	c := s.passwordCoordinator
	if c == nil {
		return s.store.CommitSSHKeyChange(id, operationID)
	}
	o := c.keyOperation(passwordParticipant{s.passwordScope, id})
	if o == nil {
		return s.store.CommitSSHKeyChange(id, operationID)
	}
	if o.Phase == "cleanup" {
		return nil
	}
	if o.Phase != "active" && o.Phase != "promote" {
		return ErrSSHKeyPending
	}
	if data.Plan == nil {
		return ErrInvalidInput
	}
	if o.Phase == "active" {
		if e := c.sharedKeyPhase(o, "promote"); e != nil {
			return e
		}
	}
	for _, m := range o.Participants {
		if e := ctx.Err(); e != nil {
			return e
		}
		st := c.stores[m.Scope]
		if st == nil {
			return ErrNotFound
		}
		a, e := c.asset(m.passwordParticipant)
		if e != nil || passwordIdentity(a) != o.Identity {
			return ErrCredentialChanged
		}
		p, d, e := st.PendingSSHKeyChange(m.AssetID)
		if e != nil || p.OperationID != o.ID || d.NewFingerprint != o.NewFingerprint {
			return ErrCredentialChanged
		}
		if d.Plan == nil {
			if e = st.SaveSSHKeyPlan(m.AssetID, o.ID, *data.Plan); e != nil {
				return e
			}
		}
		// The initiating active route is verified before promotion. Disabled copies
		// retain the shared credential but must never open a remote connection.
		if !a.AccountDisabled {
			_, target, _, e := st.connection(m.AssetID)
			if e != nil {
				return e
			}
			verify := s.verifyPassword
			if service := c.services[m.Scope]; service != nil {
				verify = service.verifyPassword
			}
			if e = verify(ctx, target, data.New, 8*time.Second); e != nil {
				return e
			}
		}
		if e = st.CommitSSHKeyChange(m.AssetID, o.ID); e != nil {
			return e
		}
		c.invalidate(m.passwordParticipant)
	}
	return c.sharedKeyPhase(o, "cleanup")
}
func (s *Service) finishKeyChange(id, operationID string, cancelled bool) error {
	c := s.passwordCoordinator
	if c == nil {
		return s.store.FinishSSHKeyChange(id, operationID, cancelled)
	}
	o := c.keyOperation(passwordParticipant{s.passwordScope, id})
	if o == nil {
		return s.store.FinishSSHKeyChange(id, operationID, cancelled)
	}
	phase := "finish"
	if cancelled {
		phase = "cancel_finish"
	}
	if e := c.sharedKeyPhase(o, phase); e != nil {
		return e
	}
	return c.finishSharedKeyOperation(o, cancelled)
}
func (c *PasswordCoordinator) finishSharedKeyOperation(o *sharedKeyOperation, cancelled bool) error {
	for _, m := range o.Participants {
		st := c.stores[m.Scope]
		if st == nil {
			return ErrNotFound
		}
		a, e := c.asset(m.passwordParticipant)
		if e != nil || passwordIdentity(a) != o.Identity {
			return ErrCredentialChanged
		}
		if st.HasPendingSSHKeyChange(m.AssetID) {
			if e = st.FinishSSHKeyChange(m.AssetID, o.ID, cancelled); e != nil {
				return e
			}
		} else {
			st.mu.RLock()
			record := st.assets[m.AssetID]
			st.mu.RUnlock()
			result := "completed"
			if cancelled {
				result = "cancelled"
			}
			finished := record.LastKeyRequestID == m.RequestID && record.LastKeyRequestRevision == m.Revision && record.LastKeyResult == result
			if !finished && !(cancelled && record.CredentialRevision == m.Revision && record.KeyFingerprint == o.OldFingerprint) {
				return ErrCredentialChanged
			}
			if cancelled && !finished {
				if e = st.RecordSSHKeyAttempt(m.AssetID, "", time.Now().UTC()); e != nil {
					return e
				}
			}
		}
		service := c.services[m.Scope]
		if service == nil {
			service = NewService(st, nil)
		}
		result := "success"
		if cancelled {
			result = "cancelled"
		}
		if e = service.appendRotationAuditDetails(a, "shared_ssh_key_completed", "ssh_key", result, "", "", "", o.ID); e != nil {
			return e
		}
	}
	delete(c.keys.ops, o.ID)
	if e := c.saveSharedKeys(); e != nil {
		c.keys.ops[o.ID] = o
		return e
	}
	c.refreshSharedKeyCounts()
	return nil
}
func (c *PasswordCoordinator) recoverSharedKeys(ctx context.Context) {
	ids := make([]string, 0, len(c.keys.ops))
	for id := range c.keys.ops {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		if ctx.Err() != nil {
			return
		}
		o := c.keys.ops[id]
		if o == nil {
			continue
		}
		if last := c.keys.attempts[id]; !last.IsZero() && time.Since(last) < rotationRetryInterval {
			continue
		}
		c.keys.attempts[id] = time.Now().UTC()
		if o.Phase == "finish" || o.Phase == "cancel_finish" {
			_ = c.finishSharedKeyOperation(o, o.Phase == "cancel_finish")
			continue
		}
		st := c.stores[o.Source.Scope]
		if st == nil {
			continue
		}
		service := c.services[o.Source.Scope]
		if service == nil {
			service = NewService(st, nil)
			service.passwordCoordinator = c
			service.passwordScope = o.Source.Scope
		}
		if e := service.claimKeyChange(o.Source.AssetID); e != nil {
			continue
		}
		_ = service.continueSSHKeyChange(ctx, o.Source.AssetID, o.ID, "system/shared-key-recovery")
		service.releaseRotation(o.Source.AssetID)
	}
}
