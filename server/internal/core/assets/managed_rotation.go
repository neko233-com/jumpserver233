package assets

import (
	"context"
	"encoding/hex"
	"errors"
	"time"

	"github.com/neko233-com/jumpserver233/server/internal/connector/sshclient"
	"github.com/neko233-com/jumpserver233/server/internal/core/credentialpolicy"
	"github.com/neko233-com/jumpserver233/server/internal/core/rotationplans"
)

type plannedPasswordIntent struct {
	FixedSecretID  string                 `json:"fixed_secret_id,omitempty"`
	PasswordPolicy credentialpolicy.Rules `json:"password_policy,omitzero"`
	RequestID      string                 `json:"request_id"`
	Revision       uint64                 `json:"revision"`
	Version        string                 `json:"version"`
	Actor          rotationplans.Actor    `json:"actor"`
}
type plannedPasswordReceipt struct {
	plannedPasswordIntent
	State         string    `json:"state"`
	AfterRevision uint64    `json:"after_revision"`
	At            time.Time `json:"at"`
}
type managedRotationKey struct{}
type managedRotationContext struct {
	Intent   rotationplans.Intent
	Guard    func() error
	Recovery bool
}

func managedContext(ctx context.Context) *managedRotationContext {
	v, _ := ctx.Value(managedRotationKey{}).(*managedRotationContext)
	return v
}
func plannedPassword(ctx context.Context) *plannedPasswordIntent {
	v := managedContext(ctx)
	if v == nil {
		return nil
	}
	return &plannedPasswordIntent{FixedSecretID: v.Intent.FixedSecretID, PasswordPolicy: v.Intent.PasswordPolicy, RequestID: v.Intent.RequestID, Revision: v.Intent.Target.Revision, Version: v.Intent.Target.Version, Actor: v.Intent.Actor}
}
func validRotationVersion(v string) bool {
	if len(v) != 64 {
		return false
	}
	_, e := hex.DecodeString(v)
	return e == nil
}
func validPlannedPassword(p *plannedPasswordIntent) bool {
	return p != nil && (p.FixedSecretID == "" || rotationplans.IDPattern.MatchString(p.FixedSecretID)) && p.PasswordPolicy.OptionalValid() && rotationplans.IDPattern.MatchString(p.RequestID) && p.Revision > 0 && p.Revision < 1<<53 && validRotationVersion(p.Version) && rotationplans.ValidActor(p.Actor)
}
func hasPlannedRotationMetadata(r storedAsset) bool {
	return r.PlannedPasswordReceipt != nil || r.PendingRotation != nil && r.PendingRotation.Planned != nil
}
func validatePlannedRotationRecord(r storedAsset) error {
	if p := r.PlannedPasswordReceipt; p != nil {
		if !validPlannedPassword(&p.plannedPasswordIntent) || p.At.IsZero() || p.State != "succeeded" && p.State != "failed" || p.State == "succeeded" && p.AfterRevision != p.Revision+1 || p.State == "failed" && p.AfterRevision != p.Revision {
			return ErrInvalidInput
		}
	}
	if r.PendingRotation != nil && r.PendingRotation.Planned != nil {
		if !validPlannedPassword(r.PendingRotation.Planned) || r.PendingRotation.Planned.Revision != r.CredentialRevision || r.PendingRotation.BackupID != "" {
			return ErrInvalidInput
		}
	}
	return nil
}

func sameRotationHost(a, b Asset) bool {
	a.Username = ""
	b.Username = ""
	return passwordIdentity(a) == passwordIdentity(b)
}

type rotationRoute struct {
	ID       string
	Identity string
}

func (s *Store) rotationRouteLocked(id string) ([]rotationRoute, error) {
	out := []rotationRoute{}
	seen := map[string]bool{}
	for id != "" {
		r, ok := s.assets[id]
		if !ok {
			return nil, ErrNotFound
		}
		if seen[id] || len(out) > sshclient.MaxGatewayHops || !IsSSH(r.Asset) || r.AccountDisabled {
			return nil, ErrInvalidInput
		}
		seen[id] = true
		out = append(out, rotationRoute{id, passwordIdentity(r.Asset)})
		id = r.GatewayID
	}
	return out, nil
}
func (s *Store) prepareManagedRotationLocked(in rotationplans.Selection) (rotationplans.Prepared, error) {
	r, ok := s.assets[in.AccountID]
	if !ok {
		return rotationplans.Prepared{}, ErrNotFound
	}
	a := r.Asset
	if !IsSSH(a) || a.AccountDisabled || remoteAccountPending(a) {
		return rotationplans.Prepared{}, ErrInvalidInput
	}
	route, e := s.rotationRouteLocked(a.ID)
	if e != nil {
		return rotationplans.Prepared{}, e
	}
	parent := s.assets[ResourceID(a)]
	kind := credentialType(a.CredentialType)
	ref := rotationplans.Ref{AssetID: ResourceID(a), AccountID: a.ID, AssetName: parent.Name, Username: a.Username, CredentialType: kind}
	var collector []rotationRoute
	if in.CollectorID != "" && in.CollectorID != a.ID {
		c, ok := s.assets[in.CollectorID]
		if !ok || kind != CredentialPassword || !IsSSH(c.Asset) || c.AccountDisabled || !sameRotationHost(a, c.Asset) || remoteAccountPending(c.Asset) {
			return rotationplans.Prepared{}, ErrInvalidInput
		}
		collector, e = s.rotationRouteLocked(c.ID)
		if e != nil {
			return rotationplans.Prepared{}, e
		}
		ref.CollectorID, ref.CollectorUsername = c.ID, c.Username
	}
	binding := s.importMAC("managed-rotation-binding/v1", struct {
		Route, Collector []rotationRoute
		Kind             string
	}{route, collector, kind})
	group := s.importMAC("managed-rotation-group/v1", struct{ Identity, Kind, Fingerprint string }{passwordIdentity(a), kind, a.KeyFingerprint})
	rotated := r.PasswordRotatedAt
	if kind == CredentialSSHKey {
		rotated = a.KeyRotatedAt
	}
	return rotationplans.Prepared{Ref: ref, Version: accountVersion(a), Revision: a.CredentialRevision, Binding: binding, Group: group, RotatedAt: rotated}, nil
}

// PrepareManagedRotations snapshots metadata only. Version and route checks are
// repeated inside the coordinator mutation boundary immediately before staging.
func (s *Service) PrepareManagedRotations(ctx context.Context, in []rotationplans.Selection) ([]rotationplans.Prepared, error) {
	if len(in) < 1 || len(in) > rotationplans.MaxTargets {
		return nil, rotationplans.ErrInvalid
	}
	s.store.mu.RLock()
	defer s.store.mu.RUnlock()
	out := make([]rotationplans.Prepared, 0, len(in))
	seen := map[string]bool{}
	for _, v := range in {
		if e := ctx.Err(); e != nil {
			return nil, e
		}
		if seen[v.AccountID] {
			return nil, rotationplans.ErrInvalid
		}
		seen[v.AccountID] = true
		p, e := s.store.prepareManagedRotationLocked(v)
		if e != nil {
			return nil, e
		}
		out = append(out, p)
	}
	return out, nil
}
func (s *Service) guardManagedRotation(ctx context.Context, id string) error {
	v := managedContext(ctx)
	if v == nil {
		return nil
	}
	if e := ctx.Err(); e != nil {
		return e
	}
	if e := v.Guard(); e != nil {
		return e
	}
	s.store.mu.RLock()
	defer s.store.mu.RUnlock()
	a, e := s.store.prepareManagedRotationLocked(rotationplans.Selection{AccountID: id, CollectorID: v.Intent.Target.CollectorID})
	if e != nil {
		return e
	}
	if a.AccountID != v.Intent.Target.AccountID || a.Binding != v.Intent.Target.Binding {
		return ErrCredentialChanged
	}
	if v.Recovery {
		r := s.store.assets[id]
		if r.PendingKeyChange == nil || r.PendingKeyChange.RequestID != v.Intent.RequestID || r.PendingKeyChange.ExpectedRevision != v.Intent.Target.Revision {
			return ErrCredentialChanged
		}
	} else if a.Version != v.Intent.Target.Version || a.Revision != v.Intent.Target.Revision {
		return ErrCredentialChanged
	}
	return nil
}
func (s *Service) InspectManagedRotation(ctx context.Context, in rotationplans.Intent) (rotationplans.Outcome, error) {
	if in.FixedSecretID != "" && (!rotationplans.IDPattern.MatchString(in.FixedSecretID) || in.Target.CredentialType != CredentialPassword) {
		return rotationplans.Outcome{}, rotationplans.ErrInvalid
	}
	if !in.PasswordPolicy.OptionalValid() || !in.PasswordPolicy.IsZero() && in.Target.CredentialType != CredentialPassword {
		return rotationplans.Outcome{}, rotationplans.ErrInvalid
	}
	if s.passwordCoordinator == nil {
		return rotationplans.Outcome{}, rotationplans.ErrBusy
	}
	if e := ctx.Err(); e != nil {
		return rotationplans.Outcome{}, e
	}
	c := s.passwordCoordinator
	s.store.mu.RLock()
	defer s.store.mu.RUnlock()
	r, ok := s.store.assets[in.Target.AccountID]
	if !ok {
		return rotationplans.Outcome{State: "changed", Code: "not_found"}, nil
	}
	if c.hasPendingCredential(s.passwordScope, r.ID) || r.PendingRotation != nil || r.PendingKeyChange != nil {
		return rotationplans.Outcome{State: "recovery_required", Code: "credential_pending"}, nil
	}
	if p := r.PlannedPasswordReceipt; p != nil && p.RequestID == in.RequestID {
		if p.FixedSecretID != in.FixedSecretID || p.PasswordPolicy != in.PasswordPolicy || p.Revision != in.Target.Revision || p.Version != in.Target.Version || p.Actor.ID != in.Actor.ID {
			return rotationplans.Outcome{}, rotationplans.ErrConflict
		}
		return rotationplans.Outcome{State: p.State, Revision: p.AfterRevision, At: p.At}, nil
	}
	if r.LastKeyRequestID == in.RequestID {
		if r.LastKeyRequestRevision != in.Target.Revision {
			return rotationplans.Outcome{}, rotationplans.ErrConflict
		}
		state := "succeeded"
		revision := in.Target.Revision + 1
		if r.LastKeyResult != "completed" {
			state = "failed"
			revision = in.Target.Revision
		}
		return rotationplans.Outcome{State: state, Revision: revision, At: r.KeyRotatedAt}, nil
	}
	a, e := s.store.prepareManagedRotationLocked(rotationplans.Selection{AccountID: r.ID, CollectorID: in.Target.CollectorID})
	if e != nil || a.Version != in.Target.Version || a.Binding != in.Target.Binding {
		return rotationplans.Outcome{State: "changed", Code: "source_changed"}, nil
	}
	return rotationplans.Outcome{State: "not_started"}, nil
}
func (s *Service) ExecuteManagedRotation(ctx context.Context, in rotationplans.Intent, guard func() error) (rotationplans.Outcome, error) {
	if in.FixedSecretID != "" && (!rotationplans.IDPattern.MatchString(in.FixedSecretID) || !credentialpolicy.ValidFixedPassword(in.FixedPassword) || in.Target.CredentialType != CredentialPassword) || in.FixedSecretID == "" && in.FixedPassword != "" {
		return rotationplans.Outcome{}, rotationplans.ErrInvalid
	}
	if !in.PasswordPolicy.OptionalValid() || !in.PasswordPolicy.IsZero() && in.Target.CredentialType != CredentialPassword {
		return rotationplans.Outcome{}, rotationplans.ErrInvalid
	}
	if guard == nil || !rotationplans.ValidActor(in.Actor) || !rotationplans.IDPattern.MatchString(in.RequestID) || !validRotationVersion(in.Target.Version) || in.Target.Revision == 0 {
		return rotationplans.Outcome{}, rotationplans.ErrInvalid
	}
	if e := guard(); e != nil {
		return rotationplans.Outcome{}, e
	}
	prior, e := s.InspectManagedRotation(ctx, in)
	if e != nil || prior.State != "not_started" {
		return prior, e
	}
	ctx = context.WithValue(ctx, managedRotationKey{}, &managedRotationContext{Intent: in, Guard: guard})
	if in.Target.CredentialType == CredentialPassword {
		e = s.rotatePasswordTo(ctx, in.Target.AccountID, "planned", in.Actor.ID, "")
	} else if in.Target.CredentialType == CredentialSSHKey && in.Target.CollectorID == "" {
		_, e = s.RotateSSHKey(ctx, in.Target.AccountID, in.RequestID, in.Target.Revision, in.Actor.ID)
	} else {
		return rotationplans.Outcome{}, rotationplans.ErrInvalid
	}
	// Inspect is separate from the caller's cancelled context: completed metadata
	// remains authoritative even when transport/timeout lost the final response.
	result, inspection := s.InspectManagedRotation(context.WithoutCancel(ctx), in)
	if inspection != nil {
		return rotationplans.Outcome{}, inspection
	}
	if result.State == "not_started" && e != nil {
		result.State = "failed"
		result.Code = managedRotationError(e)
	}
	if result.State == "changed" && e != nil {
		result.Code = managedRotationError(e)
	}
	return result, e
}
func managedRotationError(e error) string {
	switch {
	case errors.Is(e, credentialpolicy.ErrConflict):
		return "password_policy_conflict"
	case errors.Is(e, ErrCredentialChanged):
		return "source_changed"
	case errors.Is(e, ErrRotationInProgress), errors.Is(e, ErrRotationPending), errors.Is(e, ErrSSHKeyPending):
		return "credential_pending"
	case errors.Is(e, context.Canceled):
		return "cancelled"
	case errors.Is(e, context.DeadlineExceeded):
		return "timeout"
	case errors.Is(e, rotationplans.ErrDenied):
		return "denied"
	default:
		return "rotation_failed"
	}
}
func (s *Service) changeManagedPassword(ctx context.Context, a Asset, target sshclient.Target, current sshclient.Credentials, next string) error {
	v := managedContext(ctx)
	if v == nil || v.Intent.Target.CollectorID == "" {
		return s.changePassword(ctx, target, current, next, 15*time.Second)
	}
	if e := v.Guard(); e != nil {
		return e
	}
	collector, route, credentials, e := s.store.connection(v.Intent.Target.CollectorID)
	if e != nil {
		return e
	}
	if !sameRotationHost(a, collector) {
		return ErrCredentialChanged
	}
	change := s.changePasswordFor
	if change == nil {
		change = sshclient.ChangePasswordFor
	}
	return change(ctx, route, credentials, a.Username, next, 15*time.Second)
}

// RecoverManagedRotation resumes only the previously recorded operation. A
// different pending operation is never borrowed by a plan's recovery request.
func (s *Service) RecoverManagedRotation(ctx context.Context, in rotationplans.Intent, as rotationplans.Actor, guard func() error) (rotationplans.Outcome, error) {
	if in.FixedSecretID != "" && (!rotationplans.IDPattern.MatchString(in.FixedSecretID) || in.Target.CredentialType != CredentialPassword) {
		return rotationplans.Outcome{}, rotationplans.ErrInvalid
	}
	if !rotationplans.ValidActor(as) || guard == nil || !in.PasswordPolicy.OptionalValid() || !in.PasswordPolicy.IsZero() && in.Target.CredentialType != CredentialPassword {
		return rotationplans.Outcome{}, rotationplans.ErrInvalid
	}
	if e := guard(); e != nil {
		return rotationplans.Outcome{}, e
	}
	c := s.passwordCoordinator
	if c == nil {
		return rotationplans.Outcome{}, rotationplans.ErrBusy
	}
	if e := c.lockCredentialContext(ctx); e != nil {
		return rotationplans.Outcome{}, e
	}
	s.store.mu.RLock()
	r, ok := s.store.assets[in.Target.AccountID]
	current, e := s.store.prepareManagedRotationLocked(rotationplans.Selection{AccountID: in.Target.AccountID, CollectorID: in.Target.CollectorID})
	s.store.mu.RUnlock()
	if !ok || e != nil || current.Binding != in.Target.Binding {
		c.mu.Unlock()
		return rotationplans.Outcome{State: "recovery_required", Code: "source_changed"}, nil
	}
	shared := c.ops[passwordIdentity(r.Asset)]
	ownedPassword := r.PendingRotation != nil && r.PendingRotation.Planned != nil && r.PendingRotation.Planned.RequestID == in.RequestID && r.PendingRotation.Planned.Actor.ID == in.Actor.ID && r.PendingRotation.Planned.PasswordPolicy == in.PasswordPolicy && r.PendingRotation.Planned.FixedSecretID == in.FixedSecretID
	ownedKey := r.PendingKeyChange != nil && r.PendingKeyChange.RequestID == in.RequestID && r.PendingKeyChange.ExpectedRevision == in.Target.Revision
	if shared != nil {
		if shared.Planned == nil || shared.Planned.RequestID != in.RequestID || shared.Planned.PasswordPolicy != in.PasswordPolicy || shared.Planned.FixedSecretID != in.FixedSecretID || shared.Source != (passwordParticipant{s.passwordScope, r.ID}) {
			c.mu.Unlock()
			return rotationplans.Outcome{State: "recovery_required", Code: "different_operation"}, nil
		}
		if e := guard(); e != nil {
			c.mu.Unlock()
			return rotationplans.Outcome{}, e
		}
		delete(c.lastRecovery, shared.Identity)
		c.recoverOperation(ctx, shared.Identity)
		c.mu.Unlock()
	} else if ownedPassword {
		asset, e := s.claimRotation(r.ID, time.Now().UTC(), "recovery_required", false)
		if e == nil {
			if e = guard(); e == nil {
				_, e = s.reconcilePendingRotation(ctx, asset, "recovery", time.Now().UTC(), "planned_recovery", as.ID, "")
			}
			s.releaseRotation(r.ID)
		}
		c.mu.Unlock()
		if e != nil {
			return rotationplans.Outcome{State: "recovery_required", Code: managedRotationError(e)}, e
		}
	} else if ownedKey {
		c.mu.Unlock()
		if e := guard(); e != nil {
			return rotationplans.Outcome{}, e
		}
		ctx = context.WithValue(ctx, managedRotationKey{}, &managedRotationContext{Intent: in, Guard: guard, Recovery: true})
		_, _ = s.RotateSSHKey(ctx, r.ID, in.RequestID, in.Target.Revision, as.ID)
	} else {
		c.mu.Unlock()
	}
	return s.InspectManagedRotation(context.WithoutCancel(ctx), in)
}
