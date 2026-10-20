package assets

import (
	"context"
	"errors"
	"time"

	"github.com/neko233-com/jumpserver233/server/internal/connector/sshclient"
	"github.com/neko233-com/jumpserver233/server/internal/core/rotationplans"
)

// CheckManagedAccount authenticates against the pinned principal and route.
// Windows local identities are checked through the selected SSH collector's
// system account API; ordinary SSH remains an authentication-only check.
func (s *Service) CheckManagedAccount(ctx context.Context, in rotationplans.Intent, guard func() error) (rotationplans.Outcome, error) {
	if guard == nil || !rotationplans.ValidActor(in.Actor) || !rotationplans.IDPattern.MatchString(in.RequestID) || in.Target.Revision == 0 || !validRotationVersion(in.Target.Version) || in.FixedPassword != "" || in.FixedSecretID != "" || !in.PasswordPolicy.IsZero() {
		return rotationplans.Outcome{}, rotationplans.ErrInvalid
	}
	ctx, release, admissionErr := s.store.admissionGate().Enter(ctx, "probes")
	if admissionErr != nil {
		return checkOutcome(admissionErr, 0), admissionErr
	}
	defer release()
	check := func() error {
		if e := ctx.Err(); e != nil {
			return e
		}
		if e := guard(); e != nil {
			return e
		}
		if s.passwordCoordinator != nil && s.passwordCoordinator.hasPendingCredential(s.passwordScope, in.Target.AccountID) {
			return ErrRotationPending
		}
		s.store.mu.RLock()
		defer s.store.mu.RUnlock()
		fresh, e := s.store.prepareManagedRotationLocked(rotationplans.Selection{AccountID: in.Target.AccountID, CollectorID: in.Target.CollectorID})
		if e != nil || fresh.Version != in.Target.Version || fresh.Revision != in.Target.Revision || fresh.Binding != in.Target.Binding {
			return ErrCredentialChanged
		}
		r := s.store.assets[in.Target.AccountID]
		if r.PendingRotation != nil || r.PendingKeyChange != nil {
			return ErrRotationPending
		}
		return nil
	}
	if e := check(); e != nil {
		return checkOutcome(e, 0), e
	}
	s.store.mu.RLock()
	binding, e := s.store.connectionBindingLocked(in.Target.AccountID)
	s.store.mu.RUnlock()
	if e != nil {
		return checkOutcome(e, 0), e
	}
	a, target, credentials, e := s.store.connectionForProtocolBound(in.Target.AccountID, false, binding)
	if e != nil {
		return checkOutcome(e, 0), e
	}
	if e = check(); e != nil {
		return checkOutcome(e, 0), e
	}
	started := time.Now()
	ctx = context.WithValue(ctx, managedRotationKey{}, &managedRotationContext{Intent: in, Guard: check})
	if IsSSH(a) && !WindowsPAM(a) {
		e = sshclient.VerifyPassword(ctx, target, credentials, 8*time.Second)
	} else {
		e = s.verifyAssetPassword(ctx, a, target, credentials, 8*time.Second)
	}
	duration := max(int64(1), time.Since(started).Milliseconds())
	if current := check(); current != nil {
		return checkOutcome(current, duration), current
	}
	return checkOutcome(e, duration), e
}
func checkOutcome(e error, duration int64) rotationplans.Outcome {
	out := rotationplans.Outcome{State: "succeeded", CheckDurationMS: duration, At: time.Now().UTC()}
	if e == nil {
		return out
	}
	out.State = "failed"
	switch {
	case errors.Is(e, rotationplans.ErrDenied):
		out.State = "denied"
		out.Code = "denied"
	case errors.Is(e, ErrCredentialChanged), errors.Is(e, ErrNotFound):
		out.State = "changed"
		out.Code = "source_changed"
	case errors.Is(e, ErrRotationPending):
		out.State = "changed"
		out.Code = "credential_pending"
	case errors.Is(e, context.Canceled):
		out.State = "interrupted"
		out.Code = "check_interrupted"
	default:
		out.Code = classifyProbeError(e)
	}
	return out
}
