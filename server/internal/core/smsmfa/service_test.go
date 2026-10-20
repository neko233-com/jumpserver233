package smsmfa

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/neko233-com/jumpserver233/server/internal/connector/cloudnotify"
	"github.com/neko233-com/jumpserver233/server/internal/core/auth"
	"github.com/neko233-com/jumpserver233/server/internal/workgate"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type fakeTransport struct {
	mu             sync.Mutex
	codes          []string
	phones         []string
	revision       atomic.Int32
	outcome        string
	block, entered chan struct{}
}

func (f *fakeTransport) MFARevision() int { return int(f.revision.Load()) }
func (f *fakeTransport) SendMFA(ctx context.Context, _ int, phone, _ string, code string, check func() error) cloudnotify.Outcome {
	if check() != nil {
		return cloudnotify.Outcome{State: "failed"}
	}
	f.mu.Lock()
	f.codes = append(f.codes, code)
	f.phones = append(f.phones, phone)
	block, entered, out := f.block, f.entered, f.outcome
	f.mu.Unlock()
	if entered != nil {
		select {
		case entered <- struct{}{}:
		default:
		}
	}
	if block != nil {
		select {
		case <-block:
		case <-ctx.Done():
			return cloudnotify.Outcome{State: "uncertain"}
		}
	}
	if out == "" {
		out = "sent"
	}
	return cloudnotify.Outcome{State: out}
}
func (f *fakeTransport) last() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.codes[len(f.codes)-1]
}
func setup(t *testing.T) (*Service, *auth.Service, auth.User, *fakeTransport, string) {
	t.Helper()
	root := t.TempDir()
	a, e := auth.OpenServiceWithVaultKey(filepath.Join(root, "users.json"), make([]byte, 32))
	require.NoError(t, e)
	u, e := a.Bootstrap("sms.admin", "synthetic-sms-admin-password")
	require.NoError(t, e)
	f := &fakeTransport{}
	f.revision.Store(1)
	path := filepath.Join(root, "sms-mfa.json")
	s, e := Open(path, make([]byte, 32), nil, a, f)
	require.NoError(t, e)
	t.Cleanup(s.Close)
	_, e = s.Save(Input{Config: Config{Enabled: true, Policy: "all"}, RequestID: "sms-settings-001"}, u.ID)
	require.NoError(t, e)
	return s, a, u, f, path
}
func primary(t *testing.T, a *auth.Service, u auth.User) auth.QuarantinedLogin {
	t.Helper()
	session, e := a.Authenticate(u.Username, "synthetic-sms-admin-password")
	require.NoError(t, e)
	proof, e := a.QuarantineLogin(session.AccessToken)
	require.NoError(t, e)
	return proof
}
func begin(t *testing.T, s *Service, a *auth.Service, u auth.User) (string, Status) {
	t.Helper()
	p := primary(t, a, u)
	ticket, status, e := s.BeginLogin(t.Context(), BeginInput{UserID: u.ID, Proof: p.Proof, AuthSource: "local", SourceIP: "192.0.2.1", ExpiresAt: p.ExpiresAt})
	require.NoError(t, e)
	return ticket, status
}
func TestSMSMFAForcedEnrollmentExactlyOnceAndPrivateCodeHash(t *testing.T) {
	s, a, u, f, path := setup(t)
	ticket, status := begin(t, s, a, u)
	assert.True(t, status.NeedsPhone)
	assert.Empty(t, f.codes)
	status, e := s.BindLoginPhone(t.Context(), ticket, "192.0.2.1", "+8613800000000", "bind-request-001")
	require.NoError(t, e)
	assert.Equal(t, "sent", status.DeliveryState)
	again, e := s.BindLoginPhone(t.Context(), ticket, "192.0.2.1", "+8613800000000", "bind-request-001")
	require.NoError(t, e)
	assert.Equal(t, status, again)
	_, e = s.BindLoginPhone(t.Context(), ticket, "192.0.2.1", "+8613800000001", "bind-request-001")
	assert.ErrorIs(t, e, ErrConflict)
	assert.Len(t, f.codes, 1)
	_, e = s.Status(ticket, "192.0.2.2")
	assert.ErrorIs(t, e, ErrFlow)
	var login auth.LoginSession
	code := f.last()
	require.NoError(t, s.Finish(t.Context(), ticket, "192.0.2.1", code, func(v Verified, stamp func() string) error {
		var e error
		login, e = a.ResumeLoginProofWithSMSContact(v.Proof, v.Phone, v.Generation)
		if e != nil {
			return e
		}
		return a.SetSessionSMSStamp(login.AccessToken, v.UserID, stamp())
	}))
	assert.True(t, login.User.SMSMFAEnabled)
	assert.True(t, s.ValidStamp(u.ID, a.SessionSMSStamp(login.AccessToken)))
	assert.ErrorIs(t, s.Finish(t.Context(), ticket, "192.0.2.1", code, func(Verified, func() string) error { t.Fatal("replayed code reached action"); return nil }), ErrFlow)
	raw, e := os.ReadFile(path)
	require.NoError(t, e)
	assert.NotContains(t, string(raw), `"code"`)
	assert.NotContains(t, string(raw), "+8613800000000")
	audit, _ := json.Marshal(s.Audit())
	assert.NotContains(t, string(audit), `"code"`)
	assert.NotContains(t, string(audit), "13800000000")
}
func TestSMSMFARetryCooldownExpiryAndMaximumAttempts(t *testing.T) {
	s, a, u, f, _ := setup(t)
	_, e := a.SetVerifiedSMSContact(u.ID, "+8613800000000", u.AuthGeneration)
	require.NoError(t, e)
	ticket, _ := begin(t, s, a, u)
	_, e = s.Resend(t.Context(), ticket, "192.0.2.1", "resend-001")
	assert.ErrorIs(t, e, ErrRate)
	s.mu.Lock()
	clock := s.now()
	s.now = func() time.Time { return clock }
	s.mu.Unlock()
	clock = clock.Add(61 * time.Second)
	_, e = s.Resend(t.Context(), ticket, "192.0.2.1", "resend-002")
	require.NoError(t, e)
	_, e = s.Resend(t.Context(), ticket, "192.0.2.1", "resend-002")
	require.NoError(t, e)
	assert.Len(t, f.codes, 2)
	code := f.last()
	wrong := "000000"
	if code == wrong {
		wrong = "111111"
	}
	for i := 0; i < 5; i++ {
		e = s.Finish(t.Context(), ticket, "192.0.2.1", wrong, func(Verified, func() string) error { return errors.New("must not apply") })
		assert.ErrorIs(t, e, ErrRejected)
	}
	_, e = s.Status(ticket, "192.0.2.1")
	assert.ErrorIs(t, e, ErrFlow)
	// Expiry is strict and cannot be extended by a resend.
	clock = time.Now().Add(123 * time.Second)
	ticket, status := begin(t, s, a, u)
	clock = status.ExpiresAt
	_, e = s.Status(ticket, "192.0.2.1")
	assert.ErrorIs(t, e, ErrFlow)
}
func TestSMSMFARevisionReceiptsTransportChangeRestartAndDrain(t *testing.T) {
	s, a, u, f, path := setup(t)
	in := Input{Config: s.Snapshot(), RequestID: "sms-settings-002"}
	saved, e := s.Save(in, u.ID)
	require.NoError(t, e)
	again, e := s.Save(in, u.ID)
	require.NoError(t, e)
	assert.Equal(t, saved, again)
	changed := in
	changed.Policy = "admins"
	_, e = s.Save(changed, u.ID)
	assert.ErrorIs(t, e, ErrConflict)
	ticket, _ := begin(t, s, a, u)
	_, e = s.BindLoginPhone(t.Context(), ticket, "192.0.2.1", "+8613800000000", "bind-restart-001")
	require.NoError(t, e)
	code := f.last()
	s.Close()
	reopened, e := Open(path, make([]byte, 32), nil, a, f)
	require.NoError(t, e)
	defer reopened.Close()
	require.NoError(t, reopened.Finish(t.Context(), ticket, "192.0.2.1", code, func(Verified, func() string) error { return nil }))
	_, e = reopened.Save(in, u.ID)
	require.NoError(t, e)
	oldStamp := reopened.Stamp(u.ID)
	assert.True(t, reopened.ValidStamp(u.ID, oldStamp))
	ticket, _ = begin(t, reopened, a, u)
	f.revision.Store(2)
	assert.False(t, reopened.ValidStamp(u.ID, oldStamp))
	_, e = reopened.Status(ticket, "192.0.2.1")
	assert.ErrorIs(t, e, ErrFlow)
	gate := workgate.New()
	gate.SetClosed(true)
	_, _, e = reopened.BeginLogin(workgate.WithGate(t.Context(), gate), BeginInput{UserID: u.ID, Proof: primary(t, a, u).Proof, AuthSource: "local", SourceIP: "192.0.2.1"})
	assert.ErrorIs(t, e, workgate.ErrDraining)
}
func TestSMSMFACloseCancelsAndJoinsAnUncertainSend(t *testing.T) {
	s, a, u, f, _ := setup(t)
	f.block = make(chan struct{})
	f.entered = make(chan struct{}, 1)
	_, e := a.SetVerifiedSMSContact(u.ID, "+8613800000000", u.AuthGeneration)
	require.NoError(t, e)
	done := make(chan error, 1)
	p := primary(t, a, u)
	go func() {
		_, _, e := s.BeginLogin(t.Context(), BeginInput{UserID: u.ID, Proof: p.Proof, AuthSource: "local", SourceIP: "192.0.2.1", ExpiresAt: p.ExpiresAt})
		done <- e
	}()
	select {
	case <-f.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("send did not start")
	}
	s.Close()
	select {
	case e := <-done:
		require.Error(t, e)
	case <-time.After(5 * time.Second):
		t.Fatal("send did not stop")
	}
	s.Close()
}
