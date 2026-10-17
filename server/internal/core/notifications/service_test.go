package notifications

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/neko233-com/jumpserver233/server/internal/core/eventfeed"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type testFixture struct {
	mu        sync.Mutex
	peers     map[string]Principal
	events    []eventfeed.Event
	visible   bool
	feedError bool
	sent      []Outbound
	outcome   Outcome
	clock     atomic.Int64
}

func setup(t *testing.T) (*Service, *testFixture, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "notifications.json")
	s, e := Open(path, make([]byte, 32), nil)
	require.NoError(t, e)
	t.Cleanup(s.Close)
	f := &testFixture{peers: map[string]Principal{"admin": {Actor: Actor{ID: "admin", Name: "Synthetic admin"}, CanManage: true, CanAudit: true, CanRetry: true}, "operator": {Actor: Actor{ID: "operator", Name: "Synthetic operator"}}}, visible: true, outcome: Outcome{State: "sent", Receipt: "synthetic-accepted"}}
	f.clock.Store(time.Now().Add(time.Second).UnixNano())
	s.now = func() time.Time { return time.Unix(0, f.clock.Load()).UTC() }
	s.SetRunner(f.runner())
	return s, f, path
}
func (f *testFixture) runner() Runner {
	return Runner{
		Principal: func(ctx context.Context, id string) (Principal, error) {
			f.mu.Lock()
			defer f.mu.Unlock()
			p, ok := f.peers[id]
			if !ok {
				return Principal{}, ErrDenied
			}
			return p, ctx.Err()
		},
		Feeds: []Feed{{Name: "jobs", Read: func(_ context.Context, after string, since time.Time, limit int) (eventfeed.Batch, error) {
			f.mu.Lock()
			defer f.mu.Unlock()
			if f.feedError {
				return eventfeed.Batch{}, ErrUnavailable
			}
			return eventfeed.Read(f.events, after, since, limit), nil
		},
			Recipients: func(_ context.Context, e eventfeed.Event) ([]Recipient, error) {
				return []Recipient{{UserID: e.OwnerID, Topic: "jobs"}}, nil
			},
			Allowed: func(ctx context.Context, _ string, _ Source) (bool, error) {
				f.mu.Lock()
				defer f.mu.Unlock()
				return f.visible, ctx.Err()
			},
		}},
		Send: func(ctx context.Context, v Outbound) Outcome {
			if e := v.Guard(); e != nil {
				return Outcome{State: "suppressed", Code: "permission_changed"}
			}
			f.mu.Lock()
			defer f.mu.Unlock()
			f.sent = append(f.sent, v)
			return f.outcome
		},
	}
}
func (f *testFixture) add(id string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.events = append(f.events, eventfeed.Event{ID: eventfeed.Digest(id), ResourceID: id, OwnerID: "operator", Name: "Synthetic job", State: "succeeded", At: time.Unix(0, f.clock.Load())})
}
func drain(t *testing.T, s *Service) {
	t.Helper()
	s.Tick()
	require.Eventually(t, func() bool { s.mu.Lock(); defer s.mu.Unlock(); return len(s.active) == 0 }, 2*time.Second, time.Millisecond)
}
func subscribe(t *testing.T, s *Service) {
	t.Helper()
	ctx := context.Background()
	cfg, e := s.Settings(ctx, "admin")
	require.NoError(t, e)
	secret := "synthetic-hook-signing-233"
	_, e = s.SaveSettings(ctx, "admin", SettingsInput{Revision: cfg.Revision, SMTP: cfg.SMTP, Webhook: HTTPChannel{Enabled: true, URL: "https://capture.invalid/webhook"}, WebhookSecret: &secret})
	require.NoError(t, e)
	prefs, e := s.Preferences(ctx, "operator")
	require.NoError(t, e)
	prefs.Topics["jobs"] = []string{"inbox", "webhook"}
	prefs.Topics["system"] = []string{"inbox", "webhook"}
	_, e = s.SavePreferences(ctx, "operator", PreferencesInput{Revision: prefs.Revision, Language: "auto", Topics: prefs.Topics})
	require.NoError(t, e)
}
func TestPersistentFeedIdempotenceReadAndCurrentPermissions(t *testing.T) {
	s, f, path := setup(t)
	subscribe(t, s)
	f.add("job-a")
	drain(t, s)
	drain(t, s)
	ctx := context.Background()
	page, count, e := s.Inbox(ctx, "operator", false, 0, 20)
	require.NoError(t, e)
	require.Len(t, page.Results, 1)
	assert.Equal(t, 1, count)
	f.mu.Lock()
	assert.Len(t, f.sent, 1)
	f.mu.Unlock()
	require.NoError(t, s.Read(ctx, "operator", page.Results[0].ID, false))
	_, count, e = s.Inbox(ctx, "operator", false, 0, 20)
	require.NoError(t, e)
	assert.Zero(t, count)
	_, _, e = s.Inbox(ctx, "operator", false, -1, 20)
	assert.ErrorIs(t, e, ErrInvalid)
	assert.ErrorIs(t, s.Read(ctx, "admin", page.Results[0].ID, false), ErrNotFound)
	f.mu.Lock()
	f.visible = false
	f.mu.Unlock()
	page, count, e = s.Inbox(ctx, "operator", false, 0, 20)
	require.NoError(t, e)
	assert.Empty(t, page.Results)
	assert.Zero(t, count)
	s.Close()
	reopened, e := Open(path, make([]byte, 32), nil)
	require.NoError(t, e)
	defer reopened.Close()
	reopened.SetRunner(f.runner())
	drain(t, reopened)
	f.mu.Lock()
	assert.Len(t, f.sent, 1)
	f.mu.Unlock()
	raw, e := os.ReadFile(path)
	require.NoError(t, e)
	for _, hidden := range []string{"Synthetic job", "operator", "capture.invalid", "synthetic-hook-signing-233"} {
		assert.NotContains(t, string(raw), hidden)
	}
	_, e = Open(path, bytesKey(1), nil)
	assert.Error(t, e)
}
func bytesKey(b byte) []byte { return []byte(strings.Repeat(string([]byte{b}), 32)) }
func TestSettingsCASSecretsAndValidation(t *testing.T) {
	s, _, _ := setup(t)
	ctx := context.Background()
	_, e := s.Settings(ctx, "operator")
	assert.ErrorIs(t, e, ErrDenied)
	cfg, e := s.Settings(ctx, "admin")
	require.NoError(t, e)
	secret := "synthetic-only-password"
	input := SettingsInput{Revision: cfg.Revision, SMTP: cfg.SMTP, SMTPPassword: &secret}
	v, e := s.SaveSettings(ctx, "admin", input)
	require.NoError(t, e)
	assert.True(t, v.SMTP.PasswordConfigured)
	raw, _ := json.Marshal(v)
	assert.NotContains(t, string(raw), secret)
	_, e = s.SaveSettings(ctx, "admin", input)
	assert.ErrorIs(t, e, ErrConflict)
	input.Revision = v.Revision
	input.SMTPPassword = nil
	v, e = s.SaveSettings(ctx, "admin", input)
	require.NoError(t, e)
	assert.True(t, v.SMTP.PasswordConfigured)
	empty := ""
	input.Revision = v.Revision
	input.SMTPPassword = &empty
	v, e = s.SaveSettings(ctx, "admin", input)
	require.NoError(t, e)
	assert.False(t, v.SMTP.PasswordConfigured)
	for _, endpoint := range []string{"http://localhost", "https://u:p@localhost", "https://localhost?q=secret", "https://localhost/#secret", "https://localhost:99999", "https://localhost/\n"} {
		t.Run(endpoint, func(t *testing.T) {
			bad := input
			bad.Revision = v.Revision
			bad.Webhook = HTTPChannel{Enabled: true, URL: endpoint}
			_, e := s.SaveSettings(ctx, "admin", bad)
			assert.ErrorIs(t, e, ErrInvalid)
		})
	}
	input.Revision = v.Revision
	input.SMTP.CA = "-----BEGIN PRIVATE KEY-----\nsynthetic\n-----END PRIVATE KEY-----"
	_, e = s.SaveSettings(ctx, "admin", input)
	assert.ErrorIs(t, e, ErrInvalid)
}
func TestContactVerificationOneUseRateLimitContactChangeAndNoPublicCode(t *testing.T) {
	s, f, _ := setup(t)
	ctx := context.Background()
	cfg, _ := s.Settings(ctx, "admin")
	cfg.SMTP = SMTP{Enabled: true, Host: "capture.invalid", Port: 465, Mode: "tls", From: "sender@jumpserver233.invalid"}
	_, e := s.SaveSettings(ctx, "admin", SettingsInput{Revision: cfg.Revision, SMTP: cfg.SMTP, SMS: HTTPChannel{Enabled: true, URL: "https://capture.invalid/sms"}})
	require.NoError(t, e)
	p, _ := s.Preferences(ctx, "operator")
	p, e = s.SavePreferences(ctx, "operator", PreferencesInput{Revision: p.Revision, Language: "zh-CN", Email: "operator@jumpserver233.invalid", Phone: "+15555550123", Topics: p.Topics})
	require.NoError(t, e)
	topics := cloneTopics(p.Topics)
	topics["jobs"] = []string{"email"}
	_, e = s.SavePreferences(ctx, "operator", PreferencesInput{Revision: p.Revision, Language: p.Language, Email: p.Email, Phone: p.Phone, Topics: topics})
	assert.ErrorIs(t, e, ErrVerification)
	for _, channel := range []string{"email", "sms"} {
		p, e = s.RequestVerification(ctx, "operator", channel)
		require.NoError(t, e)
		_, e = s.RequestVerification(ctx, "operator", channel)
		assert.ErrorIs(t, e, ErrRateLimit)
		drain(t, s)
		f.mu.Lock()
		code := f.sent[len(f.sent)-1].VerificationCode
		f.mu.Unlock()
		require.Len(t, code, 6)
		raw, _ := json.Marshal(p)
		assert.NotContains(t, string(raw), code)
		_, e = s.Verify(ctx, "operator", channel, "wrong")
		assert.ErrorIs(t, e, ErrVerification)
		p, e = s.Verify(ctx, "operator", channel, code)
		require.NoError(t, e)
		_, e = s.Verify(ctx, "operator", channel, code)
		assert.ErrorIs(t, e, ErrVerification)
	}
	assert.True(t, p.EmailVerified)
	assert.True(t, p.PhoneVerified)
	p.Topics["jobs"] = []string{"email", "sms"}
	p, e = s.SavePreferences(ctx, "operator", PreferencesInput{Revision: p.Revision, Language: p.Language, Email: p.Email, Phone: p.Phone, Topics: p.Topics})
	require.NoError(t, e)
	p.Topics["jobs"] = []string{"inbox"}
	p, e = s.SavePreferences(ctx, "operator", PreferencesInput{Revision: p.Revision, Language: p.Language, Email: "new@jumpserver233.invalid", Phone: p.Phone, Topics: p.Topics})
	require.NoError(t, e)
	assert.False(t, p.EmailVerified)
	_, e = s.RequestVerification(ctx, "operator", "webhook")
	assert.ErrorIs(t, e, ErrInvalid)
}
func TestVerificationAttemptsAndExpiry(t *testing.T) {
	s, f, _ := setup(t)
	ctx := context.Background()
	cfg, _ := s.Settings(ctx, "admin")
	cfg.SMS = HTTPChannel{Enabled: true, URL: "https://capture.invalid/sms"}
	_, e := s.SaveSettings(ctx, "admin", SettingsInput{Revision: cfg.Revision, SMTP: cfg.SMTP, SMS: cfg.SMS})
	require.NoError(t, e)
	p, _ := s.Preferences(ctx, "operator")
	_, e = s.SavePreferences(ctx, "operator", PreferencesInput{Revision: p.Revision, Language: "en", Phone: "+15555550123", Topics: p.Topics})
	require.NoError(t, e)
	_, e = s.RequestVerification(ctx, "operator", "sms")
	require.NoError(t, e)
	drain(t, s)
	f.mu.Lock()
	code := f.sent[0].VerificationCode
	f.mu.Unlock()
	for range 8 {
		_, e = s.Verify(ctx, "operator", "sms", "WRONG")
		assert.ErrorIs(t, e, ErrVerification)
	}
	_, e = s.Verify(ctx, "operator", "sms", code)
	assert.ErrorIs(t, e, ErrVerification)
	f.clock.Add(int64(11 * time.Minute))
	_, e = s.RequestVerification(ctx, "operator", "sms")
	require.NoError(t, e)
	f.clock.Add(int64(11 * time.Minute))
	drain(t, s)
	v, e := s.Deliveries(ctx, "operator", "suppressed", 0, 20)
	require.NoError(t, e)
	assert.NotEmpty(t, v.Results)
}
func TestUncertainRetryCASAndPermissionSuppression(t *testing.T) {
	s, f, _ := setup(t)
	subscribe(t, s)
	f.mu.Lock()
	f.outcome = Outcome{State: "uncertain", Code: "receipt_unavailable"}
	f.mu.Unlock()
	f.add("job-uncertain")
	drain(t, s)
	ctx := context.Background()
	p, e := s.Deliveries(ctx, "operator", "uncertain", 0, 20)
	require.NoError(t, e)
	require.Len(t, p.Results, 1)
	v := p.Results[0]
	assert.True(t, v.CanRetry)
	assert.Equal(t, "organization-webhook", v.Destination)
	_, e = s.Retry(ctx, "operator", v.ID, v.Revision, false)
	assert.ErrorIs(t, e, ErrConflict)
	_, e = s.Retry(ctx, "operator", v.ID, v.Revision+1, true)
	assert.ErrorIs(t, e, ErrConflict)
	_, e = s.Retry(ctx, "operator", v.ID, v.Revision, true)
	require.NoError(t, e)
	f.mu.Lock()
	f.visible = false
	f.mu.Unlock()
	drain(t, s)
	s.mu.Lock()
	assert.Equal(t, "suppressed", s.data.Deliveries[v.ID].State)
	s.mu.Unlock()
	f.mu.Lock()
	assert.Len(t, f.sent, 1)
	f.mu.Unlock()
}
func TestSourceCursorAtomicityGapAndUnavailableHealth(t *testing.T) {
	s, f, _ := setup(t)
	f.add("job-a")
	s.saveHook = func([]byte) error { return errors.New("synthetic disk unavailable") }
	assert.Error(t, s.syncFeed(context.Background(), s.snapshotRunner().Feeds[0]))
	s.mu.Lock()
	assert.Empty(t, s.data.Messages)
	assert.Empty(t, s.data.Cursors)
	s.mu.Unlock()
	s.saveHook = nil
	drain(t, s)
	f.mu.Lock()
	f.events = nil
	f.mu.Unlock()
	drain(t, s)
	h, e := s.Health(context.Background(), "admin")
	require.NoError(t, e)
	assert.Contains(t, h.SourceGaps, "jobs")
	f.mu.Lock()
	f.feedError = true
	f.mu.Unlock()
	drain(t, s)
	h, e = s.Health(context.Background(), "admin")
	require.NoError(t, e)
	assert.Contains(t, h.SourceErrors, "jobs")
	f.mu.Lock()
	f.feedError = false
	f.mu.Unlock()
	drain(t, s)
	h, _ = s.Health(context.Background(), "admin")
	assert.Empty(t, h.SourceErrors)
}
func TestReceiptPersistenceFailureAndRestartNeverAutoResend(t *testing.T) {
	s, f, path := setup(t)
	subscribe(t, s)
	f.add("job-persist")
	r := f.runner()
	r.Send = func(ctx context.Context, v Outbound) Outcome {
		s.mu.Lock()
		s.saveHook = func([]byte) error { return errors.New("synthetic receipt fault") }
		s.mu.Unlock()
		f.mu.Lock()
		f.sent = append(f.sent, v)
		f.mu.Unlock()
		return Outcome{State: "sent"}
	}
	s.SetRunner(r)
	drain(t, s)
	s.mu.Lock()
	s.saveHook = nil
	for _, v := range s.data.Deliveries {
		assert.Equal(t, "sending", v.State)
	}
	s.mu.Unlock()
	drain(t, s)
	p, e := s.Deliveries(context.Background(), "operator", "uncertain", 0, 20)
	require.NoError(t, e)
	assert.Len(t, p.Results, 1)
	s.Close()
	other, e := Open(path, make([]byte, 32), nil)
	require.NoError(t, e)
	defer other.Close()
	other.SetRunner(f.runner())
	drain(t, other)
	f.mu.Lock()
	assert.Len(t, f.sent, 1)
	f.mu.Unlock()
}
func TestRecoveryOfSendingAndRetentionKeepsParentConsistency(t *testing.T) {
	s, f, path := setup(t)
	subscribe(t, s)
	f.add("job-old")
	drain(t, s)
	require.NoError(t, s.mutate(func(d *state) error {
		for id, v := range d.Deliveries {
			v.State = "sending"
			d.Deliveries[id] = v
		}
		return nil
	}))
	s.Close()
	r, e := Open(path, make([]byte, 32), nil)
	require.NoError(t, e)
	defer r.Close()
	r.SetRunner(f.runner())
	p, e := r.Deliveries(context.Background(), "operator", "uncertain", 0, 20)
	require.NoError(t, e)
	assert.Len(t, p.Results, 1)
	r.now = func() time.Time { return time.Now().Add(32 * 24 * time.Hour) }
	require.NoError(t, r.maintain())
	r.mu.Lock()
	assert.Empty(t, r.data.Messages)
	assert.Empty(t, r.data.Deliveries)
	assert.NoError(t, validate(r.data))
	r.mu.Unlock()
}
func TestCloseCancelsBlockedSendAndPreventsLatePersistence(t *testing.T) {
	s, f, _ := setup(t)
	subscribe(t, s)
	f.add("job-blocked")
	entered := make(chan struct{})
	r := f.runner()
	r.Send = func(ctx context.Context, _ Outbound) Outcome {
		close(entered)
		<-ctx.Done()
		return Outcome{State: "sent"}
	}
	s.SetRunner(r)
	s.Tick()
	<-entered
	s.Close()
	s.mu.Lock()
	for _, v := range s.data.Deliveries {
		assert.Equal(t, "sending", v.State)
	}
	s.mu.Unlock()
	_, e := s.Test(context.Background(), "operator", "late")
	assert.ErrorIs(t, e, ErrUnavailable)
	s.Close()
}
func TestTestMessagesIdempotentBoundedAndPrivateOwnership(t *testing.T) {
	s, _, _ := setup(t)
	ctx := context.Background()
	first, e := s.Test(ctx, "operator", "same")
	require.NoError(t, e)
	again, e := s.Test(ctx, "operator", "same")
	require.NoError(t, e)
	assert.Equal(t, first.ID, again.ID)
	for i := range 9 {
		_, e = s.Test(ctx, "operator", fmt.Sprintf("test-%d", i))
		require.NoError(t, e)
	}
	_, e = s.Test(ctx, "operator", "overflow")
	assert.ErrorIs(t, e, ErrRateLimit)
	assert.ErrorIs(t, s.Read(ctx, "admin", first.ID, false), ErrNotFound)
	_, e = s.Audit(ctx, "operator", 0, 20)
	assert.ErrorIs(t, e, ErrDenied)
}
func TestAutomaticRetryBackoffStopsAtFiveAttempts(t *testing.T) {
	s, f, _ := setup(t)
	subscribe(t, s)
	f.add("retry-five")
	f.mu.Lock()
	f.outcome = Outcome{State: "retry", Code: "connection_failed"}
	f.mu.Unlock()
	for attempt := 1; attempt <= 5; attempt++ {
		drain(t, s)
		page, e := s.Deliveries(context.Background(), "operator", "", 0, 20)
		require.NoError(t, e)
		require.Len(t, page.Results, 1)
		assert.Equal(t, attempt, page.Results[0].Attempts)
		if attempt < 5 {
			assert.Equal(t, "retry", page.Results[0].State)
			assert.True(t, page.Results[0].NextAttempt.After(time.Unix(0, f.clock.Load())))
		} else {
			assert.Equal(t, "failed", page.Results[0].State)
			assert.Equal(t, "attempts_exhausted", page.Results[0].ErrorCode)
		}
		f.clock.Add(int64(time.Hour))
	}
	drain(t, s)
	f.mu.Lock()
	assert.Len(t, f.sent, 5)
	f.mu.Unlock()
}
func TestConfigurationRevisionAndUnsubscriptionStopQueuedDelivery(t *testing.T) {
	for _, change := range []string{"configuration", "subscription", "account"} {
		t.Run(change, func(t *testing.T) {
			s, f, _ := setup(t)
			subscribe(t, s)
			f.add("queued-change")
			ctx := context.Background()
			require.NoError(t, s.syncFeed(ctx, s.snapshotRunner().Feeds[0]))
			switch change {
			case "configuration":
				cfg, e := s.Settings(ctx, "admin")
				require.NoError(t, e)
				_, e = s.SaveSettings(ctx, "admin", SettingsInput{Revision: cfg.Revision, SMTP: cfg.SMTP, Webhook: cfg.Webhook})
				require.NoError(t, e)
			case "subscription":
				p, e := s.Preferences(ctx, "operator")
				require.NoError(t, e)
				p.Topics["jobs"] = []string{"inbox"}
				_, e = s.SavePreferences(ctx, "operator", PreferencesInput{Revision: p.Revision, Language: p.Language, Topics: p.Topics})
				require.NoError(t, e)
			case "account":
				f.mu.Lock()
				delete(f.peers, "operator")
				f.mu.Unlock()
			}
			drain(t, s)
			f.mu.Lock()
			assert.Empty(t, f.sent)
			f.mu.Unlock()
			s.mu.Lock()
			for _, v := range s.data.Deliveries {
				if change == "configuration" {
					assert.Equal(t, "failed", v.State)
					assert.Equal(t, "configuration_changed", v.ErrorCode)
				} else {
					assert.Equal(t, "suppressed", v.State)
				}
			}
			s.mu.Unlock()
		})
	}
}
func TestMutedHistoryIsNotReplayedAfterSubscriptionChanges(t *testing.T) {
	s, f, _ := setup(t)
	ctx := context.Background()
	p, _ := s.Preferences(ctx, "operator")
	_, e := s.SavePreferences(ctx, "operator", PreferencesInput{Revision: p.Revision, Language: p.Language, Topics: map[string][]string{}})
	require.NoError(t, e)
	f.add("muted")
	drain(t, s)
	page, _, e := s.Inbox(ctx, "operator", false, 0, 20)
	require.NoError(t, e)
	assert.Empty(t, page.Results)
	p, _ = s.Preferences(ctx, "operator")
	_, e = s.SavePreferences(ctx, "operator", PreferencesInput{Revision: p.Revision, Language: p.Language, Topics: defaultProfile().Topics})
	require.NoError(t, e)
	drain(t, s)
	page, _, e = s.Inbox(ctx, "operator", false, 0, 20)
	require.NoError(t, e)
	assert.Empty(t, page.Results)
	f.add("subscribed")
	drain(t, s)
	page, _, e = s.Inbox(ctx, "operator", false, 0, 20)
	require.NoError(t, e)
	require.Len(t, page.Results, 1)
	assert.Equal(t, "subscribed", page.Results[0].Source.ID)
}
