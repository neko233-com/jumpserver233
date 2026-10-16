package loginreviews

import (
	"crypto/sha256"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	coreauth "github.com/neko233-com/jumpserver233/server/internal/core/auth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func testStore(t *testing.T) (*Store, *time.Time) {
	t.Helper()
	s, e := Open(filepath.Join(t.TempDir(), "reviews.json"), []byte(strings.Repeat("r", 32)), nil)
	require.NoError(t, e)
	now := time.Now().UTC().Truncate(time.Second)
	s.now = func() time.Time { return now }
	return s, &now
}
func testBegin(t *testing.T, s *Store) (Review, string) {
	t.Helper()
	r, ticket, e := s.Begin(Input{UserID: "user", Username: "test.operator", SourceIP: "192.0.2.5", AuthSource: "local", RuleID: "policy", RuleName: "approval rule", RuleRevision: 1, Proof: "opaque-proof", ExpiresAt: s.now().Add(5 * time.Minute), Browser: true})
	require.NoError(t, e)
	return r, ticket
}
func approveTest(t *testing.T, s *Store, r Review) {
	t.Helper()
	require.NoError(t, s.Resolve(r.ID, "reviewer", nil, true, func(p Payload) error { assert.Equal(t, "opaque-proof", p.Proof); return nil }))
}
func testSession() coreauth.LoginSession {
	return coreauth.LoginSession{AccessToken: "fresh-session-token", User: coreauth.User{ID: "user"}}
}
func TestEncryptedReviewRestartOneUseAndCancelCompletion(t *testing.T) {
	s, _ := testStore(t)
	r, ticket := testBegin(t, s)
	_, e := s.Status(ticket, "192.0.2.6")
	assert.ErrorIs(t, e, ErrNotFound)
	_, e = s.Complete(ticket, "192.0.2.5", nil, nil)
	assert.ErrorIs(t, e, ErrState)
	assert.ErrorIs(t, s.Resolve(r.ID, "user", nil, true, func(Payload) error { return nil }), ErrReviewer)
	approveTest(t, s, r)
	raw, e := os.ReadFile(s.path)
	require.NoError(t, e)
	for _, value := range []string{ticket, "opaque-proof", "test.operator", "192.0.2.5"} {
		assert.NotContains(t, string(raw), value)
	}
	restored, e := Open(s.path, []byte(strings.Repeat("r", 32)), nil)
	require.NoError(t, e)
	done, e := restored.Complete(ticket, "192.0.2.5", func(Payload) (coreauth.LoginSession, error) { return testSession(), nil }, func(string) error { return nil })
	require.NoError(t, e)
	assert.True(t, done.Browser)
	_, e = restored.Complete(ticket, "192.0.2.5", func(Payload) (coreauth.LoginSession, error) { t.Fatal("replayed"); return testSession(), nil }, func(string) error { return nil })
	assert.ErrorIs(t, e, ErrState)
	revoked := false
	require.NoError(t, restored.Cancel(ticket, "192.0.2.5", func(digest []byte) error {
		hash := sha256.Sum256([]byte(testSession().AccessToken))
		assert.Equal(t, hash[:], digest)
		revoked = true
		return nil
	}))
	assert.True(t, revoked)
	current, e := restored.Get(r.ID)
	require.NoError(t, e)
	assert.Equal(t, Cancelled, current.State)
	assert.Empty(t, restored.data.Records[r.ID].Proof)
	assert.Empty(t, restored.data.Records[r.ID].CompletedSessionHash)
	_, e = Open(s.path, []byte(strings.Repeat("w", 32)), nil)
	assert.Error(t, e)
}
func TestReviewExpiryInvalidationDenialAndSelection(t *testing.T) {
	t.Run("selected", func(t *testing.T) {
		r := Review{UserID: "self", ApproverIDs: []string{"reviewer"}, ApproverGroupIDs: []string{"group"}}
		assert.False(t, ReviewerAllowed(r, "self", []string{"group"}))
		assert.False(t, ReviewerAllowed(r, "other", nil))
		assert.True(t, ReviewerAllowed(r, "other", []string{"group"}))
		assert.True(t, ReviewerAllowed(r, "reviewer", nil))
	})
	for _, kind := range []string{"pending expiry", "approved expiry", "denied", "cancelled", "invalidated"} {
		t.Run(kind, func(t *testing.T) {
			s, now := testStore(t)
			r, ticket := testBegin(t, s)
			switch kind {
			case "pending expiry":
				*now = now.Add(5 * time.Minute)
			case "approved expiry":
				approveTest(t, s, r)
				*now = now.Add(time.Minute)
			case "denied":
				require.NoError(t, s.Resolve(r.ID, "reviewer", nil, false, nil))
			case "cancelled":
				require.NoError(t, s.Cancel(ticket, "192.0.2.5"))
			case "invalidated":
				assert.ErrorIs(t, s.Resolve(r.ID, "reviewer", nil, true, func(Payload) error { return ErrInvalidated }), ErrInvalidated)
			}
			item, e := s.Status(ticket, "192.0.2.5")
			require.NoError(t, e)
			assert.False(t, live(item.State))
			assert.Empty(t, s.data.Records[r.ID].Proof)
			_, e = s.Complete(ticket, "192.0.2.5", nil, nil)
			assert.ErrorIs(t, e, ErrState)
			*now = now.Add(Retention + time.Minute)
			_, _, e = s.List("", 0, 20)
			require.NoError(t, e)
			_, e = s.Get(r.ID)
			assert.ErrorIs(t, e, ErrNotFound)
		})
	}
}
func TestReviewSaveRollbackConcurrencyAndPublicMetadata(t *testing.T) {
	s, _ := testStore(t)
	r, ticket := testBegin(t, s)
	approveTest(t, s, r)
	original := s.path
	s.path = filepath.Join(original, "cannot-write")
	rolled := false
	_, e := s.Complete(ticket, "192.0.2.5", func(Payload) (coreauth.LoginSession, error) { return testSession(), nil }, func(token string) error { rolled = token == testSession().AccessToken; return nil })
	require.Error(t, e)
	assert.True(t, rolled)
	assert.Equal(t, Approved, s.data.Records[r.ID].State)
	_, e = s.Status(strings.Repeat("x", 43), "192.0.2.5")
	assert.ErrorIs(t, e, ErrNotFound)
	s.path = original
	var completed atomic.Int32
	var wg sync.WaitGroup
	for range 12 {
		wg.Go(func() {
			_, e := s.Complete(ticket, "192.0.2.5", func(Payload) (coreauth.LoginSession, error) { completed.Add(1); return testSession(), nil }, func(string) error { return nil })
			if e != nil {
				assert.ErrorIs(t, e, ErrState)
			}
		})
	}
	wg.Wait()
	assert.EqualValues(t, 1, completed.Load())
	rows, total, e := s.List("", 0, 25)
	require.NoError(t, e)
	assert.Equal(t, 1, total)
	events, _ := s.Audit(0, 25)
	raw, e := json.Marshal([]any{rows, events})
	require.NoError(t, e)
	for _, secret := range []string{ticket, "opaque-proof", testSession().AccessToken, "ticket_hash", "completed_session_hash"} {
		assert.NotContains(t, string(raw), secret)
	}
}
func TestReviewInvalidationOnCompleteAndCapacity(t *testing.T) {
	s, _ := testStore(t)
	r, ticket := testBegin(t, s)
	approveTest(t, s, r)
	_, e := s.Complete(ticket, "192.0.2.5", func(Payload) (coreauth.LoginSession, error) { return coreauth.LoginSession{}, ErrInvalidated }, func(string) error { return nil })
	assert.ErrorIs(t, e, ErrInvalidated)
	item, e := s.Get(r.ID)
	require.NoError(t, e)
	assert.Equal(t, Invalidated, item.State)
	for range 5 {
		testBegin(t, s)
	}
	_, _, e = s.Begin(Input{UserID: "user", Username: "u", RuleID: "rule", RuleRevision: 1, Proof: "proof", ExpiresAt: s.now().Add(time.Minute)})
	assert.ErrorIs(t, e, ErrCapacity)
	require.NoError(t, s.Notify(Input{UserID: "user", Username: "u", RuleID: "rule", RuleName: "notify", RuleRevision: 1, AuthSource: "local"}))
	rows, total, e := s.List(Notified, 0, 10)
	require.NoError(t, e)
	assert.Equal(t, 1, total)
	assert.Equal(t, Notified, rows[0].State)
}
