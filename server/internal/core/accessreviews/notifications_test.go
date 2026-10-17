package accessreviews

import (
	"context"
	"encoding/json"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"path/filepath"
	"testing"
	"time"
)

func TestNotificationReviewLifecycleNoPermitAndRevisit(t *testing.T) {
	s, e := OpenStore(filepath.Join(t.TempDir(), "reviews"))
	require.NoError(t, e)
	r, e := s.RequestAction("owner", "Owner", "asset", "Synthetic host", "ops", ActionSFTP)
	require.NoError(t, e)
	first, e := s.NotificationFeed(context.Background(), "", time.Time{}, 100)
	require.NoError(t, e)
	require.Len(t, first.Events, 1)
	assert.Empty(t, first.Cursor)
	require.NoError(t, s.Resolve(r.ID, "Reviewer", true))
	approved, e := s.NotificationFeed(context.Background(), first.Cursor, time.Time{}, 100)
	require.NoError(t, e)
	require.Len(t, approved.Events, 2)
	raw, _ := json.Marshal(approved)
	assert.NotContains(t, string(raw), "permit")
	assert.NotContains(t, string(raw), "ops")
	assert.NotContains(t, string(raw), "scope")
	s.mu.Lock()
	for id, r := range s.records {
		past := time.Now().UTC().Add(-time.Second)
		r.PermitExpiresAt = &past
		s.records[id] = r
	}
	s.mu.Unlock()
	expired, e := s.NotificationFeed(context.Background(), "", time.Time{}, 100)
	require.NoError(t, e)
	require.Len(t, expired.Events, 3)
	states := []string{}
	for _, v := range expired.Events {
		states = append(states, v.State)
	}
	assert.Contains(t, states, "asset_review_approved")
	assert.Contains(t, states, "asset_review_expired")
}
func TestNotificationExpiryPersistsAndCancellation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "reviews")
	s, e := OpenStore(path)
	require.NoError(t, e)
	r, e := s.Request("owner", "Owner", "asset", "Synthetic host", "ops")
	require.NoError(t, e)
	s.mu.Lock()
	stored := s.records[r.ID]
	stored.RequestedAt = time.Now().UTC().Add(-requestLifetime - time.Second)
	stored.ExpiresAt = time.Now().UTC().Add(-time.Second)
	s.records[r.ID] = stored
	s.mu.Unlock()
	batch, e := s.NotificationFeed(context.Background(), "", time.Time{}, 100)
	require.NoError(t, e)
	require.Len(t, batch.Events, 2)
	states := []string{batch.Events[0].State, batch.Events[1].State}
	assert.Contains(t, states, "asset_review_expired")
	peer, e := OpenStore(path)
	require.NoError(t, e)
	info, e := peer.NotificationInfo(r.ID)
	require.NoError(t, e)
	assert.Equal(t, StateExpired, info.State)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, e = s.NotificationFeed(ctx, "", time.Time{}, 1)
	require.ErrorIs(t, e, context.Canceled)
}
