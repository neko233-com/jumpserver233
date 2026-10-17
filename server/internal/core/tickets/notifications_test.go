package tickets

import (
	"context"
	"encoding/json"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"
	"time"
)

func TestNotificationMetadataAndAmendmentReschedulesCurrentReviewer(t *testing.T) {
	s, _, _ := setup(t)
	p := publish(t, s, 2)
	v := apply(t, s, p, "notify")
	ctx := context.Background()
	batch, e := s.NotificationFeed(ctx, "", time.Time{}, 100)
	require.NoError(t, e)
	require.NotEmpty(t, batch.Events)
	event := batch.Events[len(batch.Events)-1]
	recipients, e := s.NotificationRecipients(ctx, event)
	require.NoError(t, e)
	assert.Contains(t, recipients, NotificationRecipient{"reviewer-a", "approvals"})
	ok, e := s.NotificationAllowed(ctx, "reviewer-a", v.ID, v.Revision, true)
	require.NoError(t, e)
	assert.True(t, ok)
	priorRevision := v.Revision
	v, e = s.Amend(ctx, "requester", v.ID, Amendment{Revision: v.Revision, Reason: "Synthetic adjustment", Targets: []Target{{Kind: "asset", ID: "asset-a", Account: "managed", Actions: []string{"connect"}}}, StartsAt: v.StartsAt, EndsAt: v.EndsAt.Add(-time.Minute)})
	require.NoError(t, e)
	next, e := s.NotificationFeed(ctx, event.ID, time.Time{}, 100)
	require.NoError(t, e)
	require.NotEmpty(t, next.Events)
	event = next.Events[len(next.Events)-1]
	assert.Equal(t, "amended_approvals_reset", event.State)
	recipients, e = s.NotificationRecipients(ctx, event)
	require.NoError(t, e)
	assert.Contains(t, recipients, NotificationRecipient{"reviewer-a", "approvals"})
	ok, e = s.NotificationAllowed(ctx, "reviewer-a", v.ID, priorRevision, true)
	require.NoError(t, e)
	assert.False(t, ok)
	raw, _ := json.Marshal(event)
	assert.NotContains(t, string(raw), "password")
	assert.NotContains(t, string(raw), "Binding")
}
