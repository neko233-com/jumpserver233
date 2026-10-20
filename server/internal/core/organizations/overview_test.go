package organizations

import (
	"context"
	"encoding/json"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"
	"time"
)

func TestOrganizationOverviewMetadataManualExclusionsAndManagedPrecedence(t *testing.T) {
	s := testStore(t)
	o, err := s.Save("", Input{Name: "Overview operations", Enabled: true}, "admin")
	require.NoError(t, err)
	_, err = s.SaveMember(DefaultID, MemberInput{UserID: "excluded", Role: "none"}, "admin")
	require.NoError(t, err)
	_, err = s.SaveMember(o.ID, MemberInput{UserID: "operator", Role: "none"}, "admin")
	require.NoError(t, err)
	s.SetManagedMemberships(func(id string) map[string]Member {
		if id != o.ID {
			return nil
		}
		return map[string]Member{"operator": {MemberInput: MemberInput{UserID: "operator", Role: "member"}}, "managed": {MemberInput: MemberInput{UserID: "managed", Role: "auditor"}}, "disabled-user": {MemberInput: MemberInput{UserID: "disabled-user", Role: "member"}}}
	}, nil, nil)
	rows := s.OverviewMetadata(false, []string{"operator", "managed", "excluded", "operator"})
	require.Len(t, rows, 2)
	assert.Equal(t, 2, rows[0].Members)
	assert.Equal(t, 1, rows[1].Members)
	raw, err := json.Marshal(rows)
	require.NoError(t, err)
	assert.NotContains(t, string(raw), "disabled-user")
	assert.NotContains(t, string(raw), `"user_id"`)
}
func TestOrganizationOverviewIsRepeatablePartialAndNeverStartsDisabledStores(t *testing.T) {
	s := testStore(t)
	o, err := s.Save("", Input{Name: "Broken", Enabled: true}, "admin")
	require.NoError(t, err)
	disabled, err := s.Save("", Input{Name: "Disabled", Enabled: false}, "admin")
	require.NoError(t, err)
	archived, err := s.Save("", Input{Name: "Archived", Enabled: true}, "admin")
	require.NoError(t, err)
	require.NoError(t, s.Archive(archived.ID, archived.Revision, false, "admin"))
	rows := s.OverviewMetadata(true, []string{"operator"})
	protocols := map[string]int{"ssh": 2, "mysql": 1}
	calls := 0
	collect := func(_ context.Context, id string) (ResourceCounts, error) {
		calls++
		assert.NotEqual(t, disabled.ID, id)
		assert.NotEqual(t, archived.ID, id)
		if id == o.ID {
			return ResourceCounts{}, ErrOverviewUnavailable
		}
		return ResourceCounts{Assets: 3, SSHAssets: 2, Online: 1, Offline: 1, Unknown: 1, Nodes: 2, Groups: 1, ActiveJobs: 1, Protocols: protocols}, nil
	}
	now := time.Now().UTC()
	first, err := BuildOverview(t.Context(), rows, collect, now)
	require.NoError(t, err)
	second, err := BuildOverview(t.Context(), rows, collect, now)
	require.NoError(t, err)
	assert.Equal(t, first, second)
	assert.Equal(t, 4, calls)
	assert.True(t, first.Partial)
	assert.Equal(t, 1, first.CollectedOrganizations)
	assert.Equal(t, 2, first.EnabledOrganizations)
	assert.Equal(t, 3, first.Totals.Assets)
	for _, row := range first.Results {
		if row.ID == o.ID {
			assert.Equal(t, "unavailable", row.State)
			assert.Nil(t, row.Counts)
		}
	}
	protocols["ssh"] = 100
	assert.Equal(t, 2, first.Results[0].Counts.Protocols["ssh"])
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	_, err = BuildOverview(ctx, rows, collect, now)
	assert.ErrorIs(t, err, context.Canceled)
	bad := append(rows, rows[0])
	_, err = BuildOverview(t.Context(), bad, collect, now)
	assert.ErrorIs(t, err, ErrInvalid)
	_, err = BuildOverview(t.Context(), rows, nil, now)
	assert.ErrorIs(t, err, ErrInvalid)
}
func TestOrganizationOverviewRejectsInvalidCountersAndNormalizesEmptyProtocols(t *testing.T) {
	rows := []OverviewItem{{ID: DefaultID, Revision: 1, Enabled: true}}
	for _, counts := range []ResourceCounts{{Assets: -1}, {Assets: 1, Unknown: 0, Protocols: map[string]int{"ssh": 1}}, {Assets: 1, Unknown: 1, Protocols: map[string]int{"secret-hostname": 1}}} {
		out, err := BuildOverview(t.Context(), rows, func(context.Context, string) (ResourceCounts, error) { return counts, nil }, time.Now())
		require.NoError(t, err)
		assert.True(t, out.Partial)
		assert.Nil(t, out.Results[0].Counts)
	}
	out, err := BuildOverview(t.Context(), rows, func(context.Context, string) (ResourceCounts, error) { return ResourceCounts{}, nil }, time.Now())
	require.NoError(t, err)
	assert.NotNil(t, out.Results[0].Counts.Protocols)
}
