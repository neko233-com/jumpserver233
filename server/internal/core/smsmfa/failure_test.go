package smsmfa

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSMSMFAFailedConsumptionWriteDoesNotApplyAndCanRetryIdempotently(t *testing.T) {
	s, a, u, f, path := setup(t)
	ticket, _ := begin(t, s, a, u)
	_, e := s.BindLoginPhone(t.Context(), ticket, "192.0.2.1", "+8613800000000", "failure-bind-001")
	require.NoError(t, e)
	s.path = t.TempDir()
	applied := 0
	e = s.Finish(t.Context(), ticket, "192.0.2.1", f.last(), func(Verified, func() string) error { applied++; return nil })
	require.Error(t, e)
	assert.Zero(t, applied)
	s.path = path
	require.NoError(t, s.Finish(t.Context(), ticket, "192.0.2.1", f.last(), func(Verified, func() string) error { applied++; return nil }))
	assert.Equal(t, 1, applied)
	assert.ErrorIs(t, s.Finish(t.Context(), ticket, "192.0.2.1", f.last(), func(Verified, func() string) error { applied++; return nil }), ErrFlow)
	assert.Equal(t, 1, applied)
}
func TestSMSMFAMalformedCodesConsumeTheSameFiveAttemptBudget(t *testing.T) {
	s, a, u, _, _ := setup(t)
	ticket, _ := begin(t, s, a, u)
	_, e := s.BindLoginPhone(t.Context(), ticket, "192.0.2.1", "+8613800000000", "shape-bind-001")
	require.NoError(t, e)
	for _, code := range []string{"", "1", "1234567", "invalid", "+12345"} {
		assert.ErrorIs(t, s.Finish(t.Context(), ticket, "192.0.2.1", code, func(Verified, func() string) error { t.Fatal("invalid shape applied"); return nil }), ErrRejected)
	}
	_, e = s.Status(ticket, "192.0.2.1")
	assert.ErrorIs(t, e, ErrFlow)
}
