package logintickets

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTicketsExpireConsumeAndLimitAttempts(t *testing.T) {
	s := New()
	now := time.Now()
	s.now = func() time.Time { return now }
	token, e := s.Issue("user", 3)
	require.NoError(t, e)
	p, e := s.Read(token, false)
	require.NoError(t, e)
	assert.Equal(t, 3, p.Revision)
	require.NoError(t, s.SetSetup(token, "setup"))
	require.NoError(t, s.BindGeneration(token, 7))
	p, e = s.Read(token, false)
	require.NoError(t, e)
	assert.Equal(t, "setup", p.SetupToken)
	assert.Equal(t, 7, p.AuthGeneration)
	assert.Error(t, s.BindGeneration(token, -1))
	for i := 0; i < 5; i++ {
		_, e = s.Read(token, true)
		require.NoError(t, e)
	}
	_, e = s.Read(token, true)
	assert.ErrorIs(t, e, ErrTicket)
	token, e = s.Issue("user", 3)
	require.NoError(t, e)
	assert.True(t, s.Consume(token))
	assert.False(t, s.Consume(token))
	token, e = s.Issue("user", 3)
	require.NoError(t, e)
	now = now.Add(6 * time.Minute)
	_, e = s.Read(token, false)
	assert.ErrorIs(t, e, ErrTicket)
	token, e = s.Issue("user", 4)
	require.NoError(t, e)
	s.Reset()
	_, e = s.Read(token, false)
	assert.ErrorIs(t, e, ErrTicket)
}
