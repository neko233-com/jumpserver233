package sessionshares

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestInviteIdentityCodeExpiryControlAndRevocation(t *testing.T) {
	var audit []Event
	s := New(func(e Event) error { audit = append(audit, e); return nil })
	now := time.Now()
	s.now = func() time.Time { return now }
	owner := Actor{ID: "owner", Name: "operator"}
	guest := Actor{ID: "guest", Name: "collaborator"}
	created, e := s.Create(Input{SessionID: "session", Mode: ReadWrite, Minutes: 2, AllowedUsers: []string{guest.ID, guest.ID}}, owner)
	require.NoError(t, e)
	require.Len(t, created.AllowedUsers, 1)
	created.AllowedUsers[0] = "mutated"
	_, e = s.Join(created.ID, created.Code, Actor{ID: "stranger", Name: "other"})
	assert.ErrorIs(t, e, ErrDenied)
	_, e = s.Join(created.ID, "wrong", guest)
	assert.ErrorIs(t, e, ErrDenied)
	m, e := s.Join(created.ID, created.Code, guest)
	require.NoError(t, e)
	require.NoError(t, s.TakeControl(m.ID, guest.ID))
	assert.Equal(t, m.ID, s.Controller("session"))
	assert.ErrorIs(t, s.Reclaim("session", guest), ErrDenied)
	assert.ErrorIs(t, s.Revoke(created.ID, guest), ErrDenied)
	require.NoError(t, s.Kick(m.ID, owner))
	_, e = s.Member(m.ID, guest.ID)
	assert.ErrorIs(t, e, ErrDenied)
	assert.Equal(t, m.ID, s.Controller("session"), "revocation must not resume a half-entered line")
	require.NoError(t, s.Reclaim("session", owner))
	assert.Empty(t, s.Controller("session"))
	m, e = s.Join(created.ID, created.Code, guest)
	require.NoError(t, e)
	require.NoError(t, s.TakeControl(m.ID, guest.ID))
	now = now.Add(2 * time.Minute)
	_, e = s.Member(m.ID, guest.ID)
	assert.ErrorIs(t, e, ErrDenied)
	_, e = s.Join(created.ID, created.Code, guest)
	assert.ErrorIs(t, e, ErrDenied)
	require.NoError(t, s.Reclaim("session", owner))
	assert.Empty(t, s.List("session", owner.ID))
	encoded, e := json.Marshal(audit)
	require.NoError(t, e)
	assert.NotContains(t, string(encoded), created.Code)
	assert.Contains(t, string(encoded), "share_control_taken")
	assert.Contains(t, string(encoded), "share_kicked")
}

func TestReadOnlyBoundsAndCodeThrottle(t *testing.T) {
	s := New(func(Event) error { return nil })
	now := time.Now()
	s.now = func() time.Time { return now }
	owner := Actor{ID: "owner", Name: "owner"}
	guest := Actor{ID: "guest", Name: "guest"}
	input := Input{SessionID: "session", Mode: ReadOnly, Minutes: 1, AllowedUsers: []string{guest.ID}}
	c, e := s.Create(input, owner)
	require.NoError(t, e)
	for i := 0; i < 5; i++ {
		_, e = s.Join(c.ID, "bad", guest)
		require.ErrorIs(t, e, ErrDenied)
	}
	_, e = s.Join(c.ID, c.Code, guest)
	require.ErrorIs(t, e, ErrDenied)
	// Advance without expiring this invitation.
	s.shares[c.ID].blockedUntil = now
	m, e := s.Join(c.ID, c.Code, guest)
	require.NoError(t, e)
	assert.ErrorIs(t, s.TakeControl(m.ID, guest.ID), ErrDenied)
	assert.Empty(t, s.List("session", guest.ID))
	assert.Empty(t, s.Members("session", guest.ID))
	for i := 1; i < maxSessionMembers; i++ {
		_, e = s.Join(c.ID, c.Code, guest)
		require.NoError(t, e)
	}
	_, e = s.Join(c.ID, c.Code, guest)
	assert.ErrorIs(t, e, ErrCapacity)
	s.CloseSession("session")
	assert.Empty(t, s.List("session", owner.ID))
	assert.Empty(t, s.Controller("session"))
	for _, bad := range []Input{{}, {SessionID: "session", Mode: "admin", Minutes: 1, AllowedUsers: []string{guest.ID}}, {SessionID: "session", Mode: ReadOnly, Minutes: 1441, AllowedUsers: []string{guest.ID}}, {SessionID: "session", Mode: ReadOnly, Minutes: 1, AllowedUsers: []string{owner.ID}}} {
		_, e = s.Create(bad, owner)
		assert.ErrorIs(t, e, ErrInvalid)
	}
	for i := 0; i < maxSessionShares; i++ {
		_, e = s.Create(input, owner)
		require.NoError(t, e)
	}
	_, e = s.Create(input, owner)
	assert.ErrorIs(t, e, ErrCapacity)
}

func TestAuditFailureCannotGrantAndCannotKeepRevokedAccess(t *testing.T) {
	failed := false
	s := New(func(Event) error {
		if failed {
			return errors.New("disk unavailable")
		}
		return nil
	})
	owner := Actor{ID: "owner", Name: "owner"}
	guest := Actor{ID: "guest", Name: "guest"}
	in := Input{SessionID: "session", Mode: ReadWrite, Minutes: 5, AllowedUsers: []string{guest.ID}}
	failed = true
	_, e := s.Create(in, owner)
	require.ErrorIs(t, e, ErrAudit)
	assert.Empty(t, s.List("session", owner.ID))
	failed = false
	c, e := s.Create(in, owner)
	require.NoError(t, e)
	failed = true
	_, e = s.Join(c.ID, c.Code, guest)
	require.ErrorIs(t, e, ErrAudit)
	assert.Empty(t, s.Members("session", owner.ID))
	failed = false
	m, e := s.Join(c.ID, c.Code, guest)
	require.NoError(t, e)
	failed = true
	require.ErrorIs(t, s.TakeControl(m.ID, guest.ID), ErrAudit)
	assert.Empty(t, s.Controller("session"))
	require.ErrorIs(t, s.Kick(m.ID, owner), ErrAudit)
	_, e = s.Member(m.ID, guest.ID)
	assert.ErrorIs(t, e, ErrDenied)
	require.ErrorIs(t, s.Revoke(c.ID, owner), ErrAudit)
	_, e = s.Join(c.ID, c.Code, guest)
	assert.ErrorIs(t, e, ErrDenied)
}

func TestConcurrentInvitesAndMembersAreBounded(t *testing.T) {
	s := New(func(Event) error { return nil })
	var wg sync.WaitGroup
	owner := Actor{ID: "owner", Name: "owner"}
	guest := Actor{ID: "guest", Name: "guest"}
	for i := 0; i < 64; i++ {
		wg.Go(func() {
			_, e := s.Create(Input{SessionID: "session", Mode: ReadOnly, Minutes: 1, AllowedUsers: []string{guest.ID}}, owner)
			if e != nil {
				assert.ErrorIs(t, e, ErrCapacity)
			}
		})
	}
	wg.Wait()
	invites := s.List("session", owner.ID)
	require.Len(t, invites, maxSessionShares)
	for i := 0; i < maxShares-maxSessionShares; i++ {
		_, e := s.Create(Input{SessionID: fmt.Sprint("other-", i), Mode: ReadOnly, Minutes: 1, AllowedUsers: []string{guest.ID}}, owner)
		require.NoError(t, e)
	}
	_, e := s.Create(Input{SessionID: "overflow", Mode: ReadOnly, Minutes: 1, AllowedUsers: []string{guest.ID}}, owner)
	assert.ErrorIs(t, e, ErrCapacity)
	for _, i := range invites {
		require.NoError(t, s.Revoke(i.ID, owner))
	}
	assert.Empty(t, s.List("session", owner.ID))
	assert.False(t, strings.Contains(fmt.Sprint(s), "code:"))
}

func TestOwnerAuthorityIsRecheckedAndConcurrentJoinsStayBounded(t *testing.T) {
	var allowed atomic.Bool
	allowed.Store(true)
	s := New(func(Event) error { return nil })
	owner := Actor{ID: "owner", Name: "owner"}
	guest := Actor{ID: "guest", Name: "guest"}
	c, e := s.Create(Input{SessionID: "session", Mode: ReadWrite, Minutes: 5, AllowedUsers: []string{guest.ID}, Authorize: func() error {
		if !allowed.Load() {
			return ErrDenied
		}
		return nil
	}}, owner)
	require.NoError(t, e)
	var wg sync.WaitGroup
	for i := 0; i < 40; i++ {
		wg.Go(func() {
			_, e := s.Join(c.ID, c.Code, guest)
			if e != nil {
				assert.ErrorIs(t, e, ErrCapacity)
			}
		})
	}
	wg.Wait()
	members := s.Members("session", owner.ID)
	require.Len(t, members, maxSessionMembers)
	allowed.Store(false)
	_, e = s.Member(members[0].ID, guest.ID)
	assert.ErrorIs(t, e, ErrDenied)
	assert.ErrorIs(t, s.TakeControl(members[0].ID, guest.ID), ErrDenied)
	_, e = s.Join(c.ID, c.Code, guest)
	assert.ErrorIs(t, e, ErrDenied)
	require.NoError(t, s.Revoke(c.ID, owner))
	assert.Empty(t, s.Members("session", owner.ID))
}
