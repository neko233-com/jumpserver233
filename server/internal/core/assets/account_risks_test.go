package assets

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/neko233-com/jumpserver233/server/internal/core/accountrisks"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAccountRiskSourceLockCoversScanPublicationAndReview(t *testing.T) {
	s, _, parent, _ := newRotationServiceTest(t)
	current, e := s.ManagedAccount(parent.ID, parent.ID)
	require.NoError(t, e)
	entered, release, done := make(chan struct{}), make(chan struct{}), make(chan error, 1)
	go func() {
		done <- s.CollectAccountRisks(context.Background(), accountrisks.DefaultPolicy(), time.Now().UTC(), nil, nil, func(v accountrisks.Snapshot) error {
			close(entered)
			<-release
			return nil
		})
	}()
	<-entered
	updated := make(chan error, 1)
	go func() {
		_, e := s.UpdateManagedAccount(parent.ID, parent.ID, AccountInput{Name: new("After scan"), Version: current.Version}, importActor())
		updated <- e
	}()
	select {
	case <-updated:
		t.Fatal("source changed while snapshot was being published")
	case <-time.After(20 * time.Millisecond):
	}
	close(release)
	require.NoError(t, <-done)
	require.NoError(t, <-updated)
	called := false
	e = s.WithAccountRiskVersion(parent.ID, current.Version, func() error { called = true; return nil })
	assert.ErrorIs(t, e, accountrisks.ErrConflict)
	assert.False(t, called)
}

func TestAccountRisksVaultSnapshotPasswordReuseAgeUsageAndNoCredentialDisclosure(t *testing.T) {
	s, st, parent, _ := newRotationServiceTest(t)
	current, e := s.ManagedAccount(parent.ID, parent.ID)
	require.NoError(t, e)
	_, e = s.UpdateManagedAccount(parent.ID, parent.ID, AccountInput{Password: "admin123", Version: current.Version}, importActor())
	require.NoError(t, e)
	b := parent
	b.ID = "risk-other"
	b.Host = "192.0.2.98"
	b.Name = "Other"
	_, e = st.Create(b, "admin123")
	require.NoError(t, e)
	alias := b
	alias.ID = "risk-alias"
	_, e = st.Create(alias, "admin123")
	require.NoError(t, e)
	now := time.Now().UTC()
	st.mu.Lock()
	for id, r := range st.assets {
		r.CreatedAt = now.Add(-200 * 24 * time.Hour)
		r.PasswordRotatedAt = r.CreatedAt
		r.Asset.PasswordRotatedAt = r.CreatedAt
		st.assets[id] = r
	}
	st.mu.Unlock()
	var got accountrisks.Snapshot
	e = s.CollectAccountRisks(context.Background(), accountrisks.DefaultPolicy(), now, map[string]time.Time{parent.ID: now}, nil, func(v accountrisks.Snapshot) error { got = v; return nil })
	require.NoError(t, e)
	require.Len(t, got.Accounts, 3)
	for _, o := range got.Accounts {
		kinds := map[string]bool{}
		for _, c := range o.Checks {
			kinds[c.Kind] = true
		}
		assert.True(t, kinds["weak_password"])
		assert.True(t, kinds["duplicate_password"])
		assert.True(t, kinds["stale_credential"])
		assert.Equal(t, o.AccountID != parent.ID, kinds["unused_account"])
	}
	raw, e := json.Marshal(got)
	require.NoError(t, e)
	assert.NotContains(t, string(raw), "admin123")
	assert.NotContains(t, string(raw), "initial-credential")
	p := accountrisks.DefaultPolicy()
	p.IncludeDisabled = true
	e = s.CollectAccountRisks(context.Background(), p, now, nil, nil, func(accountrisks.Snapshot) error { return accountrisks.ErrConflict })
	assert.ErrorIs(t, e, accountrisks.ErrConflict)
}

func TestAccountRiskKeyReuseExcludesAliasesAndDoesNotExposePrivateKey(t *testing.T) {
	s, _, _, _ := newRotationServiceTest(t)
	input := keyInput()
	a, e := s.Create(input)
	require.NoError(t, e)
	input.Name = "Key alias"
	_, e = s.Create(input)
	require.NoError(t, e)
	collect := func() accountrisks.Snapshot {
		var got accountrisks.Snapshot
		require.NoError(t, s.CollectAccountRisks(context.Background(), accountrisks.DefaultPolicy(), time.Now().UTC(), nil, nil, func(v accountrisks.Snapshot) error { got = v; return nil }))
		return got
	}
	assert.Empty(t, collect().Groups)
	input.Username = "different-key-account"
	_, e = s.Create(input)
	require.NoError(t, e)
	got := collect()
	require.Len(t, got.Groups, 1)
	reused := 0
	for _, o := range got.Accounts {
		for _, c := range o.Checks {
			if c.Kind == "reused_key" {
				reused++
			}
		}
		if o.AccountID == a.ID {
			assert.NotEmpty(t, o.Identity)
		}
	}
	assert.Equal(t, 3, reused)
	raw, e := json.Marshal(got)
	require.NoError(t, e)
	assert.NotContains(t, string(raw), "PRIVATE KEY")
	assert.NotContains(t, string(raw), input.PrivateKeyPassphrase)
}
func TestAccountRisksAliasesAloneDoNotReportPasswordReuseAndKnownUsageIsIdentityBound(t *testing.T) {
	s, st, parent, _ := newRotationServiceTest(t)
	a := parent
	a.ID = "same-remote"
	_, e := st.Create(a, "initial-credential")
	require.NoError(t, e)
	p := accountrisks.DefaultPolicy()
	var before accountrisks.Snapshot
	e = s.CollectAccountRisks(context.Background(), p, time.Now(), nil, nil, func(v accountrisks.Snapshot) error { before = v; return nil })
	require.NoError(t, e)
	assert.Empty(t, before.Groups)
	for _, o := range before.Accounts {
		for _, c := range o.Checks {
			assert.NotEqual(t, "duplicate_password", c.Kind)
		}
	}
	known := map[string]accountrisks.Usage{parent.ID: {Identity: strings.Repeat("f", 64), At: time.Now().Add(time.Hour)}}
	e = s.CollectAccountRisks(context.Background(), p, time.Now(), nil, known, func(v accountrisks.Snapshot) error {
		for _, o := range v.Accounts {
			assert.True(t, o.LastUsedAt.IsZero())
		}
		return nil
	})
	require.NoError(t, e)
}
