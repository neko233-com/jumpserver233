package assets

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/neko233-com/jumpserver233/server/internal/connector/sshclient"
	"github.com/neko233-com/jumpserver233/server/internal/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestManagedAccountsParentOwnershipCannotBeReboundInVault(t *testing.T) {
	s, st, parent, path := newRotationServiceTest(t)
	a := addManagedTestAccount(t, s, parent.ID)
	other := parent
	other.ID = "other-parent"
	_, e := st.Create(other, "synthetic-other-password")
	require.NoError(t, e)
	var records []map[string]any
	require.NoError(t, json.Unmarshal(mustReadFile(t, path), &records))
	for _, r := range records {
		if r["id"] == a.ID {
			r["parent_asset_id"] = other.ID
		}
	}
	raw, e := json.Marshal(records)
	require.NoError(t, e)
	require.NoError(t, os.WriteFile(path, raw, 0600))
	_, e = OpenStore(path, []byte("0123456789abcdef0123456789abcdef"))
	require.Error(t, e)
}

func TestManagedAccountsPostgresTakeoverAndOrganizationIsolation(t *testing.T) {
	dsn := os.Getenv("JMS_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("set JMS_TEST_DATABASE_URL for PostgreSQL takeover")
	}
	docs, e := storage.OpenPostgres(context.Background(), dsn, fmt.Sprintf("managed-accounts-%d", time.Now().UnixNano()))
	require.NoError(t, e)
	t.Cleanup(func() { _ = docs.Delete("assets"); _ = docs.Close() })
	key := []byte("0123456789abcdef0123456789abcdef")
	path := filepath.Join(t.TempDir(), "assets.json")
	st, e := OpenStoreWithDocuments(path, key, docs)
	require.NoError(t, e)
	parent, e := st.Create(Asset{ID: "asset-ha", Name: "HA", Host: "host.internal", Port: 22, Username: "primary"}, "synthetic-primary")
	require.NoError(t, e)
	s := NewService(st, nil)
	a := addManagedTestAccount(t, s, parent.ID)
	raw, e := docs.Load("assets")
	require.NoError(t, e)
	assert.NotContains(t, string(raw), "synthetic-managed-password")
	peer, e := OpenStoreWithDocuments(filepath.Join(t.TempDir(), "assets.json"), key, docs)
	require.NoError(t, e)
	peerService := NewService(peer, nil)
	assert.Len(t, peerService.List(), 1)
	_, target, c, e := peer.connection(a.ID)
	require.NoError(t, e)
	assert.Equal(t, "operator", target.Username)
	assert.Equal(t, "synthetic-managed-password", c.Password)
	active := false
	_, e = peerService.UpdateManagedAccount(parent.ID, a.ID, AccountInput{Version: a.Version, Active: &active}, AccountActor{ID: "ha", Name: "takeover"})
	require.NoError(t, e)
	reopened, e := OpenStoreWithDocuments(filepath.Join(t.TempDir(), "assets.json"), key, docs)
	require.NoError(t, e)
	_, _, _, e = reopened.connection(a.ID)
	assert.ErrorIs(t, e, ErrAccountDisabled)
	events, total, e := NewService(reopened, nil).AccountActivity(parent.ID, a.ID, 0, 20)
	require.NoError(t, e)
	assert.Equal(t, 2, total)
	assert.Equal(t, "updated", events[0].Action)
	isolated, e := OpenStore(filepath.Join(t.TempDir(), "assets.json"), key)
	require.NoError(t, e)
	_, ok := isolated.lookup(a.ID)
	assert.False(t, ok)
}

func TestManagedSharedSSHKeySynchronizesDisabledCopyWithoutConnectingIt(t *testing.T) {
	f := newSharedKeyFixture(t)
	peer := f.services[1]
	current, e := peer.ManagedAccount(f.assets[1].ID, f.assets[1].ID)
	require.NoError(t, e)
	active := false
	_, e = peer.UpdateManagedAccount(current.AssetID, current.ID, AccountInput{Version: current.Version, Active: &active}, AccountActor{ID: "admin", Name: "administrator"})
	require.NoError(t, e)
	peer.verifyPassword = func(context.Context, sshclient.Target, sshclient.Credentials, time.Duration) error {
		t.Error("disabled copy must not connect")
		return ErrAccountDisabled
	}
	next, e := f.rotate(t)
	require.NoError(t, e)
	a, ok := peer.find(current.ID)
	require.True(t, ok)
	assert.Equal(t, next.KeyFingerprint, a.KeyFingerprint)
	assert.True(t, a.AccountDisabled)
	assert.Empty(t, f.c.keys.ops)
}

func TestManagedSharedPasswordSynchronizesDisabledCopyWithoutConnectingIt(t *testing.T) {
	c, e := OpenPasswordCoordinator(filepath.Join(t.TempDir(), "shared.json"), make([]byte, 32), nil)
	require.NoError(t, e)
	remote := "synthetic-managed-password"
	changes := 0
	var services []*Service
	var accounts []ManagedAccount
	for i := range 2 {
		s, _, parent, _ := newRotationServiceTest(t)
		a := addManagedTestAccount(t, s, parent.ID)
		s.changePassword = func(_ context.Context, target sshclient.Target, current sshclient.Credentials, next string, _ time.Duration) error {
			assert.Equal(t, "operator", target.Username)
			assert.Equal(t, remote, current.Password)
			remote = next
			changes++
			return nil
		}
		s.verifyPassword = func(_ context.Context, target sshclient.Target, current sshclient.Credentials, _ time.Duration) error {
			assert.Equal(t, "operator", target.Username)
			assert.Equal(t, remote, current.Password)
			return nil
		}
		require.NoError(t, s.CoordinatePasswords(c, fmt.Sprint(i)))
		services = append(services, s)
		accounts = append(accounts, a)
	}
	active := false
	_, e = services[1].UpdateManagedAccount(accounts[1].AssetID, accounts[1].ID, AccountInput{Version: accounts[1].Version, Active: &active}, AccountActor{ID: "admin", Name: "administrator"})
	require.NoError(t, e)
	services[1].verifyPassword = func(context.Context, sshclient.Target, sshclient.Credentials, time.Duration) error {
		t.Error("disabled copy must not connect")
		return ErrAccountDisabled
	}
	_, e = services[0].RotatePassword(context.Background(), accounts[0].ID)
	require.NoError(t, e)
	assert.Equal(t, 1, changes)
	for i, s := range services {
		got, e := s.store.Password(accounts[i].ID)
		require.NoError(t, e)
		assert.Equal(t, remote, got)
		primary, e := s.store.Password(accounts[i].AssetID)
		require.NoError(t, e)
		assert.Equal(t, "initial-credential", primary)
	}
}

func addManagedTestAccount(t *testing.T, s *Service, parent string) ManagedAccount {
	t.Helper()
	rows, e := s.ManagedAccounts(parent)
	require.NoError(t, e)
	a, e := s.CreateManagedAccount(parent, AccountInput{Username: "operator", Password: "synthetic-managed-password", Version: rows[0].Version}, AccountActor{ID: "admin-id", Name: "administrator"})
	require.NoError(t, e)
	return a
}
func TestManagedAccountsInheritOnePhysicalTargetAndPreserveEncryptedHistory(t *testing.T) {
	s, st, parent, path := newRotationServiceTest(t)
	a := addManagedTestAccount(t, s, parent.ID)
	assert.False(t, a.Default)
	assert.Equal(t, parent.ID, a.AssetID)
	assert.Len(t, s.List(), 1)
	view, target, secret, e := st.connection(a.ID)
	require.NoError(t, e)
	assert.Equal(t, parent.Host, target.Host)
	assert.Equal(t, "operator", target.Username)
	assert.Equal(t, "synthetic-managed-password", secret.Password)
	assert.Equal(t, parent.ID, ResourceID(view))
	assert.NotContains(t, string(mustReadFile(t, path)), secret.Password)
	var records []map[string]any
	require.NoError(t, json.Unmarshal(mustReadFile(t, path), &records))
	for _, row := range records {
		if row["id"] == a.ID {
			assert.Equal(t, parent.ID, row["parent_asset_id"])
			assert.Empty(t, row["host"])
			assert.Empty(t, row["gateway_id"])
		}
	}
	nextHost := parent
	nextHost.Host = "192.0.2.99"
	_, e = st.Update(nextHost, "")
	require.NoError(t, e)
	_, target, _, e = st.connection(a.ID)
	require.NoError(t, e)
	assert.Equal(t, nextHost.Host, target.Host)
	rows, e := s.ManagedAccounts(parent.ID)
	require.NoError(t, e)
	assert.Len(t, rows, 2)
	assert.NotEqual(t, a.Version, rows[1].Version)
	_, e = s.UpdateManagedAccount(parent.ID, a.ID, AccountInput{Version: a.Version, Password: "synthetic-next-password"}, AccountActor{ID: "a", Name: "admin"})
	assert.ErrorIs(t, e, ErrCredentialChanged)
	updated, e := s.UpdateManagedAccount(parent.ID, a.ID, AccountInput{Version: rows[1].Version, Password: "synthetic-next-password"}, AccountActor{ID: "a", Name: "admin"})
	require.NoError(t, e)
	assert.NotEqual(t, rows[1].Version, updated.Version)
	backups, e := st.ListCredentialBackups(a.ID)
	require.NoError(t, e)
	assert.Len(t, backups, 1)
	primaryPassword, e := st.Password(parent.ID)
	require.NoError(t, e)
	assert.Equal(t, "initial-credential", primaryPassword)
	reopened, e := OpenStore(path, []byte("0123456789abcdef0123456789abcdef"))
	require.NoError(t, e)
	_, target, secret, e = reopened.connection(a.ID)
	require.NoError(t, e)
	assert.Equal(t, nextHost.Host, target.Host)
	assert.Equal(t, "synthetic-next-password", secret.Password)
	assert.NotContains(t, string(mustReadFile(t, path)), secret.Password)
}

func TestManagedAccountsScopesDisabledStateUniquenessAndDurableDeletion(t *testing.T) {
	s, st, parent, _ := newRotationServiceTest(t)
	a := addManagedTestAccount(t, s, parent.ID)
	rows, e := s.ManagedAccounts(parent.ID)
	require.NoError(t, e)
	_, e = s.CreateManagedAccount(parent.ID, AccountInput{Username: "operator", Password: "another", Version: rows[0].Version}, AccountActor{ID: "a", Name: "admin"})
	assert.ErrorIs(t, e, ErrAccountDuplicate)
	assert.Len(t, st.List(), 2)
	_, e = s.UpdateManagedAccount("wrong-parent", a.ID, AccountInput{Version: a.Version}, AccountActor{ID: "a", Name: "admin"})
	assert.ErrorIs(t, e, ErrNotFound)
	_, e = s.UpdateManagedAccount(parent.ID, a.ID, AccountInput{Version: a.Version, Username: "root"}, AccountActor{ID: "a", Name: "admin"})
	assert.ErrorIs(t, e, ErrInvalidInput)
	active := false
	disabled, e := s.UpdateManagedAccount(parent.ID, a.ID, AccountInput{Version: a.Version, Active: &active}, AccountActor{ID: "a", Name: "admin"})
	require.NoError(t, e)
	_, e = s.Get(a.ID)
	assert.ErrorIs(t, e, ErrAccountDisabled)
	_, _, _, e = st.connection(a.ID)
	assert.ErrorIs(t, e, ErrAccountDisabled)
	_, e = s.Get(parent.ID)
	require.NoError(t, e)
	assert.ErrorIs(t, s.Delete(parent.ID), ErrAccountInUse)
	assert.ErrorIs(t, s.Delete(a.ID), ErrInvalidInput)
	assert.ErrorIs(t, s.DeleteManagedAccount(parent.ID, parent.ID, rows[0].Version, AccountActor{ID: "a", Name: "admin"}), ErrInvalidInput)
	require.NoError(t, s.DeleteManagedAccount(parent.ID, a.ID, disabled.Version, AccountActor{ID: "a", Name: "admin"}))
	_, e = s.Get(a.ID)
	assert.ErrorIs(t, e, ErrNotFound)
	events, total, e := s.AccountActivity(parent.ID, parent.ID, 0, 20)
	require.NoError(t, e)
	assert.Equal(t, 3, total)
	assert.Equal(t, "deleted", events[0].Action)
	assert.Equal(t, a.ID, events[0].AccountID)
	raw, e := json.Marshal(events)
	require.NoError(t, e)
	assert.NotContains(t, string(raw), "synthetic-managed-password")
}

func TestManagedAccountFailedParentWriteAndPendingRotationKeepTargetStable(t *testing.T) {
	s, st, parent, path := newRotationServiceTest(t)
	a := addManagedTestAccount(t, s, parent.ID)
	require.NoError(t, os.Rename(path, path+".original"))
	require.NoError(t, os.Mkdir(path, 0700))
	t.Cleanup(func() { _ = os.Remove(path); _ = os.Rename(path+".original", path) })
	changed := parent
	changed.Host = "192.0.2.88"
	_, e := st.Update(changed, "")
	require.Error(t, e)
	_, target, _, e := st.connection(a.ID)
	require.NoError(t, e)
	assert.Equal(t, parent.Host, target.Host)
	require.NoError(t, os.Remove(path))
	require.NoError(t, os.Rename(path+".original", path))
	st.mu.Lock()
	r := st.assets[a.ID]
	r.PendingRotation = &pendingRotation{}
	st.assets[a.ID] = r
	st.mu.Unlock()
	in := Input{Name: parent.Name, Host: changed.Host, Port: parent.Port, Username: parent.Username, HostKeyFingerprint: parent.HostKeyFingerprint}
	_, e = s.Update(parent.ID, in)
	assert.ErrorIs(t, e, ErrRotationPending)
	assert.ErrorIs(t, s.DeleteManagedAccount(parent.ID, a.ID, a.Version, AccountActor{ID: "a", Name: "admin"}), ErrRotationPending)
}

func TestManagedAccountsRotateEachDueIdentityAndHonorScheduleDisable(t *testing.T) {
	s, st, parent, _ := newRotationServiceTest(t)
	a := addManagedTestAccount(t, s, parent.ID)
	st.mu.Lock()
	for _, id := range []string{parent.ID, a.ID} {
		r := st.assets[id]
		r.PasswordRotatedAt = time.Now().UTC().Add(-8 * 24 * time.Hour)
		r.Asset.PasswordRotatedAt = r.PasswordRotatedAt
		st.assets[id] = r
	}
	st.mu.Unlock()
	var users []string
	s.changePassword = func(_ context.Context, target sshclient.Target, _ sshclient.Credentials, _ string, _ time.Duration) error {
		users = append(users, target.Username)
		return nil
	}
	s.verifyPassword = func(context.Context, sshclient.Target, sshclient.Credentials, time.Duration) error { return nil }
	rows, e := s.ManagedAccounts(parent.ID)
	require.NoError(t, e)
	enabled := false
	_, e = s.UpdateManagedAccount(parent.ID, a.ID, AccountInput{Version: rows[1].Version, PasswordRotationEnabled: &enabled}, AccountActor{ID: "a", Name: "admin"})
	require.NoError(t, e)
	s.RotateDuePasswords(context.Background())
	assert.Equal(t, []string{"deploy"}, users)
	rows, e = s.ManagedAccounts(parent.ID)
	require.NoError(t, e)
	assert.Equal(t, "disabled", rows[1].PasswordRotation.State)
	enabled = true
	_, e = s.UpdateManagedAccount(parent.ID, a.ID, AccountInput{Version: rows[1].Version, PasswordRotationEnabled: &enabled}, AccountActor{ID: "a", Name: "admin"})
	require.NoError(t, e)
	s.RotateDuePasswords(context.Background())
	assert.Equal(t, []string{"deploy", "operator"}, users)
	assert.False(t, strings.Contains(strings.Join(users, ","), "password"))
}
