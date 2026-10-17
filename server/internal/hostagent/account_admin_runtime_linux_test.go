//go:build linux

package hostagent

import (
	"context"
	"errors"
	"os"
	"strings"
	"syscall"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type fakeAdminSystem struct {
	row                                    accountAdminIdentity
	exists                                 bool
	creates, provisions, modifies, deletes int
	interruptProvision                     bool
	interruptModify                        bool
}

func (s *fakeAdminSystem) lookup(context.Context, string) (accountAdminIdentity, bool, error) {
	return s.row, s.exists, nil
}
func (s *fakeAdminSystem) create(_ context.Context, t AccountAdminTask) (accountAdminIdentity, error) {
	s.creates++
	s.exists = true
	s.row = accountAdminIdentity{Account: Account{Username: t.Username, UID: 1001, GID: 1001, Home: "/home/" + t.Username, Shell: "/usr/sbin/nologin"}, Marker: "jumpserver233/" + t.ID}
	return s.row, nil
}
func (s *fakeAdminSystem) provision(_ context.Context, t AccountAdminTask, _ accountAdminIdentity) error {
	s.provisions++
	if s.interruptProvision {
		return context.Canceled
	}
	s.row.Shell = t.Shell
	return nil
}
func (s *fakeAdminSystem) modify(_ context.Context, _ accountAdminIdentity, expiry, shell string) error {
	s.modifies++
	s.row.Expiry = expiry
	s.row.Shell = shell
	if s.interruptModify {
		return context.Canceled
	}
	return nil
}
func (s *fakeAdminSystem) prepareRemove(context.Context, accountAdminIdentity) (accountHomeProof, error) {
	return accountHomeProof{Device: 1, Inode: 1}, nil
}
func (s *fakeAdminSystem) remove(context.Context, accountAdminIdentity, accountHomeProof) error {
	s.deletes++
	s.exists = false
	return nil
}

func TestAccountAdminNativeStateRequiresExplicitResumeAndReconcilesInterruptedEffects(t *testing.T) {
	dir := t.TempDir()
	system := &fakeAdminSystem{interruptProvision: true}
	task := adminTestTask(t)
	req := AccountAdminRequest{Task: task, Mode: "apply"}
	r, e := runAccountAdmin(context.Background(), req, dir, system)
	require.ErrorIs(t, e, context.Canceled)
	assert.Equal(t, "incomplete", r.State)
	assert.Equal(t, "account_created", r.Stage)
	assert.Equal(t, 1, system.creates)
	req.Mode = "inspect"
	read, e := runAccountAdmin(context.Background(), req, dir, system)
	require.NoError(t, e)
	assert.Equal(t, r, read)
	assert.Equal(t, 1, system.provisions)
	system.interruptProvision = false
	req.Mode = "apply"
	r, e = runAccountAdmin(context.Background(), req, dir, system)
	require.NoError(t, e)
	assert.Equal(t, "applied", r.State)
	assert.Equal(t, 1, system.creates)
	assert.Equal(t, 2, system.provisions)
	_, e = runAccountAdmin(context.Background(), req, dir, system)
	require.NoError(t, e)
	assert.Equal(t, 2, system.provisions, "completed tasks are never executed again")
	req.Task.Shell = "/bin/bash"
	_, e = runAccountAdmin(context.Background(), req, dir, system)
	require.Error(t, e)
	assert.Equal(t, 2, system.provisions)
	req.Task = task
	req.Mode = "inspect"
	system.row.UID++
	r, e = runAccountAdmin(context.Background(), req, dir, system)
	require.Error(t, e)
	assert.Equal(t, "conflict", r.State)
}
func TestAccountAdminNativeDisableAndEnablePreserveOriginalExpiryAcrossInterruptedMutation(t *testing.T) {
	dir := t.TempDir()
	system := &fakeAdminSystem{exists: true, row: accountAdminIdentity{Account: Account{Username: "adminqa_test", UID: 1001, GID: 1001, Home: "/home/adminqa_test", Shell: "/bin/sh"}, Expiry: "40000"}, interruptModify: true}
	task := AccountAdminTask{ID: "ra-" + strings.Repeat("a", 32), Action: "disable", Username: "adminqa_test", UID: 1001}
	req := AccountAdminRequest{Task: task, Mode: "apply"}
	r, e := runAccountAdmin(context.Background(), req, dir, system)
	require.ErrorIs(t, e, context.Canceled)
	assert.Equal(t, "disable_started", r.Stage)
	assert.Equal(t, "1", system.row.Expiry)
	system.interruptModify = false
	r, e = runAccountAdmin(context.Background(), req, dir, system)
	require.NoError(t, e)
	assert.Equal(t, "applied", r.State)
	assert.Equal(t, 1, system.modifies)
	req.Task.ID = "ra-" + strings.Repeat("b", 32)
	req.Task.Action = "enable"
	system.interruptModify = true
	r, e = runAccountAdmin(context.Background(), req, dir, system)
	require.ErrorIs(t, e, context.Canceled)
	assert.Equal(t, "enable_started", r.Stage)
	system.interruptModify = false
	r, e = runAccountAdmin(context.Background(), req, dir, system)
	require.NoError(t, e)
	assert.Equal(t, "applied", r.State)
	assert.Equal(t, "40000", system.row.Expiry)
	assert.Equal(t, "/bin/sh", system.row.Shell)
	assert.Equal(t, 2, system.modifies)
	system.row.UID = 1002
	req.Task.ID = "ra-" + strings.Repeat("c", 32)
	req.Task.Action = "delete"
	_, e = runAccountAdmin(context.Background(), req, dir, system)
	require.Error(t, e)
	assert.Zero(t, system.deletes)
}
func TestAccountAdminNativeReadOnlyUnknownAndUnsafeReceiptsNeverExecute(t *testing.T) {
	dir := t.TempDir()
	system := &fakeAdminSystem{}
	task := adminTestTask(t)
	req := AccountAdminRequest{Task: task, Mode: "inspect"}
	r, e := runAccountAdmin(context.Background(), req, dir, system)
	require.NoError(t, e)
	assert.Equal(t, "absent", r.State)
	assert.Zero(t, system.creates)
	require.NoError(t, os.WriteFile(dir+"/"+task.ID+".json", []byte(`{"task":{}}`), 0600))
	req.Mode = "apply"
	_, e = runAccountAdmin(context.Background(), req, dir, system)
	require.Error(t, e)
	assert.Zero(t, system.creates)
	system.row = accountAdminIdentity{Account: Account{Username: task.Username, UID: 1001, GID: 1001}, Marker: "foreign"}
	system.exists = true
	req.Task.ID = "ra-" + strings.Repeat("b", 32)
	_, e = runAccountAdmin(context.Background(), req, dir, system)
	require.ErrorIs(t, e, errAdminIdentity)
	assert.Zero(t, system.creates)
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	_, e = runAccountAdmin(cancelled, req, t.TempDir(), system)
	assert.True(t, errors.Is(e, context.Canceled))
	assert.Zero(t, system.creates)
}

func TestAccountAdminCancellationFencesLateApplyAndRefusesExistingEffects(t *testing.T) {
	for _, action := range []string{"create", "disable", "enable", "delete"} {
		t.Run(action, func(t *testing.T) {
			dir := t.TempDir()
			task := adminTestTask(t)
			task.Action = action
			system := &fakeAdminSystem{}
			if action != "create" {
				task.PublicKey = ""
				task.Shell = ""
				task.UID = 1001
				system.exists = true
				system.row = accountAdminIdentity{Account: Account{Username: task.Username, UID: 1001, GID: 1001, Home: "/home/" + task.Username, Shell: "/bin/sh"}}
			}
			r, e := runAccountAdmin(context.Background(), AccountAdminRequest{Task: task, Mode: "cancel"}, dir, system)
			require.NoError(t, e)
			assert.Equal(t, "cancelled", r.State)
			_, e = runAccountAdmin(context.Background(), AccountAdminRequest{Task: task, Mode: "apply"}, dir, system)
			require.Error(t, e)
			assert.Zero(t, system.creates+system.modifies+system.deletes+system.provisions)
		})
	}
	dir := t.TempDir()
	task := adminTestTask(t)
	system := &fakeAdminSystem{interruptProvision: true}
	_, e := runAccountAdmin(context.Background(), AccountAdminRequest{Task: task, Mode: "apply"}, dir, system)
	require.Error(t, e)
	_, e = runAccountAdmin(context.Background(), AccountAdminRequest{Task: task, Mode: "cancel"}, dir, system)
	require.Error(t, e)
	assert.True(t, system.exists)
	system.interruptProvision = false
	_, e = runAccountAdmin(context.Background(), AccountAdminRequest{Task: task, Mode: "apply"}, dir, system)
	require.NoError(t, e)
	system.row.Marker = "foreign-created-same-uid"
	_, e = runAccountAdmin(context.Background(), AccountAdminRequest{Task: task, Mode: "inspect"}, dir, system)
	require.Error(t, e, "same UID alone cannot establish provisioned identity")
}

func TestAccountAdminRemovalHomeProofPinsInodeAndNeverFollowsReplacementSymlink(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root inside the isolated Linux test container")
	}
	root := t.TempDir()
	home := root + "/home"
	require.NoError(t, os.Mkdir(home, 0700))
	require.NoError(t, os.Chown(home, 1001, 1001))
	info, e := os.Stat(home)
	require.NoError(t, e)
	stat := info.Sys().(*syscall.Stat_t)
	proof := accountHomeProof{Device: uint64(stat.Dev), Inode: stat.Ino}
	identity := accountAdminIdentity{Account: Account{UID: 1001, GID: 1001, Home: home}}
	f, e := openAdminRemovalHome(identity, proof)
	require.NoError(t, e)
	require.NoError(t, f.Close())
	require.NoError(t, os.Chown(home, 0, 0))
	f, e = openAdminRemovalHome(identity, proof)
	require.NoError(t, e)
	require.NoError(t, f.Close(), "same quarantined inode can be resumed")
	require.NoError(t, os.Rename(home, root+"/retained"))
	require.NoError(t, os.Mkdir(home, 0700))
	_, e = openAdminRemovalHome(identity, proof)
	require.ErrorIs(t, e, errAdminHome, "different root owned directory cannot be quarantined")
	require.NoError(t, os.Remove(home))
	require.NoError(t, os.Symlink(root+"/retained", home))
	_, e = openAdminRemovalHome(identity, proof)
	require.ErrorIs(t, e, errAdminHome)
}
