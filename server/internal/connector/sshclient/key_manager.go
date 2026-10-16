package sshclient

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"io"
	"os"
	"path"
	"strings"
	"time"

	"github.com/pkg/sftp"
	xssh "golang.org/x/crypto/ssh"
)

// AuthorizedKeysUpdater owns a cooperative per-account lock. Close retains the
// lock for recovery; Release explicitly removes only this operation's lock.
type AuthorizedKeysUpdater struct {
	client      *sftp.Client
	transport   *xssh.Client
	directory   string
	operationID string
	owner       uint32
	stop        func() bool
	cancel      context.CancelFunc
}

func OpenAuthorizedKeys(ctx context.Context, target Target, credentials Credentials, operationID string) (*AuthorizedKeysUpdater, error) {
	return openAuthorizedKeys(ctx, target, credentials, operationID, true)
}
func openAuthorizedKeys(ctx context.Context, target Target, credentials Credentials, operationID string, lockNeeded bool) (*AuthorizedKeysUpdater, error) {
	if !ValidKeyOperationID(operationID) {
		return nil, ErrKeyPlan
	}
	ctx, cancel := context.WithTimeout(ctx, 45*time.Second)
	transport, _, e := dial(ctx, target, credentials, 12*time.Second)
	if e != nil {
		cancel()
		return nil, e
	}
	stop := context.AfterFunc(ctx, func() { _ = transport.Close() })
	client, e := sftp.NewClient(transport)
	if e != nil {
		stop()
		cancel()
		_ = transport.Close()
		return nil, e
	}
	m := &AuthorizedKeysUpdater{client: client, transport: transport, operationID: operationID, stop: stop, cancel: cancel}
	fail := func(e error) (*AuthorizedKeysUpdater, error) { _ = m.Close(); return nil, e }
	if _, ok := client.HasExtension("posix-rename@openssh.com"); !ok {
		return fail(ErrAuthorizedKeysUnsupported)
	}
	if version, ok := client.HasExtension("fsync@openssh.com"); !ok || version != "1" {
		return fail(ErrAuthorizedKeysUnsupported)
	}
	home, e := client.RealPath(".")
	if e != nil || !path.IsAbs(home) || strings.ContainsRune(home, 0) {
		return fail(ErrAuthorizedKeysUnsupported)
	}
	info, e := client.Lstat(home)
	if e != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0022 != 0 {
		return fail(ErrAuthorizedKeysUnsafe)
	}
	stat, ok := info.Sys().(*sftp.FileStat)
	if !ok {
		return fail(ErrAuthorizedKeysUnsupported)
	}
	m.owner = stat.UID
	m.directory = path.Join(home, ".ssh")
	info, e = client.Lstat(m.directory)
	if os.IsNotExist(e) {
		if !lockNeeded {
			return m, nil
		}
		if e = client.Mkdir(m.directory); e != nil {
			return fail(e)
		}
		if e = client.Chmod(m.directory, 0700); e != nil {
			return fail(e)
		}
	} else if e != nil {
		return fail(e)
	}
	if e = m.checkDirectory(); e != nil {
		return fail(e)
	}
	if !lockNeeded {
		return m, nil
	}
	lock := path.Join(m.directory, ".jumpserver233-key.lock")
	var nonce [16]byte
	if _, e = rand.Read(nonce[:]); e != nil {
		return fail(e)
	}
	candidate := path.Join(m.directory, ".key-lock."+operationID+"."+hex.EncodeToString(nonce[:])+".tmp")
	file, e := client.OpenFile(candidate, os.O_CREATE|os.O_EXCL|os.O_WRONLY)
	if e != nil {
		return fail(e)
	}
	defer func() { _ = client.Remove(candidate) }()
	if e = file.Chmod(0600); e == nil {
		var count int
		count, e = io.WriteString(file, operationID+"\n")
		if e == nil && count != len(operationID)+1 {
			e = io.ErrShortWrite
		}
	}
	if e == nil {
		e = file.Sync()
	}
	closeErr := file.Close()
	if e == nil {
		e = closeErr
	}
	if e != nil {
		return fail(e)
	}
	if e = m.checkFile(candidate); e != nil {
		return fail(e)
	}
	// SFTP v3 RENAME refuses an existing destination; OpenSSH implements this
	// without replacing a competing lock. The token file is complete first.
	if e = client.Rename(candidate, lock); e != nil {
		if e = m.checkFile(lock); e != nil {
			return fail(ErrAuthorizedKeysLocked)
		}
		data, e := m.readBounded(lock, 128)
		if e != nil || string(data) != operationID+"\n" {
			return fail(ErrAuthorizedKeysLocked)
		}
	}

	if e = m.cleanTemps(); e != nil {
		return fail(e)
	}
	return m, nil
}
func (m *AuthorizedKeysUpdater) Close() error {
	m.stop()
	m.cancel()
	e := m.client.Close()
	_ = m.transport.Close()
	return e
}
func (m *AuthorizedKeysUpdater) checkDirectory() error {
	info, e := m.client.Lstat(m.directory)
	if e != nil {
		return e
	}
	stat, ok := info.Sys().(*sftp.FileStat)
	if !ok || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0022 != 0 || stat.UID != m.owner {
		return ErrAuthorizedKeysUnsafe
	}
	return nil
}
func (m *AuthorizedKeysUpdater) checkFile(name string) error {
	info, e := m.client.Lstat(name)
	if e != nil {
		return e
	}
	stat, ok := info.Sys().(*sftp.FileStat)
	if !ok || !info.Mode().IsRegular() || info.Mode().Perm()&0022 != 0 || stat.UID != m.owner {
		return ErrAuthorizedKeysUnsafe
	}
	return nil
}
func (m *AuthorizedKeysUpdater) readBounded(name string, max int64) ([]byte, error) {
	if e := m.checkFile(name); e != nil {
		return nil, e
	}
	file, e := m.client.Open(name)
	if e != nil {
		return nil, e
	}
	defer file.Close()
	data, e := io.ReadAll(io.LimitReader(file, max+1))
	if e != nil {
		return nil, e
	}
	if int64(len(data)) > max {
		return nil, ErrKeyPlan
	}
	return data, nil
}
func (m *AuthorizedKeysUpdater) readKeys() ([]byte, error) {
	if e := m.checkDirectory(); e != nil {
		return nil, e
	}
	data, e := m.readBounded(path.Join(m.directory, "authorized_keys"), maxAuthorizedKeysBytes)
	if os.IsNotExist(e) {
		return nil, nil
	}
	return data, e
}
func (m *AuthorizedKeysUpdater) checkLock() error {
	data, e := m.readBounded(path.Join(m.directory, ".jumpserver233-key.lock"), 128)
	if e != nil || string(data) != m.operationID+"\n" {
		return ErrAuthorizedKeysLocked
	}
	return nil
}
func (m *AuthorizedKeysUpdater) Prepare(oldPublic, newPublic []byte) (KeyPlan, error) {
	if e := m.checkLock(); e != nil {
		return KeyPlan{}, e
	}
	data, e := m.readKeys()
	if e != nil {
		return KeyPlan{}, e
	}
	return prepareKeyPlan(data, oldPublic, newPublic, m.operationID)
}
func (m *AuthorizedKeysUpdater) Install(plan KeyPlan) error  { return m.apply(plan, "install") }
func (m *AuthorizedKeysUpdater) Retire(plan KeyPlan) error   { return m.apply(plan, "retire") }
func (m *AuthorizedKeysUpdater) Rollback(plan KeyPlan) error { return m.apply(plan, "rollback") }
func (m *AuthorizedKeysUpdater) Release() error {
	if e := m.checkDirectory(); e != nil {
		return e
	}
	if e := m.checkLock(); e != nil {
		return e
	}
	if e := m.client.Remove(path.Join(m.directory, ".jumpserver233-key.lock")); e != nil {
		return e
	}
	return m.syncDirectory()
}
func (m *AuthorizedKeysUpdater) syncDirectory() error {
	file, e := m.client.Open(m.directory)
	if e != nil {
		return e
	}
	defer file.Close()
	return file.Sync()
}
func (m *AuthorizedKeysUpdater) apply(plan KeyPlan, action string) error {
	if plan.OperationID != m.operationID {
		return ErrKeyPlan
	}
	if e := m.checkLock(); e != nil {
		return e
	}
	before, e := m.readKeys()
	if e != nil {
		return e
	}
	after, e := transformKeyFile(before, plan, action)
	if e != nil {
		return e
	}
	if bytes.Equal(before, after) {
		return m.syncDirectory()
	}
	var nonce [16]byte
	if _, e = rand.Read(nonce[:]); e != nil {
		return e
	}
	temporary := path.Join(m.directory, ".authorized_keys."+m.operationID+"."+hex.EncodeToString(nonce[:])+".tmp")
	file, e := m.client.OpenFile(temporary, os.O_CREATE|os.O_EXCL|os.O_WRONLY)
	if e != nil {
		return e
	}
	defer func() { _ = file.Close(); _ = m.client.Remove(temporary) }()
	if e = file.Chmod(0600); e != nil {
		return e
	}
	if _, e = io.Copy(file, bytes.NewReader(after)); e != nil {
		return e
	}
	if e = file.Sync(); e != nil {
		return e
	}
	if e = file.Close(); e != nil {
		return e
	}
	current, e := m.readKeys()
	if e != nil {
		return e
	}
	if !bytes.Equal(current, before) {
		return ErrAuthorizedKeysChanged
	}
	if e = m.checkLock(); e != nil {
		return e
	}
	if e = m.client.PosixRename(temporary, path.Join(m.directory, "authorized_keys")); e != nil {
		return e
	}
	return m.syncDirectory()
}
func (m *AuthorizedKeysUpdater) cleanTemps() error {
	entries, e := m.client.ReadDir(m.directory)
	if e != nil {
		return e
	}
	for _, entry := range entries {
		prefix := ".authorized_keys." + m.operationID + "."
		if strings.HasPrefix(entry.Name(), ".key-lock."+m.operationID+".") {
			prefix = ".key-lock." + m.operationID + "."
		}
		if !strings.HasPrefix(entry.Name(), prefix) || !strings.HasSuffix(entry.Name(), ".tmp") {
			continue
		}
		token := strings.TrimSuffix(strings.TrimPrefix(entry.Name(), prefix), ".tmp")
		if len(token) != 32 {
			continue
		}
		if _, e = hex.DecodeString(token); e != nil {
			continue
		}
		name := path.Join(m.directory, entry.Name())
		if e = m.checkFile(name); e != nil {
			return e
		}
		if e = m.client.Remove(name); e != nil {
			return e
		}
	}
	return nil
}

// CheckSSHKeyChange performs read-only capability and authorization checks
// before the core creates a pending operation or any remote lock file.
func CheckSSHKeyChange(ctx context.Context, target Target, c Credentials, oldPublic, newPublic []byte) error {
	m, e := openAuthorizedKeys(ctx, target, c, "kr-00000000000000000000000000000000", false)
	if e != nil {
		return e
	}
	defer m.Close()
	data, e := m.readKeys()
	if os.IsNotExist(e) {
		data = nil
		e = nil
	}
	if e != nil {
		return e
	}
	_, e = prepareKeyPlan(data, oldPublic, newPublic, m.operationID)
	return e
}
