//go:build linux

package hostagent

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

func adminTrustedDirectory(dir string, modes ...os.FileMode) error {
	mode := os.FileMode(0700)
	if len(modes) == 1 {
		mode = modes[0]
	}
	if !filepath.IsAbs(dir) || filepath.Clean(dir) != dir {
		return ErrAccountAdmin
	}
	current := "/"
	for _, part := range strings.Split(strings.TrimPrefix(dir, "/"), "/") {
		current = filepath.Join(current, part)
		if e := os.Mkdir(current, mode); e == nil {
			if e = os.Chmod(current, mode); e != nil {
				return ErrAccountAdmin
			}
		} else if !errors.Is(e, os.ErrExist) {
			return ErrAccountAdmin
		}
		s, e := os.Lstat(current)
		if e != nil || !s.IsDir() || !owned(s) || s.Mode().Perm()&0022 != 0 {
			return ErrAccountAdmin
		}
	}
	return nil
}

// InstallAccountAdmin only copies the running, verified helper as root into a
// root-owned global directory. Non-root SSH accounts cannot bootstrap it with sudo.
func InstallAccountAdmin() (string, string, error) {
	if os.Geteuid() != 0 || adminTrustedDirectory(AccountAdminBinaryDirectory, 0755) != nil {
		return "", "", ErrAccountAdmin
	}
	executable, e := os.Executable()
	if e != nil {
		return "", "", ErrAccountAdmin
	}
	f, e := openSnapshot(executable)
	if e != nil {
		return "", "", ErrAccountAdmin
	}
	defer f.Close()
	s, e := f.Stat()
	if e != nil || !s.Mode().IsRegular() || !owned(s) || s.Size() > 32<<20 || s.Mode().Perm()&0022 != 0 {
		return "", "", ErrAccountAdmin
	}
	data, e := io.ReadAll(io.LimitReader(f, 32<<20+1))
	if e != nil || len(data) > 32<<20 {
		return "", "", ErrAccountAdmin
	}
	h := sha256.Sum256(data)
	digest := hex.EncodeToString(h[:])
	name := filepath.Join(AccountAdminBinaryDirectory, "agent-recovery-"+digest)
	if current, e := os.Lstat(name); e == nil {
		if !current.Mode().IsRegular() || !owned(current) || current.Mode().Perm() != 0755 {
			return "", "", ErrAccountAdmin
		}
		existing, e := os.ReadFile(name)
		if e != nil || !bytes.Equal(data, existing) {
			return "", "", ErrAccountAdmin
		}
		return name, digest, nil
	} else if !errors.Is(e, os.ErrNotExist) {
		return "", "", ErrAccountAdmin
	}
	stage, e := os.CreateTemp(AccountAdminBinaryDirectory, ".account-admin-*")
	if e != nil {
		return "", "", ErrAccountAdmin
	}
	defer os.Remove(stage.Name())
	if e = stage.Chmod(0755); e == nil {
		_, e = stage.Write(data)
	}
	if e == nil {
		e = stage.Sync()
	}
	ce := stage.Close()
	if e != nil || ce != nil {
		return "", "", ErrAccountAdmin
	}
	if e = os.Rename(stage.Name(), name); e != nil {
		return "", "", ErrAccountAdmin
	}
	if syncDirectory(AccountAdminBinaryDirectory) != nil {
		return "", "", ErrAccountAdmin
	}
	return name, digest, nil
}

func RunAccountAdmin(ctx context.Context, req AccountAdminRequest) (AccountAdminResult, error) {
	if os.Geteuid() != 0 || req.Validate() != nil || adminTrustedDirectory(AccountAdminDirectory) != nil {
		return AccountAdminResult{}, ErrAccountAdmin
	}
	return runAccountAdmin(ctx, req, AccountAdminDirectory, linuxAccountAdmin{})
}

type linuxAccountAdmin struct{}

func adminRun(ctx context.Context, program string, args []string, input []byte) ([]byte, error) {
	s, e := os.Stat(program)
	if e != nil || !s.Mode().IsRegular() || !owned(s) || s.Mode().Perm()&0022 != 0 {
		return nil, errAdminCommand
	}
	c := exec.CommandContext(ctx, program, args...)
	c.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C", "LC_ALL=C", "HOME=/root"}
	c.Stdin = bytes.NewReader(input)
	var out bytes.Buffer
	c.Stdout = &boundedAdminOutput{out: &out}
	c.Stderr = io.Discard
	if e = c.Run(); e != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, errAdminCommand
	}
	return out.Bytes(), nil
}

type boundedAdminOutput struct{ out *bytes.Buffer }

func (w *boundedAdminOutput) Write(b []byte) (int, error) {
	if w.out.Len()+len(b) > MaxAccountAdminBytes {
		return 0, errAdminCommand
	}
	return w.out.Write(b)
}

func readAdminAccounts() (map[string]accountAdminIdentity, error) {
	f, e := openSnapshot("/etc/passwd")
	if e != nil {
		return nil, errAdminIdentity
	}
	defer f.Close()
	s, e := f.Stat()
	if e != nil || !trustedAccountFile(s) {
		return nil, errAdminIdentity
	}
	raw, e := io.ReadAll(io.LimitReader(f, maxPasswdBytes+1))
	if e != nil || len(raw) > maxPasswdBytes {
		return nil, errAdminIdentity
	}
	rows, e := ParseAccounts(raw)
	if e != nil {
		return nil, errAdminIdentity
	}
	markers := map[string]string{}
	for _, line := range strings.Split(string(raw), "\n") {
		parts := strings.Split(line, ":")
		if len(parts) == 7 {
			markers[parts[0]] = parts[4]
		}
	}
	result := map[string]accountAdminIdentity{}
	for _, row := range rows {
		result[row.Username] = accountAdminIdentity{Account: row, Marker: markers[row.Username]}
	}
	return result, nil
}
func adminExpiry(username string) (string, error) {
	f, e := openSnapshot("/etc/shadow")
	if e != nil {
		return "", errAdminIdentity
	}
	defer f.Close()
	s, e := f.Stat()
	if e != nil || !trustedAccountFile(s) {
		return "", errAdminIdentity
	}
	// Keep only the selected expiration field; never expose or persist hash text.
	raw, e := io.ReadAll(io.LimitReader(f, maxPasswdBytes+1))
	if e != nil || len(raw) > maxPasswdBytes {
		return "", errAdminIdentity
	}
	defer func() {
		for i := range raw {
			raw[i] = 0
		}
	}()
	value := ""
	found := false
	for _, line := range bytes.Split(raw, []byte{'\n'}) {
		parts := bytes.Split(line, []byte{':'})
		if len(parts) > 0 && string(parts[0]) == username {
			if found || len(parts) != 9 {
				return "", errAdminIdentity
			}
			value = string(parts[7])
			found = true
		}
	}
	if !found {
		return "", errAdminIdentity
	}
	if value != "" {
		n, e := strconv.ParseUint(value, 10, 31)
		if e != nil || strconv.FormatUint(n, 10) != value {
			return "", errAdminIdentity
		}
	}
	return value, nil
}
func (linuxAccountAdmin) lookup(ctx context.Context, name string) (accountAdminIdentity, bool, error) {
	rows, e := readAdminAccounts()
	if e != nil {
		return accountAdminIdentity{}, false, e
	}
	v, ok := rows[name]
	if !ok {
		return v, false, nil
	}
	count := 0
	for _, a := range rows {
		if a.UID == v.UID {
			count++
		}
	}
	if count != 1 {
		return accountAdminIdentity{}, false, errAdminIdentity
	}
	v.Expiry, e = adminExpiry(name)
	return v, true, e
}
func adminSameIdentity(ctx context.Context, expected accountAdminIdentity) error {
	v, ok, e := (linuxAccountAdmin{}).lookup(ctx, expected.Username)
	if e != nil || !ok || v.Account != expected.Account || v.Expiry != expected.Expiry {
		return errAdminIdentity
	}
	return nil
}

func adminHomeMarker(t AccountAdminTask) string {
	return "jumpserver233/" + t.ID + "/" + t.Digest() + "\n"
}
func prepareAdminHome(t AccountAdminTask) error {
	if adminTrustedDirectory("/home", 0755) != nil {
		return errAdminHome
	}
	home := "/home/" + t.Username
	created := false
	if e := os.Mkdir(home, 0700); e == nil {
		created = true
	} else if !errors.Is(e, os.ErrExist) {
		return errAdminHome
	}
	s, e := os.Lstat(home)
	if e != nil || !s.IsDir() || !owned(s) || s.Mode().Perm() != 0700 {
		return errAdminHome
	}
	marker := filepath.Join(home, ".jumpserver233-provision")
	if !created {
		if _, e := os.Lstat(marker); e != nil {
			return errAdminHome
		}
	}
	f, e := os.OpenFile(marker, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0600)
	if errors.Is(e, os.ErrExist) {
		f, e := openSnapshot(marker)
		if e != nil {
			return errAdminHome
		}
		defer f.Close()
		s, e := f.Stat()
		if e != nil || !s.Mode().IsRegular() || !owned(s) || s.Mode().Perm() != 0600 {
			return errAdminHome
		}
		raw, e := io.ReadAll(io.LimitReader(f, 512))
		if e != nil || string(raw) != adminHomeMarker(t) {
			return errAdminHome
		}
		return nil
	}
	if e != nil {
		return errAdminHome
	}
	_, e = f.WriteString(adminHomeMarker(t))
	if e == nil {
		e = f.Sync()
	}
	ce := f.Close()
	if e != nil || ce != nil {
		return errAdminHome
	}
	return syncDirectory(home)
}
func (linuxAccountAdmin) create(ctx context.Context, t AccountAdminTask) (accountAdminIdentity, error) {
	// NSS identities must never be silently shadowed by a local account.
	probe := exec.CommandContext(ctx, "/usr/bin/getent", "passwd", t.Username)
	probe.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C", "LC_ALL=C"}
	probe.Stdout = io.Discard
	probe.Stderr = io.Discard
	e := probe.Run()
	var exit *exec.ExitError
	if e == nil || !errors.As(e, &exit) || exit.ExitCode() != 2 {
		return accountAdminIdentity{}, errAdminIdentity
	}
	if e = prepareAdminHome(t); e != nil {
		return accountAdminIdentity{}, e
	}
	args := []string{"--no-create-home", "--user-group", "--groups", "", "--home-dir", "/home/" + t.Username, "--shell", "/usr/sbin/nologin", "--comment", "jumpserver233/" + t.ID, "--expiredate", "", "--inactive", "-1", "-K", "UID_MIN=1000", "-K", "UID_MAX=60000", "--", t.Username}
	if _, e = adminRun(ctx, "/usr/sbin/useradd", args, nil); e != nil {
		return accountAdminIdentity{}, e
	}
	v, ok, e := (linuxAccountAdmin{}).lookup(ctx, t.Username)
	if e != nil || !ok || v.UID < 1000 || v.UID > 60000 || v.GID == 0 || v.Marker != "jumpserver233/"+t.ID || v.Home != "/home/"+t.Username {
		return accountAdminIdentity{}, errAdminIdentity
	}
	return v, nil
}

func (linuxAccountAdmin) provision(ctx context.Context, t AccountAdminTask, identity accountAdminIdentity) error {
	if identity.Home != "/home/"+t.Username || identity.Marker != "jumpserver233/"+t.ID {
		return errAdminIdentity
	}
	if e := adminSameIdentity(ctx, identity); e != nil {
		return e
	}
	home, e := openAdminDirectory(identity.Home, 0)
	if e != nil {
		home, e = openAdminDirectory(identity.Home, identity.UID)
	}
	if e != nil {
		return e
	}
	defer home.Close()
	if e = syscall.Mkdirat(int(home.Fd()), ".ssh", 0700); e != nil && !errors.Is(e, syscall.EEXIST) {
		return errAdminHome
	}
	fd, e := syscall.Openat(int(home.Fd()), ".ssh", syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if e != nil {
		return errAdminHome
	}
	sshDir := os.NewFile(uintptr(fd), ".ssh")
	defer sshDir.Close()
	s, e := sshDir.Stat()
	dirStat, dirOK := safelyAdminStat(s)
	if e != nil || !dirOK || (dirStat.Uid != 0 && dirStat.Uid != identity.UID) || s.Mode().Perm() != 0700 {
		return errAdminHome
	}
	keyData := t.PublicKey + " jumpserver233/" + t.ID + "\n"
	keyFD, e := syscall.Openat(fd, "authorized_keys", syscall.O_WRONLY|syscall.O_CREAT|syscall.O_EXCL|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0600)
	if e == nil {
		f := os.NewFile(uintptr(keyFD), "authorized_keys")
		_, e = f.WriteString(keyData)
		if e == nil {
			e = f.Sync()
		}
		ce := f.Close()
		if e != nil || ce != nil {
			return errAdminHome
		}
	} else if !errors.Is(e, syscall.EEXIST) {
		return errAdminHome
	}
	keyFD, e = syscall.Openat(fd, "authorized_keys", syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if e != nil {
		return errAdminHome
	}
	key := os.NewFile(uintptr(keyFD), "authorized_keys")
	defer key.Close()
	s, e = key.Stat()
	stat, ok := safelyAdminStat(s)
	if e != nil || !ok || !s.Mode().IsRegular() || (stat.Uid != 0 && stat.Uid != identity.UID) || stat.Nlink != 1 || s.Mode().Perm() != 0600 {
		return errAdminHome
	}
	actual, e := io.ReadAll(io.LimitReader(key, MaxAccountAdminBytes))
	if e != nil || string(actual) != keyData {
		return errAdminHome
	}
	// Password material is generated on the host, sent only over a local pipe,
	// discarded immediately, and never returned to the platform or command line.
	if e = adminSameIdentity(ctx, identity); e != nil {
		return e
	}
	var secret [32]byte
	if _, e = rand.Read(secret[:]); e != nil {
		return errAdminCommand
	}
	input := []byte(t.Username + ":" + hex.EncodeToString(secret[:]) + "\n")
	for i := range secret {
		secret[i] = 0
	}
	_, e = adminRun(ctx, "/usr/sbin/chpasswd", nil, input)
	for i := range input {
		input[i] = 0
	}
	if e != nil {
		return e
	}
	if e = key.Chown(int(identity.UID), int(identity.GID)); e != nil {
		return errAdminHome
	}
	if e = sshDir.Chown(int(identity.UID), int(identity.GID)); e != nil {
		return errAdminHome
	}
	if e = home.Chown(int(identity.UID), int(identity.GID)); e != nil {
		return errAdminHome
	}
	_, e = adminRun(ctx, "/usr/sbin/usermod", []string{"--shell", t.Shell, "--", t.Username}, nil)
	return e
}
func safelyAdminStat(s os.FileInfo) (*syscall.Stat_t, bool) {
	if s == nil {
		return nil, false
	}
	v, ok := s.Sys().(*syscall.Stat_t)
	return v, ok
}
func openAdminDirectory(path string, expectedUID uint32) (*os.File, error) {
	fd, e := syscall.Open(path, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if e != nil {
		return nil, errAdminHome
	}
	f := os.NewFile(uintptr(fd), path)
	s, e := f.Stat()
	stat, ok := safelyAdminStat(s)
	if e != nil || !ok || stat.Uid != expectedUID || !s.IsDir() || s.Mode().Perm()&0022 != 0 {
		f.Close()
		return nil, errAdminHome
	}
	return f, nil
}
func (linuxAccountAdmin) modify(ctx context.Context, identity accountAdminIdentity, expiry, shell string) error {
	if e := adminSameIdentity(ctx, identity); e != nil {
		return e
	}
	if !validAccountText(shell, 512) || shell != "" && (!filepath.IsAbs(shell) || filepath.Clean(shell) != shell) {
		return errAdminIdentity
	}
	if expiry != "" {
		if _, e := strconv.ParseUint(expiry, 10, 31); e != nil {
			return errAdminIdentity
		}
	}
	_, e := adminRun(ctx, "/usr/sbin/usermod", []string{"--expiredate", expiry, "--shell", shell, "--", identity.Username}, nil)
	if e != nil {
		return e
	}
	v, ok, e := (linuxAccountAdmin{}).lookup(ctx, identity.Username)
	if e != nil || !ok || v.UID != identity.UID || v.Expiry != expiry || v.Shell != shell {
		return errAdminIdentity
	}
	return nil
}
func (linuxAccountAdmin) prepareRemove(ctx context.Context, identity accountAdminIdentity) (accountHomeProof, error) {
	if e := adminSameIdentity(ctx, identity); e != nil {
		return accountHomeProof{}, e
	}
	if !filepath.IsAbs(identity.Home) || filepath.Clean(identity.Home) != identity.Home {
		return accountHomeProof{}, errAdminHome
	}
	if _, e := os.Lstat(identity.Home); errors.Is(e, os.ErrNotExist) {
		return accountHomeProof{Absent: true}, nil
	}
	f, e := openAdminDirectory(identity.Home, identity.UID)
	if e != nil {
		return accountHomeProof{}, e
	}
	defer f.Close()
	info, e := f.Stat()
	stat, ok := safelyAdminStat(info)
	if e != nil || !ok {
		return accountHomeProof{}, errAdminHome
	}
	return accountHomeProof{Device: uint64(stat.Dev), Inode: stat.Ino}, nil
}

func (linuxAccountAdmin) remove(ctx context.Context, identity accountAdminIdentity, proof accountHomeProof) error {
	if e := adminSameIdentity(ctx, identity); e != nil {
		return e
	}
	if proof.Absent {
		if _, e := os.Lstat(identity.Home); !errors.Is(e, os.ErrNotExist) {
			return errAdminHome
		}
	} else {
		home, e := openAdminRemovalHome(identity, proof)
		if e != nil {
			return e
		}
		defer home.Close()
		if e = home.Chmod(0700); e != nil {
			return errAdminHome
		}
		if e = home.Chown(0, 0); e != nil {
			return errAdminHome
		}
	}
	// Preserve the home and all data. Busy accounts are refused by userdel;
	// there is no force, process kill, recursive removal or arbitrary path.
	if _, e := adminRun(ctx, "/usr/sbin/userdel", []string{"--", identity.Username}, nil); e != nil {
		return e
	}
	_, exists, e := (linuxAccountAdmin{}).lookup(ctx, identity.Username)
	if e != nil || exists {
		return errAdminIdentity
	}
	return nil
}

func openAdminRemovalHome(identity accountAdminIdentity, proof accountHomeProof) (*os.File, error) {
	home, e := openAdminDirectory(identity.Home, identity.UID)
	if e != nil {
		home, e = openAdminDirectory(identity.Home, 0)
	}
	if e != nil {
		return nil, e
	}
	info, e := home.Stat()
	stat, ok := safelyAdminStat(info)
	if e != nil || !ok || proof.Absent || proof.Device != uint64(stat.Dev) || proof.Inode != stat.Ino {
		home.Close()
		return nil, errAdminHome
	}
	return home, nil
}

// Keep the installer response independent from operational account metadata.
func AccountAdminInstallJSON() (json.RawMessage, error) {
	file, digest, e := InstallAccountAdmin()
	if e != nil {
		return nil, e
	}
	return json.Marshal(map[string]string{"format": AccountAdminFormat, "path": file, "sha256": digest})
}
