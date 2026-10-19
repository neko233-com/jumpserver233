//go:build linux

package hostagent

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"unsafe"

	"golang.org/x/sys/unix"
)

const workspaceRead = unix.LANDLOCK_ACCESS_FS_EXECUTE | unix.LANDLOCK_ACCESS_FS_READ_FILE | unix.LANDLOCK_ACCESS_FS_READ_DIR
const workspaceWrite = unix.LANDLOCK_ACCESS_FS_WRITE_FILE | unix.LANDLOCK_ACCESS_FS_REMOVE_DIR | unix.LANDLOCK_ACCESS_FS_REMOVE_FILE | unix.LANDLOCK_ACCESS_FS_MAKE_DIR | unix.LANDLOCK_ACCESS_FS_MAKE_REG | unix.LANDLOCK_ACCESS_FS_MAKE_SYM | unix.LANDLOCK_ACCESS_FS_REFER | unix.LANDLOCK_ACCESS_FS_TRUNCATE

// Handle special-file creation as well, but never grant it.
const workspaceHandled = workspaceRead | workspaceWrite | unix.LANDLOCK_ACCESS_FS_MAKE_CHAR | unix.LANDLOCK_ACCESS_FS_MAKE_BLOCK | unix.LANDLOCK_ACCESS_FS_MAKE_FIFO | unix.LANDLOCK_ACCESS_FS_MAKE_SOCK

func workspaceABI() (int, error) {
	n, _, e := unix.Syscall(unix.SYS_LANDLOCK_CREATE_RULESET, 0, 0, unix.LANDLOCK_CREATE_RULESET_VERSION)
	if e != 0 || n < 3 {
		return 0, ErrWorkspaceUnavailable
	}
	return int(n), nil
}

// Open the entire absolute path without symlinks or magic links.
// The held descriptor pins the object used for both cwd and the Landlock grant.
func openWorkspace(directory string) (int, error) {
	if ValidateWorkspace(directory) != nil {
		return -1, ErrWorkspaceInvalid
	}
	fd, e := unix.Openat2(unix.AT_FDCWD, directory, &unix.OpenHow{Flags: unix.O_PATH | unix.O_DIRECTORY | unix.O_CLOEXEC, Resolve: unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS})
	if e != nil {
		return -1, ErrWorkspaceInvalid
	}
	return fd, nil
}

func CheckWorkspace(directory string) (WorkspaceStatus, error) {
	fd, e := openWorkspace(directory)
	if e != nil {
		return WorkspaceStatus{}, e
	}
	defer unix.Close(fd)
	abi, e := workspaceABI()
	if e != nil {
		return WorkspaceStatus{}, e
	}
	identity, e := workspaceIdentity(fd)
	if e != nil {
		return WorkspaceStatus{}, e
	}
	return WorkspaceStatus{Format: "jms233-workspace-v1", Directory: directory, LandlockABI: abi, Identity: identity}, nil
}

// Read identity from the held descriptor, never from PWD or terminal text.
// Birth time avoids accepting a recycled inode; boot ID invalidates a proof
// after host restart. Filesystems without these fields fail closed.
func workspaceIdentity(fd int) (string, error) {
	var st unix.Statx_t
	const fields = unix.STATX_INO | unix.STATX_BTIME | unix.STATX_TYPE
	if unix.Statx(fd, "", unix.AT_EMPTY_PATH|unix.AT_STATX_SYNC_AS_STAT, fields, &st) != nil || st.Mask&fields != fields || st.Mode&unix.S_IFMT != unix.S_IFDIR {
		return "", ErrWorkspaceUnavailable
	}
	boot, e := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if e != nil || len(strings.TrimSpace(string(boot))) != 36 {
		return "", ErrWorkspaceUnavailable
	}
	raw, _ := json.Marshal(struct {
		Boot         string
		Major, Minor uint32
		Inode        uint64
		Birth        unix.StatxTimestamp
	}{strings.TrimSpace(string(boot)), st.Dev_major, st.Dev_minor, st.Ino, st.Btime})
	digest := sha256.Sum256(raw)
	return hex.EncodeToString(digest[:]), nil
}

func addWorkspaceRule(ruleset, fd int, rights uint64) error {
	// The Linux UAPI structure is packed: an eight-byte mask followed by int32.
	attr := struct {
		Access uint64
		Parent int32
	}{rights, int32(fd)}
	_, _, e := unix.Syscall6(unix.SYS_LANDLOCK_ADD_RULE, uintptr(ruleset), unix.LANDLOCK_RULE_PATH_BENEATH, uintptr(unsafe.Pointer(&attr)), 0, 0, 0)
	if e != 0 {
		return e
	}
	return nil
}

// ExecWorkspace replaces this helper process. It must only be called by the
// dedicated CLI process, never by the application server or a reusable worker.
// Any setup failure is fatal to that CLI process; no unrestricted fallback exists.
func ExecWorkspace(directory, command string, interactive bool, expected ...string) error {
	if len(command) > 8192 || !interactive && command == "" {
		return ErrWorkspaceInvalid
	}
	args := []string{"sh", "-c", command}
	if interactive {
		args = []string{"sh", "-i"}
	}
	return execWorkspace(directory, "/bin/sh", args, false, expected...)
}

func ExecWorkspaceSFTP(directory string, expected ...string) error {
	self, e := os.Executable()
	if e != nil {
		return ErrWorkspaceUnavailable
	}
	return execWorkspace(directory, self, []string{"jms-agent", "workspace-sftp-internal"}, true, expected...)
}

func execWorkspace(directory, executable string, args []string, nativeSFTP bool, expected ...string) error {
	if len(expected) > 1 || len(expected) == 1 && expected[0] != "" && !ValidWorkspaceIdentity(expected[0]) {
		return ErrWorkspaceInvalid
	}
	self, e := os.Executable()
	if e != nil || ValidateWorkspaceControl(directory, self) != nil {
		return ErrWorkspaceInvalid
	}
	if _, e := workspaceABI(); e != nil {
		return e
	}
	root, e := openWorkspace(directory)
	if e != nil {
		return e
	}
	defer unix.Close(root)
	if len(expected) == 1 && expected[0] != "" {
		identity, err := workspaceIdentity(root)
		if err != nil || identity != expected[0] {
			return ErrWorkspaceInvalid
		}
	}
	handoff := -1
	if nativeSFTP {
		var st unix.Stat_t
		if unix.Fstat(root, &st) != nil {
			return ErrWorkspaceInvalid
		}
		raw, _ := json.Marshal(workspaceHandoff{Format: "jms233-workspace-sftp-v1", PID: os.Getpid(), Device: uint64(st.Dev), Inode: st.Ino})
		handoff, e = unix.MemfdCreate("jms233-workspace", unix.MFD_CLOEXEC|unix.MFD_ALLOW_SEALING)
		if e != nil {
			return ErrWorkspaceUnavailable
		}
		if handoff == 3 {
			moved, moveErr := unix.FcntlInt(uintptr(handoff), unix.F_DUPFD_CLOEXEC, 4)
			_ = unix.Close(handoff)
			if moveErr != nil {
				return ErrWorkspaceUnavailable
			}
			handoff = moved
		}
		defer unix.Close(handoff)
		if _, e = unix.Write(handoff, raw); e != nil {
			return ErrWorkspaceUnavailable
		}
		if _, e = unix.Seek(handoff, 0, 0); e != nil {
			return ErrWorkspaceUnavailable
		}
		if _, e = unix.FcntlInt(uintptr(handoff), unix.F_ADD_SEALS, workspaceSeals); e != nil {
			return ErrWorkspaceUnavailable
		}
	}
	attr := struct{ Access uint64 }{workspaceHandled}
	value, _, errno := unix.Syscall(unix.SYS_LANDLOCK_CREATE_RULESET, uintptr(unsafe.Pointer(&attr)), unsafe.Sizeof(attr), 0)
	if errno != 0 {
		return ErrWorkspaceUnavailable
	}
	ruleset := int(value)
	defer unix.Close(ruleset)
	if e = addWorkspaceRule(ruleset, root, workspaceRead|workspaceWrite); e != nil {
		return ErrWorkspaceUnavailable
	}
	// System executables/libraries are read-only. No /etc tree, home, /proc or
	// inherited environment is exposed. Resolve only these fixed OS aliases.
	runtimePaths := []string{"/usr/bin", "/usr/sbin", "/usr/lib", "/usr/lib64", "/bin", "/sbin", "/lib", "/lib64", "/etc/ld.so.cache", "/etc/localtime", "/dev/null", "/dev/tty"}
	if nativeSFTP {
		runtimePaths = []string{self}
	} // Static Go service needs no OS runtime tree.
	for _, name := range runtimePaths {
		resolved, err := filepath.EvalSymlinks(name)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return ErrWorkspaceUnavailable
		}
		fd, err := unix.Open(resolved, unix.O_PATH|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		if err != nil {
			return ErrWorkspaceUnavailable
		}
		var st unix.Stat_t
		err = unix.Fstat(fd, &st)
		rights := uint64(workspaceRead)
		if st.Mode&unix.S_IFMT != unix.S_IFDIR {
			rights = unix.LANDLOCK_ACCESS_FS_READ_FILE | unix.LANDLOCK_ACCESS_FS_EXECUTE
		}
		if name == "/dev/null" || name == "/dev/tty" {
			rights = unix.LANDLOCK_ACCESS_FS_READ_FILE | unix.LANDLOCK_ACCESS_FS_WRITE_FILE
		}
		if err == nil {
			err = addWorkspaceRule(ruleset, fd, rights)
		}
		unix.Close(fd)
		if err != nil {
			return ErrWorkspaceUnavailable
		}
	}
	environment := []string{"PATH=/usr/bin:/bin", "LANG=C", "LC_ALL=C", "HOME=" + directory, "PWD=" + directory, "TMPDIR=" + directory, "TERM=xterm-256color", "ENV=/dev/null", "BASH_ENV=/dev/null"}
	runtime.LockOSThread() // Landlock and seccomp apply to this thread and its descendants.
	if e = unix.Fchdir(root); e != nil {
		return ErrWorkspaceInvalid
	}
	if os.Geteuid() == 0 {
		// Prevent uid 0 from regaining implicit capabilities across exec.
		if e = unix.Prctl(unix.PR_SET_SECUREBITS, 3, 0, 0, 0); e != nil {
			return ErrWorkspaceUnavailable
		}
	}
	if e = unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); e != nil {
		return ErrWorkspaceUnavailable
	}
	var capabilities [2]unix.CapUserData
	if e = unix.Capset(&unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}, &capabilities[0]); e != nil {
		return ErrWorkspaceUnavailable
	}
	_, _, errno = unix.Syscall(unix.SYS_LANDLOCK_RESTRICT_SELF, uintptr(ruleset), 0, 0)
	if errno != 0 {
		return ErrWorkspaceUnavailable
	}
	if e = workspaceSeccomp(); e != nil {
		return ErrWorkspaceUnavailable
	}
	// No inherited control socket, open outside file or directory descriptor can
	// be reused to bypass path checks. stdin/stdout/stderr retain the SSH stream.
	firstClose := uint(3)
	if nativeSFTP {
		// Detach the descriptor table before replacing fd 3. Other Go runtime
		// threads may still own that number until exec terminates them.
		if e = unix.CloseRange(3, 3, unix.CLOSE_RANGE_UNSHARE); e != nil {
			return ErrWorkspaceUnavailable
		}
		if e = unix.Dup3(handoff, 3, 0); e != nil {
			return ErrWorkspaceUnavailable
		}
		firstClose = 4
	}
	if e = unix.CloseRange(firstClose, ^uint(0), unix.CLOSE_RANGE_UNSHARE); e != nil {
		return ErrWorkspaceUnavailable
	}
	return unix.Exec(executable, args, environment)
}
