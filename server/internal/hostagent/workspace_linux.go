//go:build linux

package hostagent

import (
	"os"
	"path/filepath"
	"runtime"
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
	return WorkspaceStatus{Format: "jms233-workspace-v1", Directory: directory, LandlockABI: abi}, nil
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
func ExecWorkspace(directory, command string, interactive bool) error {
	if len(command) > 8192 || !interactive && command == "" {
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
	for _, name := range []string{"/usr/bin", "/usr/sbin", "/usr/lib", "/usr/lib64", "/bin", "/sbin", "/lib", "/lib64", "/etc/ld.so.cache", "/etc/localtime", "/dev/null", "/dev/tty"} {
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
	args := []string{"sh", "-c", command}
	if interactive {
		args = []string{"sh", "-i"}
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
	if e = unix.CloseRange(3, ^uint(0), unix.CLOSE_RANGE_UNSHARE); e != nil {
		return ErrWorkspaceUnavailable
	}
	return unix.Exec("/bin/sh", args, environment)
}
