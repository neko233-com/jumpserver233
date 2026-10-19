//go:build linux && (amd64 || arm64)

// Test-only syscall probe. The production packager never includes testsupport.
package main

import (
	"fmt"
	"golang.org/x/sys/unix"
	"os"
)

func main() {
	for _, domain := range []int{unix.AF_INET, unix.AF_UNIX} {
		if fd, e := unix.Socket(domain, unix.SOCK_STREAM, 0); e != unix.EPERM {
			if fd >= 0 {
				unix.Close(fd)
			}
			os.Exit(91)
		}
	}
	for _, nr := range []uintptr{unix.SYS_UNSHARE, unix.SYS_PTRACE, unix.SYS_IO_URING_SETUP, unix.SYS_PIDFD_OPEN, unix.SYS_BPF} {
		if _, _, e := unix.Syscall(nr, 0, 0, 0); e != unix.EPERM {
			os.Exit(92)
		}
	}
	var capabilities [2]unix.CapUserData
	if _, _, e := unix.Syscall(unix.SYS_TGKILL, uintptr(os.Getpid()+1), 0, 0); e != unix.EPERM {
		os.Exit(95)
	}
	if unix.Capget(&unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}, &capabilities[0]) != nil || capabilities[0] != (unix.CapUserData{}) || capabilities[1] != (unix.CapUserData{}) {
		os.Exit(93)
	}
	var st unix.Stat_t
	if e := unix.Fstat(3, &st); e == nil && st.Mode&unix.S_IFMT == unix.S_IFREG {
		os.Exit(94)
	}
	fmt.Print("workspace-syscalls-denied")
}
