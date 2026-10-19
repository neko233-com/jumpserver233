//go:build linux && amd64

package hostagent

import "golang.org/x/sys/unix"

func workspaceLegacyDenied() []uint32 {
	return []uint32{unix.SYS_CHMOD, unix.SYS_CHOWN, unix.SYS_LCHOWN, unix.SYS_UTIME, unix.SYS_UTIMES, unix.SYS_FUTIMESAT, unix.SYS_SEMOP}
}
