//go:build linux

package hostagent

import (
	"os"
	"syscall"
)

func stateLock(path string) (func(), error) {
	fd, e := syscall.Open(path, syscall.O_CREAT|syscall.O_RDWR|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0600)
	if e != nil {
		return nil, ErrBusy
	}
	f := os.NewFile(uintptr(fd), path)
	s, e := f.Stat()
	if e != nil || !s.Mode().IsRegular() || s.Mode().Perm()&0022 != 0 || !owned(s) {
		f.Close()
		return nil, ErrBusy
	}
	if e = syscall.Flock(fd, syscall.LOCK_EX|syscall.LOCK_NB); e != nil {
		f.Close()
		return nil, ErrBusy
	}
	return func() { _ = syscall.Flock(fd, syscall.LOCK_UN); _ = f.Close() }, nil
}
