//go:build unix

package maintenance

import (
	"golang.org/x/sys/unix"
	"os"
)

func lockFile(f *os.File) error { return unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB) }
func unlockFile(f *os.File)     { _ = unix.Flock(int(f.Fd()), unix.LOCK_UN) }
func syncDirectory(path string) error {
	f, e := os.Open(path)
	if e != nil {
		return e
	}
	defer f.Close()
	return f.Sync()
}
