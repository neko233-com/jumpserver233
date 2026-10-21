package nativeaccess

import (
	"errors"
	"os"
	"path/filepath"
	"strings"

	"github.com/neko233-com/jumpserver233/server/internal/maintenance"
)

// Upload staging stays outside application backups. The OS lease protects live
// instances. Only exact, marked, unlocked directories for this Vault identity
// are eligible for stale cleanup; another project's temporary files are left.
func openSpool(identity string) (string, *maintenance.Lock, error) {
	base, e := filepath.EvalSymlinks(os.TempDir())
	if e != nil {
		return "", nil, e
	}
	base, e = filepath.Abs(base)
	if e != nil {
		return "", nil, e
	}
	prefix := "jumpserver233-native-sftp-" + identity + "-"
	marker := "jumpserver233-native-sftp-v1\n" + identity + "\n"
	entries, e := os.ReadDir(base)
	if e != nil {
		return "", nil, e
	}
	for _, entry := range entries {
		if !entry.IsDir() || entry.Type()&os.ModeSymlink != 0 || !strings.HasPrefix(entry.Name(), prefix) {
			continue
		}
		directory := filepath.Join(base, entry.Name())
		if filepath.Dir(directory) != base {
			continue
		}
		root, e := os.OpenRoot(directory)
		if e != nil {
			continue
		}
		info, e := root.Lstat("owner")
		if e != nil || !info.Mode().IsRegular() || info.Size() != int64(len(marker)) {
			root.Close()
			continue
		}
		raw, e := root.ReadFile("owner")
		root.Close()
		if e != nil || string(raw) != marker {
			continue
		}
		lease, e := maintenance.Acquire(directory)
		if e != nil {
			continue
		}
		_ = lease.Close()
		if e = os.RemoveAll(directory); e != nil {
			return "", nil, e
		}
	}
	directory, e := os.MkdirTemp(base, prefix)
	if e != nil {
		return "", nil, e
	}
	lease, e := maintenance.Acquire(directory)
	if e != nil {
		_ = os.RemoveAll(directory)
		return "", nil, e
	}
	if e = os.WriteFile(filepath.Join(directory, "owner"), []byte(marker), 0600); e != nil {
		_ = lease.Close()
		_ = os.RemoveAll(directory)
		return "", nil, e
	}
	return directory, lease, nil
}
func removeSpool(directory string, lease *maintenance.Lock) error {
	if lease == nil || directory == "" {
		return nil
	}
	if filepath.Dir(directory) == directory || !strings.HasPrefix(filepath.Base(directory), "jumpserver233-native-sftp-") {
		return errors.New("invalid owned spool directory")
	}
	if e := lease.Close(); e != nil {
		return e
	}
	return os.RemoveAll(directory)
}
