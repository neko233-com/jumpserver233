//go:build linux

package hostagent

import (
	"encoding/json"
	"errors"
	"io"
	"os"
	"path"
	"strings"
	"sync"

	"github.com/pkg/sftp"
	"golang.org/x/sys/unix"
)

type workspaceFS struct{ root *os.Root }

const workspaceSeals = unix.F_SEAL_WRITE | unix.F_SEAL_GROW | unix.F_SEAL_SHRINK | unix.F_SEAL_SEAL

type workspaceHandoff struct {
	Format string `json:"format"`
	PID    int    `json:"pid"`
	Device uint64 `json:"device"`
	Inode  uint64 `json:"inode"`
}
type workspaceStdio struct{}

func (workspaceStdio) Read(p []byte) (int, error)  { return os.Stdin.Read(p) }
func (workspaceStdio) Write(p []byte) (int, error) { return os.Stdout.Write(p) }
func (workspaceStdio) Close() error                { return errors.Join(os.Stdin.Close(), os.Stdout.Close()) }

// ServeWorkspaceSFTP runs only after self-exec. Thus all Go runtime threads
// inherit the caller's Landlock/seccomp domain, rather than just one thread.
func ServeWorkspaceSFTP() error {
	// Only a sealed, bounded descriptor from the first stage survives exec.
	// This is a lifecycle handoff, not a remote authentication credential.
	sealed, e := unix.FcntlInt(3, unix.F_GET_SEALS, 0)
	if e != nil || sealed&workspaceSeals != workspaceSeals {
		return ErrWorkspaceUnavailable
	}
	handoff := os.NewFile(3, "workspace-handoff")
	if handoff == nil {
		return ErrWorkspaceUnavailable
	}
	raw, e := io.ReadAll(io.LimitReader(handoff, 513))
	_ = handoff.Close()
	var state workspaceHandoff
	var cwd unix.Stat_t
	if e != nil || len(raw) > 512 || json.Unmarshal(raw, &state) != nil || state.Format != "jms233-workspace-sftp-v1" || state.PID != os.Getpid() || unix.Stat(".", &cwd) != nil || state.Device != uint64(cwd.Dev) || state.Inode != cwd.Ino {
		return ErrWorkspaceUnavailable
	}
	nnp, e := unix.PrctlRetInt(unix.PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0)
	if e != nil || nnp != 1 {
		return ErrWorkspaceUnavailable
	}
	mode, e := unix.PrctlRetInt(unix.PR_GET_SECCOMP, 0, 0, 0, 0)
	if e != nil || mode != unix.SECCOMP_MODE_FILTER {
		return ErrWorkspaceUnavailable
	}
	var caps [2]unix.CapUserData
	if unix.Capget(&unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}, &caps[0]) != nil || caps[0] != (unix.CapUserData{}) || caps[1] != (unix.CapUserData{}) {
		return ErrWorkspaceUnavailable
	}
	root, e := os.OpenRoot(".")
	if e != nil {
		return e
	}
	defer root.Close()
	fs := &workspaceFS{root: root}
	server := sftp.NewRequestServer(workspaceStdio{}, sftp.Handlers{FileGet: fs, FilePut: fs, FileCmd: fs, FileList: fs}, sftp.WithStartDirectory("/"))
	defer server.Close()
	e = server.Serve()
	if errors.Is(e, io.EOF) {
		return nil
	}
	return e
}

func workspaceFileName(name string) (string, error) {
	if len(name) > 4096 || strings.ContainsAny(name, "\x00\\") {
		return "", os.ErrInvalid
	}
	for _, part := range strings.Split(name, "/") {
		if part == ".." {
			return "", os.ErrPermission
		}
	}
	name = strings.TrimPrefix(path.Clean("/"+name), "/")
	if name == "" {
		name = "."
	}
	return name, nil
}

func (fs *workspaceFS) RealPath(name string) (string, error) {
	name, e := workspaceFileName(name)
	if e != nil {
		return "", e
	}
	if name == "." {
		return "/", nil
	}
	return "/" + name, nil
}
func (*workspaceFS) Readlink(string) (string, error)     { return "", os.ErrPermission }
func (*workspaceFS) LookupUserName(value string) string  { return value }
func (*workspaceFS) LookupGroupName(value string) string { return value }

type workspaceFile struct {
	*os.File
	appendMode bool
}

func (f *workspaceFile) WriteAt(p []byte, off int64) (int, error) {
	if f.appendMode {
		return f.File.Write(p)
	}
	return f.File.WriteAt(p, off)
}

func (fs *workspaceFS) openFile(r *sftp.Request, write bool) (*workspaceFile, error) {
	name, e := workspaceFileName(r.Filepath)
	if e != nil {
		return nil, e
	}
	flags := r.Pflags()
	if r.Flags & ^uint32(0x3f) != 0 || !write && (flags.Write || flags.Append || flags.Creat || flags.Trunc || flags.Excl) || write && !flags.Write {
		return nil, os.ErrInvalid
	}
	mode := os.O_RDONLY
	if write {
		mode = os.O_WRONLY
		if flags.Read {
			mode = os.O_RDWR
		}
	}
	if flags.Creat {
		mode |= os.O_CREATE
	}
	if flags.Trunc {
		mode |= os.O_TRUNC
	}
	if flags.Excl {
		mode |= os.O_EXCL
	}
	if flags.Append {
		mode |= os.O_APPEND
	}
	f, e := fs.root.OpenFile(name, mode|unix.O_NONBLOCK, 0600)
	if e != nil {
		return nil, e
	}
	st, e := f.Stat()
	if e != nil || !st.Mode().IsRegular() {
		f.Close()
		return nil, os.ErrPermission
	}
	return &workspaceFile{File: f, appendMode: flags.Append}, nil
}
func (fs *workspaceFS) Fileread(r *sftp.Request) (io.ReaderAt, error)  { return fs.openFile(r, false) }
func (fs *workspaceFS) Filewrite(r *sftp.Request) (io.WriterAt, error) { return fs.openFile(r, true) }
func (fs *workspaceFS) OpenFile(r *sftp.Request) (sftp.WriterAtReaderAt, error) {
	return fs.openFile(r, true)
}

type workspaceInfo []os.FileInfo

func (rows workspaceInfo) ListAt(out []os.FileInfo, off int64) (int, error) {
	if off < 0 {
		return 0, os.ErrInvalid
	}
	if off >= int64(len(rows)) {
		return 0, io.EOF
	}
	n := copy(out, rows[off:])
	if n < len(out) {
		return n, io.EOF
	}
	return n, nil
}

type workspaceDirectory struct {
	file   *os.File
	mu     sync.Mutex
	offset int64
}

func (d *workspaceDirectory) Close() error { return d.file.Close() }
func (d *workspaceDirectory) ListAt(out []os.FileInfo, off int64) (int, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if off < 0 || off != d.offset {
		return 0, os.ErrInvalid
	}
	if len(out) == 0 {
		return 0, nil
	}
	rows, e := d.file.Readdir(len(out))
	n := copy(out, rows)
	d.offset += int64(n)
	return n, e
}
func (fs *workspaceFS) Filelist(r *sftp.Request) (sftp.ListerAt, error) {
	name, e := workspaceFileName(r.Filepath)
	if e != nil {
		return nil, e
	}
	switch r.Method {
	case "List":
		f, e := fs.root.OpenFile(name, os.O_RDONLY|unix.O_DIRECTORY|unix.O_NONBLOCK, 0)
		if e != nil {
			return nil, e
		}
		st, e := f.Stat()
		if e != nil || !st.IsDir() {
			f.Close()
			return nil, unix.ENOTDIR
		}
		return &workspaceDirectory{file: f}, nil
	case "Stat":
		st, e := fs.root.Stat(name)
		if e != nil {
			return nil, e
		}
		return workspaceInfo{st}, nil
	default:
		return nil, sftp.ErrSSHFxOpUnsupported
	}
}
func (fs *workspaceFS) Lstat(r *sftp.Request) (sftp.ListerAt, error) {
	name, e := workspaceFileName(r.Filepath)
	if e != nil {
		return nil, e
	}
	st, e := fs.root.Lstat(name)
	if e != nil {
		return nil, e
	}
	return workspaceInfo{st}, nil
}

func (fs *workspaceFS) parent(name string) (*os.File, string, error) {
	if name == "." {
		return nil, "", os.ErrPermission
	}
	f, e := fs.root.OpenFile(path.Dir(name), os.O_RDONLY|unix.O_DIRECTORY|unix.O_NONBLOCK, 0)
	if e != nil {
		return nil, "", e
	}
	st, e := f.Stat()
	if e != nil || !st.IsDir() {
		f.Close()
		return nil, "", unix.ENOTDIR
	}
	return f, path.Base(name), nil
}
func (fs *workspaceFS) rename(r *sftp.Request, overwrite bool) error {
	oldName, e := workspaceFileName(r.Filepath)
	if e != nil {
		return e
	}
	newName, e := workspaceFileName(r.Target)
	if e != nil {
		return e
	}
	oldDir, oldBase, e := fs.parent(oldName)
	if e != nil {
		return e
	}
	defer oldDir.Close()
	newDir, newBase, e := fs.parent(newName)
	if e != nil {
		return e
	}
	defer newDir.Close()
	flags := uint(0)
	if !overwrite {
		flags = unix.RENAME_NOREPLACE
	}
	return unix.Renameat2(int(oldDir.Fd()), oldBase, int(newDir.Fd()), newBase, flags)
}
func (fs *workspaceFS) PosixRename(r *sftp.Request) error { return fs.rename(r, true) }
func (fs *workspaceFS) Filecmd(r *sftp.Request) error {
	name, e := workspaceFileName(r.Filepath)
	if e != nil {
		return e
	}
	switch r.Method {
	case "Mkdir":
		return fs.root.Mkdir(name, 0700)
	case "Rename":
		return fs.rename(r, false)
	case "Remove", "Rmdir":
		dir, base, e := fs.parent(name)
		if e != nil {
			return e
		}
		defer dir.Close()
		flags := 0
		if r.Method == "Rmdir" {
			flags = unix.AT_REMOVEDIR
		}
		return unix.Unlinkat(int(dir.Fd()), base, flags)
	case "Setstat", "Link", "Symlink":
		return os.ErrPermission
	default:
		return sftp.ErrSSHFxOpUnsupported
	}
}
