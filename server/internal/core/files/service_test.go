package files

import (
	"bytes"
	"context"
	"io"
	"os"
	"path"
	"strings"
	"testing"
	"time"

	"github.com/neko233-com/jumpserver233/server/internal/connector/sshclient"
	"github.com/pkg/sftp"
)

func TestResolveKeepsPathsInsideSFTPHome(t *testing.T) {
	for _, raw := range []string{"../etc/passwd", "a/../file.txt", "a/../../etc/passwd", "/etc/passwd", `folder\file`, "file\x00name"} {
		if _, _, err := resolve("/home/operator", raw); err == nil {
			t.Errorf("resolve(%q) unexpectedly succeeded", raw)
		}
	}
	got, parent, err := resolve("/home/operator", "reports/result.txt")
	if err != nil {
		t.Fatal(err)
	}
	if got != "/home/operator/reports/result.txt" || parent != "reports" {
		t.Fatalf("resolve() = (%q, %q), want home-rooted path and relative parent", got, parent)
	}
	root, _, err := resolve("/home/operator", "")
	if err != nil || root != "/home/operator" {
		t.Fatalf("resolve root = %q, %v", root, err)
	}
}

func TestWorkspaceVirtualSFTPRootKeepsRelativeFilesAndRejectsTraversal(t *testing.T) {
	full, parent, e := resolve("/", "folder/file.txt")
	if e != nil || full != "/folder/file.txt" || parent != "folder" {
		t.Fatalf("virtual root mapping: %q %q %v", full, parent, e)
	}
	for _, name := range []string{"../private", "folder/../private", "/etc/passwd", `a\b`} {
		if _, _, e := resolve("/", name); e == nil {
			t.Fatalf("accepted %q", name)
		}
	}
}

func TestUploadDownloadAndTransferAudit(t *testing.T) {
	remote := newMemoryRemote()
	remote.dirs["/home/operator/reports"] = true
	audit, err := OpenAuditStore(t.TempDir() + "/file-transfers/index.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	service := NewService(func(context.Context, string) (Remote, error) { return remote, nil }, audit)

	content := []byte("release report\n")
	bytesWritten, err := service.Upload(context.Background(), "alice", "asset-1", "reports/result.txt", bytes.NewReader(content), false)
	if err != nil || bytesWritten != int64(len(content)) {
		t.Fatalf("Upload() = %d, %v", bytesWritten, err)
	}
	if _, err := service.Upload(context.Background(), "alice", "asset-1", "reports/result.txt", bytes.NewReader(content), false); err != ErrConflict {
		t.Fatalf("second Upload() error = %v, want ErrConflict", err)
	}
	download, err := service.OpenDownload(context.Background(), "alice", "asset-1", "reports/result.txt")
	if err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(download.Reader)
	if err != nil {
		t.Fatal(err)
	}
	download.Finish(int64(len(got)), nil)
	if !bytes.Equal(got, content) {
		t.Fatalf("download = %q, want %q", got, content)
	}
	entries, total, err := service.ListAudit("alice", 0, 10)
	if err != nil || total != 3 || len(entries) != 3 {
		t.Fatalf("ListAudit() = %d entries, total %d, err %v", len(entries), total, err)
	}
	if entries[0].Action != "download" || !entries[0].Success || entries[1].ErrorCode != "already_exists" || entries[1].Success || entries[2].Action != "upload" {
		t.Fatalf("unexpected audit entries: %+v", entries)
	}
	auditContent, err := os.ReadFile(audit.path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(auditContent), string(content)) {
		t.Fatal("audit index contains transferred file content")
	}
}

func TestFileManagerDoesNotFollowSymlinks(t *testing.T) {
	remote := newMemoryRemote()
	remote.symlinks["/home/operator/outside"] = true
	service := NewService(func(context.Context, string) (Remote, error) { return remote, nil }, nil)
	if _, err := service.List(context.Background(), "asset-1", "outside"); err != ErrUnsafePath {
		t.Fatalf("List(symlink) error = %v, want ErrUnsafePath", err)
	}
	if _, err := service.Upload(context.Background(), "alice", "asset-1", "outside/secret.txt", strings.NewReader("secret"), false); err != ErrUnsafePath {
		t.Fatalf("Upload(through symlink) error = %v, want ErrUnsafePath", err)
	}
	if err := service.Delete(context.Background(), "alice", "asset-1", "outside"); err != nil {
		t.Fatalf("Delete(symlink itself) error = %v", err)
	}
}

type memoryRemote struct {
	dirs     map[string]bool
	files    map[string][]byte
	symlinks map[string]bool
}

func newMemoryRemote() *memoryRemote {
	return &memoryRemote{
		dirs:     map[string]bool{"/home/operator": true},
		files:    make(map[string][]byte),
		symlinks: make(map[string]bool),
	}
}

func (r *memoryRemote) Root() string { return "/home/operator" }
func (r *memoryRemote) Close() error { return nil }

func (r *memoryRemote) ReadDir(_ context.Context, name string) ([]sshclient.FileInfo, error) {
	if !r.dirs[name] {
		return nil, sftp.ErrSSHFxNoSuchFile
	}
	prefix := strings.TrimSuffix(name, "/") + "/"
	entries := make(map[string]sshclient.FileInfo)
	add := func(full string, info sshclient.FileInfo) {
		if !strings.HasPrefix(full, prefix) {
			return
		}
		rest := strings.TrimPrefix(full, prefix)
		if rest == "" {
			return
		}
		first, _, nested := strings.Cut(rest, "/")
		if nested {
			info = sshclient.FileInfo{Name: first, IsDir: true, ModTime: time.Now().UTC()}
		} else {
			info.Name = first
		}
		entries[first] = info
	}
	for full := range r.dirs {
		add(full, sshclient.FileInfo{IsDir: true})
	}
	for full, data := range r.files {
		add(full, sshclient.FileInfo{Size: int64(len(data)), ModTime: time.Now().UTC()})
	}
	for full := range r.symlinks {
		add(full, sshclient.FileInfo{IsSymlink: true, ModTime: time.Now().UTC()})
	}
	result := make([]sshclient.FileInfo, 0, len(entries))
	for _, info := range entries {
		result = append(result, info)
	}
	return result, nil
}

func (r *memoryRemote) Lstat(_ context.Context, name string) (sshclient.FileInfo, error) {
	if r.symlinks[name] {
		return sshclient.FileInfo{Name: path.Base(name), IsSymlink: true}, nil
	}
	if r.dirs[name] {
		return sshclient.FileInfo{Name: path.Base(name), IsDir: true}, nil
	}
	if content, ok := r.files[name]; ok {
		return sshclient.FileInfo{Name: path.Base(name), Size: int64(len(content)), IsRegular: true}, nil
	}
	return sshclient.FileInfo{}, sftp.ErrSSHFxNoSuchFile
}

func (r *memoryRemote) Mkdir(_ context.Context, name string) error {
	if _, err := r.Lstat(context.Background(), name); err == nil {
		return sftp.ErrSSHFxFailure
	}
	if !r.dirs[path.Dir(name)] {
		return sftp.ErrSSHFxNoSuchFile
	}
	r.dirs[name] = true
	return nil
}

func (r *memoryRemote) Remove(_ context.Context, name string) error {
	if r.symlinks[name] {
		delete(r.symlinks, name)
		return nil
	}
	if _, ok := r.files[name]; !ok {
		return sftp.ErrSSHFxNoSuchFile
	}
	delete(r.files, name)
	return nil
}

func (r *memoryRemote) RemoveDirectory(_ context.Context, name string) error {
	prefix := strings.TrimSuffix(name, "/") + "/"
	for full := range r.dirs {
		if strings.HasPrefix(full, prefix) {
			return sftp.ErrSSHFxFailure
		}
	}
	for full := range r.files {
		if strings.HasPrefix(full, prefix) {
			return sftp.ErrSSHFxFailure
		}
	}
	delete(r.dirs, name)
	return nil
}

func (r *memoryRemote) OpenRead(_ context.Context, name string) (io.ReadCloser, error) {
	data, ok := r.files[name]
	if !ok {
		return nil, sftp.ErrSSHFxNoSuchFile
	}
	return io.NopCloser(bytes.NewReader(data)), nil
}

func (r *memoryRemote) CreateExclusive(_ context.Context, name string) (io.WriteCloser, error) {
	if _, err := r.Lstat(context.Background(), name); err == nil {
		return nil, sftp.ErrSSHFxFailure
	}
	return &memoryWriteCloser{commit: func(data []byte) { r.files[name] = append([]byte(nil), data...) }}, nil
}

func (r *memoryRemote) Rename(_ context.Context, oldName, newName string, overwrite bool) error {
	if _, exists := r.files[newName]; exists && !overwrite {
		return sftp.ErrSSHFxFailure
	}
	data, exists := r.files[oldName]
	if !exists {
		return sftp.ErrSSHFxNoSuchFile
	}
	r.files[newName] = data
	delete(r.files, oldName)
	return nil
}

type memoryWriteCloser struct {
	bytes.Buffer
	commit func([]byte)
}

func (w *memoryWriteCloser) Close() error {
	w.commit(w.Bytes())
	return nil
}
