package nativeaccess

import (
	"context"
	"errors"
	"io"
	"net/url"
	"os"
	"path"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/neko233-com/jumpserver233/server/internal/connector/sshclient"
	"github.com/neko233-com/jumpserver233/server/internal/core/files"
	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

type nativeFS struct {
	ctx            context.Context
	client         *apiClient
	server         *Server
	mu             sync.Mutex
	sessions       map[string]string
	targetID, root string
}

func (s *Server) serveSFTP(ctx context.Context, c *apiClient, ch ssh.Channel) error {
	fs := &nativeFS{ctx: ctx, client: c, server: s, sessions: map[string]string{}}
	defer fs.close()
	if id, release, e := c.holdTarget(ctx); e == nil {
		defer release()
		fs.targetID = id
		var rootErr error
		e = fs.access("GET", "/api/v1/assets/"+url.PathEscape(id)+"/files", id, func(ctx context.Context, service *files.Service, _ string) { fs.root, rootErr = service.Root(ctx, id) })
		if e != nil {
			return e
		}
		if rootErr != nil {
			return rootErr
		}
	}
	r := sftp.NewRequestServer(ch, sftp.Handlers{FileGet: fs, FilePut: fs, FileList: fs, FileCmd: fs}, sftp.WithStartDirectory("/"))
	defer r.Close()
	e := r.Serve()
	if errors.Is(e, io.EOF) {
		return nil
	}
	return e
}

func (fs *nativeFS) resolve(value string) (string, string, error) {
	id, relative, e := virtualPath(value)
	if e != nil || fs.targetID == "" {
		return id, relative, e
	}
	// Keep the stable /account-id path usable for existing CLI clients.
	if id == fs.targetID {
		return id, relative, nil
	}
	clean := path.Clean("/" + value)
	if fs.root != "" && (clean == fs.root || strings.HasPrefix(clean, strings.TrimRight(fs.root, "/")+"/")) {
		clean = strings.TrimPrefix(clean, fs.root)
	}
	return fs.targetID, strings.TrimPrefix(clean, "/"), nil
}
func (fs *nativeFS) close() {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	for id, token := range fs.sessions {
		if token == "" {
			continue
		}
		r, e := fs.client.request(context.Background(), "DELETE", "/api/v1/assets/"+url.PathEscape(id)+"/files/session", nil, token)
		if e == nil {
			r.Body.Close()
		}
	}
}
func virtualPath(value string) (string, string, error) {
	if len(value) > 4096 || strings.ContainsAny(value, "\\\x00") {
		return "", "", os.ErrPermission
	}
	for _, p := range strings.Split(value, "/") {
		if p == ".." {
			return "", "", os.ErrPermission
		}
	}
	clean := strings.TrimPrefix(path.Clean("/"+value), "/")
	if clean == "" || clean == "." {
		return "", "", nil
	}
	id, relative, _ := strings.Cut(clean, "/")
	if at := strings.LastIndex(id, "@"); at >= 0 {
		id = id[at+1:]
	}
	if id == "" || len(id) > 128 || strings.ContainsAny(id, "%?#:") {
		return "", "", os.ErrPermission
	}
	return id, relative, nil
}
func directoryName(a assetChoice) string {
	slug := func(value string) string {
		value = strings.Map(func(r rune) rune {
			if unicode.IsLetter(r) || unicode.IsDigit(r) || r == '-' || r == '_' {
				return r
			}
			return '-'
		}, value)
		r := []rune(value)
		if len(r) > 32 {
			r = r[:32]
		}
		return strings.Trim(string(r), "-")
	}
	return slug(a.Title) + "--" + slug(a.Account) + "@" + a.ID
}
func (fs *nativeFS) session(id string) (string, error) {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	if value, ok := fs.sessions[id]; ok {
		return value, nil
	}
	var result struct {
		Token string `json:"session_token"`
	}
	if e := fs.client.json(fs.ctx, "POST", "/api/v1/assets/"+url.PathEscape(id)+"/files/session", nil, &result); e != nil {
		return "", sftp.ErrSSHFxPermissionDenied
	}
	fs.sessions[id] = result.Token
	return result.Token, nil
}
func (fs *nativeFS) access(method, endpoint, id string, operation func(context.Context, *files.Service, string)) error {
	token, e := fs.session(id)
	if e != nil {
		return e
	}
	if e = fs.client.fileOperation(fs.ctx, method, endpoint, token, operation); e != nil {
		return sftp.ErrSSHFxPermissionDenied
	}
	return nil
}
func fileEndpoint(id, relative string) string {
	return "/api/v1/assets/" + url.PathEscape(id) + "/files/content?path=" + url.QueryEscape(relative)
}
func (fs *nativeFS) Fileread(r *sftp.Request) (io.ReaderAt, error) {
	id, relative, e := fs.resolve(r.Filepath)
	if e != nil || id == "" || relative == "" {
		return nil, os.ErrPermission
	}
	var download *files.Download
	var binding string
	e = fs.access("GET", fileEndpoint(id, relative), id, func(ctx context.Context, service *files.Service, b string) {
		binding = b
		download, e = service.OpenDownload(ctx, fs.client.username(), id, relative)
	})
	if e != nil {
		return nil, e
	}
	if download == nil {
		return nil, sftp.ErrSSHFxFailure
	}
	reader, ok := download.Reader.(io.ReaderAt)
	if !ok {
		download.Finish(0, os.ErrInvalid)
		return nil, sftp.ErrSSHFxOpUnsupported
	}
	return &nativeDownload{fs: fs, reader: reader, download: download, id: id, relative: relative, binding: binding}, nil
}

type nativeDownload struct {
	mu                    sync.Mutex
	fs                    *nativeFS
	reader                io.ReaderAt
	download              *files.Download
	id, relative, binding string
	bytes                 int64
	failure               error
	closed                bool
}

func (d *nativeDownload) ReadAt(p []byte, offset int64) (int, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed {
		return 0, os.ErrClosed
	}
	if offset < 0 {
		return 0, os.ErrInvalid
	}
	var allowed bool
	e := d.fs.access("GET", fileEndpoint(d.id, d.relative), d.id, func(_ context.Context, _ *files.Service, b string) { allowed = b == d.binding })
	if e != nil || !allowed {
		d.failure = os.ErrPermission
		return 0, os.ErrPermission
	}
	n, e := d.reader.ReadAt(p, offset)
	d.bytes += int64(n)
	if e != nil && !errors.Is(e, io.EOF) {
		d.failure = e
	}
	return n, e
}
func (d *nativeDownload) TransferError(e error) { d.mu.Lock(); defer d.mu.Unlock(); d.failure = e }
func (d *nativeDownload) Close() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if !d.closed {
		d.closed = true
		d.download.Finish(d.bytes, d.failure)
	}
	return nil
}

func (fs *nativeFS) Filewrite(r *sftp.Request) (io.WriterAt, error) {
	id, relative, e := fs.resolve(r.Filepath)
	if e != nil || id == "" || relative == "" {
		return nil, os.ErrPermission
	}
	flags := r.Pflags()
	// Partial overwrite and append cannot preserve atomicity. Standard put/scp
	// create+truncate and create+exclusive uploads are supported.
	if !flags.Write || flags.Append || !flags.Creat || !flags.Trunc && !flags.Excl || r.Flags & ^uint32(0x3f) != 0 {
		return nil, sftp.ErrSSHFxOpUnsupported
	}
	var binding string
	var audit *files.Service
	if e = fs.access("PUT", fileEndpoint(id, relative), id, func(_ context.Context, service *files.Service, b string) { binding = b; audit = service }); e != nil {
		return nil, e
	}
	select {
	case fs.server.spoolSlots <- struct{}{}:
	default:
		return nil, sftp.ErrSSHFxFailure
	}
	f, e := os.CreateTemp(fs.server.temp, "upload-")
	if e != nil {
		<-fs.server.spoolSlots
		return nil, sftp.ErrSSHFxFailure
	}
	return &nativeUpload{fs: fs, file: f, id: id, relative: relative, binding: binding, overwrite: !flags.Excl, audit: audit}, nil
}

type nativeUpload struct {
	mu                    sync.Mutex
	fs                    *nativeFS
	file                  *os.File
	id, relative, binding string
	overwrite             bool
	failure               error
	closed                bool
	size                  int64
	ranges                []byteRange
	audit                 *files.Service
}
type byteRange struct{ start, end int64 }

func (fs *nativeFS) OpenFile(r *sftp.Request) (sftp.WriterAtReaderAt, error) {
	writer, e := fs.Filewrite(r)
	if e != nil {
		return nil, e
	}
	return writer.(*nativeUpload), nil
}
func (u *nativeUpload) ReadAt(p []byte, offset int64) (int, error) {
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.closed {
		return 0, os.ErrClosed
	}
	allowed := false
	e := u.fs.access("GET", fileEndpoint(u.id, u.relative), u.id, func(_ context.Context, _ *files.Service, b string) { allowed = b == u.binding })
	if e != nil || !allowed {
		return 0, os.ErrPermission
	}
	return u.file.ReadAt(p, offset)
}
func (u *nativeUpload) WriteAt(p []byte, offset int64) (int, error) {
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.closed {
		return 0, os.ErrClosed
	}
	if offset < 0 || offset > files.MaxTransferSize-int64(len(p)) {
		u.failure = os.ErrPermission
		return 0, os.ErrPermission
	}
	if u.failure != nil {
		return 0, sftp.ErrSSHFxFailure
	}
	// Per-packet authorization also catches a grant/account/route change while
	// a client is still staging a file; commit rechecks the same binding.
	allowed := false
	e := u.fs.access("PUT", fileEndpoint(u.id, u.relative), u.id, func(_ context.Context, _ *files.Service, b string) { allowed = b == u.binding })
	if e != nil || !allowed {
		u.failure = os.ErrPermission
		return 0, os.ErrPermission
	}
	n, e := u.file.WriteAt(p, offset)
	if e != nil {
		u.failure = e
	}
	if n > 0 {
		u.addRange(offset, offset+int64(n))
		if offset+int64(n) > u.size {
			u.size = offset + int64(n)
		}
	}
	return n, e
}
func (u *nativeUpload) addRange(start, end int64) {
	out := make([]byteRange, 0, len(u.ranges)+1)
	inserted := false
	for _, r := range u.ranges {
		if r.end < start {
			out = append(out, r)
		} else if end < r.start {
			if !inserted {
				out = append(out, byteRange{start, end})
				inserted = true
			}
			out = append(out, r)
		} else {
			if r.start < start {
				start = r.start
			}
			if r.end > end {
				end = r.end
			}
		}
	}
	if !inserted {
		out = append(out, byteRange{start, end})
	}
	u.ranges = out
	if len(out) > 4096 {
		u.failure = os.ErrPermission
	}
}
func (u *nativeUpload) TransferError(e error) { u.mu.Lock(); defer u.mu.Unlock(); u.failure = e }
func (u *nativeUpload) Close() (result error) {
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.closed {
		return nil
	}
	u.closed = true
	submitted := false
	defer func() {
		name := u.file.Name()
		_ = u.file.Close()
		_ = os.Remove(name)
		<-u.fs.server.spoolSlots
		if result != nil && !submitted && u.audit != nil {
			u.audit.RecordAbortedUpload(u.fs.client.username(), u.id, u.relative, u.size)
		}
	}()
	if u.failure != nil || u.fs.ctx.Err() != nil {
		return sftp.ErrSSHFxFailure
	}
	if u.size > 0 && (len(u.ranges) != 1 || u.ranges[0].start != 0 || u.ranges[0].end != u.size) {
		return sftp.ErrSSHFxFailure
	}
	if _, e := u.file.Seek(0, io.SeekStart); e != nil {
		return sftp.ErrSSHFxFailure
	}
	var transferErr error
	e := u.fs.access("PUT", fileEndpoint(u.id, u.relative), u.id, func(ctx context.Context, service *files.Service, b string) {
		if b != u.binding {
			transferErr = os.ErrPermission
			return
		}
		submitted = true
		_, transferErr = service.Upload(ctx, u.fs.client.username(), u.id, u.relative, u.file, u.overwrite)
	})
	if e != nil || transferErr != nil {
		return sftp.ErrSSHFxFailure
	}
	return nil
}

type fileInfo struct {
	name string
	size int64
	mode os.FileMode
	at   time.Time
}

func (f fileInfo) Name() string       { return f.name }
func (f fileInfo) Size() int64        { return f.size }
func (f fileInfo) Mode() os.FileMode  { return f.mode }
func (f fileInfo) ModTime() time.Time { return f.at }
func (f fileInfo) IsDir() bool        { return f.mode.IsDir() }
func (f fileInfo) Sys() any           { return nil }

type infoList []os.FileInfo

func (l infoList) ListAt(out []os.FileInfo, offset int64) (int, error) {
	if offset < 0 {
		return 0, os.ErrInvalid
	}
	if offset >= int64(len(l)) {
		return 0, io.EOF
	}
	n := copy(out, l[offset:])
	if n < len(out) {
		return n, io.EOF
	}
	return n, nil
}
func remoteInfo(f sshclient.FileInfo) os.FileInfo {
	mode := os.FileMode(0600)
	if f.IsDir {
		mode = os.ModeDir | 0700
	}
	if f.IsSymlink {
		mode = os.ModeSymlink | 0600
	}
	return fileInfo{f.Name, f.Size, mode, f.ModTime}
}
func (fs *nativeFS) listing(id, relative string) ([]os.FileInfo, error) {
	if id == "" {
		rows, e := fs.client.assets(fs.ctx)
		if e != nil {
			return nil, os.ErrPermission
		}
		out := []os.FileInfo{}
		for _, a := range rows {
			if a.SFTP {
				out = append(out, fileInfo{name: directoryName(a), mode: os.ModeDir | 0700})
			}
		}
		return out, nil
	}
	var rows []sshclient.FileInfo
	var operationErr error
	e := fs.access("GET", "/api/v1/assets/"+url.PathEscape(id)+"/files?path="+url.QueryEscape(relative), id, func(ctx context.Context, service *files.Service, _ string) {
		rows, operationErr = service.List(ctx, id, relative)
	})
	if e != nil {
		return nil, e
	}
	if operationErr != nil {
		return nil, sftp.ErrSSHFxFailure
	}
	out := []os.FileInfo{}
	for _, f := range rows {
		out = append(out, remoteInfo(f))
	}
	return out, nil
}
func (fs *nativeFS) Filelist(r *sftp.Request) (sftp.ListerAt, error) {
	id, relative, e := fs.resolve(r.Filepath)
	if e != nil {
		return nil, e
	}
	if r.Method == "List" {
		rows, e := fs.listing(id, relative)
		return infoList(rows), e
	}
	if r.Method != "Stat" && r.Method != "Lstat" {
		return nil, sftp.ErrSSHFxOpUnsupported
	}
	if id == "" {
		if _, e = fs.client.assets(fs.ctx); e != nil {
			return nil, os.ErrPermission
		}
		return infoList{fileInfo{name: "/", mode: os.ModeDir | 0700}}, nil
	}
	if relative == "" {
		if _, e = fs.listing(id, ""); e != nil {
			return nil, e
		}
		return infoList{fileInfo{name: id, mode: os.ModeDir | 0700}}, nil
	}
	rows, e := fs.listing(id, path.Dir(relative))
	if e != nil {
		return nil, e
	}
	for _, f := range rows {
		if f.Name() == path.Base(relative) {
			return infoList{f}, nil
		}
	}
	return nil, os.ErrNotExist
}
func (fs *nativeFS) Lstat(r *sftp.Request) (sftp.ListerAt, error) { return fs.Filelist(r) }
func (fs *nativeFS) RealPath(value string) (string, error) {
	id, relative, e := fs.resolve(value)
	if e != nil {
		return "", e
	}
	if id != "" {
		if _, e = fs.session(id); e != nil {
			return "", e
		}
	}
	if fs.targetID != "" {
		return path.Join(fs.root, relative), nil
	}
	return path.Join("/", id, relative), nil
}
func (fs *nativeFS) Filecmd(r *sftp.Request) error {
	id, relative, e := fs.resolve(r.Filepath)
	if e != nil || id == "" || relative == "" {
		return os.ErrPermission
	}
	var actionErr error
	switch r.Method {
	case "Rename", "PosixRename":
		targetID, target, e := fs.resolve(r.Target)
		if e != nil || targetID != id || target == "" {
			return os.ErrPermission
		}
		e = fs.access("POST", "/api/v1/assets/"+url.PathEscape(id)+"/files/rename", id, func(ctx context.Context, service *files.Service, _ string) {
			actionErr = service.Rename(ctx, fs.client.username(), id, relative, target, r.Method == "PosixRename")
		})
		if e != nil {
			return e
		}
		if actionErr != nil {
			return sftp.ErrSSHFxFailure
		}
		return nil
	case "Mkdir":
		e = fs.access("POST", "/api/v1/assets/"+url.PathEscape(id)+"/directories", id, func(ctx context.Context, service *files.Service, _ string) {
			actionErr = service.MakeDirectory(ctx, fs.client.username(), id, relative)
		})
	case "Remove", "Rmdir":
		e = fs.access("DELETE", fileEndpoint(id, relative), id, func(ctx context.Context, service *files.Service, _ string) {
			actionErr = service.Delete(ctx, fs.client.username(), id, relative)
		})
	default:
		return sftp.ErrSSHFxOpUnsupported
	}
	if e != nil {
		return e
	}
	if actionErr != nil {
		return sftp.ErrSSHFxFailure
	}
	return nil
}
func (fs *nativeFS) PosixRename(r *sftp.Request) error {
	return fs.Filecmd(&sftp.Request{Method: "PosixRename", Filepath: r.Filepath, Target: r.Target})
}
