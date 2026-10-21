package files

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path"
	"strings"
	"sync"
	"time"

	"github.com/neko233-com/jumpserver233/server/internal/connector/sshclient"
	"github.com/pkg/sftp"
)

var (
	ErrInvalidPath = errors.New("invalid remote path")
	ErrUnsafePath  = errors.New("remote path traverses a symbolic link")
	ErrConflict    = errors.New("remote file already exists")
	ErrNotFile     = errors.New("remote path is not a regular file")
	ErrTooLarge    = errors.New("file exceeds transfer size limit")
)

const MaxTransferSize int64 = 1 << 30

type Remote interface {
	Root() string
	ReadDir(context.Context, string) ([]sshclient.FileInfo, error)
	Lstat(context.Context, string) (sshclient.FileInfo, error)
	Mkdir(context.Context, string) error
	Remove(context.Context, string) error
	RemoveDirectory(context.Context, string) error
	OpenRead(context.Context, string) (io.ReadCloser, error)
	CreateExclusive(context.Context, string) (io.WriteCloser, error)
	Rename(context.Context, string, string, bool) error
	Close() error
}

type Opener func(context.Context, string) (Remote, error)

type Service struct {
	open  Opener
	audit *AuditStore
}

func NewService(open Opener, audit *AuditStore) *Service {
	return &Service{open: open, audit: audit}
}

func (s *Service) List(ctx context.Context, assetID, relativePath string) ([]sshclient.FileInfo, error) {
	remote, err := s.open(ctx, assetID)
	if err != nil {
		return nil, err
	}
	defer remote.Close()
	resolved, _, err := resolve(remote.Root(), relativePath)
	if err != nil {
		return nil, err
	}
	if err := s.checkNoSymlink(ctx, remote, remote.Root(), relativePath, true); err != nil {
		return nil, err
	}
	return remote.ReadDir(ctx, resolved)
}

func (s *Service) MakeDirectory(ctx context.Context, actor, assetID, relativePath string) error {
	remote, err := s.open(ctx, assetID)
	if err != nil {
		s.record(actor, assetID, "mkdir", relativePath, 0, err)
		return err
	}
	defer remote.Close()
	resolved, parent, err := resolve(remote.Root(), relativePath)
	if err == nil {
		err = s.checkNoSymlink(ctx, remote, remote.Root(), parent, true)
	}
	if err == nil {
		_, statErr := remote.Lstat(ctx, resolved)
		if statErr == nil {
			err = ErrConflict
		} else if !isNotExist(statErr) {
			err = statErr
		}
	}
	if err == nil {
		err = remote.Mkdir(ctx, resolved)
	}
	s.record(actor, assetID, "mkdir", relativePath, 0, err)
	return err
}

func (s *Service) Delete(ctx context.Context, actor, assetID, relativePath string) error {
	remote, err := s.open(ctx, assetID)
	if err != nil {
		s.record(actor, assetID, "delete", relativePath, 0, err)
		return err
	}
	defer remote.Close()
	resolved, parent, err := resolve(remote.Root(), relativePath)
	if err == nil && resolved == path.Clean(remote.Root()) {
		err = ErrInvalidPath
	}
	if err == nil {
		err = s.checkNoSymlink(ctx, remote, remote.Root(), parent, true)
	}
	if err == nil {
		var info sshclient.FileInfo
		info, err = remote.Lstat(ctx, resolved)
		if err == nil {
			if info.IsDir && !info.IsSymlink {
				err = remote.RemoveDirectory(ctx, resolved)
			} else {
				err = remote.Remove(ctx, resolved)
			}
		}
	}
	s.record(actor, assetID, "delete", relativePath, 0, err)
	return err
}

func (s *Service) Upload(ctx context.Context, actor, assetID, relativePath string, source io.Reader, overwrite bool) (int64, error) {
	remote, err := s.open(ctx, assetID)
	if err != nil {
		s.record(actor, assetID, "upload", relativePath, 0, err)
		return 0, err
	}
	defer remote.Close()
	resolved, parent, err := resolve(remote.Root(), relativePath)
	if err == nil && resolved == path.Clean(remote.Root()) {
		err = ErrInvalidPath
	}
	if err == nil {
		err = s.checkNoSymlink(ctx, remote, remote.Root(), parent, true)
	}
	var prior sshclient.FileInfo
	if err == nil {
		prior, err = remote.Lstat(ctx, resolved)
		if err != nil && !isNotExist(err) {
			// The target can be absent; all other errors are meaningful.
		} else if err != nil {
			err = nil
		} else if err == nil {
			if prior.IsSymlink {
				err = ErrUnsafePath
			} else if !prior.IsRegular {
				err = ErrNotFile
			} else if !overwrite {
				err = ErrConflict
			}
		}
	}
	tempPath := ""
	var uploaded int64
	if err == nil {
		var token [12]byte
		if _, randomErr := rand.Read(token[:]); randomErr != nil {
			err = fmt.Errorf("generate temporary upload name: %w", randomErr)
		} else {
			tempPath = path.Join(parentPath(resolved), ".jms233-"+hex.EncodeToString(token[:])+".upload")
		}
	}
	if err == nil {
		var destination io.WriteCloser
		destination, err = remote.CreateExclusive(ctx, tempPath)
		if err == nil {
			uploaded, err = io.Copy(destination, io.LimitReader(source, MaxTransferSize+1))
			closeErr := destination.Close()
			if err == nil {
				err = closeErr
			}
			if uploaded > MaxTransferSize {
				err = ErrTooLarge
			}
		}
	}
	if err == nil {
		err = remote.Rename(ctx, tempPath, resolved, overwrite)
	}
	if err != nil && tempPath != "" {
		_ = remote.Remove(ctx, tempPath)
	}
	s.record(actor, assetID, "upload", relativePath, uploaded, err)
	return uploaded, err
}

// Rename stays on one pinned account and checks both parent paths. Cross-asset
// moves, symlink traversal and replacement of directories are never implicit.
func (s *Service) Rename(ctx context.Context, actor, assetID, source, destination string, overwrite bool) error {
	remote, err := s.open(ctx, assetID)
	if err != nil {
		s.record(actor, assetID, "rename", source+" -> "+destination, 0, err)
		return err
	}
	defer remote.Close()
	from, parent, err := resolve(remote.Root(), source)
	if err == nil {
		err = s.checkNoSymlink(ctx, remote, remote.Root(), parent, true)
	}
	var target, targetParent string
	if err == nil {
		target, targetParent, err = resolve(remote.Root(), destination)
	}
	if err == nil && (from == path.Clean(remote.Root()) || target == path.Clean(remote.Root())) {
		err = ErrInvalidPath
	}
	if err == nil {
		err = s.checkNoSymlink(ctx, remote, remote.Root(), targetParent, true)
	}
	if err == nil {
		var st sshclient.FileInfo
		st, err = remote.Lstat(ctx, from)
		if err == nil && st.IsSymlink {
			err = ErrUnsafePath
		}
		if err == nil {
			prior, e := remote.Lstat(ctx, target)
			if e == nil {
				if !overwrite {
					err = ErrConflict
				} else if !st.IsRegular || !prior.IsRegular || prior.IsSymlink {
					err = ErrNotFile
				}
			} else if !isNotExist(e) {
				err = e
			}
		}
	}
	if err == nil {
		err = remote.Rename(ctx, from, target, overwrite)
	}
	s.record(actor, assetID, "rename", source+" -> "+destination, 0, err)
	return err
}

type Download struct {
	Info         sshclient.FileInfo
	Reader       io.ReadCloser
	remote       Remote
	service      *Service
	actor        string
	assetID      string
	relativePath string
	once         sync.Once
}

func (s *Service) OpenDownload(ctx context.Context, actor, assetID, relativePath string) (*Download, error) {
	remote, err := s.open(ctx, assetID)
	if err != nil {
		s.record(actor, assetID, "download", relativePath, 0, err)
		return nil, err
	}
	resolved, _, err := resolve(remote.Root(), relativePath)
	if err == nil && resolved == path.Clean(remote.Root()) {
		err = ErrInvalidPath
	}
	if err == nil {
		err = s.checkNoSymlink(ctx, remote, remote.Root(), relativePath, true)
	}
	var info sshclient.FileInfo
	if err == nil {
		info, err = remote.Lstat(ctx, resolved)
	}
	if err == nil && !info.IsRegular {
		err = ErrNotFile
	}
	if err == nil && info.Size > MaxTransferSize {
		err = ErrTooLarge
	}
	var reader io.ReadCloser
	if err == nil {
		reader, err = remote.OpenRead(ctx, resolved)
	}
	if err != nil {
		_ = remote.Close()
		s.record(actor, assetID, "download", relativePath, 0, err)
		return nil, err
	}
	return &Download{Info: info, Reader: reader, remote: remote, service: s, actor: actor, assetID: assetID, relativePath: relativePath}, nil
}

func (d *Download) Finish(bytes int64, transferErr error) {
	d.once.Do(func() {
		if closeErr := d.Reader.Close(); transferErr == nil {
			transferErr = closeErr
		}
		if closeErr := d.remote.Close(); transferErr == nil {
			transferErr = closeErr
		}
		d.service.record(d.actor, d.assetID, "download", d.relativePath, bytes, transferErr)
	})
}

func (s *Service) checkNoSymlink(ctx context.Context, remote Remote, root, relativePath string, includeFinal bool) error {
	resolved, _, err := resolve(root, relativePath)
	if err != nil {
		return err
	}
	root = path.Clean(root)
	if resolved == root {
		return nil
	}
	parts := strings.Split(strings.TrimPrefix(resolved, strings.TrimSuffix(root, "/")+"/"), "/")
	current := root
	for i, part := range parts {
		current = path.Join(current, part)
		if !includeFinal && i == len(parts)-1 {
			break
		}
		info, statErr := remote.Lstat(ctx, current)
		if statErr != nil {
			if isNotExist(statErr) {
				return nil
			}
			return statErr
		}
		if info.IsSymlink {
			return ErrUnsafePath
		}
		if i != len(parts)-1 && !info.IsDir {
			return ErrInvalidPath
		}
	}
	return nil
}

func resolve(root, relativePath string) (string, string, error) {
	root = path.Clean(root)
	if !path.IsAbs(root) || strings.ContainsRune(root, '\x00') || strings.Contains(relativePath, "\\") || strings.ContainsRune(relativePath, '\x00') || strings.HasPrefix(relativePath, "/") {
		return "", "", ErrInvalidPath
	}
	for _, segment := range strings.Split(relativePath, "/") {
		if segment == ".." {
			return "", "", ErrInvalidPath
		}
	}
	clean := path.Clean(relativePath)
	if clean == "." {
		clean = ""
	}
	if clean == ".." || strings.HasPrefix(clean, "../") {
		return "", "", ErrInvalidPath
	}
	resolved := root
	if clean != "" {
		resolved = path.Join(root, clean)
	}
	if resolved != root && !strings.HasPrefix(resolved, strings.TrimSuffix(root, "/")+"/") {
		return "", "", ErrInvalidPath
	}
	parent := path.Dir(clean)
	if clean == "" || parent == "." {
		parent = ""
	}
	return resolved, parent, nil
}

func parentPath(fullPath string) string { return path.Dir(fullPath) }

func isNotExist(err error) bool {
	return errors.Is(err, os.ErrNotExist) || errors.Is(err, sftp.ErrSSHFxNoSuchFile)
}

func IsNotExist(err error) bool { return isNotExist(err) }

func (s *Service) ListAudit(actor string, offset, limit int) ([]Transfer, int, error) {
	if s.audit == nil {
		return []Transfer{}, 0, nil
	}
	return s.audit.List(actor, offset, limit)
}

func (s *Service) record(actor, assetID, action, relativePath string, bytes int64, err error) {
	if s.audit == nil {
		return
	}
	entry := Transfer{Actor: actor, AssetID: assetID, Action: action, Path: relativePath, Bytes: bytes, At: time.Now().UTC()}
	if err != nil {
		entry.Success = false
		entry.ErrorCode = classifyError(err)
	} else {
		entry.Success = true
	}
	if err := s.audit.Append(entry); err != nil {
		slog.Error("file transfer audit append failed", "asset_id", assetID, "action", action, "err", err)
	}
}

// RecordAbortedUpload retains an authenticated staging attempt that never
// reached Upload, including disconnects and revoked grants.
func (s *Service) RecordAbortedUpload(actor, assetID, relativePath string, bytes int64) {
	s.record(actor, assetID, "upload", relativePath, bytes, context.Canceled)
}

func classifyError(err error) string {
	switch {
	case errors.Is(err, ErrInvalidPath):
		return "invalid_path"
	case errors.Is(err, ErrUnsafePath):
		return "unsafe_path"
	case errors.Is(err, ErrConflict):
		return "already_exists"
	case errors.Is(err, ErrNotFile):
		return "not_a_file"
	case errors.Is(err, ErrTooLarge):
		return "file_too_large"
	default:
		return "transfer_failed"
	}
}
