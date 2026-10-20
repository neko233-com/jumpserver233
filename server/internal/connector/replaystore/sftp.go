package replaystore

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path"
	"strings"
	"time"

	"github.com/neko233-com/jumpserver233/server/internal/connector/sshclient"
)

type SFTP struct {
	remote    *sshclient.SFTP
	directory string
}

func NewSFTP(remote *sshclient.SFTP, directory string) (*SFTP, error) {
	if remote == nil || !ValidKey(directory) {
		return nil, ErrInvalid
	}
	return &SFTP{remote: remote, directory: directory}, nil
}
func (s *SFTP) target(ctx context.Context, key string, create bool) (string, error) {
	if !ValidKey(key) {
		return "", ErrInvalid
	}
	parts := strings.Split(s.directory+"/"+key, "/")
	current := s.remote.Root()
	for _, part := range parts[:len(parts)-1] {
		current = path.Join(current, part)
		info, e := s.remote.Lstat(ctx, current)
		if errors.Is(e, os.ErrNotExist) && create {
			if e = s.remote.Mkdir(ctx, current); e != nil {
				info, e = s.remote.Lstat(ctx, current)
			} else {
				info, e = s.remote.Lstat(ctx, current)
			}
		}
		if errors.Is(e, os.ErrNotExist) {
			return "", ErrNotFound
		}
		if e != nil || !info.IsDir || info.IsSymlink {
			return "", ErrUnavailable
		}
	}
	return path.Join(current, parts[len(parts)-1]), nil
}
func (s *SFTP) Get(ctx context.Context, key string) (io.ReadCloser, error) {
	p, e := s.target(ctx, key, false)
	if e != nil {
		return nil, e
	}
	info, e := s.remote.Lstat(ctx, p)
	if errors.Is(e, os.ErrNotExist) {
		return nil, ErrNotFound
	}
	if e != nil || !info.IsRegular || info.IsSymlink {
		return nil, ErrUnavailable
	}
	r, e := s.remote.OpenRead(ctx, p)
	if e != nil {
		return nil, ErrUnavailable
	}
	return r, nil
}
func (s *SFTP) Put(ctx context.Context, key string, body io.Reader, size int64, digest string) error {
	if size < 1 || size > MaxObjectBytes || !ValidDigest(digest) || body == nil {
		return ErrInvalid
	}
	p, e := s.target(ctx, key, true)
	if e != nil {
		return e
	}
	if info, e := s.remote.Lstat(ctx, p); e == nil {
		if info.IsRegular && !info.IsSymlink {
			return ErrExists
		}
		return ErrUnavailable
	} else if !errors.Is(e, os.ErrNotExist) {
		return ErrUnavailable
	}
	raw := make([]byte, 16)
	if _, e = rand.Read(raw); e != nil {
		return e
	}
	tmp := path.Join(path.Dir(p), ".jms-replay-"+hex.EncodeToString(raw))
	w, e := s.remote.CreateExclusive(ctx, tmp)
	if e != nil {
		return ErrUnavailable
	}
	committed := false
	defer func() {
		if committed {
			return
		}
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Second)
		defer cancel()
		_ = s.remote.Remove(cleanup, tmp)
	}()
	h := sha256.New()
	n, e := io.Copy(io.MultiWriter(w, h), io.LimitReader(body, size+1))
	ce := w.Close()
	if e != nil || ce != nil {
		return ErrUnavailable
	}
	if n != size || hex.EncodeToString(h.Sum(nil)) != digest {
		return ErrIntegrity
	}
	if e = s.remote.Rename(ctx, tmp, p, false); e != nil {
		if info, se := s.remote.Lstat(ctx, p); se == nil && info.IsRegular && !info.IsSymlink {
			return ErrExists
		}
		return ErrUnavailable
	}
	committed = true
	return nil
}
func (s *SFTP) Close() error { return s.remote.Close() }
