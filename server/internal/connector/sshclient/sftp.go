package sshclient

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"strings"
	"sync"
	"time"

	"github.com/pkg/sftp"
	xssh "golang.org/x/crypto/ssh"
)

// SFTP is a server-side file channel over a host-key-pinned SSH connection.
// It never exposes or retains the credential used by the SSH handshake.
type SFTP struct {
	sshClient   *xssh.Client
	session     *xssh.Session
	sessionDone chan struct{}
	client      *sftp.Client
	root        string
	closeOnce   sync.Once
	closeError  error
}

// FileInfo contains only metadata safe to return from the file manager API.
type FileInfo struct {
	Name      string    `json:"name"`
	Size      int64     `json:"size"`
	Mode      string    `json:"mode"`
	ModTime   time.Time `json:"mod_time"`
	IsDir     bool      `json:"is_dir"`
	IsRegular bool      `json:"is_regular"`
	IsSymlink bool      `json:"is_symlink"`
}

// OpenSFTP opens an SFTP subsystem using the asset's pinned host key. The
// returned root is the SFTP server's canonical starting directory (usually
// the managed account's home directory).
func OpenSFTP(ctx context.Context, target Target, credentials Credentials, timeout time.Duration) (*SFTP, error) {
	return openSFTP(ctx, target, credentials, timeout, "")
}

// OpenSFTPCommand starts a server-authored helper on a pinned SSH exec channel.
// It never falls back to the host's ordinary SFTP subsystem.
func OpenSFTPCommand(ctx context.Context, target Target, credentials Credentials, timeout time.Duration, startup string) (*SFTP, error) {
	if strings.TrimSpace(startup) == "" || len(startup) > 16384 {
		return nil, errors.New("invalid SFTP startup helper")
	}
	return openSFTP(ctx, target, credentials, timeout, startup)
}

func openSFTP(ctx context.Context, target Target, credentials Credentials, timeout time.Duration, startup string) (*SFTP, error) {
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	setupCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	sshClient, _, err := dial(setupCtx, target, credentials, timeout)
	if err != nil {
		return nil, err
	}
	stopClose := context.AfterFunc(setupCtx, func() { _ = sshClient.Close() })
	var session *xssh.Session
	var sessionDone chan struct{}
	var client *sftp.Client
	fail := func(cause error) (*SFTP, error) {
		stopClose()
		_ = sshClient.Close()
		if session != nil {
			_ = session.Close()
		}
		if client != nil {
			_ = client.Close()
		}
		if sessionDone != nil {
			<-sessionDone
		}
		return nil, cause
	}
	if startup == "" {
		client, err = sftp.NewClient(sshClient)
	} else {
		session, err = sshClient.NewSession()
		if err == nil {
			var input io.WriteCloser
			var output io.Reader
			input, err = session.StdinPipe()
			if err == nil {
				output, err = session.StdoutPipe()
			}
			session.Stderr = io.Discard
			if err == nil {
				err = session.Start(startup)
			}
			if err == nil {
				sessionDone = make(chan struct{})
				go func() { defer close(sessionDone); _ = session.Wait(); _ = sshClient.Close() }()
				client, err = sftp.NewClientPipe(output, input)
			}
		}
	}
	if err != nil {
		return fail(fmt.Errorf("open SSH SFTP subsystem: %w", err))
	}
	root, err := client.Getwd()
	if err == nil {
		root, err = client.RealPath(root)
	}
	if err != nil {
		return fail(fmt.Errorf("resolve SFTP home directory: %w", err))
	}
	if !path.IsAbs(root) || strings.ContainsRune(root, '\x00') {
		return fail(fmt.Errorf("SFTP server returned an invalid home directory"))
	}
	if !stopClose() {
		return fail(setupCtx.Err())
	}
	return &SFTP{sshClient: sshClient, session: session, sessionDone: sessionDone, client: client, root: path.Clean(root)}, nil
}

func (s *SFTP) Root() string { return s.root }

func (s *SFTP) ReadDir(ctx context.Context, remotePath string) ([]FileInfo, error) {
	stop := context.AfterFunc(ctx, func() { _ = s.Close() })
	defer stop()
	items, err := s.client.ReadDirContext(ctx, remotePath)
	if err != nil {
		return nil, err
	}
	result := make([]FileInfo, 0, len(items))
	for _, item := range items {
		result = append(result, fileInfo(item))
	}
	return result, nil
}

func (s *SFTP) Lstat(ctx context.Context, remotePath string) (FileInfo, error) {
	stop := context.AfterFunc(ctx, func() { _ = s.Close() })
	defer stop()
	item, err := s.client.Lstat(remotePath)
	if err != nil {
		return FileInfo{}, err
	}
	return fileInfo(item), nil
}

func (s *SFTP) Mkdir(ctx context.Context, remotePath string) error {
	stop := context.AfterFunc(ctx, func() { _ = s.Close() })
	defer stop()
	return s.client.Mkdir(remotePath)
}

func (s *SFTP) Remove(ctx context.Context, remotePath string) error {
	stop := context.AfterFunc(ctx, func() { _ = s.Close() })
	defer stop()
	return s.client.Remove(remotePath)
}

func (s *SFTP) RemoveDirectory(ctx context.Context, remotePath string) error {
	stop := context.AfterFunc(ctx, func() { _ = s.Close() })
	defer stop()
	return s.client.RemoveDirectory(remotePath)
}

func (s *SFTP) OpenRead(ctx context.Context, remotePath string) (io.ReadCloser, error) {
	stop := context.AfterFunc(ctx, func() { _ = s.Close() })
	file, err := s.client.Open(remotePath)
	if err != nil {
		stop()
		return nil, err
	}
	return &sftpReadCloser{File: file, stop: stop}, nil
}

func (s *SFTP) CreateExclusive(ctx context.Context, remotePath string) (io.WriteCloser, error) {
	stop := context.AfterFunc(ctx, func() { _ = s.Close() })
	file, err := s.client.OpenFile(remotePath, os.O_WRONLY|os.O_CREATE|os.O_EXCL)
	if err != nil {
		stop()
		return nil, err
	}
	return &sftpWriteCloser{File: file, stop: stop}, nil
}

func (s *SFTP) Rename(ctx context.Context, oldPath, newPath string, overwrite bool) error {
	stop := context.AfterFunc(ctx, func() { _ = s.Close() })
	defer stop()
	if overwrite {
		if _, supported := s.client.HasExtension("posix-rename@openssh.com"); supported {
			return s.client.PosixRename(oldPath, newPath)
		}
	}
	return s.client.Rename(oldPath, newPath)
}

func (s *SFTP) Close() error {
	s.closeOnce.Do(func() {
		// Closing SSH first releases outstanding requests even if the remote
		// server ignores EOF. The optional exec waiter must finish as well.
		transportErr := s.sshClient.Close()
		if s.session != nil {
			_ = s.session.Close()
		}
		s.closeError = errors.Join(s.client.Close(), transportErr)
		if s.sessionDone != nil {
			<-s.sessionDone
		}
	})
	return s.closeError
}

type sftpReadCloser struct {
	*sftp.File
	stop func() bool
}

func (f *sftpReadCloser) Close() error {
	f.stop()
	return f.File.Close()
}

type sftpWriteCloser struct {
	*sftp.File
	stop func() bool
}

func (f *sftpWriteCloser) Close() error {
	f.stop()
	return f.File.Close()
}

func fileInfo(info os.FileInfo) FileInfo {
	return FileInfo{
		Name:      info.Name(),
		Size:      info.Size(),
		Mode:      info.Mode().String(),
		ModTime:   info.ModTime().UTC(),
		IsDir:     info.IsDir(),
		IsRegular: info.Mode().IsRegular(),
		IsSymlink: info.Mode()&os.ModeSymlink != 0,
	}
}
