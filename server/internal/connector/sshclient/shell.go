package sshclient

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	xssh "golang.org/x/crypto/ssh"
)

// Shell is an interactive SSH PTY. Credentials are used only during the
// server-side handshake and are never retained on the Shell value.
type Shell struct {
	client      *xssh.Client
	session     *xssh.Session
	input       io.WriteCloser
	output      *io.PipeReader
	outputWrite *io.PipeWriter
	closeOnce   sync.Once
	mu          sync.Mutex
	waitErr     error
	done        chan struct{}
}

// OpenShell connects to a pinned SSH host and starts an xterm-compatible PTY.
func OpenShell(ctx context.Context, target Target, credentials Credentials, timeout time.Duration, cols, rows int) (*Shell, error) {
	return OpenShellCommand(ctx, target, credentials, timeout, cols, rows, "")
}

// OpenShellCommand is reserved for a server-authored, pinned startup helper.
// User terminal input remains on the PTY and never becomes the startup command.
func OpenShellCommand(ctx context.Context, target Target, credentials Credentials, timeout time.Duration, cols, rows int, startup string) (*Shell, error) {
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	setupCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	if cols < 2 || cols > 500 || rows < 2 || rows > 500 {
		return nil, fmt.Errorf("terminal dimensions must be between 2 and 500")
	}

	client, _, err := dial(setupCtx, target, credentials, timeout)
	if err != nil {
		return nil, err
	}
	stopClose := context.AfterFunc(setupCtx, func() { _ = client.Close() })
	failed := func(err error) (*Shell, error) {
		stopClose()
		_ = client.Close()
		return nil, err
	}

	session, err := client.NewSession()
	if err != nil {
		return failed(fmt.Errorf("open SSH terminal session: %w", err))
	}
	input, err := session.StdinPipe()
	if err != nil {
		_ = session.Close()
		return failed(fmt.Errorf("open SSH terminal input: %w", err))
	}
	outputRead, outputWrite := io.Pipe()
	session.Stdout = outputWrite
	session.Stderr = outputWrite
	modes := xssh.TerminalModes{
		xssh.ECHO:          1,
		xssh.TTY_OP_ISPEED: 14400,
		xssh.TTY_OP_OSPEED: 14400,
	}
	if err := session.RequestPty("xterm-256color", rows, cols, modes); err != nil {
		_ = input.Close()
		_ = outputRead.Close()
		_ = outputWrite.Close()
		_ = session.Close()
		return failed(fmt.Errorf("request SSH PTY: %w", err))
	}
	start := session.Shell
	if startup != "" {
		start = func() error { return session.Start(startup) }
	}
	if err := start(); err != nil {
		_ = input.Close()
		_ = outputRead.Close()
		_ = outputWrite.Close()
		_ = session.Close()
		return failed(fmt.Errorf("start SSH shell: %w", err))
	}
	if !stopClose() {
		_ = input.Close()
		_ = outputRead.Close()
		_ = outputWrite.Close()
		_ = session.Close()
		_ = client.Close()
		return nil, setupCtx.Err()
	}

	shell := &Shell{
		client:      client,
		session:     session,
		input:       input,
		output:      outputRead,
		outputWrite: outputWrite,
		done:        make(chan struct{}),
	}
	go func() {
		err := session.Wait()
		shell.mu.Lock()
		shell.waitErr = err
		shell.mu.Unlock()
		_ = outputWrite.CloseWithError(err)
		close(shell.done)
	}()
	return shell, nil
}

func (s *Shell) Read(p []byte) (int, error) {
	return s.output.Read(p)
}

func (s *Shell) Write(p []byte) (int, error) {
	return s.input.Write(p)
}

// Resize updates the remote PTY window dimensions.
func (s *Shell) Resize(cols, rows int) error {
	if cols < 2 || cols > 500 || rows < 2 || rows > 500 {
		return fmt.Errorf("terminal dimensions must be between 2 and 500")
	}
	return s.session.WindowChange(rows, cols)
}

// Wait returns when the remote shell exits.
func (s *Shell) Wait() error {
	<-s.done
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.waitErr
}

func (s *Shell) Close() error {
	var closeErr error
	s.closeOnce.Do(func() {
		_ = s.input.Close()
		if err := s.session.Close(); err != nil && !errors.Is(err, io.EOF) {
			closeErr = err
		}
		if err := s.client.Close(); closeErr == nil && err != nil {
			closeErr = err
		}
		_ = s.output.Close()
		_ = s.outputWrite.Close()
	})
	return closeErr
}
