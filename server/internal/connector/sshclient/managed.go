package sshclient

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"time"

	"github.com/pkg/sftp"
	xssh "golang.org/x/crypto/ssh"
)

// ManagedHost keeps commands, SFTP and loopback requests on the same pinned
// transport. Cancellation closes that transport, including gateway hops.
type ManagedHost struct {
	client *xssh.Client
	Files  *SFTP
	stop   func() bool
}

func (h *ManagedHost) Root() string { return h.Files.Root() }
func OpenManagedHost(ctx context.Context, target Target, credentials Credentials) (*ManagedHost, error) {
	c, _, e := dial(ctx, target, credentials, 12*time.Second)
	if e != nil {
		return nil, e
	}
	stop := context.AfterFunc(ctx, func() { _ = c.Close() })
	f, e := sftp.NewClient(c)
	if e != nil {
		stop()
		c.Close()
		return nil, e
	}
	root, e := f.Getwd()
	if e == nil {
		root, e = f.RealPath(root)
	}
	if e != nil {
		stop()
		f.Close()
		c.Close()
		return nil, e
	}
	return &ManagedHost{client: c, Files: &SFTP{sshClient: c, client: f, root: root}, stop: stop}, nil
}
func (h *ManagedHost) Close() error { h.stop(); return h.Files.Close() }
func (h *ManagedHost) Run(ctx context.Context, command string) (ExecResult, error) {
	return h.RunInput(ctx, command, nil)
}

// RunInput sends bounded input over the encrypted SSH channel. Input never
// becomes command text, process arguments or captured output.
func (h *ManagedHost) RunInput(ctx context.Context, command string, input []byte) (ExecResult, error) {
	r := ExecResult{ExitCode: -1}
	if len(input) > 16<<10 {
		return r, errors.New("SSH input exceeds operation limit")
	}
	if e := ctx.Err(); e != nil {
		return r, e
	}
	s, e := h.client.NewSession()
	if e != nil {
		return r, e
	}
	defer s.Close()
	stop := context.AfterFunc(ctx, func() { _ = h.Close() })
	defer stop()
	b := &outputBudget{remaining: MaxExecOutput}
	out, stderr := &limitedOutput{budget: b}, &limitedOutput{budget: b}
	s.Stdout, s.Stderr = out, stderr
	s.Stdin = bytes.NewReader(input)
	e = s.Run(command)
	r.Stdout, r.Stderr, r.Truncated = string(out.data), string(stderr.data), b.truncated
	if ctx.Err() != nil {
		return r, ctx.Err()
	}
	if e == nil {
		r.ExitCode = 0
		return r, nil
	}
	var exit *xssh.ExitError
	if errors.As(e, &exit) {
		r.ExitCode = exit.ExitStatus()
		return r, nil
	}
	return r, e
}

// DialLoopback is deliberately restricted to the managed exporter endpoint.
func (h *ManagedHost) DialLoopback(ctx context.Context) (net.Conn, error) {
	return h.client.DialContext(ctx, "tcp", "127.0.0.1:19100")
}
func (h *ManagedHost) Upload(ctx context.Context, remote string, r io.Reader) error {
	f, e := h.Files.CreateExclusive(ctx, remote)
	if e != nil {
		return e
	}
	_, e = io.Copy(f, r)
	return errors.Join(e, f.Close())
}
