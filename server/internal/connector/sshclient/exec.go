package sshclient

import (
	"context"
	"errors"
	"sync"
	"time"

	xssh "golang.org/x/crypto/ssh"
)

const MaxExecOutput = 64 * 1024

type ExecResult struct {
	Stdout    string `json:"stdout"`
	Stderr    string `json:"stderr"`
	ExitCode  int    `json:"exit_code"`
	Truncated bool   `json:"truncated"`
}

type outputBudget struct {
	mu        sync.Mutex
	remaining int
	truncated bool
}
type limitedOutput struct {
	budget *outputBudget
	data   []byte
}

func (w *limitedOutput) Write(p []byte) (int, error) {
	w.budget.mu.Lock()
	defer w.budget.mu.Unlock()
	n := min(len(p), w.budget.remaining)
	w.data = append(w.data, p[:n]...)
	w.budget.remaining -= n
	if n < len(p) {
		w.budget.truncated = true
	}
	return len(p), nil // Keep draining the remote channel after the capture limit.
}

// Exec runs one non-PTY command on a pinned SSH host. Cancellation closes the
// transport; it cannot guarantee termination of detached remote descendants.
func Exec(ctx context.Context, target Target, credentials Credentials, command string) (ExecResult, error) {
	result := ExecResult{ExitCode: -1}
	client, _, err := dial(ctx, target, credentials, 12*time.Second)
	if err != nil {
		return result, err
	}
	defer client.Close()
	stop := context.AfterFunc(ctx, func() { _ = client.Close() })
	defer stop()
	session, err := client.NewSession()
	if err != nil {
		return result, err
	}
	defer session.Close()
	budget := &outputBudget{remaining: MaxExecOutput}
	out, stderr := &limitedOutput{budget: budget}, &limitedOutput{budget: budget}
	session.Stdout, session.Stderr = out, stderr
	err = session.Run(command)
	result.Stdout, result.Stderr, result.Truncated = string(out.data), string(stderr.data), budget.truncated
	if ctx.Err() != nil {
		return result, ctx.Err()
	}
	if err == nil {
		result.ExitCode = 0
		return result, nil
	}
	var exit *xssh.ExitError
	if errors.As(err, &exit) {
		result.ExitCode = exit.ExitStatus()
		return result, nil
	}
	return result, err
}
