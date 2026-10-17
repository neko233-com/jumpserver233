package sshclient

import (
	"context"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"
	"time"

	xssh "golang.org/x/crypto/ssh"
)

var (
	ErrInvalidRotationAccount   = errors.New("invalid SSH account for password rotation")
	ErrInvalidGeneratedPassword = errors.New("invalid generated SSH password")
)

var (
	rotationAccountPattern  = regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_.-]{0,127}$`)
	rotationPasswordPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{32,128}$`)
)

// ChangePassword replaces the login account's password without putting the new
// secret in a shell command, SSH command argument, or process environment. The
// value is sent only through the encrypted SSH channel's stdin.
func ChangePassword(ctx context.Context, target Target, credentials Credentials, newPassword string, timeout time.Duration) error {
	if !rotationPasswordPattern.MatchString(newPassword) {
		return ErrInvalidGeneratedPassword
	}
	return restorePassword(ctx, target, credentials, newPassword, timeout)
}

// RestorePassword accepts an existing vault password without weakening the
// generated-password policy. Record separators are rejected before SSH opens.
func RestorePassword(ctx context.Context, target Target, credentials Credentials, password string, timeout time.Duration) error {
	if len(password) == 0 || len(password) > 4096 || strings.ContainsAny(password, "\r\n\x00") {
		return ErrInvalidGeneratedPassword
	}
	return restorePassword(ctx, target, credentials, password, timeout)
}

func restorePassword(ctx context.Context, target Target, credentials Credentials, newPassword string, timeout time.Duration) error {
	return restorePasswordFor(ctx, target, credentials, target.Username, newPassword, timeout)
}

// ChangePasswordFor authenticates a selected privileged collector and sends the
// target account/password only over encrypted stdin, never in command arguments.
func ChangePasswordFor(ctx context.Context, collector Target, credentials Credentials, username, password string, timeout time.Duration) error {
	if !rotationPasswordPattern.MatchString(password) {
		return ErrInvalidGeneratedPassword
	}
	return restorePasswordFor(ctx, collector, credentials, username, password, timeout)
}
func restorePasswordFor(ctx context.Context, target Target, credentials Credentials, username, newPassword string, timeout time.Duration) error {
	if !rotationAccountPattern.MatchString(target.Username) || !rotationAccountPattern.MatchString(username) {
		return ErrInvalidRotationAccount
	}
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	client, _, err := dial(ctx, target, credentials, timeout)
	if err != nil {
		return err
	}
	defer client.Close()

	uidOutput, err := runOutput(ctx, client, "id -u")
	if err != nil {
		return fmt.Errorf("check SSH password rotation privileges: %w", err)
	}
	uid := strings.TrimSpace(string(uidOutput))
	if uid == "" || strings.ContainsAny(uid, "\r\n") {
		return errors.New("invalid SSH identity response")
	}
	command := "sudo -n chpasswd"
	if uid == "0" {
		command = "chpasswd"
	}

	session, err := client.NewSession()
	if err != nil {
		return fmt.Errorf("open SSH password rotation session: %w", err)
	}
	defer session.Close()
	stdin, err := session.StdinPipe()
	if err != nil {
		return fmt.Errorf("open SSH password rotation input: %w", err)
	}
	if err := session.Start(command); err != nil {
		return fmt.Errorf("start SSH password rotation command: %w", err)
	}

	result := make(chan error, 1)
	go func() {
		_, writeErr := io.WriteString(stdin, username+":"+newPassword+"\n")
		closeErr := stdin.Close()
		waitErr := session.Wait()
		if writeErr != nil {
			result <- fmt.Errorf("send SSH password rotation input: %w", writeErr)
			return
		}
		if closeErr != nil {
			result <- fmt.Errorf("close SSH password rotation input: %w", closeErr)
			return
		}
		if waitErr != nil {
			result <- errors.New("SSH password rotation command failed")
			return
		}
		result <- nil
	}()
	select {
	case <-ctx.Done():
		_ = session.Close()
		return ctx.Err()
	case err := <-result:
		return err
	}
}

// VerifyPassword checks SSH authentication and the pinned host key without
// running a remote command.
func VerifyPassword(ctx context.Context, target Target, credentials Credentials, timeout time.Duration) error {
	if timeout <= 0 {
		timeout = 8 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	client, _, err := dial(ctx, target, credentials, timeout)
	if err != nil {
		return err
	}
	return client.Close()
}

func runOutput(ctx context.Context, client *xssh.Client, command string) ([]byte, error) {
	session, err := client.NewSession()
	if err != nil {
		return nil, fmt.Errorf("open SSH command session: %w", err)
	}
	defer session.Close()
	type outputResult struct {
		output []byte
		err    error
	}
	result := make(chan outputResult, 1)
	go func() {
		output, commandErr := session.Output(command)
		result <- outputResult{output: output, err: commandErr}
	}()
	select {
	case <-ctx.Done():
		_ = session.Close()
		return nil, ctx.Err()
	case command := <-result:
		if command.err != nil {
			return nil, errors.New("SSH privilege check command failed")
		}
		return command.output, nil
	}
}
