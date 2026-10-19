package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/neko233-com/jumpserver233/server/internal/core/jobs"
	"github.com/neko233-com/jumpserver233/server/internal/sessionclient"
)

type remoteExitError struct{ Code int }

func (e *remoteExitError) Error() string {
	return fmt.Sprintf("remote command exited with status %d", e.Code)
}
func runExec(args []string, selected ...string) error {
	serverURL := os.Getenv("JMS_SERVER_URL")
	if serverURL == "" {
		serverURL = "http://127.0.0.1:8080"
	}
	client, err := clientFromEnvironment(serverURL, selected...)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return executeCommand(ctx, client, args, os.Stdout, os.Stderr)
}
func executeCommand(ctx context.Context, client *sessionclient.Client, args []string, stdout, stderr io.Writer) error {
	if len(args) < 3 {
		return fmt.Errorf("usage: jms exec <asset-id> [--directory /workspace/subdir] [--timeout 60] [--json] -- <command>")
	}
	input := jobs.Input{AssetID: args[0], TimeoutSeconds: 60}
	asJSON := false
	separator := -1
	for i := 1; i < len(args); i++ {
		switch args[i] {
		case "--":
			separator = i
			i = len(args)
		case "--json":
			asJSON = true
		case "--directory":
			i++
			if i >= len(args) || args[i] == "" {
				return jobs.ErrInvalid
			}
			input.WorkingDirectory = args[i]
		case "--timeout":
			i++
			if i >= len(args) {
				return jobs.ErrInvalid
			}
			value, err := strconv.Atoi(args[i])
			if err != nil {
				return jobs.ErrInvalid
			}
			input.TimeoutSeconds = value
		default:
			return fmt.Errorf("unsupported exec option: %s", args[i])
		}
	}
	if separator < 0 || separator+1 >= len(args) {
		return jobs.ErrInvalid
	}
	input.Command = strings.Join(args[separator+1:], " ")
	input, err := jobs.Validate(input)
	if err != nil {
		return err
	}
	var raw [16]byte
	if _, err = rand.Read(raw[:]); err != nil {
		return err
	}
	input.RequestID = hex.EncodeToString(raw[:])
	ctx, cancel := context.WithTimeout(ctx, time.Duration(input.TimeoutSeconds)*time.Second+6*time.Minute)
	defer cancel()
	var job jobs.Job
	for {
		job, err = client.SubmitJob(ctx, input)
		if err == nil {
			break
		}
		var pending *sessionclient.AccessReviewPendingError
		if !errors.As(err, &pending) {
			return err
		}
		fmt.Fprintln(stderr, accessReviewNotice("pending"))
		state, err := client.WaitForAccessReview(ctx, pending.ReviewID)
		if err != nil {
			return err
		}
		if state != "approved" {
			return fmt.Errorf("%s", accessReviewNotice(state))
		}
	}
	fmt.Fprintf(stderr, "Job: %s\n", job.ID)
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for job.State == "running" || job.State == "pending_review" {
		select {
		case <-ctx.Done():
			closeCtx, closeCancel := context.WithTimeout(context.Background(), 3*time.Second)
			_ = client.CancelJob(closeCtx, job.ID)
			closeCancel()
			return ctx.Err()
		case <-ticker.C:
			job, err = client.GetJob(ctx, job.ID)
			if err != nil {
				return err
			}
		}
	}
	if asJSON {
		if err = json.NewEncoder(stdout).Encode(job); err != nil {
			return err
		}
	} else {
		if _, err = io.WriteString(stdout, job.Stdout); err != nil {
			return err
		}
		if _, err = io.WriteString(stderr, job.Stderr); err != nil {
			return err
		}
	}
	if job.State == "succeeded" {
		return nil
	}
	if job.ErrorCode == "remote_exit" && job.ExitCode > 0 && job.ExitCode < 256 {
		return &remoteExitError{Code: job.ExitCode}
	}
	return fmt.Errorf("SSH job %s: %s (%s)", job.ID, job.State, job.ErrorCode)
}
