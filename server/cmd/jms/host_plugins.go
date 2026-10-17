package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"github.com/neko233-com/jumpserver233/server/internal/core/hostplugins"
	"github.com/neko233-com/jumpserver233/server/internal/core/jobs"
	"github.com/neko233-com/jumpserver233/server/internal/sessionclient"
	"io"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func runPlugins(args []string, selected ...string) error {
	endpoint := os.Getenv("JMS_SERVER_URL")
	if endpoint == "" {
		endpoint = "http://127.0.0.1:8080"
	}
	client, e := clientFromEnvironment(endpoint, selected...)
	if e != nil {
		return e
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	return executePlugin(ctx, client, args, os.Stdout)
}
func executePlugin(ctx context.Context, c *sessionclient.Client, args []string, out io.Writer) error {
	if len(args) == 1 && args[0] == "catalog" {
		v, e := c.HostPlugins(ctx)
		if e != nil {
			return e
		}
		return json.NewEncoder(out).Encode(v)
	}
	if len(args) == 2 && (args[0] == "job" || args[0] == "cancel") {
		if args[0] == "cancel" {
			if e := c.CancelJob(ctx, args[1]); e != nil {
				return e
			}
		}
		j, e := c.GetJob(ctx, args[1])
		if e != nil {
			return e
		}
		return json.NewEncoder(out).Encode(j)
	}
	if len(args) < 3 {
		return fmt.Errorf("usage: jms plugin catalog | jms plugin <asset-id> <plugin-id> <action> [--version PIN] [--policy-file PATH] [--request-id ID] [--timeout 180] [--no-wait] | jms plugin job|cancel <job-id>")
	}
	f := flag.NewFlagSet("plugin", flag.ContinueOnError)
	f.SetOutput(io.Discard)
	in := sessionclient.PluginRequest{Action: args[2]}
	noWait := false
	policyFile := ""
	f.StringVar(&in.RequestID, "request-id", "", "")
	f.StringVar(&in.Version, "version", "", "")
	f.StringVar(&policyFile, "policy-file", "", "")
	f.IntVar(&in.TimeoutSeconds, "timeout", 180, "")
	f.BoolVar(&noWait, "no-wait", false, "")
	if f.Parse(args[3:]) != nil || f.NArg() != 0 || in.TimeoutSeconds < 1 || in.TimeoutSeconds > 300 {
		return jobs.ErrInvalid
	}
	if policyFile != "" {
		file, e := os.Open(policyFile)
		if e != nil {
			return e
		}
		raw, e := io.ReadAll(io.LimitReader(file, 8193))
		file.Close()
		if e != nil || len(raw) > 8192 {
			return jobs.ErrInvalid
		}
		var p hostplugins.ProtectionPolicy
		d := json.NewDecoder(bytes.NewReader(raw))
		d.DisallowUnknownFields()
		if d.Decode(&p) != nil || d.Decode(new(any)) != io.EOF {
			return jobs.ErrInvalid
		}
		p, e = p.Normalize()
		if e != nil || in.Action != "protection_apply" {
			return jobs.ErrInvalid
		}
		in.Protection = &p
	}
	if in.Action == "protection_apply" && in.Protection == nil {
		return jobs.ErrInvalid
	}
	if in.RequestID == "" {
		var raw [16]byte
		if _, e := rand.Read(raw[:]); e != nil {
			return e
		}
		in.RequestID = hex.EncodeToString(raw[:])
	}
	ctx, cancel := context.WithTimeout(ctx, time.Duration(in.TimeoutSeconds)*time.Second+6*time.Minute)
	defer cancel()
	var j jobs.Job
	for {
		var e error
		j, e = c.SubmitPlugin(ctx, args[0], args[1], in)
		if e == nil {
			break
		}
		var pending *sessionclient.AccessReviewPendingError
		if !errors.As(e, &pending) {
			return e
		}
		if noWait {
			return json.NewEncoder(out).Encode(map[string]string{"review_id": pending.ReviewID, "state": "pending_login_review", "request_id": in.RequestID})
		}
		state, e := c.WaitForAccessReview(ctx, pending.ReviewID)
		if e != nil {
			return e
		}
		if state != "approved" {
			return fmt.Errorf("login review %s", state)
		}
		in.ReviewID = pending.ReviewID
	}
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()
	for !noWait && (j.State == "running" || j.State == "pending_review") {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			var e error
			j, e = c.GetJob(ctx, j.ID)
			if e != nil {
				return e
			}
		}
	}
	if e := json.NewEncoder(out).Encode(j); e != nil {
		return e
	}
	if !noWait && j.State != "succeeded" {
		return &remoteExitError{Code: 1}
	}
	return nil
}
