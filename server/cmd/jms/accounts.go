package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/neko233-com/jumpserver233/server/internal/sessionclient"
)

const accountsUsage = "usage: jms accounts list|audit ASSET [--offset N] [--limit 50] | jms accounts discover ASSET [--request-id ID] [--review-id ID] [--timeout 180] [--no-wait] | jms accounts review ASSET FINDING --state acknowledged|ignored|unreviewed --revision N [--note TEXT] | jms accounts job|cancel JOB | " + accountCollectionUsage

func runAccounts(args []string, selected ...string) error {
	endpoint := os.Getenv("JMS_SERVER_URL")
	if endpoint == "" {
		endpoint = "http://127.0.0.1:8080"
	}
	c, e := clientFromEnvironment(endpoint, selected...)
	if e != nil {
		return e
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	return executeAccounts(ctx, c, args, os.Stdout)
}
func executeAccounts(ctx context.Context, c *sessionclient.Client, args []string, out io.Writer) error {
	if len(args) < 2 || args[1] == "" {
		return errors.New(accountsUsage)
	}
	f := flag.NewFlagSet("accounts", flag.ContinueOnError)
	f.SetOutput(io.Discard)
	switch args[0] {
	case "plans", "schedule", "plan", "collections":
		return executeAccountCollection(ctx, c, args, out)
	case "job", "cancel":
		if len(args) != 2 {
			return errors.New(accountsUsage)
		}
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
	case "list", "audit":
		offset, limit := f.Int("offset", 0, ""), f.Int("limit", 50, "")
		if f.Parse(args[2:]) != nil || f.NArg() != 0 || *offset < 0 || *limit < 1 || *limit > 100 {
			return errors.New(accountsUsage)
		}
		if args[0] == "audit" {
			v, e := c.AccountDiscoveryAudit(ctx, args[1], *offset, *limit)
			if e != nil {
				return e
			}
			return json.NewEncoder(out).Encode(v)
		}
		v, e := c.DiscoveredAccounts(ctx, args[1], *offset, *limit)
		if e != nil {
			return e
		}
		return json.NewEncoder(out).Encode(v)
	case "review":
		if len(args) < 3 || args[2] == "" {
			return errors.New(accountsUsage)
		}
		state, note, revision := f.String("state", "", ""), f.String("note", "", ""), f.Int("revision", 0, "")
		if f.Parse(args[3:]) != nil || f.NArg() != 0 || *revision < 1 || (*state != "acknowledged" && *state != "ignored" && *state != "unreviewed") {
			return errors.New(accountsUsage)
		}
		v, e := c.ReviewDiscoveredAccount(ctx, args[1], args[2], *state, *note, *revision)
		if e != nil {
			return e
		}
		return json.NewEncoder(out).Encode(v)
	case "discover":
		in := sessionclient.AccountDiscoveryRequest{}
		noWait := false
		f.StringVar(&in.RequestID, "request-id", "", "")
		f.StringVar(&in.ReviewID, "review-id", "", "")
		f.IntVar(&in.Timeout, "timeout", 180, "")
		f.BoolVar(&noWait, "no-wait", false, "")
		if f.Parse(args[2:]) != nil || f.NArg() != 0 || in.Timeout < 1 || in.Timeout > 300 {
			return errors.New(accountsUsage)
		}
		if in.RequestID == "" {
			var nonce [16]byte
			if _, e := rand.Read(nonce[:]); e != nil {
				return e
			}
			in.RequestID = hex.EncodeToString(nonce[:])
		}
		ctx, cancel := context.WithTimeout(ctx, time.Duration(in.Timeout)*time.Second+6*time.Minute)
		defer cancel()
		for {
			j, e := c.DiscoverAccounts(ctx, args[1], in)
			if e != nil {
				var pending *sessionclient.AccessReviewPendingError
				if !errors.As(e, &pending) {
					return e
				}
				if noWait {
					return json.NewEncoder(out).Encode(map[string]string{"review_id": pending.ReviewID, "request_id": in.RequestID, "state": "pending_login_review"})
				}
				state, e := c.WaitForAccessReview(ctx, pending.ReviewID)
				if e != nil {
					return e
				}
				if state != "approved" {
					return fmt.Errorf("login review %s", state)
				}
				in.ReviewID = pending.ReviewID
				continue
			}
			ticker := time.NewTicker(500 * time.Millisecond)
			defer ticker.Stop()
			for !noWait && (j.State == "running" || j.State == "pending_review") {
				select {
				case <-ctx.Done():
					return ctx.Err()
				case <-ticker.C:
					j, e = c.GetJob(ctx, j.ID)
					if e != nil {
						return e
					}
				}
			}
			if e = json.NewEncoder(out).Encode(j); e != nil {
				return e
			}
			if !noWait && j.State != "succeeded" {
				return &remoteExitError{Code: 1}
			}
			return nil
		}
	}
	return errors.New(accountsUsage)
}
