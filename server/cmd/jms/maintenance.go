package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"github.com/neko233-com/jumpserver233/server/internal/core/servicemaintenance"
	"github.com/neko233-com/jumpserver233/server/internal/sessionclient"
	"io"
	"time"
)

const drainUsage = "usage: jms update drain-status | drain-start --instance ID --revision N --request-id ID [--wait 60s] | drain-cancel --instance ID --revision N --request-id ID"

func executeDrain(ctx context.Context, c *sessionclient.Client, args []string, out io.Writer) error {
	if len(args) == 1 && args[0] == "drain-status" {
		status, e := c.MaintenanceStatus(ctx)
		if e != nil {
			return e
		}
		return json.NewEncoder(out).Encode(status)
	}
	fs := flag.NewFlagSet("update drain", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	instance := fs.String("instance", "", "")
	revision := fs.Int("revision", 0, "")
	id := fs.String("request-id", "", "")
	wait := fs.Duration("wait", 0, "")
	if len(args) == 0 || fs.Parse(args[1:]) != nil || fs.NArg() != 0 || *instance == "" || *revision < 1 || *id == "" || *wait < 0 || *wait > 24*time.Hour || args[0] != "drain-start" && args[0] != "drain-cancel" || args[0] == "drain-cancel" && *wait != 0 {
		return errors.New(drainUsage)
	}
	status, e := c.SetMaintenance(ctx, servicemaintenance.Input{Instance: *instance, Revision: *revision, RequestID: *id, Draining: args[0] == "drain-start"})
	if e != nil {
		return e
	}
	if *wait > 0 && status.Draining && !status.Ready {
		waitCtx, cancel := context.WithTimeout(ctx, *wait)
		defer cancel()
		ticker := time.NewTicker(250 * time.Millisecond)
		defer ticker.Stop()
		for !status.Ready {
			select {
			case <-waitCtx.Done():
				return waitCtx.Err()
			case <-ticker.C:
			}
			next, e := c.MaintenanceStatus(waitCtx)
			if e != nil {
				return e
			}
			if next.Instance != status.Instance || next.Revision != status.Revision || !next.Draining {
				return servicemaintenance.ErrConflict
			}
			status = next
		}
	}
	return json.NewEncoder(out).Encode(status)
}
