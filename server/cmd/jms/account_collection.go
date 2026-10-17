package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"github.com/neko233-com/jumpserver233/server/internal/sessionclient"
	"io"
	"time"
)

const accountCollectionUsage = "usage: jms accounts plans ASSET | schedule ASSET --interval 3600 [--request-id ID] [--name LABEL] | plan ASSET PLAN --enabled=false --revision N [--interval SECONDS] | collections ASSET [--before N] [--limit 50]"

func executeAccountCollection(ctx context.Context, c *sessionclient.Client, args []string, out io.Writer) error {
	if len(args) < 2 || args[1] == "" {
		return errors.New(accountCollectionUsage)
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	f := flag.NewFlagSet("account-collection", flag.ContinueOnError)
	f.SetOutput(io.Discard)
	switch args[0] {
	case "plans":
		if len(args) != 2 {
			return errors.New(accountCollectionUsage)
		}
		v, e := c.AccountCollectionPlans(ctx, args[1])
		if e != nil {
			return e
		}
		return json.NewEncoder(out).Encode(v)
	case "schedule":
		interval := f.Int("interval", 3600, "")
		requestID := f.String("request-id", "", "")
		name := f.String("name", "Linux account discovery", "")
		if f.Parse(args[2:]) != nil || f.NArg() != 0 || *interval < 60 || *interval > 86400 {
			return errors.New(accountCollectionUsage)
		}
		if *requestID == "" {
			var nonce [16]byte
			if _, e := rand.Read(nonce[:]); e != nil {
				return e
			}
			*requestID = hex.EncodeToString(nonce[:])
		}
		v, e := c.CreateAccountCollectionPlan(ctx, args[1], sessionclient.AccountCollectionPlanInput{Name: *name, Interval: *interval, RequestID: *requestID})
		if e != nil {
			return e
		}
		return json.NewEncoder(out).Encode(v)
	case "plan":
		if len(args) < 3 || args[2] == "" {
			return errors.New(accountCollectionUsage)
		}
		enabled, revision, interval := f.Bool("enabled", false, ""), f.Int("revision", 0, ""), f.Int("interval", 0, "")
		if f.Parse(args[3:]) != nil || f.NArg() != 0 || *revision < 1 || *interval != 0 && (*interval < 60 || *interval > 86400) {
			return errors.New(accountCollectionUsage)
		}
		explicit := false
		f.Visit(func(v *flag.Flag) {
			if v.Name == "enabled" {
				explicit = true
			}
		})
		if !explicit {
			return errors.New(accountCollectionUsage)
		}
		v, e := c.UpdateAccountCollectionPlan(ctx, args[1], args[2], sessionclient.AccountCollectionPlanUpdate{Enabled: *enabled, Revision: *revision, Interval: *interval})
		if e != nil {
			return e
		}
		return json.NewEncoder(out).Encode(v)
	case "collections":
		before, limit := f.Uint64("before", 0, ""), f.Int("limit", 50, "")
		if f.Parse(args[2:]) != nil || f.NArg() != 0 || *limit < 1 || *limit > 100 {
			return errors.New(accountCollectionUsage)
		}
		v, e := c.AccountCollectionHistory(ctx, args[1], *before, *limit)
		if e != nil {
			return e
		}
		return json.NewEncoder(out).Encode(v)
	}
	return errors.New(accountCollectionUsage)
}
