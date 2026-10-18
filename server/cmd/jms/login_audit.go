package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"github.com/neko233-com/jumpserver233/server/internal/sessionclient"
	"io"
	"os"
	"time"
)

const loginAuditUsage = "usage: jms login-audit list|summary|export [--all --offset N --limit N --method METHOD --outcome STATE --query TEXT --source-ip IP --user-id ID --from RFC3339 --to RFC3339] | event ID | health | approve|deny REVIEW_ID"

func runLoginAudit(args []string) error {
	endpoint := os.Getenv("JMS_SERVER_URL")
	if endpoint == "" {
		endpoint = "http://127.0.0.1:8080"
	}
	c, e := clientFromEnvironment(endpoint, "")
	if e != nil {
		return e
	}
	return executeLoginAudit(context.Background(), c, args, os.Stdout)
}
func executeLoginAudit(ctx context.Context, c *sessionclient.Client, args []string, out io.Writer) error {
	if len(args) == 0 {
		return errors.New(loginAuditUsage)
	}
	action, id, start := args[0], "", 1
	if action == "event" || action == "approve" || action == "deny" {
		if len(args) < 2 {
			return errors.New(loginAuditUsage)
		}
		id, start = args[1], 2
	}
	f := flag.NewFlagSet("login-audit", flag.ContinueOnError)
	f.SetOutput(io.Discard)
	in := sessionclient.LoginAuditFilter{}
	f.BoolVar(&in.All, "all", false, "")
	f.IntVar(&in.Offset, "offset", 0, "")
	f.IntVar(&in.Limit, "limit", 25, "")
	f.StringVar(&in.Method, "method", "", "")
	f.StringVar(&in.Outcome, "outcome", "", "")
	f.StringVar(&in.Query, "query", "", "")
	f.StringVar(&in.SourceIP, "source-ip", "", "")
	f.StringVar(&in.UserID, "user-id", "", "")
	from, to := f.String("from", "", ""), f.String("to", "", "")
	if f.Parse(args[start:]) != nil || f.NArg() != 0 || in.Offset < 0 || in.Limit < 1 || in.Limit > 200 {
		return errors.New(loginAuditUsage)
	}
	var e error
	if *from != "" {
		in.From, e = time.Parse(time.RFC3339, *from)
	}
	if e == nil && *to != "" {
		in.To, e = time.Parse(time.RFC3339, *to)
	}
	if e != nil {
		return errors.New("invalid audit time range")
	}
	emit := func(v any, e error) error {
		if e != nil {
			return e
		}
		return json.NewEncoder(out).Encode(v)
	}
	switch action {
	case "list":
		v, e := c.LoginAudits(ctx, in)
		return emit(v, e)
	case "event":
		v, e := c.LoginAuditEvent(ctx, id)
		return emit(v, e)
	case "summary":
		v, e := c.LoginAuditTotals(ctx, in)
		return emit(v, e)
	case "health":
		v, e := c.LoginAuditStatus(ctx)
		return emit(v, e)
	case "export":
		return c.ExportLoginAudits(ctx, in, out)
	case "approve", "deny":
		return c.ReviewPlatformLogin(ctx, id, action == "approve")
	}
	return errors.New(loginAuditUsage)
}
