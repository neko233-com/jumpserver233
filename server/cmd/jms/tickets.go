package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"github.com/neko233-com/jumpserver233/server/internal/sessionclient"
	"io"
	"os"
	"time"
)

const ticketUsage = "usage: jms ticket policies|list|audit [--view mine|assigned|cc|all --state STATE --search TEXT --offset 0 --limit 25] | catalog POLICY [--search TEXT --offset 0 --limit 25] | show|show-policy ID | create|policy-create --file FILE.json | amend|policy-update ID --file FILE.json | approve|reject ID --revision N [--request-id ID --comment TEXT] | cancel|revoke|policy-delete ID --revision N | comment ID --text TEXT | wait ID [--timeout-seconds 300]"

func runTickets(args []string) error {
	endpoint := os.Getenv("JMS_SERVER_URL")
	if endpoint == "" {
		endpoint = "http://127.0.0.1:8080"
	}
	c, e := clientFromEnvironment(endpoint, "")
	if e != nil {
		return e
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	return executeTickets(ctx, c, args, os.Stdout)
}
func executeTickets(ctx context.Context, c *sessionclient.Client, args []string, out io.Writer) error {
	if len(args) == 0 {
		return errors.New(ticketUsage)
	}
	emit := func(v any, e error) error {
		if e != nil {
			return e
		}
		return json.NewEncoder(out).Encode(v)
	}
	f := flag.NewFlagSet("ticket", flag.ContinueOnError)
	f.SetOutput(io.Discard)
	action := args[0]
	id := ""
	start := 1
	switch action {
	case "catalog", "show", "show-policy", "amend", "policy-update", "approve", "reject", "cancel", "revoke", "policy-delete", "comment", "wait":
		if len(args) < 2 || args[1] == "" {
			return errors.New(ticketUsage)
		}
		id = args[1]
		start = 2
	}
	switch action {
	case "policies", "list", "audit", "catalog":
		offset, limit := f.Int("offset", 0, ""), f.Int("limit", 25, "")
		search, view, state := f.String("search", "", ""), f.String("view", "mine", ""), f.String("state", "", "")
		if f.Parse(args[start:]) != nil || f.NArg() != 0 || *offset < 0 || *limit < 1 || *limit > 100 {
			return errors.New(ticketUsage)
		}
		switch action {
		case "policies":
			v, e := c.TicketPolicies(ctx, *offset, *limit)
			return emit(v, e)
		case "audit":
			v, e := c.TicketAudit(ctx, *offset, *limit)
			return emit(v, e)
		case "catalog":
			v, e := c.TicketCatalog(ctx, id, *search, *offset, *limit)
			return emit(v, e)
		default:
			v, e := c.Tickets(ctx, *view, *state, *search, *offset, *limit)
			return emit(v, e)
		}
	case "show", "show-policy":
		if len(args) != 2 {
			return errors.New(ticketUsage)
		}
		if action == "show" {
			v, e := c.Ticket(ctx, id)
			return emit(v, e)
		}
		v, e := c.TicketPolicy(ctx, id)
		return emit(v, e)
	case "create", "amend", "policy-create", "policy-update":
		path := f.String("file", "", "")
		if f.Parse(args[start:]) != nil || f.NArg() != 0 || *path == "" {
			return errors.New(ticketUsage)
		}
		file, e := os.Open(*path)
		if e != nil {
			return errors.New("could not open ticket metadata file")
		}
		defer file.Close()
		raw, e := io.ReadAll(io.LimitReader(file, (256<<10)+1))
		if e != nil || len(raw) > 256<<10 {
			return errors.New("invalid ticket metadata file")
		}
		decode := func(v any) error {
			d := json.NewDecoder(bytes.NewReader(raw))
			d.DisallowUnknownFields()
			if d.Decode(v) != nil || d.Decode(new(any)) != io.EOF {
				return errors.New("invalid ticket metadata file")
			}
			return nil
		}
		switch action {
		case "create":
			var in sessionclient.TicketInput
			if e = decode(&in); e != nil {
				return e
			}
			if in.RequestID == "" {
				in.RequestID, e = ticketRequestID()
				if e != nil {
					return e
				}
			}
			v, e := c.SubmitTicket(ctx, in)
			return emit(v, e)
		case "amend":
			var in sessionclient.TicketAmendment
			if e = decode(&in); e != nil {
				return e
			}
			v, e := c.AmendTicket(ctx, id, in)
			return emit(v, e)
		default:
			var in sessionclient.TicketPolicyInput
			if e = decode(&in); e != nil {
				return e
			}
			v, e := c.SaveTicketPolicy(ctx, id, in)
			return emit(v, e)
		}
	case "approve", "reject", "cancel", "revoke", "policy-delete":
		revision := f.Int("revision", 0, "")
		requestID, comment := f.String("request-id", "", ""), f.String("comment", "", "")
		if f.Parse(args[start:]) != nil || f.NArg() != 0 || *revision < 1 {
			return errors.New(ticketUsage)
		}
		if action == "cancel" || action == "revoke" {
			v, e := c.CancelTicket(ctx, id, *revision)
			return emit(v, e)
		}
		if action == "policy-delete" {
			return emit(map[string]bool{"deleted": true}, c.DeleteTicketPolicy(ctx, id, *revision))
		}
		if *requestID == "" {
			var e error
			*requestID, e = ticketRequestID()
			if e != nil {
				return e
			}
		}
		v, e := c.DecideTicket(ctx, id, sessionclient.TicketDecision{Revision: *revision, RequestID: *requestID, Action: action, Comment: *comment})
		return emit(v, e)
	case "comment":
		text := f.String("text", "", "")
		if f.Parse(args[start:]) != nil || f.NArg() != 0 || *text == "" {
			return errors.New(ticketUsage)
		}
		v, e := c.CommentTicket(ctx, id, *text)
		return emit(v, e)
	case "wait":
		seconds := f.Int("timeout-seconds", 300, "")
		if f.Parse(args[start:]) != nil || f.NArg() != 0 || *seconds < 1 || *seconds > 86400 {
			return errors.New(ticketUsage)
		}
		wait, cancel := context.WithTimeout(ctx, time.Duration(*seconds)*time.Second)
		defer cancel()
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			v, e := c.Ticket(wait, id)
			if e != nil {
				return e
			}
			if v.State != "pending" && v.State != "issuing" && v.State != "revoking" {
				if e = emit(v, nil); e != nil {
					return e
				}
				if v.State != "approved" {
					return errors.New("access ticket closed without an active approval")
				}
				return nil
			}
			select {
			case <-wait.Done():
				return errors.New("ticket wait timed out; query the existing ticket before retrying")
			case <-ticker.C:
			}
		}
	}
	return errors.New(ticketUsage)
}
func ticketRequestID() (string, error) {
	var b [16]byte
	if _, e := rand.Read(b[:]); e != nil {
		return "", e
	}
	return hex.EncodeToString(b[:]), nil
}
