package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"github.com/neko233-com/jumpserver233/server/internal/sessionclient"
	"io"
	"os"
)

func runUsers(args []string) error {
	server := os.Getenv("JMS_SERVER_URL")
	if server == "" {
		server = "http://127.0.0.1:8080"
	}
	c, e := clientFromEnvironment(server)
	if e != nil {
		return e
	}
	return executeUsers(context.Background(), c, args, os.Stdin, os.Stdout)
}
func executeUsers(ctx context.Context, c *sessionclient.Client, args []string, input io.Reader, output io.Writer) error {
	if len(args) < 1 {
		return errors.New("usage: jms user list|show|update|archive|restore|revoke|batch|audit")
	}
	action := args[0]
	id := ""
	args = args[1:]
	if action == "show" || action == "update" || action == "archive" || action == "restore" || action == "revoke" {
		if len(args) == 0 {
			return errors.New("user ID is required")
		}
		id, args = args[0], args[1:]
	}
	f := flag.NewFlagSet("user", flag.ContinueOnError)
	f.SetOutput(io.Discard)
	file := f.String("file", "", "")
	scope := f.String("scope", "current", "")
	query := f.String("query", "", "")
	user := f.String("user", "", "")
	offset := f.Int("offset", 0, "")
	limit := f.Int("limit", 25, "")
	revision := f.Int("revision", 0, "")
	if f.Parse(args) != nil || f.NArg() != 0 {
		return errors.New("invalid user arguments")
	}
	allowed := map[string]bool{}
	switch action {
	case "list":
		for _, v := range []string{"scope", "query", "offset", "limit"} {
			allowed[v] = true
		}
	case "audit":
		for _, v := range []string{"user", "offset", "limit"} {
			allowed[v] = true
		}
	case "update", "batch":
		allowed["file"] = true
	case "archive", "restore", "revoke":
		allowed["revision"] = true
	case "show":
	default:
		return errors.New("unknown user action")
	}
	valid := true
	f.Visit(func(v *flag.Flag) {
		if !allowed[v.Name] {
			valid = false
		}
	})
	if !valid {
		return errors.New("invalid user flags")
	}
	var out any
	var e error
	switch action {
	case "list":
		out, e = c.ManagedUsers(ctx, *scope, *query, *offset, *limit)
	case "audit":
		out, e = c.UserAudit(ctx, *user, *offset, *limit)
	case "show":
		out, e = c.ManagedUser(ctx, id)
	case "update":
		var in sessionclient.UserUpdate
		e = operationJSON(*file, input, &in)
		if e == nil {
			out, e = c.UpdateUser(ctx, id, in)
		}
	case "batch":
		var in struct {
			Changes []sessionclient.UserChange `json:"changes"`
		}
		e = operationJSON(*file, input, &in)
		if e == nil {
			out, e = c.ChangeUsers(ctx, in.Changes)
		}
	default:
		out, e = c.UserAction(ctx, id, action, *revision)
	}
	if e != nil {
		return e
	}
	return json.NewEncoder(output).Encode(out)
}
