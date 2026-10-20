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

const assistantUsage = "usage: jms assistant settings | configure --file JSON_OR_- | ask --file JSON_OR_- | list [--all --archived --offset 0 --limit 20] | show CONVERSATION_ID [--all] | archive CONVERSATION_ID --revision N --request-id ID | audit [--offset 0 --limit 20]"

func runAssistant(args []string) error {
	endpoint := os.Getenv("JMS_SERVER_URL")
	if endpoint == "" {
		endpoint = "http://127.0.0.1:8080"
	}
	c, e := clientFromEnvironment(endpoint, "")
	if e != nil {
		return e
	}
	return executeAssistant(context.Background(), c, args, os.Stdin, os.Stdout)
}
func executeAssistant(ctx context.Context, c *sessionclient.Client, args []string, stdin io.Reader, out io.Writer) error {
	if len(args) == 0 {
		return errors.New(assistantUsage)
	}
	command := args[0]
	args = args[1:]
	id := ""
	if command == "show" || command == "archive" {
		if len(args) == 0 {
			return errors.New(assistantUsage)
		}
		id, args = args[0], args[1:]
	}
	fs := flag.NewFlagSet("assistant", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	var all, archived bool
	var offset, limit, revision int
	var file, request string
	switch command {
	case "settings":
	case "configure", "ask":
		fs.StringVar(&file, "file", "", "")
	case "list", "audit":
		fs.IntVar(&offset, "offset", 0, "")
		fs.IntVar(&limit, "limit", 20, "")
		if command == "list" {
			fs.BoolVar(&all, "all", false, "")
			fs.BoolVar(&archived, "archived", false, "")
		}
	case "show":
		fs.BoolVar(&all, "all", false, "")
	case "archive":
		fs.IntVar(&revision, "revision", 0, "")
		fs.StringVar(&request, "request-id", "", "")
	default:
		return errors.New(assistantUsage)
	}
	if fs.Parse(args) != nil || fs.NArg() != 0 {
		return errors.New(assistantUsage)
	}
	var result any
	var e error
	switch command {
	case "settings":
		result, e = c.AssistantSettings(ctx)
	case "configure":
		var in sessionclient.AssistantSettingsInput
		if e = operationJSON(file, stdin, &in); e == nil {
			result, e = c.SaveAssistantSettings(ctx, in)
		}
	case "ask":
		var in sessionclient.AssistantInput
		if e = operationJSON(file, stdin, &in); e == nil {
			result, e = c.AskAssistant(ctx, in)
		}
	case "list":
		result, e = c.AssistantConversations(ctx, all, archived, offset, limit)
	case "show":
		result, e = c.AssistantConversation(ctx, id, all)
	case "archive":
		e = c.ArchiveAssistantConversation(ctx, id, revision, request)
		result = map[string]bool{"archived": e == nil}
	case "audit":
		result, e = c.AssistantAudit(ctx, offset, limit)
	}
	if e != nil {
		return e
	}
	return json.NewEncoder(out).Encode(result)
}
