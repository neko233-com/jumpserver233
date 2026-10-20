package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"os"

	"github.com/neko233-com/jumpserver233/server/internal/sessionclient"
)

const labelsUsage = "usage: jms labels list [--search TEXT --offset 0 --limit 50] | choices | save [LABEL_ID] --file JSON_OR_- | delete LABEL_ID --revision N --request-id ID | binding asset|node ID | bind asset|node ID --file JSON_OR_- | audit [--offset 0 --limit 50]"

func runLabels(args []string) error {
	endpoint := os.Getenv("JMS_SERVER_URL")
	if endpoint == "" {
		endpoint = "http://127.0.0.1:8080"
	}
	c, e := clientFromEnvironment(endpoint, "")
	if e != nil {
		return e
	}
	return executeLabels(context.Background(), c, args, os.Stdin, os.Stdout)
}
func executeLabels(ctx context.Context, c *sessionclient.Client, args []string, stdin io.Reader, out io.Writer) error {
	if len(args) == 0 {
		return errors.New(labelsUsage)
	}
	command := args[0]
	args = args[1:]
	id := ""
	resource := sessionclient.LabelResource{}
	if command == "save" && len(args) > 0 && len(args[0]) > 0 && args[0][0] != '-' {
		id, args = args[0], args[1:]
	}
	if command == "delete" {
		if len(args) == 0 {
			return errors.New(labelsUsage)
		}
		id, args = args[0], args[1:]
	}
	if command == "bind" || command == "binding" {
		if len(args) < 2 {
			return errors.New(labelsUsage)
		}
		resource.Type, resource.ID, args = args[0], args[1], args[2:]
	}
	fs := flag.NewFlagSet("labels", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	var offset, limit, revision int
	var search, file, requestID string
	switch command {
	case "list", "audit":
		fs.IntVar(&offset, "offset", 0, "")
		fs.IntVar(&limit, "limit", 50, "")
		if command == "list" {
			fs.StringVar(&search, "search", "", "")
		}
	case "choices", "binding":
	case "save", "bind":
		fs.StringVar(&file, "file", "", "")
	case "delete":
		fs.IntVar(&revision, "revision", 0, "")
		fs.StringVar(&requestID, "request-id", "", "")
	default:
		return errors.New(labelsUsage)
	}
	if fs.Parse(args) != nil || fs.NArg() != 0 {
		return errors.New(labelsUsage)
	}
	var result any
	var e error
	switch command {
	case "list":
		result, e = c.Labels(ctx, search, offset, limit)
	case "choices":
		result, e = c.LabelChoices(ctx)
	case "audit":
		result, e = c.LabelAudit(ctx, offset, limit)
	case "save":
		var in sessionclient.LabelInput
		if e = operationJSON(file, stdin, &in); e == nil {
			result, e = c.SaveLabel(ctx, id, in)
		}
	case "binding":
		result, e = c.LabelBinding(ctx, resource)
	case "bind":
		var in sessionclient.LabelBindingInput
		if e = operationJSON(file, stdin, &in); e == nil {
			result, e = c.BindLabels(ctx, resource, in)
		}
	case "delete":
		if requestID == "" {
			return errors.New(labelsUsage)
		}
		e = c.DeleteLabel(ctx, id, revision, requestID)
		result = map[string]bool{"deleted": e == nil}
	}
	if e != nil {
		return e
	}
	return json.NewEncoder(out).Encode(result)
}
