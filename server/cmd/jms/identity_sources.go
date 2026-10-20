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

const identitySourcesUsage = "usage: jms identity-sources list|audit|get ID|save [ID] --file JSON_OR_- | sync ID settings|save|entries|runs|audit|preview|apply|abort [--file JSON_OR_- --offset 0 --limit 100]"

func runIdentitySources(args []string) error {
	endpoint := os.Getenv("JMS_SERVER_URL")
	if endpoint == "" {
		endpoint = "http://127.0.0.1:8080"
	}
	c, e := clientFromEnvironment(endpoint, "")
	if e != nil {
		return e
	}
	return executeIdentitySources(context.Background(), c, args, os.Stdin, os.Stdout)
}
func executeIdentitySources(ctx context.Context, c *sessionclient.Client, args []string, in io.Reader, out io.Writer) error {
	if len(args) == 0 {
		return errors.New(identitySourcesUsage)
	}
	command, args := args[0], args[1:]
	id, resource := "", ""
	if command == "get" {
		if len(args) < 1 {
			return errors.New(identitySourcesUsage)
		}
		id, args = args[0], args[1:]
	} else if command == "save" && len(args) > 0 && args[0] != "--file" {
		id, args = args[0], args[1:]
	} else if command == "sync" {
		if len(args) < 2 {
			return errors.New(identitySourcesUsage)
		}
		id, resource, args = args[0], args[1], args[2:]
	}
	fs := flag.NewFlagSet("identity-sources", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	file := ""
	offset, limit := 0, 100
	switch command {
	case "list", "audit", "get":
	case "save":
		fs.StringVar(&file, "file", "", "")
	case "sync":
		switch resource {
		case "settings":
		case "entries", "runs", "audit":
			fs.IntVar(&offset, "offset", 0, "")
			fs.IntVar(&limit, "limit", 100, "")
		case "save", "preview", "apply", "abort":
			fs.StringVar(&file, "file", "", "")
		default:
			return errors.New(identitySourcesUsage)
		}
	default:
		return errors.New(identitySourcesUsage)
	}
	if fs.Parse(args) != nil || fs.NArg() != 0 {
		return errors.New(identitySourcesUsage)
	}
	var result any
	var e error
	switch command {
	case "list":
		result, e = c.IdentitySources(ctx)
	case "audit":
		result, e = c.IdentitySourceAudit(ctx)
	case "get":
		result, e = c.IdentitySource(ctx, id)
	case "save":
		var v sessionclient.IdentitySourceInput
		if e = operationJSON(file, in, &v); e == nil {
			result, e = c.SaveIdentitySource(ctx, id, v)
		}
	case "sync":
		switch resource {
		case "settings":
			result, e = c.DirectorySync(ctx, id, "", offset, limit)
		case "entries", "runs", "audit":
			result, e = c.DirectorySync(ctx, id, resource, offset, limit)
		case "save":
			var raw json.RawMessage
			if e = operationJSON(file, in, &raw); e == nil {
				result, e = c.SaveDirectorySync(ctx, id, raw)
			}
		default:
			var v sessionclient.IdentitySyncOperation
			if e = operationJSON(file, in, &v); e == nil {
				result, e = c.DirectorySyncAction(ctx, id, resource, v)
			}
		}
	}
	if e != nil {
		return e
	}
	return json.NewEncoder(out).Encode(result)
}
