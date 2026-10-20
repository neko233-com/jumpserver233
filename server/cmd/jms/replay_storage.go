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

const replayStorageUsage = "usage: jms replay-storage settings | save --file JSON_OR_- | records|audit [--offset 0 --limit 50] | get KIND SESSION_ID | archive|retry|verify|evict KIND SESSION_ID --request-id ID"

func runReplayStorage(args []string) error {
	endpoint := os.Getenv("JMS_SERVER_URL")
	if endpoint == "" {
		endpoint = "http://127.0.0.1:8080"
	}
	c, e := clientFromEnvironment(endpoint, "")
	if e != nil {
		return e
	}
	return executeReplayStorage(context.Background(), c, args, os.Stdin, os.Stdout)
}
func executeReplayStorage(ctx context.Context, c *sessionclient.Client, args []string, in io.Reader, out io.Writer) error {
	if len(args) == 0 {
		return errors.New(replayStorageUsage)
	}
	command, args := args[0], args[1:]
	ref := sessionclient.ReplayStorageRef{}
	if command == "get" || command == "archive" || command == "retry" || command == "verify" || command == "evict" {
		if len(args) < 2 {
			return errors.New(replayStorageUsage)
		}
		ref.Kind, ref.SessionID, args = args[0], args[1], args[2:]
	}
	fs := flag.NewFlagSet("replay-storage", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	var file, request string
	offset, limit := 0, 50
	switch command {
	case "settings", "get":
	case "records", "audit":
		fs.IntVar(&offset, "offset", 0, "")
		fs.IntVar(&limit, "limit", 50, "")
	case "save":
		fs.StringVar(&file, "file", "", "")
	case "archive", "retry", "verify", "evict":
		fs.StringVar(&request, "request-id", "", "")
	default:
		return errors.New(replayStorageUsage)
	}
	if fs.Parse(args) != nil || fs.NArg() != 0 {
		return errors.New(replayStorageUsage)
	}
	var result any
	var e error
	switch command {
	case "settings":
		result, e = c.ReplayStorage(ctx)
	case "save":
		var v sessionclient.ReplayStorageInput
		if e = operationJSON(file, in, &v); e == nil {
			result, e = c.SaveReplayStorage(ctx, v)
		}
	case "records":
		result, e = c.ReplayStorageRecords(ctx, offset, limit)
	case "audit":
		result, e = c.ReplayStorageAudit(ctx, offset, limit)
	case "get":
		result, e = c.ReplayStorageRecord(ctx, ref)
	default:
		result, e = c.ReplayStorageAction(ctx, ref, command, request)
	}
	if e != nil {
		return e
	}
	return json.NewEncoder(out).Encode(result)
}
