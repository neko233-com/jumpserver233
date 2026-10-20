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

const pamUsage = "usage: jms pam discover ASSET_ID | platform ASSET_ID --file JSON_OR_- | preview ASSET_ID --file JSON_OR_- | commit ASSET_ID --file JSON_OR_-"

func runPAM(args []string) error {
	endpoint := os.Getenv("JMS_SERVER_URL")
	if endpoint == "" {
		endpoint = "http://127.0.0.1:8080"
	}
	c, e := clientFromEnvironment(endpoint, "")
	if e != nil {
		return e
	}
	return executePAM(context.Background(), c, args, os.Stdin, os.Stdout)
}
func executePAM(ctx context.Context, c *sessionclient.Client, args []string, stdin io.Reader, out io.Writer) error {
	if len(args) < 2 {
		return errors.New(pamUsage)
	}
	command, id := args[0], args[1]
	fs := flag.NewFlagSet("pam", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	var file string
	switch command {
	case "discover":
	case "platform", "preview", "commit":
		fs.StringVar(&file, "file", "", "")
	default:
		return errors.New(pamUsage)
	}
	if fs.Parse(args[2:]) != nil || fs.NArg() != 0 {
		return errors.New(pamUsage)
	}
	var result any
	var e error
	switch command {
	case "discover":
		result, e = c.PAMPrincipals(ctx, id)
	case "platform":
		var in sessionclient.PAMPlatformInput
		if e = operationJSON(file, stdin, &in); e == nil {
			result, e = c.ConfigurePAMPlatform(ctx, id, in)
		}
	case "preview", "commit":
		var in sessionclient.PAMImportInput
		if e = operationJSON(file, stdin, &in); e == nil {
			if command == "preview" {
				result, e = c.PreviewPAMImport(ctx, id, in)
			} else {
				result, e = c.CommitPAMImport(ctx, id, in)
			}
		}
	}
	if e != nil {
		return e
	}
	return json.NewEncoder(out).Encode(result)
}
