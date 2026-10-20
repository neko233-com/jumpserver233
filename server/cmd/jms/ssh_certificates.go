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

const sshCertificatesUsage = "usage: jms ssh-certificates list | audit [--offset 0 --limit 50] | save [ISSUER_ID] --file JSON_OR_- | rotate|activate|delete ISSUER_ID --revision N --request-id ID | binding ASSET_OR_ACCOUNT_ID | bind ASSET_OR_ACCOUNT_ID --file JSON_OR_-"

func runSSHCertificates(args []string) error {
	endpoint := os.Getenv("JMS_SERVER_URL")
	if endpoint == "" {
		endpoint = "http://127.0.0.1:8080"
	}
	client, e := clientFromEnvironment(endpoint, "")
	if e != nil {
		return e
	}
	return executeSSHCertificates(context.Background(), client, args, os.Stdin, os.Stdout)
}
func executeSSHCertificates(ctx context.Context, c *sessionclient.Client, args []string, in io.Reader, out io.Writer) error {
	if len(args) == 0 {
		return errors.New(sshCertificatesUsage)
	}
	command := args[0]
	args = args[1:]
	id := ""
	if command == "save" && len(args) > 0 && len(args[0]) > 0 && args[0][0] != '-' {
		id, args = args[0], args[1:]
	}
	if command == "binding" || command == "bind" || command == "rotate" || command == "activate" || command == "delete" {
		if len(args) == 0 {
			return errors.New(sshCertificatesUsage)
		}
		id, args = args[0], args[1:]
	}
	fs := flag.NewFlagSet("ssh-certificates", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	var offset, limit, revision int
	var file, request string
	switch command {
	case "list", "binding":
	case "audit":
		fs.IntVar(&offset, "offset", 0, "")
		fs.IntVar(&limit, "limit", 50, "")
	case "save", "bind":
		fs.StringVar(&file, "file", "", "")
	case "rotate", "activate", "delete":
		fs.IntVar(&revision, "revision", 0, "")
		fs.StringVar(&request, "request-id", "", "")
	default:
		return errors.New(sshCertificatesUsage)
	}
	if fs.Parse(args) != nil || fs.NArg() != 0 {
		return errors.New(sshCertificatesUsage)
	}
	var result any
	var e error
	switch command {
	case "list":
		result, e = c.SSHIssuers(ctx)
	case "audit":
		result, e = c.SSHCertificateAudit(ctx, offset, limit)
	case "save":
		var v sessionclient.SSHIssuerInput
		if e = operationJSON(file, in, &v); e == nil {
			result, e = c.SaveSSHIssuer(ctx, id, v)
		}
	case "binding":
		result, e = c.SSHCertificateBinding(ctx, id)
	case "bind":
		var v sessionclient.SSHCertificateBindingInput
		if e = operationJSON(file, in, &v); e == nil {
			result, e = c.BindSSHCertificate(ctx, id, v)
		}
	case "rotate":
		result, e = c.RotateSSHIssuer(ctx, id, revision, request)
	case "activate":
		result, e = c.ActivateSSHIssuer(ctx, id, revision, request)
	case "delete":
		e = c.DeleteSSHIssuer(ctx, id, revision, request)
		result = map[string]bool{"deleted": e == nil}
	}
	if e != nil {
		return e
	}
	return json.NewEncoder(out).Encode(result)
}
