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

const announcementsUsage = "usage: jms announcements list [--manage] [--offset 0 --limit 20] | audit [--offset 0 --limit 20] | save [NOTICE_ID] --file JSON_OR_- | read NOTICE_ID --revision N | delete NOTICE_ID --revision N --request-id ID"

func runAnnouncements(args []string) error {
	endpoint := os.Getenv("JMS_SERVER_URL")
	if endpoint == "" {
		endpoint = "http://127.0.0.1:8080"
	}
	c, e := clientFromEnvironment(endpoint, "")
	if e != nil {
		return e
	}
	return executeAnnouncements(context.Background(), c, args, os.Stdin, os.Stdout)
}
func executeAnnouncements(ctx context.Context, c *sessionclient.Client, args []string, stdin io.Reader, out io.Writer) error {
	if len(args) == 0 {
		return errors.New(announcementsUsage)
	}
	command := args[0]
	args = args[1:]
	id := ""
	if command == "save" && len(args) > 0 && len(args[0]) > 0 && args[0][0] != '-' {
		id, args = args[0], args[1:]
	}
	if command == "read" || command == "delete" {
		if len(args) == 0 {
			return errors.New(announcementsUsage)
		}
		id, args = args[0], args[1:]
	}
	fs := flag.NewFlagSet("announcements", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	var offset, limit, revision int
	var manage bool
	var file, requestID string
	switch command {
	case "list", "audit":
		fs.IntVar(&offset, "offset", 0, "")
		fs.IntVar(&limit, "limit", 20, "")
		if command == "list" {
			fs.BoolVar(&manage, "manage", false, "")
		}
	case "save":
		fs.StringVar(&file, "file", "", "")
	case "read", "delete":
		fs.IntVar(&revision, "revision", 0, "")
		if command == "delete" {
			fs.StringVar(&requestID, "request-id", "", "")
		}
	default:
		return errors.New(announcementsUsage)
	}
	if fs.Parse(args) != nil || fs.NArg() != 0 {
		return errors.New(announcementsUsage)
	}
	var result any
	var e error
	switch command {
	case "list":
		result, e = c.Announcements(ctx, manage, offset, limit)
	case "audit":
		result, e = c.AnnouncementAudit(ctx, offset, limit)
	case "save":
		var in sessionclient.AnnouncementInput
		if e = operationJSON(file, stdin, &in); e == nil {
			result, e = c.SaveAnnouncement(ctx, id, in)
		}
	case "read":
		result, e = c.ReadAnnouncement(ctx, id, revision)
	case "delete":
		if requestID == "" {
			return errors.New(announcementsUsage)
		}
		e = c.DeleteAnnouncement(ctx, id, revision, requestID)
		result = map[string]bool{"deleted": e == nil}
	}
	if e != nil {
		return e
	}
	return json.NewEncoder(out).Encode(result)
}
