package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"github.com/neko233-com/jumpserver233/server/internal/sessionclient"
	"io"
	"os"
	"strings"
)

const notificationUsage = "usage: jms notifications list|deliveries|audit [--offset 0 --limit 25 --unread --state STATE] | preferences|settings|health | preferences-save|settings-save --file FILE.json (or - for stdin) | read ID | read-all | test --request-id ID | request-code email|sms | verify email|sms --code-stdin | retry ID --revision N [--acknowledge-uncertain]"

func runNotifications(args []string) error {
	endpoint := os.Getenv("JMS_SERVER_URL")
	if endpoint == "" {
		endpoint = "http://127.0.0.1:8080"
	}
	c, e := clientFromEnvironment(endpoint, "")
	if e != nil {
		return e
	}
	return executeNotifications(context.Background(), c, args, os.Stdin, os.Stdout)
}
func executeNotifications(ctx context.Context, c *sessionclient.Client, args []string, input io.Reader, out io.Writer) error {
	if len(args) == 0 {
		return errors.New(notificationUsage)
	}
	f := flag.NewFlagSet("notifications", flag.ContinueOnError)
	f.SetOutput(io.Discard)
	action, id, start := args[0], "", 1
	switch action {
	case "read", "retry", "request-code", "verify":
		if len(args) < 2 {
			return errors.New(notificationUsage)
		}
		id = args[1]
		start = 2
	}
	offset, limit := f.Int("offset", 0, ""), f.Int("limit", 25, "")
	unread, state := f.Bool("unread", false, ""), f.String("state", "", "")
	revision, ack := f.Int("revision", 0, ""), f.Bool("acknowledge-uncertain", false, "")
	file, requestID, codeStdin := f.String("file", "", ""), f.String("request-id", "", ""), f.Bool("code-stdin", false, "")
	if f.Parse(args[start:]) != nil || f.NArg() != 0 || *offset < 0 || *limit < 1 || *limit > 100 {
		return errors.New(notificationUsage)
	}
	emit := func(v any, e error) error {
		if e != nil {
			return e
		}
		return json.NewEncoder(out).Encode(v)
	}
	read := func(v any) error {
		if *file == "" {
			return errors.New(notificationUsage)
		}
		source := input
		if *file != "-" {
			fd, e := os.Open(*file)
			if e != nil {
				return errors.New("cannot read notification input")
			}
			defer fd.Close()
			source = fd
		}
		dec := json.NewDecoder(io.LimitReader(source, (256<<10)+1))
		dec.DisallowUnknownFields()
		if dec.Decode(v) != nil || dec.Decode(new(any)) != io.EOF {
			return errors.New("invalid notification JSON input")
		}
		return nil
	}
	switch action {
	case "list":
		v, e := c.Notifications(ctx, *unread, *offset, *limit)
		return emit(v, e)
	case "deliveries":
		v, e := c.NotificationDeliveries(ctx, *state, *offset, *limit)
		return emit(v, e)
	case "audit":
		v, e := c.NotificationAudit(ctx, *offset, *limit)
		return emit(v, e)
	case "preferences":
		v, e := c.NotificationPreferences(ctx)
		return emit(v, e)
	case "settings":
		v, e := c.NotificationSettings(ctx)
		return emit(v, e)
	case "health":
		v, e := c.NotificationHealth(ctx)
		return emit(v, e)
	case "preferences-save":
		var v sessionclient.NotificationPreferencesInput
		if e := read(&v); e != nil {
			return e
		}
		p, e := c.SaveNotificationPreferences(ctx, v)
		return emit(p, e)
	case "settings-save":
		var v sessionclient.NotificationSettingsInput
		if e := read(&v); e != nil {
			return e
		}
		p, e := c.SaveNotificationSettings(ctx, v)
		return emit(p, e)
	case "read":
		if e := c.ReadNotification(ctx, id, false); e != nil {
			return e
		}
		return emit(map[string]bool{"ok": true}, nil)
	case "read-all":
		if e := c.ReadNotification(ctx, "", true); e != nil {
			return e
		}
		return emit(map[string]bool{"ok": true}, nil)
	case "test":
		if *requestID == "" {
			return errors.New(notificationUsage)
		}
		v, e := c.TestNotification(ctx, *requestID)
		return emit(v, e)
	case "request-code":
		v, e := c.RequestContactVerification(ctx, id)
		return emit(v, e)
	case "verify":
		if !*codeStdin {
			return errors.New(notificationUsage)
		}
		raw, e := io.ReadAll(io.LimitReader(input, 18))
		if e != nil {
			return errors.New("cannot read verification code")
		}
		code := strings.TrimSpace(string(raw))
		if len(code) != 6 || strings.Trim(code, "0123456789") != "" {
			return errors.New("invalid verification code")
		}
		v, e := c.VerifyNotificationContact(ctx, id, code)
		return emit(v, e)
	case "retry":
		if *revision < 1 {
			return errors.New(notificationUsage)
		}
		v, e := c.RetryNotification(ctx, id, *revision, *ack)
		return emit(v, e)
	default:
		return errors.New(notificationUsage)
	}
}
