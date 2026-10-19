package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"github.com/neko233-com/jumpserver233/server/internal/sessionclient"
	"io"
	"os"
	"time"
)

const monitorUsage = "usage: jms monitor history ASSET_ID [--from RFC3339 --to RFC3339 --step 60] | rules|alerts|audit|health [--offset 0 --limit 25 --state firing --query TEXT] | alert ID | rule-save [ID] --file INPUT.json (or - for stdin) | rule-delete ID --revision N | mute ID --revision N --until RFC3339 [--comment TEXT] | unmute ID --revision N | acknowledge ID --revision N [--comment TEXT]"

func runMonitor(args []string) error {
	endpoint := os.Getenv("JMS_SERVER_URL")
	if endpoint == "" {
		endpoint = "http://127.0.0.1:8080"
	}
	c, e := clientFromEnvironment(endpoint, "")
	if e != nil {
		return e
	}
	return executeMonitor(context.Background(), c, args, os.Stdin, os.Stdout)
}
func executeMonitor(ctx context.Context, c *sessionclient.Client, args []string, input io.Reader, output io.Writer) error {
	if len(args) == 0 {
		return errors.New(monitorUsage)
	}
	action, id, start := args[0], "", 1
	switch action {
	case "history", "alert", "rule-delete", "mute", "unmute", "acknowledge":
		if len(args) < 2 {
			return errors.New(monitorUsage)
		}
		id, start = args[1], 2
	case "rule-save":
		if len(args) > 1 && args[1] != "--file" {
			id, start = args[1], 2
		}
	}
	f := flag.NewFlagSet("monitor", flag.ContinueOnError)
	f.SetOutput(io.Discard)
	offset, limit := f.Int("offset", 0, ""), f.Int("limit", 25, "")
	state, query := f.String("state", "", ""), f.String("query", "", "")
	revision := f.Int("revision", 0, "")
	file := f.String("file", "", "")
	until, comment := f.String("until", "", ""), f.String("comment", "", "")
	from, to, step := f.String("from", "", ""), f.String("to", "", ""), f.Int("step", 60, "")
	if f.Parse(args[start:]) != nil || f.NArg() != 0 || *offset < 0 || *limit < 1 || *limit > 200 {
		return errors.New(monitorUsage)
	}
	emit := func(v any, e error) error {
		if e != nil {
			return e
		}
		return json.NewEncoder(output).Encode(v)
	}
	switch action {
	case "history":
		end := time.Now().UTC()
		start := end.Add(-time.Hour)
		var parseErr error
		if *to != "" {
			end, parseErr = time.Parse(time.RFC3339Nano, *to)
			if parseErr != nil {
				return errors.New(monitorUsage)
			}
			start = end.Add(-time.Hour)
		}
		if *from != "" {
			start, parseErr = time.Parse(time.RFC3339Nano, *from)
			if parseErr != nil {
				return errors.New(monitorUsage)
			}
		}
		v, e := c.MonitorHistory(ctx, id, start, end, *step)
		return emit(v, e)
	case "rules":
		v, e := c.MonitorRules(ctx)
		return emit(v, e)
	case "alerts":
		v, e := c.MonitorAlerts(ctx, *offset, *limit, *state, *query)
		return emit(v, e)
	case "alert":
		v, e := c.MonitorAlert(ctx, id)
		return emit(v, e)
	case "audit":
		v, e := c.MonitorAudit(ctx, *offset, *limit)
		return emit(v, e)
	case "health":
		v, e := c.MonitorHealth(ctx)
		return emit(v, e)
	case "rule-delete":
		if *revision < 1 {
			return errors.New(monitorUsage)
		}
		return c.DeleteMonitorRule(ctx, id, *revision)
	case "mute", "unmute":
		if *revision < 1 {
			return errors.New(monitorUsage)
		}
		var at time.Time
		var e error
		if action == "mute" {
			at, e = time.Parse(time.RFC3339, *until)
			if e != nil {
				return errors.New(monitorUsage)
			}
		}
		v, e := c.MuteMonitorRule(ctx, id, *revision, at, *comment)
		return emit(v, e)
	case "acknowledge":
		if *revision < 1 {
			return errors.New(monitorUsage)
		}
		v, e := c.AcknowledgeMonitorAlert(ctx, id, *revision, *comment)
		return emit(v, e)
	case "rule-save":
		if *file == "" {
			return errors.New(monitorUsage)
		}
		source := input
		if *file != "-" {
			fd, e := os.Open(*file)
			if e != nil {
				return errors.New("cannot read monitoring rule")
			}
			defer fd.Close()
			source = fd
		}
		var in sessionclient.MonitorRuleInput
		dec := json.NewDecoder(io.LimitReader(source, (128<<10)+1))
		dec.DisallowUnknownFields()
		if dec.Decode(&in) != nil || dec.Decode(new(any)) != io.EOF {
			return errors.New("invalid monitoring rule JSON")
		}
		v, e := c.SaveMonitorRule(ctx, id, in)
		return emit(v, e)
	}
	return errors.New(monitorUsage)
}
