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
	"time"
)

const reportsUsage = "usage: jms reports overview|export [--from RFC3339 --to RFC3339 --sources ID,ID --include-platform --allow-partial] | exports [--all --offset N --limit N] | organizations [--include-archived]"

func runReports(args []string) error {
	endpoint := os.Getenv("JMS_SERVER_URL")
	if endpoint == "" {
		endpoint = "http://127.0.0.1:8080"
	}
	c, e := clientFromEnvironment(endpoint, "")
	if e != nil {
		return e
	}
	return executeReports(context.Background(), c, args, os.Stdout)
}
func executeReports(ctx context.Context, c *sessionclient.Client, args []string, out io.Writer) error {
	if len(args) == 0 {
		return errors.New(reportsUsage)
	}
	f := flag.NewFlagSet("reports", flag.ContinueOnError)
	f.SetOutput(io.Discard)
	from, to, sources := f.String("from", "", ""), f.String("to", "", ""), f.String("sources", "", "")
	platform, partial, all := f.Bool("include-platform", false, ""), f.Bool("allow-partial", false, ""), f.Bool("all", false, "")
	offset, limit := f.Int("offset", 0, ""), f.Int("limit", 25, "")
	archived := f.Bool("include-archived", false, "")
	if f.Parse(args[1:]) != nil || f.NArg() != 0 || *offset < 0 || *limit < 1 || *limit > 100 {
		return errors.New(reportsUsage)
	}
	if args[0] == "organizations" {
		invalid := false
		f.Visit(func(v *flag.Flag) {
			if v.Name != "include-archived" {
				invalid = true
			}
		})
		if invalid {
			return errors.New(reportsUsage)
		}
		value, err := c.OrganizationOverview(ctx, *archived)
		if err != nil {
			return err
		}
		return json.NewEncoder(out).Encode(value)
	}
	if *archived {
		return errors.New(reportsUsage)
	}
	q := sessionclient.ReportQuery{IncludePlatform: *platform}
	var e error
	if *from != "" {
		q.From, e = time.Parse(time.RFC3339, *from)
	}
	if e == nil && *to != "" {
		q.To, e = time.Parse(time.RFC3339, *to)
	}
	if e != nil {
		return errors.New("invalid report time range")
	}
	if *sources != "" {
		q.Sources = strings.Split(*sources, ",")
	}
	switch args[0] {
	case "overview":
		v, e := c.ReportOverview(ctx, q)
		if e != nil {
			return e
		}
		return json.NewEncoder(out).Encode(v)
	case "exports":
		v, e := c.ReportExportHistory(ctx, *all, *offset, *limit)
		if e != nil {
			return e
		}
		return json.NewEncoder(out).Encode(v)
	case "export":
		_, e := c.ExportReport(ctx, q, *partial, out)
		return e
	}
	return errors.New(reportsUsage)
}
