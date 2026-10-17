package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"os"
	"strings"

	"github.com/neko233-com/jumpserver233/server/internal/sessionclient"
)

const accountRiskUsage = "jms account risks policy | policy-update --revision N [--enabled=true] [--interval-hours N] [--min-length N] [--max-age-days N] [--unused-days N] [--checks a,b] | scan --revision N [--request-id ID] | findings [--state open] [--kind KIND] [--asset ID] [--search TEXT] [--offset 0] [--limit 50] | review ID --revision N --action confirm|ignore|reopen [--note TEXT] | scans|audit [--offset 0] [--limit 50] | cancel SCAN_ID | export --out NEW.csv [filters]"

func executeAccountRisks(ctx context.Context, c *sessionclient.Client, args []string, out io.Writer) error {
	if len(args) == 0 {
		return errors.New(accountRiskUsage)
	}
	f := flag.NewFlagSet("account-risks", flag.ContinueOnError)
	f.SetOutput(io.Discard)
	emit := func(v any, e error) error {
		if e != nil {
			return e
		}
		return json.NewEncoder(out).Encode(v)
	}
	switch args[0] {
	case "policy":
		if len(args) != 1 {
			return errors.New(accountRiskUsage)
		}
		p, e := c.AccountRiskPolicy(ctx)
		return emit(p, e)
	case "policy-update":
		revision := f.Int("revision", 0, "")
		enabled := f.Bool("enabled", false, "")
		hours := f.Int("interval-hours", 24, "")
		minLength := f.Int("min-length", 14, "")
		maxAge := f.Int("max-age-days", 7, "")
		unused := f.Int("unused-days", 90, "")
		disabled := f.Bool("include-disabled", false, "")
		resolved := f.Int("resolved-retention-days", 90, "")
		audit := f.Int("audit-retention-days", 365, "")
		checks := f.String("checks", "", "")
		if f.Parse(args[1:]) != nil || f.NArg() != 0 || *revision < 1 {
			return errors.New(accountRiskUsage)
		}
		p, e := c.AccountRiskPolicy(ctx)
		if e != nil {
			return e
		}
		p.Revision = *revision
		f.Visit(func(v *flag.Flag) {
			switch v.Name {
			case "enabled":
				p.Enabled = *enabled
			case "interval-hours":
				p.IntervalHours = *hours
			case "min-length":
				p.MinPasswordLength = *minLength
			case "max-age-days":
				p.MaxCredentialAgeDays = *maxAge
			case "unused-days":
				p.UnusedAccountDays = *unused
			case "include-disabled":
				p.IncludeDisabled = *disabled
			case "resolved-retention-days":
				p.ResolvedRetentionDays = *resolved
			case "audit-retention-days":
				p.AuditRetentionDays = *audit
			case "checks":
				p.Checks = strings.Split(*checks, ",")
			}
		})
		v, e := c.SaveAccountRiskPolicy(ctx, p)
		return emit(v, e)
	case "scan":
		revision := f.Int("revision", 0, "")
		requestID := f.String("request-id", "", "")
		if f.Parse(args[1:]) != nil || f.NArg() != 0 || *revision < 1 {
			return errors.New(accountRiskUsage)
		}
		if *requestID == "" {
			var id [16]byte
			if _, e := rand.Read(id[:]); e != nil {
				return e
			}
			*requestID = hex.EncodeToString(id[:])
		}
		v, e := c.ScanAccountRisks(ctx, *revision, *requestID)
		return emit(v, e)
	case "review":
		if len(args) < 2 {
			return errors.New(accountRiskUsage)
		}
		revision := f.Int("revision", 0, "")
		action := f.String("action", "", "")
		note := f.String("note", "", "")
		if f.Parse(args[2:]) != nil || f.NArg() != 0 || *revision < 1 || *action != "confirm" && *action != "ignore" && *action != "reopen" {
			return errors.New(accountRiskUsage)
		}
		v, e := c.ReviewAccountRisk(ctx, args[1], *revision, *action, *note)
		return emit(v, e)
	case "cancel":
		if len(args) != 2 {
			return errors.New(accountRiskUsage)
		}
		if e := c.CancelAccountRiskScan(ctx, args[1]); e != nil {
			return e
		}
		return emit(map[string]string{"state": "cancelling"}, nil)
	case "findings", "export", "scans", "audit":
		offset, limit := f.Int("offset", 0, ""), f.Int("limit", 50, "")
		state, kind, asset, search := f.String("state", "", ""), f.String("kind", "", ""), f.String("asset", "", ""), f.String("search", "", "")
		output := f.String("out", "", "")
		if f.Parse(args[1:]) != nil || f.NArg() != 0 || *offset < 0 || *limit < 1 || *limit > 200 {
			return errors.New(accountRiskUsage)
		}
		if (args[0] == "scans" || args[0] == "audit") && (*limit > 100 || *state != "" || *kind != "" || *asset != "" || *search != "") {
			return errors.New(accountRiskUsage)
		}
		q := sessionclient.AccountRiskQuery{Offset: *offset, Limit: *limit, State: *state, Kind: *kind, AssetID: *asset, Search: *search}
		if args[0] == "export" {
			if *output == "" {
				return errors.New(accountRiskUsage)
			}
			data, e := c.ExportAccountRisks(ctx, q)
			if e != nil {
				return e
			}
			file, e := os.OpenFile(*output, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
			if e != nil {
				return errors.New("choose a new account risk export file")
			}
			_, e = file.Write(data)
			ce := file.Close()
			if e != nil || ce != nil {
				return errors.New("could not save account risk export")
			}
			return emit(map[string]string{"state": "saved"}, nil)
		}
		if *output != "" {
			return errors.New(accountRiskUsage)
		}
		var results any
		var total int
		var e error
		switch args[0] {
		case "findings":
			results, total, e = c.AccountRiskFindings(ctx, q)
		case "scans":
			results, total, e = c.AccountRiskScans(ctx, *offset, *limit)
		case "audit":
			results, total, e = c.AccountRiskAudit(ctx, *offset, *limit)
		}
		return emit(map[string]any{"results": results, "total": total}, e)
	}
	return errors.New(accountRiskUsage)
}
