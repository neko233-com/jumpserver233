// jms-agent is a local recovery helper. It has no listener, platform token,
// remote SSH password, arbitrary-command facility or external network client.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/neko233-com/jumpserver233/server/internal/hostagent"
)

func run(args []string) int {
	if len(args) == 1 && args[0] == "account-admin-install" {
		raw, e := hostagent.AccountAdminInstallJSON()
		if e != nil {
			_ = json.NewEncoder(os.Stdout).Encode(map[string]string{"error": "remote_account_unavailable"})
			return 1
		}
		fmt.Fprintln(os.Stdout, string(raw))
		return 0
	}
	if len(args) == 1 && args[0] == "account-admin" {
		raw, e := io.ReadAll(io.LimitReader(os.Stdin, hostagent.MaxAccountAdminBytes+1))
		if e != nil {
			return 2
		}
		req, e := hostagent.DecodeAccountAdminRequest(raw)
		if e != nil {
			return 2
		}
		ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM, syscall.SIGHUP)
		defer cancel()
		ctx, timeout := context.WithTimeout(ctx, 90*time.Second)
		defer timeout()
		result, e := hostagent.RunAccountAdmin(ctx, req)
		if result.Format == "" {
			_ = json.NewEncoder(os.Stdout).Encode(map[string]string{"error": "remote_account_unavailable"})
			return 1
		}
		if json.NewEncoder(os.Stdout).Encode(result) != nil {
			return 1
		}
		if e != nil {
			return 1
		}
		return 0
	}
	if len(args) > 0 && args[0] == "accounts" {
		flags := flag.NewFlagSet("accounts", flag.ContinueOnError)
		flags.SetOutput(io.Discard)
		offset := flags.Int("offset", 0, "")
		if flags.Parse(args[1:]) != nil || flags.NArg() != 0 {
			return 2
		}
		page, e := hostagent.LocalAccountPage(*offset)
		if e != nil {
			_ = json.NewEncoder(os.Stdout).Encode(map[string]string{"error": "account_inventory_unavailable"})
			return 1
		}
		if json.NewEncoder(os.Stdout).Encode(page) != nil {
			return 1
		}
		return 0
	}
	if len(args) > 0 && args[0] == "supervise" {
		flags := flag.NewFlagSet("supervise", flag.ContinueOnError)
		flags.SetOutput(io.Discard)
		dir := flags.String("directory", "", "")
		plugin := flags.String("plugin", "", "")
		hash := flags.String("launcher-sha", "", "")
		if flags.Parse(args[1:]) != nil || flags.NArg() != 0 {
			return 2
		}
		ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer cancel()
		if e := hostagent.Supervise(ctx, *dir, *plugin, *hash); e != nil {
			return 1
		}
		return 0
	}

	if len(args) == 1 && args[0] == "version" {
		fmt.Println(hostagent.Version)
		return 0
	}
	if len(args) == 0 || args[0] != "check" && args[0] != "restore" && args[0] != "events" {
		return 2
	}
	flags := flag.NewFlagSet("jms-agent", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	dir := flags.String("directory", "", "")
	hash := flags.String("config-sha", "", "")
	trigger := flags.String("trigger", "manual", "")
	after := flags.Uint64("after", 0, "")
	stream := flags.String("stream", "", "")
	anchor := flags.String("anchor", "", "")
	limit := flags.Int("limit", hostagent.EventBatchLimit, "")
	if flags.Parse(args[1:]) != nil || flags.NArg() != 0 {
		return 2
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if args[0] == "events" {
		if *hash != "" || *trigger != "manual" {
			return 2
		}
		page, e := hostagent.ReadEvents(*dir, hostagent.EventCursor{Stream: *stream, Sequence: *after, Hash: *anchor}, *limit)
		if e != nil {
			_ = json.NewEncoder(os.Stdout).Encode(map[string]string{"state": "unknown", "error": e.Error()})
			return 12
		}
		_ = json.NewEncoder(os.Stdout).Encode(page)
		return 0
	}
	if *after != 0 || *stream != "" || *anchor != "" || *limit != hostagent.EventBatchLimit || args[0] == "check" && *trigger != "manual" {
		return 2
	}
	var report hostagent.Report
	var err error
	if args[0] == "check" {
		report, err = hostagent.Check(ctx, *dir, *hash)
	} else {
		report, err = hostagent.Restore(ctx, *dir, *hash, *trigger)
	}
	if err != nil {
		_ = json.NewEncoder(os.Stdout).Encode(map[string]string{"state": "unknown", "error": err.Error()})
		if errors.Is(err, hostagent.ErrForeign) {
			return 11
		}
		return 1
	}
	_ = json.NewEncoder(os.Stdout).Encode(report)
	if args[0] == "check" && report.State == "required" {
		return 10
	}
	return 0
}

func main() { os.Exit(run(os.Args[1:])) }
