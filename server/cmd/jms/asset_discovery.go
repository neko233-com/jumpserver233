package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"github.com/neko233-com/jumpserver233/server/internal/core/assetdiscovery"
	"github.com/neko233-com/jumpserver233/server/internal/sessionclient"
	"io"
	"os"
)

const assetDiscoveryUsage = "usage: jms discover sources|policies|runs|findings|audit [--source ID --offset 0 --limit 100] | source|policy save [ID] --file CONFIG.json | source show ID | source|policy delete ID --revision N | run start --file RUN.json | run show|cancel ID | preview|import --file INPUT.json | export --source ID"

func runAssetDiscovery(args []string) error {
	endpoint := os.Getenv("JMS_SERVER_URL")
	if endpoint == "" {
		endpoint = "http://127.0.0.1:8080"
	}
	c, e := clientFromEnvironment(endpoint, "")
	if e != nil {
		return e
	}
	return executeAssetDiscovery(context.Background(), c, args, os.Stdin, os.Stdout)
}
func executeAssetDiscovery(ctx context.Context, c *sessionclient.Client, args []string, input io.Reader, output io.Writer) error {
	if len(args) == 0 {
		return errors.New(assetDiscoveryUsage)
	}
	command := args[0]
	rest := args[1:]
	action, id := "", ""
	if command == "source" || command == "policy" || command == "run" {
		if len(rest) == 0 {
			return errors.New(assetDiscoveryUsage)
		}
		action = rest[0]
		rest = rest[1:]
		if len(rest) > 0 && rest[0] != "" && rest[0][0] != '-' {
			id = rest[0]
			rest = rest[1:]
		}
	}
	flags := flag.NewFlagSet("discover", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	file := flags.String("file", "", "")
	source := flags.String("source", "", "")
	revision := flags.Int("revision", 0, "")
	offset := flags.Int("offset", 0, "")
	limit := flags.Int("limit", 100, "")
	if flags.Parse(rest) != nil || flags.NArg() != 0 || *offset < 0 || *offset > 100000 || *limit < 1 || *limit > 500 {
		return errors.New(assetDiscoveryUsage)
	}
	decode := func(v any) error {
		if *file == "" {
			return errors.New(assetDiscoveryUsage)
		}
		reader := input
		if *file != "-" {
			f, e := os.Open(*file)
			if e != nil {
				return e
			}
			defer f.Close()
			reader = f
		}
		d := json.NewDecoder(io.LimitReader(reader, 512<<10))
		d.DisallowUnknownFields()
		if d.Decode(v) != nil || d.Decode(new(any)) != io.EOF {
			return errors.New("invalid discovery JSON")
		}
		return nil
	}
	emit := func(v any, e error) error {
		if e != nil {
			return e
		}
		return json.NewEncoder(output).Encode(v)
	}
	switch command {
	case "sources":
		return emit(c.DiscoverySources(ctx))
	case "policies":
		return emit(c.DiscoveryPolicies(ctx))
	case "runs":
		return emit(c.DiscoveryRuns(ctx, *source, *offset, *limit))
	case "findings":
		if *source == "" {
			return errors.New(assetDiscoveryUsage)
		}
		return emit(c.DiscoveryFindings(ctx, *source, *offset, *limit))
	case "audit":
		return emit(c.DiscoveryAudit(ctx, *offset, *limit))
	case "export":
		if *source == "" {
			return errors.New(assetDiscoveryUsage)
		}
		return c.ExportDiscoveryFindings(ctx, *source, output)
	case "source":
		switch action {
		case "show":
			if id != "" {
				return emit(c.DiscoverySource(ctx, id))
			}
		case "save":
			var in assetdiscovery.SourceInput
			if e := decode(&in); e != nil {
				return e
			}
			return emit(c.SaveDiscoverySource(ctx, id, in))
		case "delete":
			if id != "" && *revision > 0 {
				return c.DeleteDiscoverySource(ctx, id, *revision)
			}
		}
	case "policy":
		switch action {
		case "save":
			var in assetdiscovery.PolicyInput
			if e := decode(&in); e != nil {
				return e
			}
			return emit(c.SaveDiscoveryPolicy(ctx, id, in))
		case "delete":
			if id != "" && *revision > 0 {
				return c.DeleteDiscoveryPolicy(ctx, id, *revision)
			}
		}
	case "run":
		switch action {
		case "start":
			if id != "" {
				break
			}
			var in assetdiscovery.RunInput
			if e := decode(&in); e != nil {
				return e
			}
			return emit(c.StartDiscoveryRun(ctx, in))
		case "show":
			if id != "" {
				return emit(c.DiscoveryRun(ctx, id))
			}
		case "cancel":
			if id != "" {
				return emit(c.CancelDiscoveryRun(ctx, id))
			}
		}
	case "preview":
		var in assetdiscovery.PreviewInput
		if e := decode(&in); e != nil {
			return e
		}
		return emit(c.PreviewDiscoveryImport(ctx, in))
	case "import":
		var in assetdiscovery.ImportInput
		if e := decode(&in); e != nil {
			return e
		}
		return emit(c.ImportDiscoveryAssets(ctx, in))
	}
	return errors.New(assetDiscoveryUsage)
}
