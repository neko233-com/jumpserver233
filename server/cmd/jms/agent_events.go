package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/neko233-com/jumpserver233/server/internal/sessionclient"
	"io"
	"os"
)

func runAgentEvents(args []string, selected ...string) error {
	endpoint := os.Getenv("JMS_SERVER_URL")
	if endpoint == "" {
		endpoint = "http://127.0.0.1:8080"
	}
	c, e := clientFromEnvironment(endpoint, selected...)
	if e != nil {
		return e
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30e9)
	defer cancel()
	return executeAgentEvents(ctx, c, args, os.Stdout)
}
func executeAgentEvents(ctx context.Context, c *sessionclient.Client, args []string, out io.Writer) error {
	if len(args) < 1 || args[0] == "" {
		return fmt.Errorf("usage: jms agent-events ASSET|all [--before N] | jms agent-events ASSET collection [--enable|--disable] [--interval 300] [--request-id ID]")
	}
	asset := args[0]
	if asset == "all" {
		asset = ""
	}
	f := flag.NewFlagSet("agent-events", flag.ContinueOnError)
	f.SetOutput(io.Discard)
	if len(args) > 1 && args[1] == "collection" {
		if asset == "" {
			return fmt.Errorf("collection requires an asset")
		}
		enable, disable := false, false
		interval := 300
		request := ""
		f.BoolVar(&enable, "enable", false, "")
		f.BoolVar(&disable, "disable", false, "")
		f.IntVar(&interval, "interval", 300, "")
		f.StringVar(&request, "request-id", "", "")
		if f.Parse(args[2:]) != nil || f.NArg() != 0 || enable && disable || interval < 60 || interval > 86400 {
			return fmt.Errorf("invalid collection flags")
		}
		if enable || disable {
			if request == "" {
				var raw [16]byte
				if _, e := rand.Read(raw[:]); e != nil {
					return e
				}
				request = hex.EncodeToString(raw[:])
			}
			if e := c.SetAgentCollection(ctx, asset, enable, interval, request); e != nil {
				return e
			}
		}
		v, e := c.AgentCollection(ctx, asset)
		if e != nil {
			return e
		}
		return json.NewEncoder(out).Encode(v)
	}
	var before uint64
	f.Uint64Var(&before, "before", 0, "")
	if f.Parse(args[1:]) != nil || f.NArg() != 0 {
		return fmt.Errorf("invalid event flags")
	}
	v, e := c.AgentEvents(ctx, asset, before)
	if e != nil {
		return e
	}
	return json.NewEncoder(out).Encode(v)
}
