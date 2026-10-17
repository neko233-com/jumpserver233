package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"github.com/coder/websocket"
	"github.com/neko233-com/jumpserver233/server/internal/connector/rdpclient"
	"github.com/neko233-com/jumpserver233/server/internal/sessionclient"
	"io"
	"os"
	"time"
)

const desktopUsage = "usage: jms rdp <asset-id> --capture <new.png> [--input <events.json>] [--wait 2]; jms rdp monitor <session-id> --capture <new.png> [--wait 2]"

func runDesktop(args []string) error {
	endpoint := os.Getenv("JMS_SERVER_URL")
	if endpoint == "" {
		endpoint = "http://127.0.0.1:8080"
	}
	client, e := clientFromEnvironment(endpoint)
	if e != nil {
		return e
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	return executeDesktop(ctx, client, args, os.Stdout)
}
func executeDesktop(ctx context.Context, client *sessionclient.Client, args []string, stdout io.Writer) error {
	monitoring := len(args) > 0 && args[0] == "monitor"
	if monitoring {
		args = args[1:]
	}
	if len(args) < 1 || args[0] == "" {
		return errors.New(desktopUsage)
	}
	flags := flag.NewFlagSet("rdp", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	path := flags.String("capture", "", "")
	input := flags.String("input", "", "")
	wait := flags.Int("wait", 2, "")
	if flags.Parse(args[1:]) != nil || flags.NArg() != 0 || *path == "" || *wait < 1 || *wait > 15 {
		return errors.New(desktopUsage)
	}
	if monitoring && *input != "" {
		return errors.New("desktop monitoring does not accept input")
	}
	var events []rdpclient.Input
	if *input != "" {
		f, e := os.Open(*input)
		if e != nil {
			return e
		}
		raw, e := io.ReadAll(io.LimitReader(f, (128<<10)+1))
		f.Close()
		if e != nil || len(raw) > 128<<10 || json.Unmarshal(raw, &events) != nil || len(events) > 1000 {
			return errors.New("invalid desktop input file")
		}
	}
	// Reserve the output before opening a remote desktop; never overwrite a file.
	file, e := os.OpenFile(*path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if e != nil {
		return e
	}
	success := false
	defer func() {
		file.Close()
		if !success {
			_ = os.Remove(*path)
		}
	}()
	create, dial := client.CreateDesktop, client.DialDesktop
	if monitoring {
		create, dial = client.CreateDesktopMonitor, client.DialDesktopMonitor
	}
	created, e := create(ctx, args[0])
	if e != nil {
		return e
	}
	defer func() {
		if monitoring {
			return
		}
		closeCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = client.CloseDesktop(closeCtx, created.ID)
	}()
	conn, e := dial(ctx, created)
	if e != nil {
		return e
	}
	defer conn.CloseNow()
	frames := make(chan []byte, 1)
	fail := make(chan error, 1)
	readCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	go func() {
		for {
			kind, raw, e := conn.Read(readCtx)
			if e != nil {
				fail <- e
				return
			}
			if kind == websocket.MessageText {
				var message struct {
					Type string `json:"type"`
				}
				if json.Unmarshal(raw, &message) != nil {
					fail <- errors.New("invalid desktop response")
					return
				}
				if message.Type == "text_error" || message.Type == "clipboard_error" {
					fail <- errors.New("remote desktop did not accept text or clipboard input")
					return
				}
			}
			if kind == websocket.MessageBinary && len(raw) > 16 {
				select {
				case frames <- raw[8:]:
				default:
					select {
					case <-frames:
					default:
					}
					select {
					case frames <- raw[8:]:
					default:
					}
				}
			}
		}
	}()
	var png []byte
	consume := func(duration time.Duration) error {
		timer := time.NewTimer(duration)
		defer timer.Stop()
		for {
			select {
			case png = <-frames:
			case e := <-fail:
				return e
			case <-ctx.Done():
				return ctx.Err()
			case <-timer.C:
				return nil
			}
		}
	}
	if e = consume(time.Duration(*wait) * time.Second); e != nil {
		return e
	}
	if len(png) == 0 {
		return errors.New("desktop did not produce a frame")
	}
	for _, event := range events {
		raw, _ := json.Marshal(event)
		if e = conn.Write(ctx, websocket.MessageText, raw); e != nil {
			return e
		}
	}
	if len(events) > 0 {
		if e = consume(time.Second); e != nil {
			return e
		}
	}
	if _, e = file.Write(png); e != nil {
		return e
	}
	if e = file.Sync(); e != nil {
		return e
	}
	success = true
	result := map[string]any{"session_id": created.ID, "capture": *path, "bytes": len(png)}
	if monitoring {
		result["monitor"] = true
	}
	return json.NewEncoder(stdout).Encode(result)
}
