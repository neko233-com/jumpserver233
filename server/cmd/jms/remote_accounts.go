package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"strings"

	"github.com/neko233-com/jumpserver233/server/internal/sessionclient"
)

const remoteAccountUsage = "jms accounts remote-create ASSET --username USER [--shell /bin/bash] [--request-id ID] | remote-disable|remote-enable|remote-delete ASSET --username USER [--uid UID] [--confirm USER] [--request-id ID] | remote-tasks ASSET [--offset 0] [--limit 20] | remote-submit ASSET TASK | remote-attempt ASSET TASK --mode inspect|apply|cancel --revision N (returns durable task/review/job IDs; use accounts job JOB to inspect progress)"

func executeRemoteAccounts(ctx context.Context, c *sessionclient.Client, args []string, out io.Writer) error {
	if len(args) < 2 {
		return errors.New(remoteAccountUsage)
	}
	f := flag.NewFlagSet("remote-accounts", flag.ContinueOnError)
	f.SetOutput(io.Discard)
	var task sessionclient.RemoteAccountTask
	var e error
	switch args[0] {
	case "remote-tasks":
		offset, limit := f.Int("offset", 0, ""), f.Int("limit", 20, "")
		if f.Parse(args[2:]) != nil || f.NArg() != 0 || *offset < 0 || *limit < 1 || *limit > 100 {
			return errors.New(remoteAccountUsage)
		}
		v, err := c.RemoteAccountTasks(ctx, args[1], *offset, *limit)
		if err != nil {
			return err
		}
		return json.NewEncoder(out).Encode(v)
	case "remote-submit":
		if len(args) != 3 || args[2] == "" {
			return errors.New(remoteAccountUsage)
		}
		task, e = c.SubmitRemoteAccountTask(ctx, args[1], args[2])
	case "remote-attempt":
		if len(args) < 3 {
			return errors.New(remoteAccountUsage)
		}
		mode, revision := f.String("mode", "", ""), f.Int("revision", 0, "")
		if f.Parse(args[3:]) != nil || f.NArg() != 0 || *revision < 1 || (*mode != "inspect" && *mode != "apply" && *mode != "cancel") {
			return errors.New(remoteAccountUsage)
		}
		task, e = c.AttemptRemoteAccountTask(ctx, args[1], args[2], *mode, *revision)
	case "remote-create", "remote-disable", "remote-enable", "remote-delete":
		username, request, shell := f.String("username", "", ""), f.String("request-id", "", ""), f.String("shell", "/bin/bash", "")
		uid, confirm := f.Uint("uid", 0, ""), f.String("confirm", "", "")
		if f.Parse(args[2:]) != nil || f.NArg() != 0 || *username == "" || *uid > 60000 {
			return errors.New(remoteAccountUsage)
		}
		action := strings.TrimPrefix(args[0], "remote-")
		if action == "delete" && *confirm != *username {
			return errors.New("remote deletion requires --confirm USERNAME; the home directory is retained")
		}
		if action != "create" {
			f.Visit(func(v *flag.Flag) {
				if v.Name == "shell" {
					e = errors.New(remoteAccountUsage)
				}
			})
			if e != nil {
				return e
			}
		}
		if *request == "" {
			var nonce [16]byte
			if _, e = rand.Read(nonce[:]); e != nil {
				return e
			}
			*request = hex.EncodeToString(nonce[:])
		}
		in := sessionclient.RemoteAccountInput{Action: action, Username: *username, RequestID: *request}
		if action == "create" {
			if *uid != 0 || (*shell != "/bin/bash" && *shell != "/bin/sh") {
				return errors.New(remoteAccountUsage)
			}
			page, err := c.ManagedAccounts(ctx, args[1], 0, 1, "")
			if err != nil {
				return err
			}
			in.Version, in.Shell = page.Version, *shell
		} else {
			a, err := c.ResolveManagedAccount(ctx, args[1], *username)
			if err != nil {
				return err
			}
			in.Version, in.AccountID, in.UID = a.Version, a.ID, uint32(*uid)
			if in.UID == 0 && a.RemoteAccount != nil {
				in.UID = a.RemoteAccount.UID
			}
			if a.Default || in.UID < 1000 {
				return errors.New("a named managed account and its confirmed regular Linux UID are required")
			}
		}
		task, e = c.CreateRemoteAccountTask(ctx, args[1], in)
	default:
		return errors.New(remoteAccountUsage)
	}
	if e != nil {
		return e
	}
	return json.NewEncoder(out).Encode(task)
}
