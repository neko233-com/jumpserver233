package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"os"
	"strconv"
	"time"

	"github.com/neko233-com/jumpserver233/server/internal/maintenance"
	"github.com/neko233-com/jumpserver233/server/internal/releasebundle"
)

const scheduleUsage = "usage: jms update schedule-status --root ROOT | schedule --root ROOT --sha256 SHA --revision N --installation-revision N --request-id ID --at RFC3339 [--drain-timeout 60s] | schedule-cancel --root ROOT --revision N --request-id ID --plan-id ID | supervise --root ROOT --passphrase-file PRIVATE_FILE; supervise requires a global platform identity and loopback JMS_SERVER_URL"

func executeSchedule(ctx context.Context, args []string, out, diagnostic io.Writer) error {
	if len(args) == 0 {
		return errors.New(scheduleUsage)
	}
	f := flag.NewFlagSet("update schedule", flag.ContinueOnError)
	f.SetOutput(io.Discard)
	root := f.String("root", "", "")
	sha := f.String("sha256", "", "")
	revision := f.Int("revision", 0, "")
	installation := f.Int("installation-revision", 0, "")
	id := f.String("request-id", "", "")
	at := f.String("at", "", "")
	timeout := f.Duration("drain-timeout", time.Minute, "")
	plan := f.String("plan-id", "", "")
	passwordFile := f.String("passphrase-file", "", "")
	if f.Parse(args[1:]) != nil || f.NArg() != 0 || *root == "" {
		return errors.New(scheduleUsage)
	}
	allowed := map[string]bool{"root": true}
	switch args[0] {
	case "schedule":
		for _, n := range []string{"sha256", "revision", "installation-revision", "request-id", "at", "drain-timeout"} {
			allowed[n] = true
		}
	case "schedule-cancel":
		for _, n := range []string{"revision", "request-id", "plan-id"} {
			allowed[n] = true
		}
	case "supervise":
		allowed["passphrase-file"] = true
	case "schedule-status":
	default:
		return errors.New(scheduleUsage)
	}
	invalid := false
	f.Visit(func(v *flag.Flag) {
		if !allowed[v.Name] {
			invalid = true
		}
	})
	if invalid {
		return errors.New(scheduleUsage)
	}
	cluster, e := strconv.ParseBool(defaultValue(os.Getenv("JMS_CLUSTER_MODE"), "false"))
	if e != nil {
		return maintenance.ErrInvalid
	}
	if cluster {
		return maintenance.ErrCluster
	}
	var result any
	switch args[0] {
	case "schedule-status":
		result, e = releasebundle.ScheduleState(ctx, *root)
	case "schedule":
		var when time.Time
		when, e = time.Parse(time.RFC3339, *at)
		if e != nil || *timeout%time.Second != 0 || *timeout < 5*time.Second || *timeout > 24*time.Hour {
			return errors.New(scheduleUsage)
		}
		result, e = releasebundle.SaveSchedule(ctx, *root, releasebundle.ScheduleInput{Revision: *revision, RequestID: *id, InstallationRevision: *installation, ArchiveSHA256: *sha, NotBefore: when, DrainTimeoutSeconds: int(*timeout / time.Second)}, "local-operator", "local-operator")
	case "schedule-cancel":
		result, e = releasebundle.CancelSchedule(ctx, *root, releasebundle.CancelScheduleInput{Revision: *revision, RequestID: *id, PlanID: *plan}, "local-operator", "local-operator")
	case "supervise":
		if *passwordFile == "" || *passwordFile == "-" {
			return errors.New(scheduleUsage)
		}
		read := func() ([]byte, error) { return readInstallPassphrase(nil, *passwordFile, nil, false) }
		secret, e := read()
		clear(secret)
		if e != nil {
			return errors.New("checkpoint_passphrase_unavailable")
		}
		client, e := clientFromEnvironment(defaultValue(os.Getenv("JMS_SERVER_URL"), "http://127.0.0.1:8080"), "")
		if e != nil {
			return e
		}
		client, e = client.LocalSupervisor()
		if e != nil {
			return e
		}
		return releasebundle.SuperviseInstalled(ctx, releasebundle.SupervisorOptions{Root: *root, Client: client, ReadPassphrase: read, Stdout: out, Stderr: diagnostic})
	}
	if e != nil {
		return e
	}
	return json.NewEncoder(out).Encode(result)
}
