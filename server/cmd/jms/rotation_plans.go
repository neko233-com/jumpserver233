package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"github.com/neko233-com/jumpserver233/server/internal/sessionclient"
	"io"
	"os"
	"time"
)

const rotationPlanUsage = "usage: jms account rotation targets|plans|runs|audit [--offset 0 --limit 50] [--search TEXT --collector-for ACCOUNT --plan PLAN] | show-plan|show-run ID | create --file PLAN.json | update PLAN --file PLAN.json | delete PLAN --revision N | run PLAN [--request-id ID --wait --timeout-seconds 300] | cancel|recover RUN | export RUN --out NEW.csv"

func executeRotationPlans(ctx context.Context, c *sessionclient.Client, args []string, output io.Writer) error {
	if len(args) == 0 {
		return errors.New(rotationPlanUsage)
	}
	emit := func(v any, e error) error {
		if e != nil {
			return e
		}
		return json.NewEncoder(output).Encode(v)
	}
	f := flag.NewFlagSet("rotation", flag.ContinueOnError)
	f.SetOutput(io.Discard)
	switch args[0] {
	case "targets", "plans", "runs", "audit":
		offset, limit := f.Int("offset", 0, ""), f.Int("limit", 50, "")
		q, collector, plan := f.String("search", "", ""), f.String("collector-for", "", ""), f.String("plan", "", "")
		if f.Parse(args[1:]) != nil || f.NArg() != 0 || *offset < 0 || *limit < 1 || *limit > 100 {
			return errors.New(rotationPlanUsage)
		}
		if args[0] != "targets" && (*q != "" || *collector != "") || args[0] != "runs" && *plan != "" {
			return errors.New(rotationPlanUsage)
		}
		switch args[0] {
		case "targets":
			v, e := c.RotationTargets(ctx, *q, *collector, *offset, *limit)
			return emit(v, e)
		case "plans":
			v, e := c.RotationPlans(ctx, *offset, *limit)
			return emit(v, e)
		case "runs":
			v, e := c.RotationRuns(ctx, *plan, *offset, *limit)
			return emit(v, e)
		default:
			v, e := c.RotationAudit(ctx, *offset, *limit)
			return emit(v, e)
		}
	case "create", "update":
		start, id := 1, ""
		if args[0] == "update" {
			if len(args) < 2 {
				return errors.New(rotationPlanUsage)
			}
			start = 2
			id = args[1]
		}
		file := f.String("file", "", "")
		if f.Parse(args[start:]) != nil || f.NArg() != 0 || *file == "" {
			return errors.New(rotationPlanUsage)
		}
		data, e := os.Open(*file)
		if e != nil {
			return errors.New("could not open rotation plan file")
		}
		defer data.Close()
		decoder := json.NewDecoder(io.LimitReader(data, (256<<10)+1))
		decoder.DisallowUnknownFields()
		var in sessionclient.RotationPlanInput
		if decoder.Decode(&in) != nil || decoder.Decode(new(any)) != io.EOF || len(in.Targets) < 1 || len(in.Targets) > 500 {
			return errors.New("invalid rotation plan metadata")
		}
		v, e := c.SaveRotationPlan(ctx, id, in)
		return emit(v, e)
	case "show-plan", "show-run", "cancel", "recover":
		if len(args) != 2 || args[1] == "" {
			return errors.New(rotationPlanUsage)
		}
		switch args[0] {
		case "show-plan":
			v, e := c.RotationPlan(ctx, args[1])
			return emit(v, e)
		case "show-run":
			v, e := c.RotationRun(ctx, args[1])
			return emit(v, e)
		case "cancel":
			return emit(map[string]string{"state": "cancelling"}, c.CancelRotationRun(ctx, args[1]))
		default:
			return emit(map[string]string{"state": "recovery_requested"}, c.RecoverRotationRun(ctx, args[1]))
		}
	case "delete":
		revision := f.Int("revision", 0, "")
		if len(args) < 2 || f.Parse(args[2:]) != nil || f.NArg() != 0 || *revision < 1 {
			return errors.New(rotationPlanUsage)
		}
		return emit(map[string]string{"state": "deleted"}, c.DeleteRotationPlan(ctx, args[1], *revision))
	case "run":
		id, wait, seconds := f.String("request-id", "", ""), f.Bool("wait", false, ""), f.Int("timeout-seconds", 300, "")
		if len(args) < 2 || f.Parse(args[2:]) != nil || f.NArg() != 0 || *seconds < 1 || *seconds > 3600 {
			return errors.New(rotationPlanUsage)
		}
		if *id == "" {
			var raw [16]byte
			if _, e := rand.Read(raw[:]); e != nil {
				return e
			}
			*id = hex.EncodeToString(raw[:])
		}
		run, e := c.RunRotationPlan(ctx, args[1], *id)
		if e != nil {
			return e
		}
		if *wait {
			waiting, cancel := context.WithTimeout(ctx, time.Duration(*seconds)*time.Second)
			defer cancel()
			timer := time.NewTicker(time.Second)
			defer timer.Stop()
			for run.State == "queued" || run.State == "running" {
				select {
				case <-waiting.Done():
					_ = emit(run, nil)
					return errors.New("rotation wait timed out; query the existing run before retrying")
				case <-timer.C:
				}
				run, e = c.RotationRun(waiting, run.ID)
				if e != nil {
					return e
				}
			}
		}
		if e = emit(run, nil); e != nil {
			return e
		}
		if *wait && run.State != "succeeded" {
			return errors.New("rotation requires attention; inspect per-account results")
		}
		return nil
	case "export":
		path := f.String("out", "", "")
		if len(args) < 2 || f.Parse(args[2:]) != nil || f.NArg() != 0 || *path == "" {
			return errors.New(rotationPlanUsage)
		}
		raw, e := c.ExportRotationRun(ctx, args[1])
		if e != nil {
			return e
		}
		file, e := os.OpenFile(*path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if e != nil {
			return errors.New("choose a new rotation export file")
		}
		_, e = file.Write(raw)
		closed := file.Close()
		if e != nil || closed != nil {
			return errors.New("could not save rotation export")
		}
		return emit(map[string]string{"state": "saved"}, nil)
	}
	return errors.New(rotationPlanUsage)
}
