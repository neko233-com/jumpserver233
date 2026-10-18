package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"github.com/neko233-com/jumpserver233/server/internal/sessionclient"
	"io"
	"os"
)

const operationsUsage = "usage: jms ops preview|create|template-create|validate|playbook-create --file JSON_OR_- | schedule|template-update|playbook-update ID --file JSON_OR_- | enable|disable|template-delete|playbook-delete ID --revision N | trigger PLAN_ID --request-id ID | step RUN_ID ASSET_ID STEP_ID | plans|plan ID|templates|runs|run ID|events ID|cancel ID|playbooks|playbook ID|playbook-events ID|program RUN_ID [--offset N --limit N]"

func runOperations(args []string) error {
	endpoint := os.Getenv("JMS_SERVER_URL")
	if endpoint == "" {
		endpoint = "http://127.0.0.1:8080"
	}
	c, e := clientFromEnvironment(endpoint, "")
	if e != nil {
		return e
	}
	return executeOperations(context.Background(), c, args, os.Stdin, os.Stdout)
}
func operationJSON(path string, stdin io.Reader, out any) error {
	return operationJSONLimit(path, stdin, out, 64<<10)
}
func operationJSONLimit(path string, stdin io.Reader, out any, limit int64) error {
	if path == "" {
		return errors.New("structured JSON input is required (--file PATH or --file -)")
	}
	var reader io.Reader = stdin
	if path != "-" {
		f, e := os.Open(path)
		if e != nil {
			return errors.New("could not open operation JSON file")
		}
		defer f.Close()
		reader = f
	}
	raw, e := io.ReadAll(io.LimitReader(reader, limit+1))
	if e != nil || int64(len(raw)) > limit {
		return errors.New("operation JSON exceeds its input limit")
	}
	if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return errors.New("operation JSON must be an object")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(out) != nil || decoder.Decode(new(any)) != io.EOF {
		return errors.New("invalid operation JSON")
	}
	return nil
}
func executeOperations(ctx context.Context, c *sessionclient.Client, args []string, stdin io.Reader, out io.Writer) error {
	if len(args) == 0 {
		return errors.New(operationsUsage)
	}
	action := args[0]
	rest := args[1:]
	id := ""
	withID := map[string]bool{"plan": true, "schedule": true, "enable": true, "disable": true, "events": true, "run": true, "cancel": true, "template-update": true, "template-delete": true, "playbook": true, "playbook-update": true, "playbook-delete": true, "playbook-events": true, "program": true, "trigger": true, "step": true}
	known := withID[action] || action == "plans" || action == "preview" || action == "create" || action == "templates" || action == "template-create" || action == "runs" || action == "playbooks" || action == "playbook-create" || action == "validate"
	if !known {
		return errors.New(operationsUsage)
	}
	if withID[action] {
		if len(rest) == 0 {
			return errors.New(operationsUsage)
		}
		id = rest[0]
		rest = rest[1:]
	}
	assetID, stepID := "", ""
	if action == "step" {
		if len(rest) < 2 {
			return errors.New(operationsUsage)
		}
		assetID, stepID = rest[0], rest[1]
		rest = rest[2:]
	}
	f := flag.NewFlagSet("ops", flag.ContinueOnError)
	f.SetOutput(io.Discard)
	file := f.String("file", "", "")
	revision := f.Int("revision", 0, "")
	offset := f.Int("offset", 0, "")
	limit := f.Int("limit", 25, "")
	requestID := f.String("request-id", "", "")
	if f.Parse(rest) != nil || f.NArg() != 0 || *offset < 0 || *limit < 1 || *limit > 100 {
		return errors.New(operationsUsage)
	}
	allowed := map[string]bool{}
	switch action {
	case "preview", "create", "schedule", "template-create", "template-update", "validate", "playbook-create", "playbook-update":
		allowed["file"] = true
	case "enable", "disable", "template-delete", "playbook-delete":
		allowed["revision"] = true
	case "plans", "runs", "events", "playbooks", "playbook-events":
		allowed["offset"] = true
		allowed["limit"] = true
	case "trigger":
		allowed["request-id"] = true
	}
	valid := true
	f.Visit(func(v *flag.Flag) {
		if !allowed[v.Name] {
			valid = false
		}
	})
	if !valid {
		return errors.New(operationsUsage)
	}
	var value any
	var e error
	switch action {
	case "validate":
		var in sessionclient.PlaybookWorkspace
		if e = operationJSONLimit(*file, stdin, &in, 512<<10); e == nil {
			value, e = c.ValidatePlaybook(ctx, in)
		}
	case "playbooks":
		value, e = c.Playbooks(ctx, *offset, *limit)
	case "playbook":
		value, e = c.Playbook(ctx, id)
	case "playbook-create", "playbook-update":
		var in sessionclient.PlaybookInput
		if e = operationJSONLimit(*file, stdin, &in, 512<<10); e == nil {
			value, e = c.SavePlaybook(ctx, id, in)
		}
	case "playbook-delete":
		e = c.DeletePlaybook(ctx, id, *revision)
		value = map[string]bool{"deleted": e == nil}
	case "playbook-events":
		value, e = c.PlaybookEvents(ctx, id, *offset, *limit)
	case "program":
		value, e = c.OperationProgram(ctx, id)
	case "step":
		value, e = c.OperationStepOutput(ctx, id, assetID, stepID)
	case "trigger":
		value, e = c.TriggerOperationPlan(ctx, id, *requestID)
	case "preview":
		var in sessionclient.OperationPreviewInput
		if e = operationJSON(*file, stdin, &in); e == nil {
			value, e = c.PreviewOperationSchedule(ctx, in)
		}
	case "plans":
		value, e = c.OperationPlansPage(ctx, *offset, *limit)
	case "plan":
		value, e = c.OperationPlan(ctx, id)
	case "create":
		var in sessionclient.OperationPlanInput
		if e = operationJSON(*file, stdin, &in); e == nil {
			value, e = c.CreateOperationPlan(ctx, in)
		}
	case "schedule":
		var in sessionclient.OperationScheduleUpdate
		if e = operationJSON(*file, stdin, &in); e == nil {
			value, e = c.UpdateOperationSchedule(ctx, id, in)
		}
	case "enable", "disable":
		value, e = c.SetOperationPlanEnabled(ctx, id, action == "enable", *revision)
	case "events":
		value, e = c.OperationScheduleEvents(ctx, id, *offset, *limit)
	case "runs":
		value, e = c.OperationRuns(ctx, *offset, *limit)
	case "run":
		value, e = c.OperationRun(ctx, id)
	case "cancel":
		e = c.CancelOperationRun(ctx, id)
		value = map[string]any{"id": id, "cancelled": e == nil}
	case "templates":
		value, e = c.OperationTemplates(ctx)
	case "template-create", "template-update":
		var in sessionclient.OperationTemplateInput
		if e = operationJSON(*file, stdin, &in); e == nil {
			value, e = c.SaveOperationTemplate(ctx, id, in)
		}
	case "template-delete":
		e = c.DeleteOperationTemplate(ctx, id, *revision)
		value = map[string]bool{"deleted": e == nil}
	}
	if e != nil {
		return e
	}
	return json.NewEncoder(out).Encode(value)
}
