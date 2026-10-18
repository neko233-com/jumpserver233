package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/neko233-com/jumpserver233/server/internal/sessionclient"
)

type authState struct {
	Server string                             `json:"server"`
	Next   string                             `json:"next"`
	Result sessionclient.AuthenticationResult `json:"result"`
}

func authServer(value string) (string, error) {
	u, e := url.Parse(value)
	if e != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Scheme != "http" && u.Scheme != "https" {
		return "", errors.New("invalid authentication server URL")
	}
	u.Path = strings.TrimRight(u.Path, "/")
	return u.String(), nil
}
func readAuthState(path, server string) (authState, error) {
	var out authState
	f, e := os.Open(path)
	if e != nil {
		return out, errors.New("could not open authentication state")
	}
	defer f.Close()
	data, e := io.ReadAll(io.LimitReader(f, 32769))
	if e != nil || len(data) > 32768 || json.Unmarshal(data, &out) != nil {
		return out, errors.New("invalid authentication state")
	}
	expected, e := authServer(server)
	if e != nil || out.Server != expected {
		return out, errors.New("authentication state belongs to another server")
	}
	if !out.Result.ExpiresAt.IsZero() && !time.Now().Before(out.Result.ExpiresAt) {
		return out, errors.New("authentication state expired")
	}
	return out, nil
}
func saveAuthState(path string, state authState) error {
	if path == "" {
		return errors.New("--state-file is required")
	}
	raw, e := json.Marshal(state)
	if e != nil || len(raw) > 32768 {
		return errors.New("invalid authentication state")
	}
	f, e := os.CreateTemp(filepath.Dir(path), ".jms-auth-*")
	if e != nil {
		return errors.New("could not create authentication state")
	}
	defer os.Remove(f.Name())
	if e = f.Chmod(0600); e == nil {
		_, e = f.Write(raw)
	}
	if e == nil {
		e = f.Sync()
	}
	closeErr := f.Close()
	if e != nil || closeErr != nil {
		return errors.New("could not save authentication state")
	}
	if e = os.Rename(f.Name(), path); e != nil {
		return errors.New("could not replace authentication state")
	}
	return nil
}
func authNext(action string, r sessionclient.AuthenticationResult) string {
	switch {
	case r.AccessToken != "":
		return "authenticated"
	case r.ReviewRequired:
		return "review-status"
	case r.RadiusFactor:
		return "factor-complete"
	case r.RadiusChallenge:
		if action == "factor-complete" {
			return action
		}
		return "radius-challenge"
	case r.RadiusVerified:
		return "radius-complete"
	case r.MFASetupRequired:
		if action == "radius-complete" {
			return action
		}
		return "mfa-setup"
	case r.MFARequired:
		return action
	}
	return ""
}
func runAuthentication(args []string) error {
	server := os.Getenv("JMS_SERVER_URL")
	if server == "" {
		server = "http://127.0.0.1:8080"
	}
	var client *sessionclient.Client
	var e error
	if len(args) > 0 && strings.HasPrefix(args[0], "radius-") && args[0] != "radius-login" {
		client, e = clientFromEnvironment(server)
	} else {
		client, e = sessionclient.New(server, "")
	}
	if e != nil {
		return e
	}
	return executeAuthentication(context.Background(), client, server, args, os.Stdin, os.Stdout)
}
func executeAuthentication(ctx context.Context, c *sessionclient.Client, server string, args []string, input io.Reader, output io.Writer) error {
	if len(args) < 1 {
		return errors.New("usage: jms auth login|radius-login|continue|status --state-file PATH [--file JSON_OR_-] | radius-settings|radius-save|radius-audit|radius-check")
	}
	action := args[0]
	f := flag.NewFlagSet("auth", flag.ContinueOnError)
	f.SetOutput(io.Discard)
	file := f.String("file", "", "")
	stateFile := f.String("state-file", "", "")
	offset := f.Int("offset", 0, "")
	limit := f.Int("limit", 25, "")
	if f.Parse(args[1:]) != nil || f.NArg() != 0 {
		return errors.New("invalid authentication arguments")
	}
	allowed := map[string]bool{}
	switch action {
	case "login", "radius-login", "continue":
		allowed["file"] = true
		allowed["state-file"] = true
	case "status":
		allowed["state-file"] = true
	case "radius-save", "radius-check":
		allowed["file"] = true
	case "radius-audit":
		allowed["offset"] = true
		allowed["limit"] = true
	case "radius-settings":
	default:
		return errors.New("unknown authentication action")
	}
	valid := true
	f.Visit(func(v *flag.Flag) {
		if !allowed[v.Name] {
			valid = false
		}
	})
	if !valid {
		return errors.New("invalid authentication flags")
	}
	var result any
	var e error
	switch action {
	case "radius-settings":
		result, e = c.RadiusSettings(ctx)
	case "radius-save":
		var in sessionclient.RadiusSettingsInput
		e = operationJSONLimit(*file, input, &in, 256<<10)
		if e == nil {
			result, e = c.SaveRadiusSettings(ctx, in)
		}
	case "radius-audit":
		result, e = c.RadiusAudit(ctx, *offset, *limit)
	case "radius-check":
		var in struct {
			Endpoint string `json:"endpoint"`
			Username string `json:"username"`
			Password string `json:"password"`
		}
		e = operationJSON(*file, input, &in)
		if e == nil {
			var code int
			code, e = c.ProbeRadius(ctx, in.Endpoint, in.Username, in.Password)
			result = map[string]int{"authenticated_response_code": code}
		}
	default:
		if *stateFile == "" {
			return errors.New("--state-file is required; session capabilities never print to stdout")
		}
		endpoint, normalizeError := authServer(server)
		if normalizeError != nil {
			return normalizeError
		}
		current := authState{Server: endpoint}
		if action == "continue" || action == "status" {
			current, e = readAuthState(*stateFile, server)
			if e != nil {
				return e
			}
		}
		if action == "status" {
			result = map[string]any{"next": current.Next, "expires_at": current.Result.ExpiresAt, "user": current.Result.User}
			break
		}
		var in sessionclient.AuthenticationInput
		if e = operationJSON(*file, input, &in); e != nil {
			return e
		}
		step := action
		if action == "continue" {
			step = current.Next
			if step == "authenticated" || step == "" {
				return errors.New("no pending authentication step")
			}
			in.ChallengeToken = current.Result.ChallengeToken
			in.PendingToken = current.Result.PendingToken
			in.FactorToken = current.Result.FactorToken
			in.ReviewToken = current.Result.ReviewToken
			if in.SetupToken == "" {
				in.SetupToken = current.Result.SetupToken
			}
			if step == "review-status" {
				step = "review-complete"
			}
		}
		next, err := c.Authentication(ctx, step, in)
		if err != nil {
			return err
		}
		if next.PendingToken == "" {
			next.PendingToken = current.Result.PendingToken
		}
		if next.ChallengeToken == "" {
			next.ChallengeToken = current.Result.ChallengeToken
		}
		if next.FactorToken == "" {
			next.FactorToken = current.Result.FactorToken
		}
		if next.ReviewToken == "" {
			next.ReviewToken = current.Result.ReviewToken
		}
		if next.SetupToken == "" {
			next.SetupToken = current.Result.SetupToken
		}
		current.Result = next
		current.Next = authNext(step, next)
		if current.Next == "" {
			return errors.New("authentication server returned no next step")
		}
		if next.AccessToken != "" {
			current.Result.ChallengeToken = ""
			current.Result.PendingToken = ""
			current.Result.FactorToken = ""
			current.Result.ReviewToken = ""
			current.Result.SetupToken = ""
			current.Result.Enrollment = nil
		}
		if e = saveAuthState(*stateFile, current); e != nil {
			return e
		}
		result = map[string]any{"next": current.Next, "expires_at": next.ExpiresAt, "user": next.User, "enrollment_required": next.MFASetupRequired}
	}
	if e != nil {
		return e
	}
	return json.NewEncoder(output).Encode(result)
}
