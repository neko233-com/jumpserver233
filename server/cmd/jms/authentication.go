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
	f, e := privateAuthTemp(filepath.Dir(path))
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
	case action == "sms-cancel" || r.SMSBindingUpdated:
		return "login"
	case r.PasswordChanged:
		return "login"
	case r.PasswordChangeRequired:
		return "password-complete"
	case r.AccessToken != "":
		return "authenticated"
	case r.ReviewRequired:
		return "review-status"
	case r.RadiusFactor:
		return "factor-complete"
	case r.SMSFactor:
		if r.SMSStatus != nil && r.SMSStatus.NeedsPhone {
			return "sms-bind"
		}
		return "sms-complete"
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
	if len(args) > 0 && (strings.HasPrefix(args[0], "radius-") && args[0] != "radius-login" || args[0] == "password-settings" || args[0] == "password-save" || args[0] == "password-audit" || args[0] == "sms-settings" || args[0] == "sms-save" || args[0] == "sms-audit" || args[0] == "sms-profile" || args[0] == "sms-enroll") {
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
		return errors.New("usage: jms auth login|radius-login|continue|status|sms-resend|sms-cancel|sms-enroll --state-file PATH [--file JSON_OR_-] | radius-settings|radius-save|radius-audit|radius-check|sms-settings|sms-save|sms-audit|sms-profile")
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
	case "login", "radius-login", "continue", "sms-resend", "sms-cancel", "sms-enroll":
		allowed["file"] = true
		allowed["state-file"] = true
	case "status":
		allowed["state-file"] = true
	case "radius-save", "radius-check", "password-save", "sms-save":
		allowed["file"] = true
	case "radius-audit", "password-audit":
		allowed["offset"] = true
		allowed["limit"] = true
	case "radius-settings", "password-settings", "sms-settings", "sms-audit", "sms-profile":
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
	case "sms-profile":
		result, e = c.SMSProfile(ctx)
	case "sms-enroll":
		if *stateFile == "" {
			return errors.New("--state-file is required; session capabilities never print to stdout")
		}
		endpoint, err := authServer(server)
		if err != nil {
			return err
		}
		var in struct{ Phone, Password, OTP string }
		if err = operationJSON(*file, input, &in); err != nil {
			return err
		}
		pending, err := c.BeginSMSBinding(ctx, in.Phone, in.Password, in.OTP)
		if err != nil {
			return err
		}
		if pending.FactorToken == "" || len(pending.FactorToken) > 128 || pending.Status.ExpiresAt.IsZero() {
			return errors.New("invalid SMS binding response")
		}
		next := sessionclient.AuthenticationResult{SMSFactor: true, FactorToken: pending.FactorToken, SMSStatus: &pending.Status, ExpiresAt: pending.Status.ExpiresAt}
		current := authState{Server: endpoint, Next: authNext(action, next), Result: next}
		if err = saveAuthState(*stateFile, current); err != nil {
			return err
		}
		result = map[string]any{"next": current.Next, "expires_at": next.ExpiresAt, "sms_status": next.SMSStatus}
	case "sms-settings":
		result, e = c.SMSMFASettings(ctx)
	case "sms-audit":
		result, e = c.SMSMFAAudit(ctx)
	case "sms-save":
		var in sessionclient.SMSMFAInput
		e = operationJSON(*file, input, &in)
		if e == nil {
			result, e = c.SaveSMSMFASettings(ctx, in)
		}
	case "password-settings":
		result, e = c.PasswordPolicy(ctx)
	case "password-audit":
		result, e = c.PasswordPolicyAudit(ctx, *offset, *limit)
	case "password-save":
		var in sessionclient.PasswordPolicy
		e = operationJSON(*file, input, &in)
		if e == nil {
			result, e = c.SavePasswordPolicy(ctx, in)
		}
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
		if action == "continue" || action == "status" || action == "sms-resend" || action == "sms-cancel" {
			current, e = readAuthState(*stateFile, server)
			if e != nil {
				return e
			}
		}
		if action == "status" {
			if current.Next == "sms-bind" || current.Next == "sms-complete" {
				pending, err := c.Authentication(ctx, "sms-pending", sessionclient.AuthenticationInput{FactorToken: current.Result.FactorToken})
				if err != nil {
					return err
				}
				current.Result.SMSStatus = pending.SMSStatus
				current.Result.SMSFactor = true
				current.Next = authNext("sms-pending", current.Result)
				if err := saveAuthState(*stateFile, current); err != nil {
					return err
				}
			}
			if current.Next == "password-complete" {
				pending, err := c.Authentication(ctx, "password-status", sessionclient.AuthenticationInput{ChangeToken: current.Result.ChangeToken})
				if err != nil {
					return err
				}
				current.Result.User = pending.User
				current.Result.PasswordPolicy = pending.PasswordPolicy
			}
			result = map[string]any{"next": current.Next, "expires_at": current.Result.ExpiresAt, "user": current.Result.User, "password_policy": current.Result.PasswordPolicy, "sms_status": current.Result.SMSStatus}
			break
		}
		var in sessionclient.AuthenticationInput
		if e = operationJSON(*file, input, &in); e != nil {
			return e
		}
		step := action
		if action == "sms-resend" || action == "sms-cancel" {
			if current.Next != "sms-bind" && current.Next != "sms-complete" {
				return errors.New("no pending SMS verification")
			}
			in.FactorToken = current.Result.FactorToken
		}
		if action == "continue" {
			step = current.Next
			if step == "authenticated" || step == "" {
				return errors.New("no pending authentication step")
			}
			in.ChangeToken = current.Result.ChangeToken
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
		if next.ChangeToken == "" {
			next.ChangeToken = current.Result.ChangeToken
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
		if next.AccessToken != "" || next.PasswordChanged || action == "sms-cancel" || next.SMSBindingUpdated {
			current.Result.ChangeToken = ""
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
		result = map[string]any{"next": current.Next, "expires_at": next.ExpiresAt, "user": next.User, "enrollment_required": next.MFASetupRequired, "sms_status": next.SMSStatus}
	}
	if e != nil {
		return e
	}
	return json.NewEncoder(output).Encode(result)
}
