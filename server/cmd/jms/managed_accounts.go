package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
	"unicode/utf8"

	"github.com/neko233-com/jumpserver233/server/internal/sessionclient"
)

const managedAccountUsage = "usage: jms account list ASSET [--offset 0] [--limit 50] | jms account show|activity ASSET USERNAME_OR_ID | jms account create ASSET --username USER --password-stdin|--private-key-file PATH [--name LABEL] | jms account update ASSET USERNAME_OR_ID [--active=false] [--password-rotation=false] [--key-rotation=true] [--password-stdin|--private-key-file PATH] [--version TOKEN] | jms account delete ASSET ACCOUNT_ID --version TOKEN | " + accountImportUsage + " | " + accountRiskUsage + " | " + rotationPlanUsage

func runManagedAccounts(args []string) error {
	endpoint := os.Getenv("JMS_SERVER_URL")
	if endpoint == "" {
		endpoint = "http://127.0.0.1:8080"
	}
	c, e := clientFromEnvironment(endpoint)
	if e != nil {
		return e
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	duration := 30 * time.Second
	if len(args) > 0 && args[0] == "risks" {
		duration = 65 * time.Second
	}
	if len(args) > 0 && args[0] == "rotation" {
		duration = 61 * time.Minute
	}
	ctx, timeout := context.WithTimeout(ctx, duration)
	defer timeout()
	return executeManagedAccount(ctx, c, args, os.Stdin, os.Stdout)
}

func readManagedSecret(input io.Reader) (string, error) {
	raw, e := io.ReadAll(io.LimitReader(input, 4097))
	if e != nil || len(raw) > 4096 || !utf8.Valid(raw) {
		return "", errors.New("credential input must be valid UTF-8 and at most 4096 bytes")
	}
	secret := strings.TrimSuffix(strings.TrimSuffix(string(raw), "\n"), "\r")
	if secret == "" || strings.ContainsAny(secret, "\r\n\x00") {
		return "", errors.New("credential input must contain one nonempty line")
	}
	return secret, nil
}

func executeManagedAccount(ctx context.Context, c *sessionclient.Client, args []string, input io.Reader, output io.Writer) error {
	if len(args) > 0 && args[0] == "rotation" {
		return executeRotationPlans(ctx, c, args[1:], output)
	}
	if len(args) > 0 && args[0] == "risks" {
		return executeAccountRisks(ctx, c, args[1:], output)
	}
	if len(args) > 0 && strings.HasPrefix(args[0], "import") {
		return executeAccountImport(ctx, c, args, output)
	}
	if len(args) < 2 || args[1] == "" {
		return errors.New(managedAccountUsage)
	}
	mode, asset := args[0], args[1]
	f := flag.NewFlagSet("account", flag.ContinueOnError)
	f.SetOutput(io.Discard)
	switch mode {
	case "list", "show", "activity":
		offset, limit := f.Int("offset", 0, ""), f.Int("limit", 50, "")
		start := 2
		if mode != "list" {
			start = 3
			if len(args) < 3 || args[2] == "" {
				return errors.New(managedAccountUsage)
			}
		}
		if f.Parse(args[start:]) != nil || f.NArg() != 0 || *offset < 0 || *limit < 1 || *limit > 100 {
			return errors.New(managedAccountUsage)
		}
		if mode == "list" {
			v, e := c.ManagedAccounts(ctx, asset, *offset, *limit, "")
			if e != nil {
				return e
			}
			return json.NewEncoder(output).Encode(v)
		}
		a, e := c.ResolveManagedAccount(ctx, asset, args[2])
		if e != nil {
			return e
		}
		if mode == "show" {
			return json.NewEncoder(output).Encode(a)
		}
		v, e := c.ManagedAccountActivity(ctx, asset, a.ID, *offset, *limit)
		if e != nil {
			return e
		}
		return json.NewEncoder(output).Encode(v)
	case "delete":
		if len(args) < 3 || args[2] == "" {
			return errors.New(managedAccountUsage)
		}
		version := f.String("version", "", "")
		if f.Parse(args[3:]) != nil || f.NArg() != 0 || *version == "" {
			return errors.New(managedAccountUsage)
		}
		if e := c.DeleteManagedAccount(ctx, asset, args[2], *version); e != nil {
			return e
		}
		return json.NewEncoder(output).Encode(map[string]string{"state": "removed", "account_id": args[2]})
	case "create", "update":
		start := 2
		if mode == "update" {
			start = 3
			if len(args) < 3 || args[2] == "" {
				return errors.New(managedAccountUsage)
			}
		}
		username := ""
		if mode == "create" {
			f.StringVar(&username, "username", "", "")
		}
		name, note, version := f.String("name", "", ""), f.String("note", "", ""), f.String("version", "", "")
		discoveryID := f.String("discovery-id", "", "")
		active, passwordRotation, keyRotation := f.Bool("active", true, ""), f.Bool("password-rotation", true, ""), f.Bool("key-rotation", false, "")
		passwordStdin, passphraseStdin := f.Bool("password-stdin", false, ""), f.Bool("key-passphrase-stdin", false, "")
		keyFile := f.String("private-key-file", "", "")
		if f.Parse(args[start:]) != nil || f.NArg() != 0 || *passwordStdin && *keyFile != "" || *passphraseStdin && *keyFile == "" || *passwordStdin && *passphraseStdin || mode == "create" && (username == "" || !*passwordStdin && *keyFile == "") {
			return errors.New(managedAccountUsage)
		}
		in := sessionclient.ManagedAccountInput{Username: username, Version: *version}
		seen := map[string]bool{}
		f.Visit(func(v *flag.Flag) { seen[v.Name] = true })
		if seen["discovery-id"] {
			decoded, e := hex.DecodeString(*discoveryID)
			if *discoveryID != "" && (e != nil || len(decoded) != 16 || *discoveryID != strings.ToLower(*discoveryID)) {
				return errors.New("discovery ID must be a current finding ID")
			}
			in.DiscoveryID = discoveryID
		}
		if seen["name"] {
			in.Name = name
		}
		if seen["note"] {
			in.Remark = note
		}
		if seen["active"] {
			in.Active = active
		}
		if seen["password-rotation"] {
			in.PasswordRotationEnabled = passwordRotation
		}
		if seen["key-rotation"] {
			in.KeyRotationEnabled = keyRotation
		}
		if *passwordStdin {
			value, e := readManagedSecret(input)
			if e != nil {
				return e
			}
			in.CredentialType, in.Password = "password", value
		}
		if *keyFile != "" {
			file, e := os.Open(*keyFile)
			if e != nil {
				return errors.New("could not open the private key file")
			}
			raw, e := io.ReadAll(io.LimitReader(file, (64<<10)+1))
			file.Close()
			if e != nil || len(raw) == 0 || len(raw) > 64<<10 || !utf8.Valid(raw) {
				return errors.New("invalid private key file")
			}
			in.CredentialType, in.PrivateKey = "ssh_key", string(raw)
			if *passphraseStdin {
				value, e := readManagedSecret(input)
				if e != nil {
					return e
				}
				in.PrivateKeyPassphrase = value
			}
		}
		var row sessionclient.ManagedAccount
		var e error
		if mode == "create" {
			if in.Version == "" {
				page, err := c.ManagedAccounts(ctx, asset, 0, 1, "")
				if err != nil {
					return err
				}
				in.Version = page.Version
			}
			row, e = c.CreateManagedAccount(ctx, asset, in)
		} else {
			current, err := c.ResolveManagedAccount(ctx, asset, args[2])
			if err != nil {
				return err
			}
			if in.Version == "" {
				in.Version = current.Version
			}
			row, e = c.UpdateManagedAccount(ctx, asset, current.ID, in)
		}
		if e != nil {
			return e
		}
		return json.NewEncoder(output).Encode(row)
	default:
		return errors.New(managedAccountUsage)
	}
}
