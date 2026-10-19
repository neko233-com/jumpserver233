package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strconv"

	"github.com/neko233-com/jumpserver233/server/internal/maintenance"
	"golang.org/x/term"
)

const backupUsage = "usage: jms backup create|verify|restore --file BACKUP.jmsbackup [--data-dir DIR] [--passphrase-file FILE|-] [--replace] | jms backup recover --data-dir DIR [--rollback]; stop the standalone service before create/restore; passphrases are never command arguments"

func runBackup(args []string) error {
	return executeBackup(context.Background(), args, os.Stdin, os.Stdout, os.Stderr, func(confirm bool) ([]byte, error) {
		if !term.IsTerminal(int(os.Stdin.Fd())) {
			return nil, errors.New("use --passphrase-file - for protected stdin")
		}
		fmt.Fprint(os.Stderr, "Backup passphrase (12-1024 bytes): ")
		password, e := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Fprintln(os.Stderr)
		if e != nil {
			return nil, e
		}
		if confirm {
			fmt.Fprint(os.Stderr, "Confirm backup passphrase: ")
			again, e := term.ReadPassword(int(os.Stdin.Fd()))
			fmt.Fprintln(os.Stderr)
			same := bytes.Equal(password, again)
			clear(again)
			if e != nil {
				clear(password)
				return nil, e
			}
			if !same {
				clear(password)
				return nil, errors.New("backup passphrases do not match")
			}
		}
		return password, nil
	})
}
func executeBackup(ctx context.Context, args []string, input io.Reader, output, diagnostic io.Writer, prompt func(bool) ([]byte, error)) error {
	if len(args) == 0 {
		return errors.New(backupUsage)
	}
	action := args[0]
	if action != "create" && action != "verify" && action != "restore" && action != "recover" {
		return errors.New(backupUsage)
	}
	flags := flag.NewFlagSet("backup", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	dataDir := flags.String("data-dir", os.Getenv("JMS_DATA_DIR"), "")
	file := flags.String("file", "", "")
	passwordFile := flags.String("passphrase-file", "", "")
	replace := flags.Bool("replace", false, "")
	rollback := flags.Bool("rollback", false, "")
	if flags.Parse(args[1:]) != nil || flags.NArg() != 0 || *rollback && action != "recover" || *replace && action != "restore" || action != "recover" && *file == "" || action == "recover" && (*file != "" || *passwordFile != "") {
		return errors.New(backupUsage)
	}
	if action != "verify" {
		cluster, e := strconv.ParseBool(defaultValue(os.Getenv("JMS_CLUSTER_MODE"), "false"))
		if e != nil {
			return maintenance.ErrInvalid
		}
		if cluster {
			return maintenance.ErrCluster
		}
	}
	if *dataDir == "" {
		parent, e := os.UserConfigDir()
		if e != nil {
			return e
		}
		*dataDir = filepath.Join(parent, "JumpServer233")
	}
	if action == "recover" {
		lock, e := maintenance.Acquire(*dataDir)
		if e != nil {
			return e
		}
		defer lock.Close()
		if *rollback {
			e = maintenance.Rollback(ctx, lock.DataDir)
		} else {
			e = maintenance.Recover(ctx, lock.DataDir)
		}
		if e != nil {
			return e
		}
		return json.NewEncoder(output).Encode(map[string]string{"status": "ready"})
	}
	var password []byte
	var e error
	if *passwordFile == "" {
		password, e = prompt(action == "create")
	} else {
		reader := input
		if *passwordFile != "-" {
			f, err := os.Open(*passwordFile)
			if err != nil {
				return err
			}
			defer f.Close()
			info, err := f.Stat()
			if err != nil || !info.Mode().IsRegular() || runtime.GOOS != "windows" && info.Mode().Perm()&0077 != 0 {
				return errors.New("passphrase file must be private and regular")
			}
			reader = f
		}
		password, e = io.ReadAll(io.LimitReader(reader, 1027))
		if e == nil {
			password = bytes.TrimRight(password, "\r\n")
		}
	}
	defer clear(password)
	if e != nil {
		return e
	}
	if len(password) < 12 || len(password) > 1024 {
		return errors.New("backup passphrase must contain 12-1024 bytes")
	}
	opt := maintenance.Options{DataDir: *dataDir, File: *file, Version: defaultValue(os.Getenv("JMS_VERSION"), "dev"), ExternalVaultKey: os.Getenv("JMS_VAULT_KEY"), Passphrase: password, Replace: *replace}
	var result maintenance.Result
	switch action {
	case "create":
		result, e = maintenance.Create(ctx, opt)
	case "verify":
		result, e = maintenance.Verify(ctx, opt)
	case "restore":
		result, e = maintenance.Restore(ctx, opt)
	}
	if e != nil {
		return e
	}
	return json.NewEncoder(output).Encode(result)
}
func defaultValue(value, fallback string) string {
	if value == "" {
		return fallback
	}
	return value
}
