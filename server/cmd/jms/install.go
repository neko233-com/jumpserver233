package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"os"
	"runtime"
	"strconv"

	"github.com/neko233-com/jumpserver233/server/internal/buildinfo"
	"github.com/neko233-com/jumpserver233/server/internal/maintenance"
	"github.com/neko233-com/jumpserver233/server/internal/releasebundle"
)

const installUsage = "usage: jms update install --root ROOT --data-dir DATA --sha256 SHA --revision N --request-id ID [--passphrase-file FILE|-] [--source-version VERSION] | install-recover --root ROOT [--passphrase-file FILE|-] | install-status --root ROOT | run --root ROOT [--passphrase-file FILE|-]; first startup validates the candidate before business traffic; protect the checkpoint passphrase"

func executeInstallation(ctx context.Context, args []string, input io.Reader, output, diagnostic io.Writer, prompt func(bool) ([]byte, error)) error {
	if len(args) == 0 {
		return errors.New(installUsage)
	}
	flags := flag.NewFlagSet("update install", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	root := flags.String("root", "", "")
	data := flags.String("data-dir", os.Getenv("JMS_DATA_DIR"), "")
	sha := flags.String("sha256", "", "")
	revision := flags.Int("revision", -1, "")
	id := flags.String("request-id", "", "")
	source := flags.String("source-version", buildinfo.Version, "")
	passwordFile := flags.String("passphrase-file", "", "")
	if flags.Parse(args[1:]) != nil || flags.NArg() != 0 || *root == "" {
		return errors.New(installUsage)
	}
	visited := map[string]bool{}
	flags.Visit(func(f *flag.Flag) { visited[f.Name] = true })
	if args[0] != "install" {
		for name := range visited {
			if name != "root" && !((args[0] == "install-recover" || args[0] == "run") && name == "passphrase-file") {
				return errors.New(installUsage)
			}
		}
	}
	if args[0] != "install" && args[0] != "install-recover" && args[0] != "install-status" && args[0] != "run" {
		return errors.New(installUsage)
	}
	cluster, e := strconv.ParseBool(defaultValue(os.Getenv("JMS_CLUSTER_MODE"), "false"))
	if e != nil {
		return maintenance.ErrInvalid
	}
	if cluster {
		return maintenance.ErrCluster
	}
	if args[0] == "install-status" {
		status, e := releasebundle.InstallationStatus(ctx, *root)
		if e != nil {
			return e
		}
		return json.NewEncoder(output).Encode(status)
	}
	if args[0] == "run" {
		status, e := releasebundle.InstallationStatus(ctx, *root)
		if e != nil {
			return e
		}
		var password []byte
		if status.PendingUpgrade != "" && status.ActivationState != "active" {
			password, e = readInstallPassphrase(input, *passwordFile, prompt, false)
			if e != nil {
				return e
			}
			defer clear(password)
		}
		return releasebundle.RunInstalledWithPassphrase(ctx, *root, password, output, diagnostic)
	}
	if args[0] == "install" && (*data == "" || *sha == "" || *revision < 0 || *id == "") {
		return errors.New(installUsage)
	}
	password, e := readInstallPassphrase(input, *passwordFile, prompt, args[0] == "install")
	if e != nil {
		return e
	}
	defer clear(password)
	var result releasebundle.InstallResult
	if args[0] == "install" {
		result, e = releasebundle.Install(ctx, releasebundle.InstallOptions{Root: *root, DataDir: *data, ArchiveSHA256: *sha, Revision: *revision, RequestID: *id, SourceVersion: *source, ExternalVaultKey: os.Getenv("JMS_VAULT_KEY"), Passphrase: password})
	} else {
		result, e = releasebundle.RecoverInstallation(ctx, *root, password)
	}
	if result.ID != "" || e == nil {
		if emitErr := json.NewEncoder(output).Encode(result); emitErr != nil {
			return emitErr
		}
	}
	return e
}
func readInstallPassphrase(input io.Reader, path string, prompt func(bool) ([]byte, error), confirm bool) ([]byte, error) {
	if path == "" {
		if prompt == nil {
			return nil, errors.New("use --passphrase-file - for protected stdin")
		}
		password, e := prompt(confirm)
		if e != nil {
			clear(password)
			return nil, e
		}
		if len(password) < 12 || len(password) > 1024 {
			clear(password)
			return nil, errors.New("backup passphrase must contain 12-1024 bytes")
		}
		return password, nil
	}
	reader := input
	if path != "-" {
		named, e := os.Lstat(path)
		if e != nil {
			return nil, e
		}
		if !named.Mode().IsRegular() || runtime.GOOS != "windows" && named.Mode().Perm()&0077 != 0 {
			return nil, errors.New("passphrase file must be private and regular")
		}
		f, e := os.Open(path)
		if e != nil {
			return nil, e
		}
		defer f.Close()
		info, e := f.Stat()
		if e != nil || !os.SameFile(named, info) {
			return nil, maintenance.ErrInvalid
		}
		reader = f
	}
	password, e := io.ReadAll(io.LimitReader(reader, 1027))
	if e != nil {
		clear(password)
		return nil, e
	}
	password = bytes.TrimRight(password, "\r\n")
	if len(password) < 12 || len(password) > 1024 {
		clear(password)
		return nil, errors.New("backup passphrase must contain 12-1024 bytes")
	}
	return password, nil
}
