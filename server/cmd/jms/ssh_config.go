package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"unicode"

	"github.com/neko233-com/jumpserver233/server/internal/core/organizations"
	"github.com/neko233-com/jumpserver233/server/internal/sessionclient"
)

var sshConfigSafeName = regexp.MustCompile(`^[A-Za-z0-9_.-]+$`)

const sshConfigMarker = "# JumpServer233 managed SSH aliases: "

func runSSHConfig(args []string) error {
	if len(args) == 0 || args[0] != "sync" {
		return errors.New("usage: jms ssh-config sync [--host HOST] [--port 2222] [--config PATH] [--preview]")
	}
	flags := flag.NewFlagSet("ssh-config sync", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	host := flags.String("host", "", "bastion SSH host")
	port := flags.Int("port", 2222, "bastion SSH port")
	configPath := flags.String("config", "", "OpenSSH config path")
	preview := flags.Bool("preview", false, "show aliases without writing")
	if err := flags.Parse(args[1:]); err != nil || flags.NArg() != 0 {
		return errors.New("invalid ssh-config flags")
	}
	endpoint := os.Getenv("JMS_SERVER_URL")
	if endpoint == "" {
		endpoint = "http://127.0.0.1:8080"
	}
	parsed, err := url.Parse(endpoint)
	if err != nil || parsed.Hostname() == "" {
		return errors.New("invalid JMS_SERVER_URL")
	}
	if *host == "" {
		*host = parsed.Hostname()
	}
	if *configPath == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return err
		}
		*configPath = filepath.Join(home, ".ssh", "config")
	}
	client, err := clientFromEnvironment(endpoint, "")
	if err != nil {
		return err
	}
	username, assets, err := client.SSHConfigInventory(context.Background())
	if err != nil {
		return err
	}
	organization := os.Getenv("JMS_ORG_ID")
	if organization == "" {
		organization = organizations.DefaultID
	}
	return importSSHConfig(*configPath, endpoint, *host, *port, username, organization, assets, *preview, os.Stdout)
}

func sshConfigHostValid(host string) bool {
	return host != "" && (net.ParseIP(host) != nil || sshConfigSafeName.MatchString(host)) && !strings.HasPrefix(host, "-")
}

func importSSHConfig(configPath, endpoint, host string, port int, username, organization string, assets []sessionclient.SSHConfigAsset, preview bool, out io.Writer) error {
	if !sshConfigHostValid(host) || port < 1 || port > 65535 || !sshConfigSafeName.MatchString(username) || (organization != "" && !sshConfigSafeName.MatchString(organization)) {
		return errors.New("invalid SSH host, port, user or organization")
	}
	configPath, err := filepath.Abs(configPath)
	if err != nil || strings.ContainsAny(configPath, "\"\r\n\x00") {
		return errors.New("invalid SSH config path")
	}
	digest := sha256.Sum256([]byte(endpoint + "\x00" + host + "\x00" + fmt.Sprint(port) + "\x00" + username + "\x00" + organization))
	profile := hex.EncodeToString(digest[:6])
	marker := sshConfigMarker + profile
	type entry struct{ alias, id, name string }
	entries := make([]entry, 0)
	seen := map[string]bool{}
	for _, asset := range assets {
		if asset.Protocol != "" && asset.Protocol != "ssh" {
			continue
		}
		for _, account := range asset.Accounts {
			allowed := false
			for _, permission := range account.Permissions {
				if permission == "connect" {
					allowed = true
				}
			}
			if !allowed || !account.Active {
				continue
			}
			if !sshConfigSafeName.MatchString(account.ID) || strings.Contains(account.ID, ".") || len(account.ID) > 128 || seen[account.ID] {
				return errors.New("invalid or duplicate authorized account identity")
			}
			seen[account.ID] = true
			name := strings.Map(func(r rune) rune {
				if unicode.IsControl(r) {
					return ' '
				}
				return r
			}, asset.Name+" / "+account.Name)
			if len([]rune(name)) > 160 {
				name = string([]rune(name)[:160])
			}
			entries = append(entries, entry{alias: "jms-" + profile + "-" + account.ID, id: account.ID, name: name})
		}
	}
	if len(entries) == 0 {
		return errors.New("no active SSH accounts with connect permission")
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].alias < entries[j].alias })
	var content strings.Builder
	begin, end := "# BEGIN "+marker+"\n", "# END "+marker+"\n"
	content.WriteString(begin + "# Generated from authorized inventory; no target credentials are stored.\n")
	for _, entry := range entries {
		user := username + "#" + entry.id
		if organization != "" {
			user += "%" + organization
		}
		fmt.Fprintf(&content, "\n# %s\nHost %s\n    HostName %s\n    Port %d\n    User %s\n", entry.name, entry.alias, host, port, user)
		fmt.Fprintf(out, "%s  %s\n", entry.alias, entry.name)
	}
	content.WriteString(end)
	if preview {
		return nil
	}
	if err = os.MkdirAll(filepath.Dir(configPath), 0700); err != nil {
		return err
	}
	old, mode, err := readSSHConfigFile(configPath)
	if err != nil {
		return err
	}
	oldText := string(old)
	beginCount, endCount := strings.Count(oldText, begin), strings.Count(oldText, end)
	if beginCount != endCount || beginCount > 1 || (beginCount == 0 && strings.Contains(oldText, marker)) {
		return errors.New("existing managed block has changed; inspect it before syncing")
	}
	rest := oldText
	if beginCount == 1 {
		start, finish := strings.Index(oldText, begin), strings.Index(oldText, end)
		if finish < start {
			return errors.New("existing managed block is malformed")
		}
		rest = oldText[:start] + oldText[finish+len(end):]
	}
	for _, line := range strings.Split(rest, "\n") {
		fields := strings.Fields(strings.TrimSpace(line))
		if len(fields) < 2 || !strings.EqualFold(fields[0], "Host") {
			continue
		}
		for _, pattern := range fields[1:] {
			if pattern == "*" {
				continue
			}
			for _, entry := range entries {
				if !strings.HasPrefix(pattern, "!") {
					if matched, _ := path.Match(strings.ToLower(pattern), strings.ToLower(entry.alias)); matched {
						return errors.New("generated alias conflicts with an existing Host pattern")
					}
				}
			}
		}
	}
	bom := ""
	if strings.HasPrefix(rest, "\ufeff") {
		bom = "\ufeff"
		rest = strings.TrimPrefix(rest, "\ufeff")
	}
	if err = writeSSHConfigFile(configPath, []byte(bom+content.String()+rest), old, mode); err != nil {
		return err
	}
	fmt.Fprintf(out, "Updated %s; connect using an alias and authenticate to the bastion.\n", configPath)
	return nil
}

func readSSHConfigFile(filePath string) ([]byte, os.FileMode, error) {
	info, err := os.Lstat(filePath)
	if errors.Is(err, os.ErrNotExist) {
		return nil, 0600, nil
	}
	if err != nil {
		return nil, 0, err
	}
	if !info.Mode().IsRegular() || info.Size() > 4*1024*1024 {
		return nil, 0, errors.New("SSH config must be a regular file under 4 MiB")
	}
	data, err := os.ReadFile(filePath)
	return data, info.Mode().Perm(), err
}

func writeSSHConfigFile(filePath string, data, expected []byte, mode os.FileMode) error {
	f, err := os.CreateTemp(filepath.Dir(filePath), ".jms-ssh-config-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if err = f.Chmod(mode); err == nil {
		_, err = f.Write(data)
	}
	if err == nil {
		err = f.Sync()
	}
	if closeErr := f.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	current, _, err := readSSHConfigFile(filePath)
	if err != nil {
		return err
	}
	if (current == nil) != (expected == nil) || string(current) != string(expected) {
		return errors.New("SSH config changed during import; retry")
	}
	return os.Rename(f.Name(), filePath)
}
