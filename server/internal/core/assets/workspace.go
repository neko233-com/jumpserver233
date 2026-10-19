package assets

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"path"
	"strings"
	"time"

	"github.com/neko233-com/jumpserver233/server/internal/agentbundle"
	"github.com/neko233-com/jumpserver233/server/internal/connector/sshclient"
	"github.com/neko233-com/jumpserver233/server/internal/hostagent"
)

func workspaceQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", "'\"'\"'") + "'" }

// WorkspaceIdentity prepares only a trusted helper and probes the configured
// directory. It never starts an operator command while an approval is pending.
func (s *Service) WorkspaceIdentity(ctx context.Context, id string) (string, error) {
	asset, target, credentials, err := s.store.connectionForProtocolBound(id, true, expectedConnectionBinding(ctx))
	if err != nil || asset.SSHWorkspace == "" {
		return "", err
	}
	h, err := sshclient.OpenManagedHost(ctx, target, credentials)
	if err != nil {
		return "", err
	}
	defer h.Close()
	_, identity, err := prepareWorkspace(ctx, h, asset.SSHWorkspace, false)
	return identity, err
}

// Only the server calls this preparation path. The operator never receives an
// unconfined file/command channel or the asset's SSH credential.
func (s *Service) workspaceStartup(ctx context.Context, target sshclient.Target, credentials sshclient.Credentials, directory string, execInput bool) (string, error) {
	h, e := sshclient.OpenManagedHost(ctx, target, credentials)
	if e != nil {
		return "", e
	}
	defer h.Close()
	startup, _, err := prepareWorkspace(ctx, h, directory, execInput)
	return startup, err
}

func prepareWorkspace(ctx context.Context, h *sshclient.ManagedHost, directory string, execInput bool) (string, string, error) {
	if hostagent.ValidateWorkspace(directory) != nil {
		return "", "", hostagent.ErrWorkspaceInvalid
	}
	check := func(script string) (string, error) {
		out, e := h.Run(ctx, "set -eu; umask 077; "+script)
		if e != nil || out.ExitCode != 0 || out.Truncated {
			return "", hostagent.ErrWorkspaceUnavailable
		}
		return strings.TrimSpace(out.Stdout), nil
	}
	facts, e := check("uname -s; uname -m")
	platform := ""
	switch facts {
	case "Linux\nx86_64":
		platform = "linux-amd64"
	case "Linux\naarch64", "Linux\narm64":
		platform = "linux-arm64"
	}
	if e != nil || platform == "" {
		return "", "", hostagent.ErrWorkspaceUnavailable
	}
	binary, e := agentbundle.Get(platform)
	if e != nil {
		return "", "", e
	}
	home := h.Root()
	if !path.IsAbs(home) || path.Clean(home) != home || len(home) > 2048 || strings.ContainsAny(home, "\r\n\x00") {
		return "", "", hostagent.ErrWorkspaceInvalid
	}
	base := path.Join(home, ".jumpserver233")
	if hostagent.ValidateWorkspaceControl(directory, base) != nil {
		return "", "", hostagent.ErrWorkspaceInvalid
	}
	dir := path.Join(base, "workspace")
	for _, name := range []string{base, dir} {
		q := workspaceQuote(name)
		if _, e = check("[ ! -L " + q + " ]; if [ ! -e " + q + " ]; then mkdir -m 700 " + q + "; fi; [ -d " + q + " ]; [ \"$(stat -c %u " + q + ")\" = \"$(id -u)\" ]; chmod 700 " + q); e != nil {
			return "", "", e
		}
	}
	file := path.Join(dir, "jms-agent-"+binary.SHA256)
	q := workspaceQuote(file)
	verify := "[ ! -L " + q + " ]; [ -f " + q + " ]; [ \"$(sha256sum " + q + " | cut -d ' ' -f 1)\" = " + workspaceQuote(binary.SHA256) + " ]; "
	present, e := check("[ ! -L " + q + " ]; if [ -e " + q + " ]; then " + verify + "printf present; else printf missing; fi")
	if e != nil {
		return "", "", e
	}
	if present == "missing" {
		var nonce [16]byte
		if _, e = rand.Read(nonce[:]); e != nil {
			return "", "", e
		}
		stage := path.Join(dir, "upload-"+hex.EncodeToString(nonce[:]))
		if _, e = check("mkdir -m 700 " + workspaceQuote(stage)); e != nil {
			return "", "", e
		}
		defer func() {
			_, _ = check("rm -f -- " + workspaceQuote(path.Join(stage, "binary")) + "; rmdir -- " + workspaceQuote(stage))
		}()
		if e = h.Upload(ctx, path.Join(stage, "binary"), bytes.NewReader(binary.Data)); e != nil {
			return "", "", e
		}
		staged := workspaceQuote(path.Join(stage, "binary"))
		if _, e = check("[ \"$(sha256sum " + staged + " | cut -d ' ' -f 1)\" = " + workspaceQuote(binary.SHA256) + " ]; chmod 700 " + staged + "; if ln " + staged + " " + q + " 2>/dev/null; then :; else " + verify + ":; fi"); e != nil {
			return "", "", e
		}
	}
	command := "env -i PATH=/usr/bin:/bin LANG=C " + q
	status, e := check(verify + command + " workspace-check --directory " + workspaceQuote(directory))
	var state hostagent.WorkspaceStatus
	if e != nil || json.Unmarshal([]byte(status), &state) != nil || state.Format != "jms233-workspace-v1" || state.Directory != directory || state.LandlockABI < 3 || !hostagent.ValidWorkspaceIdentity(state.Identity) {
		return "", "", hostagent.ErrWorkspaceUnavailable
	}
	if expected := expectedWorkspaceIdentity(ctx); expected != "" && expected != state.Identity {
		return "", "", ErrConnectionChanged
	}
	startup := "set -eu; " + verify + "exec " + command + " workspace --directory " + workspaceQuote(directory) + " --identity " + workspaceQuote(state.Identity)
	if execInput {
		startup += " --exec-stdin"
	}
	return startup, state.Identity, nil
}

func (s *Service) openWorkspaceSFTP(ctx context.Context, target sshclient.Target, credentials sshclient.Credentials, directory string) (*sshclient.SFTP, error) {
	startup, e := s.workspaceStartup(ctx, target, credentials, directory, false)
	if e != nil {
		return nil, e
	}
	remote, e := sshclient.OpenSFTPCommand(ctx, target, credentials, 12*time.Second, startup+" --sftp")
	if e != nil {
		return nil, e
	}
	if remote.Root() != "/" {
		_ = remote.Close()
		return nil, hostagent.ErrWorkspaceUnavailable
	}
	return remote, nil
}

func (s *Service) execWorkspace(ctx context.Context, target sshclient.Target, credentials sshclient.Credentials, directory, command string) (sshclient.ExecResult, error) {
	h, e := sshclient.OpenManagedHost(ctx, target, credentials)
	if e != nil {
		return sshclient.ExecResult{ExitCode: -1}, e
	}
	defer h.Close()
	startup, _, e := prepareWorkspace(ctx, h, directory, true)
	if e != nil {
		return sshclient.ExecResult{ExitCode: -1}, e
	}
	request, e := json.Marshal(struct {
		Command string `json:"command"`
	}{command})
	if e != nil {
		return sshclient.ExecResult{ExitCode: -1}, e
	}
	return h.RunInput(ctx, startup, request)
}
