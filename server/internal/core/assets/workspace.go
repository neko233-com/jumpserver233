package assets

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"path"
	"strconv"
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

// WorkspaceDetails opens and identifies the configured root and selected cwd
// without executing an operator command. The proof is checked again at exec.
func (s *Service) WorkspaceDetails(ctx context.Context, id, workingDirectory string) (hostagent.WorkspaceStatus, error) {
	asset, target, credentials, err := s.store.connectionForProtocolBound(id, true, expectedConnectionBinding(ctx))
	if err != nil {
		return hostagent.WorkspaceStatus{}, err
	}
	if workingDirectory == "" {
		workingDirectory = asset.SSHWorkspace
	}
	if hostagent.ValidateWorkingDirectory(asset.SSHWorkspace, workingDirectory) != nil {
		return hostagent.WorkspaceStatus{}, hostagent.ErrWorkspaceInvalid
	}
	h, err := sshclient.OpenManagedHost(ctx, target, credentials)
	if err != nil {
		return hostagent.WorkspaceStatus{}, err
	}
	defer h.Close()
	expected := expectedWorkingDirectory(ctx)
	if expected.directory != "" && expected.directory != workingDirectory {
		return hostagent.WorkspaceStatus{}, ErrConnectionChanged
	}
	_, state, err := prepareWorkspaceStatus(WithWorkingDirectory(ctx, workingDirectory, expected.identity), h, asset.SSHWorkspace, true)
	return state, err
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
	startup, state, err := prepareWorkspaceStatus(ctx, h, directory, execInput)
	return startup, state.Identity, err
}

func prepareWorkspaceStatus(ctx context.Context, h *sshclient.ManagedHost, directory string, execInput bool, modes ...string) (string, hostagent.WorkspaceStatus, error) {
	if len(modes) > 1 || len(modes) == 1 && (modes[0] != "terminal" || execInput) {
		return "", hostagent.WorkspaceStatus{}, hostagent.ErrWorkspaceInvalid
	}
	if hostagent.ValidateWorkspace(directory) != nil {
		return "", hostagent.WorkspaceStatus{}, hostagent.ErrWorkspaceInvalid
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
		return "", hostagent.WorkspaceStatus{}, hostagent.ErrWorkspaceUnavailable
	}
	binary, e := agentbundle.Get(platform)
	if e != nil {
		return "", hostagent.WorkspaceStatus{}, e
	}
	home := h.Root()
	if !path.IsAbs(home) || path.Clean(home) != home || len(home) > 2048 || strings.ContainsAny(home, "\r\n\x00") {
		return "", hostagent.WorkspaceStatus{}, hostagent.ErrWorkspaceInvalid
	}
	base := path.Join(home, ".jumpserver233")
	if hostagent.ValidateWorkspaceControl(directory, base) != nil {
		return "", hostagent.WorkspaceStatus{}, hostagent.ErrWorkspaceInvalid
	}
	dir := path.Join(base, "workspace")
	for _, name := range []string{base, dir} {
		q := workspaceQuote(name)
		if _, e = check("[ ! -L " + q + " ]; if [ ! -e " + q + " ]; then mkdir -m 700 " + q + "; fi; [ -d " + q + " ]; [ \"$(stat -c %u " + q + ")\" = \"$(id -u)\" ]; chmod 700 " + q); e != nil {
			return "", hostagent.WorkspaceStatus{}, e
		}
	}
	file := path.Join(dir, "jms-agent-"+binary.SHA256)
	q := workspaceQuote(file)
	verify := "[ ! -L " + q + " ]; [ -f " + q + " ]; [ \"$(sha256sum " + q + " | cut -d ' ' -f 1)\" = " + workspaceQuote(binary.SHA256) + " ]; "
	present, e := check("[ ! -L " + q + " ]; if [ -e " + q + " ]; then " + verify + "printf present; else printf missing; fi")
	if e != nil {
		return "", hostagent.WorkspaceStatus{}, e
	}
	if present == "missing" {
		var nonce [16]byte
		if _, e = rand.Read(nonce[:]); e != nil {
			return "", hostagent.WorkspaceStatus{}, e
		}
		stage := path.Join(dir, "upload-"+hex.EncodeToString(nonce[:]))
		if _, e = check("mkdir -m 700 " + workspaceQuote(stage)); e != nil {
			return "", hostagent.WorkspaceStatus{}, e
		}
		defer func() {
			_, _ = check("rm -f -- " + workspaceQuote(path.Join(stage, "binary")) + "; rmdir -- " + workspaceQuote(stage))
		}()
		if e = h.Upload(ctx, path.Join(stage, "binary"), bytes.NewReader(binary.Data)); e != nil {
			return "", hostagent.WorkspaceStatus{}, e
		}
		staged := workspaceQuote(path.Join(stage, "binary"))
		if _, e = check("[ \"$(sha256sum " + staged + " | cut -d ' ' -f 1)\" = " + workspaceQuote(binary.SHA256) + " ]; chmod 700 " + staged + "; if ln " + staged + " " + q + " 2>/dev/null; then :; else " + verify + ":; fi"); e != nil {
			return "", hostagent.WorkspaceStatus{}, e
		}
	}
	command := "env -i PATH=/usr/bin:/bin LANG=C " + q
	working := expectedWorkingDirectory(ctx)
	checkCommand := verify + command + " workspace-check --directory " + workspaceQuote(directory)
	if working.directory != "" {
		if hostagent.ValidateWorkingDirectory(directory, working.directory) != nil {
			return "", hostagent.WorkspaceStatus{}, hostagent.ErrWorkspaceInvalid
		}
		checkCommand += " --working-directory " + workspaceQuote(working.directory)
	}
	status, e := check(checkCommand)
	var state hostagent.WorkspaceStatus
	if e != nil || json.Unmarshal([]byte(status), &state) != nil || state.Format != "jms233-workspace-v1" || state.Directory != directory || state.LandlockABI < 3 || !hostagent.ValidWorkspaceIdentity(state.Identity) {
		return "", hostagent.WorkspaceStatus{}, hostagent.ErrWorkspaceUnavailable
	}
	if expected := expectedWorkspaceIdentity(ctx); expected != "" && expected != state.Identity {
		return "", hostagent.WorkspaceStatus{}, ErrConnectionChanged
	}
	if working.directory != "" && (state.WorkingDirectory != working.directory || !hostagent.ValidWorkspaceIdentity(state.WorkingIdentity)) {
		return "", hostagent.WorkspaceStatus{}, hostagent.ErrWorkspaceUnavailable
	}
	if working.identity != "" && working.identity != state.WorkingIdentity {
		return "", hostagent.WorkspaceStatus{}, ErrConnectionChanged
	}
	action := "workspace"
	if len(modes) == 1 {
		action = "workspace-terminal"
	}
	startup := "set -eu; " + verify + "exec " + command + " " + action + " --directory " + workspaceQuote(directory) + " --identity " + workspaceQuote(state.Identity)
	if working.directory != "" {
		if !execInput {
			return "", hostagent.WorkspaceStatus{}, hostagent.ErrWorkspaceInvalid
		}
		startup += " --working-directory " + workspaceQuote(state.WorkingDirectory) + " --working-identity " + workspaceQuote(state.WorkingIdentity)
	}
	if execInput {
		startup += " --exec-stdin"
	}
	return startup, state, nil
}

func (s *Service) workspaceTerminalStartup(ctx context.Context, target sshclient.Target, credentials sshclient.Credentials, directory string, cols, rows int) (string, string, error) {
	h, e := sshclient.OpenManagedHost(ctx, target, credentials)
	if e != nil {
		return "", "", e
	}
	defer h.Close()
	startup, state, e := prepareWorkspaceStatus(ctx, h, directory, false, "terminal")
	if e != nil {
		return "", "", e
	}
	return startup + " --cols " + strconv.Itoa(cols) + " --rows " + strconv.Itoa(rows), state.Identity, nil
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
	if e = checkExecution(ctx); e != nil {
		return sshclient.ExecResult{ExitCode: -1}, e
	}
	request, e := json.Marshal(struct {
		Command string `json:"command"`
		Input   []byte `json:"input,omitempty"`
	}{command, sshclient.ExecInput(ctx)})
	if e != nil {
		return sshclient.ExecResult{ExitCode: -1}, e
	}
	return h.RunInput(ctx, startup, request)
}
