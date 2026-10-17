package hostplugins

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"path"
	"strings"
	"unicode"

	"github.com/neko233-com/jumpserver233/server/internal/hostagent"
)

func rootAdminDirectoryCheck(dir string) string {
	q := quote(dir)
	return "[ ! -L " + q + " ]; [ -d " + q + " ]; [ \"$(stat -c %u " + q + ")\" = 0 ]; admin_mode=$(stat -c %a " + q + "); [ $((0$admin_mode & 022)) -eq 0 ]; "
}

// ExecuteAccountAdmin uses one physical-host reservation shared with discovery.
// Root installs the verified helper; delegated accounts may only run the same
// root-owned global helper through an already configured noninteractive sudo rule.
func (s *Service) ExecuteAccountAdmin(ctx context.Context, assetID, jobID, physicalID string, op hostagent.AccountOperation, guard func() error) (hostagent.AccountAdminResult, error) {
	if op.Validate() != nil || guard == nil || physicalID == "" || physicalID != op.ParentAssetID || len(jobID) != 36 || !strings.HasPrefix(jobID, "job-") {
		return hostagent.AccountAdminResult{}, ErrInvalid
	}
	if _, e := hex.DecodeString(jobID[4:]); e != nil {
		return hostagent.AccountAdminResult{}, ErrInvalid
	}
	if e := guard(); e != nil {
		return hostagent.AccountAdminResult{}, e
	}
	s.discoveryMu.Lock()
	if s.discoveryActive == nil {
		s.discoveryActive = map[string]bool{}
	}
	if s.discoveryActive[physicalID] || len(s.discoveryActive) >= 4 {
		s.discoveryMu.Unlock()
		return hostagent.AccountAdminResult{}, ErrConflict
	}
	s.discoveryActive[physicalID] = true
	s.discoveryMu.Unlock()
	defer func() { s.discoveryMu.Lock(); delete(s.discoveryActive, physicalID); s.discoveryMu.Unlock() }()
	rawHost, e := s.open(ctx, assetID)
	if e != nil {
		return hostagent.AccountAdminResult{}, e
	}
	defer rawHost.Close()
	h := &guardedTransport{Transport: rawHost, guard: guard}
	facts, e := run(ctx, h, "uname -s; uname -m; id -u")
	if e != nil {
		return hostagent.AccountAdminResult{}, e
	}
	parts := strings.Split(facts, "\n")
	if len(parts) != 3 {
		return hostagent.AccountAdminResult{}, ErrUnsupported
	}
	platform, e := Platform(parts[0], parts[1])
	if e != nil || !strings.HasPrefix(platform, "linux-") {
		return hostagent.AccountAdminResult{}, ErrUnsupported
	}
	b, e := nativeRecovery(platform, hostagent.AccountAdminBinaryDirectory, "")
	if e != nil {
		return hostagent.AccountAdminResult{}, recoveryError(e)
	}
	if parts[2] == "0" {
		home := h.Root()
		if !path.IsAbs(home) || path.Clean(home) != home || len(home) > 2048 || strings.IndexFunc(home, unicode.IsControl) >= 0 {
			return hostagent.AccountAdminResult{}, ErrInvalid
		}
		base, dir := path.Join(home, ".jumpserver233"), path.Join(home, ".jumpserver233", "account-admin")
		setup := ""
		for _, p := range []string{base, dir} {
			q := quote(p)
			setup += "[ ! -L " + q + " ]; if [ ! -e " + q + " ]; then mkdir -m 700 " + q + "; fi; [ -d " + q + " ]; [ \"$(stat -c %u " + q + ")\" = 0 ]; chmod 700 " + q + "; "
		}
		if _, e = run(ctx, h, setup+"printf ready"); e != nil {
			return hostagent.AccountAdminResult{}, e
		}
		staged, e := nativeRecovery(platform, dir, "")
		if e != nil {
			return hostagent.AccountAdminResult{}, e
		}
		if e = staged.ensure(ctx, h, dir, jobID); e != nil {
			return hostagent.AccountAdminResult{}, e
		}
		installed, e := run(ctx, h, staged.verify()+"env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin LANG=C "+quote(staged.file)+" account-admin-install")
		if e != nil {
			return hostagent.AccountAdminResult{}, e
		}
		var status struct {
			Format string `json:"format"`
			Path   string `json:"path"`
			SHA    string `json:"sha256"`
		}
		if json.Unmarshal([]byte(installed), &status) != nil || status.Format != hostagent.AccountAdminFormat || status.Path != b.file || status.SHA != b.SHA256 {
			return hostagent.AccountAdminResult{}, ErrIntegrity
		}
	}
	check := ""
	for _, dir := range []string{"/usr", "/usr/local", "/usr/local/libexec", hostagent.AccountAdminBinaryDirectory} {
		check += rootAdminDirectoryCheck(dir)
	}
	check += b.verify() + "[ \"$(stat -c %u " + quote(b.file) + ")\" = 0 ]; [ \"$(stat -c %a " + quote(b.file) + ")\" = 755 ]; "
	if _, e = run(ctx, h, check+"printf ready"); e != nil {
		return hostagent.AccountAdminResult{}, ErrIntegrity
	}
	request, e := json.Marshal(hostagent.AccountAdminRequest{Task: op.Task, Mode: op.Mode})
	if e != nil {
		return hostagent.AccountAdminResult{}, ErrInvalid
	}
	command := "set -eu; umask 077; " + check
	if parts[2] != "0" {
		command += "sudo -n -- " + quote(b.file) + " account-admin"
	} else {
		command += "env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin LANG=C " + quote(b.file) + " account-admin"
	}
	out, e := h.RunInput(ctx, command, request)
	if e != nil {
		return hostagent.AccountAdminResult{}, e
	}
	if out.Truncated || out.Stderr != "" {
		return hostagent.AccountAdminResult{}, ErrIntegrity
	}
	result, e := hostagent.DecodeAccountAdminResult([]byte(out.Stdout), op.Task)
	if e != nil {
		return hostagent.AccountAdminResult{}, ErrIntegrity
	}
	if out.ExitCode != 0 {
		return result, hostagent.ErrAccountAdmin
	}
	return result, nil
}
