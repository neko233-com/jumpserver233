package hostplugins

import (
	"context"
	"encoding/hex"
	"path"
	"strconv"
	"strings"
	"unicode"

	"github.com/neko233-com/jumpserver233/server/internal/hostagent"
)

// DiscoverAccounts uses the embedded, hash-verified native helper. It never
// retrieves passwd/shadow text, changes a target account or executes its shell.
func (s *Service) DiscoverAccounts(ctx context.Context, assetID, jobID string, guard func() error) ([]hostagent.Account, string, error) {
	if guard == nil || len(jobID) != 36 || !strings.HasPrefix(jobID, "job-") {
		return nil, "", ErrInvalid
	}
	if _, e := hex.DecodeString(jobID[4:]); e != nil {
		return nil, "", ErrInvalid
	}
	if e := guard(); e != nil {
		return nil, "", e
	}
	s.discoveryMu.Lock()
	if s.discoveryActive == nil {
		s.discoveryActive = map[string]bool{}
	}
	if s.discoveryActive[assetID] || len(s.discoveryActive) >= 4 {
		s.discoveryMu.Unlock()
		return nil, "", ErrConflict
	}
	s.discoveryActive[assetID] = true
	s.discoveryMu.Unlock()
	defer func() { s.discoveryMu.Lock(); delete(s.discoveryActive, assetID); s.discoveryMu.Unlock() }()
	h, e := s.open(ctx, assetID)
	if e != nil {
		return nil, "", e
	}
	defer h.Close()
	h = &guardedTransport{Transport: h, guard: guard}
	facts, e := run(ctx, h, "uname -s; uname -m")
	if e != nil {
		return nil, "", e
	}
	parts := strings.Split(facts, "\n")
	if len(parts) != 2 {
		return nil, "", ErrUnsupported
	}
	platform, e := Platform(parts[0], parts[1])
	if e != nil || !strings.HasPrefix(platform, "linux-") {
		return nil, "", ErrUnsupported
	}
	home := h.Root()
	if !path.IsAbs(home) || path.Clean(home) != home || len(home) > 2048 || strings.IndexFunc(home, unicode.IsControl) >= 0 {
		return nil, "", ErrInvalid
	}
	base := path.Join(home, ".jumpserver233")
	dir := path.Join(base, "account-discovery")
	setup := ""
	for _, p := range []string{base, dir} {
		q := quote(p)
		setup += "[ ! -L " + q + " ]; if [ ! -e " + q + " ]; then mkdir -m 700 " + q + "; fi; [ -d " + q + " ]; [ \"$(stat -c %u " + q + ")\" = \"$(id -u)\" ]; chmod 700 " + q + "; "
	}
	if _, e = run(ctx, h, setup+"printf ready"); e != nil {
		return nil, "", e
	}
	b, e := nativeRecovery(platform, dir, "")
	if e != nil {
		return nil, "", recoveryError(e)
	}
	if e = b.ensure(ctx, h, dir, jobID); e != nil {
		return nil, "", e
	}
	rows := []hostagent.Account{}
	digest := ""
	total := 0
	for offset := 0; offset < hostagent.MaxAccounts; offset += hostagent.AccountPageSize {
		out, e := h.Run(ctx, "set -eu; umask 077; "+b.verify()+quote(b.file)+" accounts --offset "+strconv.Itoa(offset))
		if e != nil {
			return nil, "", e
		}
		if out.ExitCode != 0 || out.Truncated || len(out.Stderr) != 0 {
			return nil, "", ErrIntegrity
		}
		page, e := hostagent.DecodeAccountPage([]byte(out.Stdout))
		if e != nil || page.Offset != offset {
			return nil, "", ErrIntegrity
		}
		if offset == 0 {
			digest = page.Digest
			total = page.Total
		} else if page.Digest != digest || page.Total != total {
			return nil, "", ErrConflict
		}
		if len(rows) > 0 && rows[len(rows)-1].Username >= page.Accounts[0].Username {
			return nil, "", ErrIntegrity
		}
		rows = append(rows, page.Accounts...)
		if len(rows) == total {
			if hostagent.AccountDigest(rows) != digest {
				return nil, "", ErrIntegrity
			}
			return rows, digest, nil
		}
	}
	return nil, "", ErrIntegrity
}
