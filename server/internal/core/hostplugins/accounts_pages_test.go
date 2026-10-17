package hostplugins_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"testing"

	"github.com/neko233-com/jumpserver233/server/internal/connector/sshclient"
	"github.com/neko233-com/jumpserver233/server/internal/core/hostplugins"
	"github.com/neko233-com/jumpserver233/server/internal/hostagent"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type accountPageHost struct {
	rows  []hostagent.Account
	mode  string
	pages int
}

func (h *accountPageHost) Run(_ context.Context, cmd string) (sshclient.ExecResult, error) {
	if strings.Contains(cmd, "uname -s;") {
		return sshclient.ExecResult{ExitCode: 0, Stdout: "Linux\nx86_64"}, nil
	}
	if strings.Contains(cmd, "printf present;") {
		return sshclient.ExecResult{ExitCode: 0, Stdout: "present"}, nil
	}
	if strings.Contains(cmd, " accounts --offset ") {
		h.pages++
		parts := strings.Fields(cmd)
		offset, _ := strconv.Atoi(parts[len(parts)-1])
		page := hostagent.AccountPage{Format: hostagent.AccountFormat, Digest: hostagent.AccountDigest(h.rows), Offset: offset, Total: len(h.rows), Accounts: h.rows[offset:min(offset+hostagent.AccountPageSize, len(h.rows))]}
		if offset > 0 && h.mode == "changed" {
			page.Digest = strings.Repeat("f", 64)
		}
		if offset > 0 && h.mode == "wrong-offset" {
			page.Offset = 0
		}
		data, _ := json.Marshal(page)
		return sshclient.ExecResult{ExitCode: 0, Stdout: string(data), Truncated: offset > 0 && h.mode == "truncated"}, nil
	}
	return sshclient.ExecResult{ExitCode: 0, Stdout: "ready"}, nil
}
func (*accountPageHost) Upload(context.Context, string, io.Reader) error {
	return errors.New("unexpected upload")
}
func (*accountPageHost) Root() string { return "/home/qa" }
func (*accountPageHost) DialLoopback(context.Context) (net.Conn, error) {
	return nil, errors.New("unexpected network request")
}
func (*accountPageHost) Close() error { return nil }
func TestAccountDiscoveryPublishesOnlyCompleteConsistentPages(t *testing.T) {
	for _, mode := range []string{"complete", "changed", "wrong-offset", "truncated"} {
		t.Run(mode, func(t *testing.T) {
			h := &accountPageHost{mode: mode}
			for i := 0; i < 65; i++ {
				h.rows = append(h.rows, hostagent.Account{Username: fmt.Sprintf("qa%04d", i), UID: uint32(i + 1000), GID: 1000, Home: "/home/qa", Shell: "/bin/sh"})
			}
			s := hostplugins.New(func(context.Context, string) (hostplugins.Transport, error) { return h, nil }, nil)
			rows, digest, e := s.DiscoverAccounts(context.Background(), "asset", "job-"+strings.Repeat("a", 32), func() error { return nil })
			if mode == "complete" {
				require.NoError(t, e)
				assert.Equal(t, h.rows, rows)
				assert.Equal(t, hostagent.AccountDigest(rows), digest)
				assert.Equal(t, 3, h.pages)
			} else {
				require.Error(t, e)
				assert.Empty(t, rows)
				assert.Empty(t, digest)
				assert.Equal(t, 2, h.pages)
			}
		})
	}
}
