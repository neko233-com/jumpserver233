package releasebundle

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/neko233-com/jumpserver233/server/internal/maintenance"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNativeActivationProbeRejectsWrongInstanceVersionIndexAndUngatedTraffic(t *testing.T) {
	for _, kind := range []string{"valid", "instance", "version", "index", "api", "websocket", "redirect"} {
		t.Run(kind, func(t *testing.T) {
			index := []byte("<html>verified candidate</html>")
			sum := sha256.Sum256(index)
			m := Manifest{Version: "v1.2.3", Files: map[string]File{"web/index.html": {SHA256: hex.EncodeToString(sum[:]), Bytes: int64(len(index))}}}
			attempt := strings.Repeat("a", 32)
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("X-JMS-Activation", attempt)
				w.Header().Set("X-JMS-Activation-Phase", "trial")
				switch r.URL.Path {
				case "/api/health":
					if kind == "instance" {
						w.Header().Set("X-JMS-Activation", "wrong")
					}
					if kind == "redirect" {
						http.Redirect(w, r, "/elsewhere", 302)
						return
					}
					if kind == "version" {
						_, _ = io.WriteString(w, `{"version":"v9.9.9"}`)
					} else {
						_, _ = io.WriteString(w, `{"version":"v1.2.3"}`)
					}
				case "/":
					if kind == "index" {
						_, _ = io.WriteString(w, "wrong index")
					} else {
						_, _ = w.Write(index)
					}
				default:
					if kind == "api" && r.URL.Path == "/api/v1/assets" || kind == "websocket" && r.URL.Path == "/ws" {
						w.WriteHeader(401)
						return
					}
					w.WriteHeader(503)
					_, _ = io.WriteString(w, `{"code":"upgrade_activation_pending"}`)
				}
			}))
			defer server.Close()
			r := maintenance.ActivationRecord{Address: strings.TrimPrefix(server.URL, "http://"), Attempt: attempt}
			client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
			e := probeActivation(context.Background(), client, r, m, "trial")
			if kind == "valid" {
				require.NoError(t, e)
			} else {
				require.Error(t, e)
			}
		})
	}
}

func TestActivationRequiresVerifiedCheckpointKey(t *testing.T) {
	opt := installFixture(t)
	_, e := install(context.Background(), opt, successfulChecker)
	require.NoError(t, e)
	require.ErrorIs(t, RunInstalled(context.Background(), opt.Root, nil, nil), ErrActivationKeyRequired)
	wrong := []byte("incorrect-checkpoint-key")
	require.ErrorIs(t, RunInstalledWithPassphrase(context.Background(), opt.Root, wrong, nil, nil), maintenance.ErrIntegrity)
	assert.Equal(t, make([]byte, len(wrong)), wrong)
	state, e := InstallationStatus(context.Background(), opt.Root)
	require.NoError(t, e)
	assert.Equal(t, "awaiting_start", state.PendingUpgrade)
	assert.Equal(t, "selected", state.ActivationState)
}
func TestNativeActivationRollbackAdvancesRevisionAndCommittedRecoveryPreservesNewData(t *testing.T) {
	for _, committed := range []bool{false, true} {
		t.Run(map[bool]string{false: "trial", true: "active"}[committed], func(t *testing.T) {
			opt := installFixture(t)
			selected, e := install(context.Background(), opt, successfulChecker)
			require.NoError(t, e)
			s := installRoot(t, opt.Root)
			j, e := s.readUpgrade()
			require.NoError(t, e)
			j.Attempt = strings.Repeat("d", 32)
			j.Phase = "activating"
			require.NoError(t, s.saveUpgrade(j))
			lock, e := maintenance.Acquire(opt.DataDir)
			require.NoError(t, e)
			g := j.Guard
			g.Phase = "trial"
			g.Attempt = j.Attempt
			require.NoError(t, maintenance.SetUpgradeGuard(lock, g))
			if committed {
				g.Phase = "active"
				require.NoError(t, maintenance.SetUpgradeGuard(lock, g))
			}
			lock.Close()
			s.close()
			require.NoError(t, os.WriteFile(filepath.Join(opt.DataDir, "new-data"), []byte("new business"), 0600))
			r, e := RecoverInstallation(context.Background(), opt.Root, opt.Passphrase)
			require.NoError(t, e)
			state, e := InstallationStatus(context.Background(), opt.Root)
			require.NoError(t, e)
			if committed {
				assert.Equal(t, "selected", r.Status)
				assert.Equal(t, selected.Revision, state.Revision)
				assert.FileExists(t, filepath.Join(opt.DataDir, "new-data"))
			} else {
				assert.Equal(t, "rolled_back", r.Status)
				assert.Equal(t, 2, state.Revision)
				assert.Empty(t, state.Current.ArchiveSHA256)
				assert.NoFileExists(t, filepath.Join(opt.DataDir, "new-data"))
				opt.Revision = 2
				opt.RequestID = "activation-next-request"
				next, e := install(context.Background(), opt, successfulChecker)
				require.NoError(t, e)
				assert.Equal(t, 3, next.Revision)
			}
		})
	}
}
