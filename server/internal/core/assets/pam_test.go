package assets

import (
	"context"
	"errors"
	"github.com/neko233-com/jumpserver233/server/internal/connector/pamtypes"
	"github.com/neko233-com/jumpserver233/server/internal/connector/sshclient"
	"github.com/neko233-com/jumpserver233/server/internal/core/rotationplans"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func pamService(t *testing.T, protocol string) (*Service, *Store, Asset, pamtypes.Principal, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "assets.json")
	st, e := OpenStore(path, []byte("0123456789abcdef0123456789abcdef"))
	require.NoError(t, e)
	s := NewService(st, nil)
	in := Input{Name: "PAM host", Protocol: protocol, Host: "192.0.2.17", Username: "collector", Password: "initial-credential"}
	settings := &MySQLInput{Database: "qa", TLSMode: "verify-full"}
	p := pamtypes.Principal{Username: "operator", Enabled: true}
	switch protocol {
	case ProtocolSSH:
		in.HostKeyFingerprint = "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
		in.PAM = &PAMSettings{Platform: "windows"}
		p.Scope = "local"
		p.ID = "S-1-5-21-100-200-300-1001"
	case ProtocolPostgreSQL:
		in.PostgreSQL = settings
		p.Scope = "cluster"
		p.ID = "12345"
	case ProtocolMySQL, ProtocolMariaDB:
		in.MySQL = settings
		p.Scope = "server"
		p.Host = "%"
		p.ID = pamtypes.MySQLID(p.Username, p.Host)
		p.Plugin = "mysql_native_password"
	case ProtocolSQLServer:
		in.SQLServer = settings
		p.Scope = "instance"
		p.ID = "01020304"
	default:
		t.Fatal("unsupported fixture")
	}
	a, e := s.Create(in)
	require.NoError(t, e)
	s.pamDiscover = func(context.Context, Asset, sshclient.Target, sshclient.Credentials) ([]pamtypes.Principal, error) {
		return []pamtypes.Principal{p}, nil
	}
	return s, st, a, p, path
}
func enrollPAM(t *testing.T, s *Service, a Asset, p pamtypes.Principal, id string) (PAMImportInput, AccountImportReceipt) {
	t.Helper()
	in := PAMImportInput{Principal: p, Version: accountVersion(a), Password: "initial-credential", RequestID: id}
	preview, e := s.PreviewPAMImport(t.Context(), a.ID, in, importActor(), func() error { return nil })
	require.NoError(t, e)
	require.Empty(t, preview.Issues)
	require.NotEmpty(t, preview.Token)
	in.PreviewToken = preview.Token
	r, e := s.CommitPAMImport(t.Context(), a.ID, in, importActor())
	require.NoError(t, e)
	require.Len(t, r.Rows, 1)
	return in, r
}
func TestPAMEnrollmentIsIdempotentEncryptedAndSurvivesReopen(t *testing.T) {
	for _, protocol := range []string{ProtocolSSH, ProtocolPostgreSQL, ProtocolMySQL, ProtocolMariaDB, ProtocolSQLServer} {
		t.Run(protocol, func(t *testing.T) {
			s, st, a, p, path := pamService(t, protocol)
			in, receipt := enrollPAM(t, s, a, p, "pam-enrollment")
			row, e := s.Get(receipt.Rows[0].AccountID)
			require.NoError(t, e)
			require.NotNil(t, row.PAM)
			assert.Equal(t, p, row.PAM.Principal)
			assert.True(t, row.PasswordRotationDisabled)
			assert.Equal(t, p.ID, receipt.Rows[0].PrincipalID)
			assert.Equal(t, p.Host, receipt.Rows[0].AccountHost)
			s.pamDiscover = func(context.Context, Asset, sshclient.Target, sshclient.Credentials) ([]pamtypes.Principal, error) {
				t.Fatal("receipt replay reconnected")
				return nil, nil
			}
			again, e := s.CommitPAMImport(t.Context(), a.ID, in, importActor())
			require.NoError(t, e)
			assert.Equal(t, receipt, again)
			preview, e := s.PreviewPAMImport(t.Context(), a.ID, in, importActor(), func() error { return nil })
			require.NoError(t, e)
			assert.True(t, preview.Committed)
			changed := in
			changed.Automatic = true
			_, e = s.CommitPAMImport(t.Context(), a.ID, changed, importActor())
			assert.ErrorIs(t, e, ErrAccountImportConflict)
			changed = in
			changed.Principal.ID = "changed-principal"
			_, e = s.CommitPAMImport(t.Context(), a.ID, changed, importActor())
			assert.Error(t, e)
			raw, e := os.ReadFile(path)
			require.NoError(t, e)
			assert.Contains(t, string(raw), `"format": 5`)
			assert.NotContains(t, string(raw), "initial-credential")
			reopened, e := OpenStore(path, []byte("0123456789abcdef0123456789abcdef"))
			require.NoError(t, e)
			assert.Len(t, reopened.List(), 2)
			got, e := reopened.Password(row.ID)
			require.NoError(t, e)
			assert.Equal(t, "initial-credential", got)
			_, _, _, e = st.passwordConnection(row.ID)
			require.NoError(t, e)
			var records []storedAsset
			var imports []accountImportRecord
			require.NoError(t, decodeRemoteAssetRecords(raw, &records, &imports))
			for _, format := range []string{"2", "3", "4"} {
				bad := strings.Replace(string(raw), `"format": 5`, `"format": `+format, 1)
				assert.Error(t, decodeRemoteAssetRecords([]byte(bad), &records, &imports))
			}
		})
	}
}
func TestPAMEnrollmentRejectsForgedPrincipalActorAndStaleRevision(t *testing.T) {
	s, _, a, p, _ := pamService(t, ProtocolPostgreSQL)
	ctx := t.Context()
	in := PAMImportInput{Principal: p, Version: accountVersion(a), Password: "initial-credential", RequestID: "pam-pinned-import"}
	forged := in
	forged.Principal.ID = "12346"
	_, e := s.PreviewPAMImport(ctx, a.ID, forged, importActor(), func() error { return nil })
	assert.ErrorIs(t, e, ErrCredentialChanged)
	preview, e := s.PreviewPAMImport(ctx, a.ID, in, importActor(), func() error { return nil })
	require.NoError(t, e)
	require.NotEmpty(t, preview.Token)
	in.PreviewToken = preview.Token
	other := AccountActor{ID: "different-owner", Name: "Different owner"}
	_, e = s.CommitPAMImport(ctx, a.ID, in, other)
	assert.ErrorIs(t, e, ErrAccountImportConflict)
	current, e := s.ManagedAccount(a.ID, a.ID)
	require.NoError(t, e)
	label := "changed"
	_, e = s.UpdateManagedAccount(a.ID, a.ID, AccountInput{Version: current.Version, Name: &label}, importActor())
	require.NoError(t, e)
	_, e = s.CommitPAMImport(ctx, a.ID, in, importActor())
	assert.ErrorIs(t, e, ErrAccountImportConflict)
}

func TestPAMModeReceiptReplayAfterDefaultAccountEnrollmentKeepsPin(t *testing.T) {
	s, _, a, p, _ := pamService(t, ProtocolSSH)
	before := accountVersion(a)
	mode, e := s.ConfigurePAMPlatform(t.Context(), a.ID, "windows", before, "pam-mode-request", importActor())
	require.NoError(t, e)
	fresh, e := s.Get(a.ID)
	require.NoError(t, e)
	p.Username = a.Username
	s.pamDiscover = func(context.Context, Asset, sshclient.Target, sshclient.Credentials) ([]pamtypes.Principal, error) {
		return []pamtypes.Principal{p}, nil
	}
	in := PAMImportInput{Principal: p, Version: accountVersion(fresh), Update: true, RequestID: "pam-default-enroll"}
	preview, e := s.PreviewPAMImport(t.Context(), a.ID, in, importActor(), func() error { return nil })
	require.NoError(t, e)
	require.Empty(t, preview.Issues)
	in.PreviewToken = preview.Token
	_, e = s.CommitPAMImport(t.Context(), a.ID, in, importActor())
	require.NoError(t, e)
	again, e := s.ConfigurePAMPlatform(t.Context(), a.ID, "windows", before, "pam-mode-request", importActor())
	require.NoError(t, e)
	assert.Equal(t, mode, again)
	current, e := s.Get(a.ID)
	require.NoError(t, e)
	assert.True(t, current.PAM.Enabled)
	assert.Equal(t, p, current.PAM.Principal)
	_, e = s.ConfigurePAMPlatform(t.Context(), a.ID, "linux", accountVersion(current), "pam-mode-clear-denied", importActor())
	assert.ErrorIs(t, e, ErrCredentialChanged)
}
func TestPAMMySQLAccountHostAndWindowsCaseIdentity(t *testing.T) {
	s, st, a, p, _ := pamService(t, ProtocolMySQL)
	_, one := enrollPAM(t, s, a, p, "pam-host-one")
	second := p
	second.Host = "localhost"
	second.ID = pamtypes.MySQLID(second.Username, second.Host)
	s.pamDiscover = func(context.Context, Asset, sshclient.Target, sshclient.Credentials) ([]pamtypes.Principal, error) {
		return []pamtypes.Principal{p, second}, nil
	}
	_, two := enrollPAM(t, s, a, second, "pam-host-two")
	assert.NotEqual(t, one.Rows[0].AccountID, two.Rows[0].AccountID)
	assert.Len(t, st.List(), 3)
	windows := Asset{ID: "windows", Username: "Operator", PAM: &PAMSettings{Platform: "windows", Principal: p}}
	alias := windows
	alias.Username = "operator"
	assert.Equal(t, accountNameKey(windows), accountNameKey(alias))
	assert.Equal(t, passwordIdentity(windows), passwordIdentity(alias))
	windows.Username = "Σ"
	alias.Username = "ς"
	assert.Equal(t, accountNameKey(windows), accountNameKey(alias))
	assert.Equal(t, passwordIdentity(windows), passwordIdentity(alias))
}
func TestPAMManagedRotationReceiptAndUncertainRecoveryDoNotResetAgain(t *testing.T) {
	for _, uncertain := range []bool{false, true} {
		t.Run(map[bool]string{false: "receipt", true: "recovery"}[uncertain], func(t *testing.T) {
			s, st, a, p, path := pamService(t, ProtocolPostgreSQL)
			_, receipt := enrollPAM(t, s, a, p, "pam-rotate-enroll")
			id := receipt.Rows[0].AccountID
			attachManagedCoordinator(t, s)
			remote := "initial-credential"
			resets := 0
			unreachable := uncertain
			s.pamReset = func(ctx context.Context, target, collector Asset, _ sshclient.Target, _ sshclient.Credentials, next string, guard pamtypes.Guard) error {
				require.NoError(t, guard())
				assert.Equal(t, id, target.ID)
				assert.Equal(t, a.ID, collector.ID)
				resets++
				remote = next
				if uncertain {
					return pamtypes.ErrUnavailable
				}
				return nil
			}
			s.pamVerify = func(_ context.Context, _ Asset, _ sshclient.Target, c sshclient.Credentials) error {
				if unreachable || c.Password != remote {
					return pamtypes.ErrUnavailable
				}
				return nil
			}
			in := managedIntent(t, s, id, a.ID, "pam-planned-rotation")
			out, e := s.ExecuteManagedRotation(t.Context(), in, func() error { return nil })
			if uncertain {
				require.Error(t, e)
				assert.Equal(t, "recovery_required", out.State)
				require.True(t, st.HasPendingPasswordRotation(id))
				unreachable = false
				_, e = s.RecoverManagedRotation(t.Context(), in, in.Actor, func() error { return nil })
				require.NoError(t, e)
			} else {
				require.NoError(t, e)
				assert.Equal(t, "succeeded", out.State)
			}
			saved, e := st.Password(id)
			require.NoError(t, e)
			assert.Equal(t, remote, saved)
			assert.False(t, st.HasPendingPasswordRotation(id))
			assert.Equal(t, 1, resets)
			reopened, e := OpenStore(path, []byte("0123456789abcdef0123456789abcdef"))
			require.NoError(t, e)
			peer := NewService(reopened, nil)
			attachManagedCoordinator(t, peer)
			peer.pamReset = func(context.Context, Asset, Asset, sshclient.Target, sshclient.Credentials, string, pamtypes.Guard) error {
				t.Fatal("replayed reset")
				return nil
			}
			again, e := peer.ExecuteManagedRotation(t.Context(), in, func() error { return nil })
			require.NoError(t, e)
			assert.Equal(t, "succeeded", again.State)
			changed := in
			changed.Target.CollectorID = ""
			_, e = peer.ExecuteManagedRotation(t.Context(), changed, func() error { return nil })
			assert.ErrorIs(t, e, rotationplans.ErrConflict)
			raw, e := os.ReadFile(path)
			require.NoError(t, e)
			assert.NotContains(t, string(raw), remote)
		})
	}
}
func TestPAMCheckCarriesCollectorAndRejectsFreshBindingChanges(t *testing.T) {
	s, _, a, p, _ := pamService(t, ProtocolSSH)
	_, receipt := enrollPAM(t, s, a, p, "pam-check-enroll")
	id := receipt.Rows[0].AccountID
	in := managedIntent(t, s, id, a.ID, "pam-check-collector")
	s.pamVerify = func(ctx context.Context, _ Asset, _ sshclient.Target, _ sshclient.Credentials) error {
		v := managedContext(ctx)
		require.NotNil(t, v)
		assert.Equal(t, a.ID, v.Intent.Target.CollectorID)
		return v.Guard()
	}
	out, e := s.CheckManagedAccount(t.Context(), in, func() error { return nil })
	require.NoError(t, e)
	assert.Equal(t, "succeeded", out.State)
	denied := errors.New("revoked")
	_, e = s.CheckManagedAccount(t.Context(), in, func() error { return denied })
	assert.ErrorIs(t, e, denied)
	current, e := s.ManagedAccount(a.ID, a.ID)
	require.NoError(t, e)
	_, e = s.UpdateManagedAccount(a.ID, a.ID, AccountInput{Version: current.Version, Password: "changed-collector-password"}, importActor())
	require.NoError(t, e)
	_, e = s.CheckManagedAccount(t.Context(), in, func() error { return nil })
	assert.ErrorIs(t, e, ErrCredentialChanged)
}

func TestPAMSharedOrganizationsCommitOneNativeMutationAndKeepVaultsConsistent(t *testing.T) {
	coordinator, e := OpenPasswordCoordinator(filepath.Join(t.TempDir(), "shared.json"), make([]byte, 32), nil)
	require.NoError(t, e)
	remote := "initial-credential"
	resets := 0
	services := []*Service{}
	ids := []string{}
	collectors := []string{}
	for _, scope := range []string{"default", "peer"} {
		s, _, a, p, _ := pamService(t, ProtocolPostgreSQL)
		_, receipt := enrollPAM(t, s, a, p, "pam-shared-enrollment")
		ids = append(ids, receipt.Rows[0].AccountID)
		collectors = append(collectors, a.ID)
		s.pamReset = func(context.Context, Asset, Asset, sshclient.Target, sshclient.Credentials, string, pamtypes.Guard) error {
			t.Fatal("unexpected peer reset")
			return nil
		}
		s.pamVerify = func(_ context.Context, _ Asset, _ sshclient.Target, c sshclient.Credentials) error {
			if c.Password != remote {
				return pamtypes.ErrUnavailable
			}
			return nil
		}
		require.NoError(t, s.CoordinatePasswords(coordinator, scope))
		services = append(services, s)
	}
	services[0].pamReset = func(_ context.Context, _ Asset, _ Asset, _ sshclient.Target, _ sshclient.Credentials, next string, guard pamtypes.Guard) error {
		require.NoError(t, guard())
		for i, s := range services {
			assert.True(t, s.store.HasPendingPasswordRotation(ids[i]))
		}
		resets++
		remote = next
		return nil
	}
	in := managedIntent(t, services[0], ids[0], collectors[0], "pam-shared-run")
	out, e := services[0].ExecuteManagedRotation(t.Context(), in, func() error { return nil })
	require.NoError(t, e)
	assert.Equal(t, "succeeded", out.State)
	assert.Equal(t, 1, resets)
	for i, s := range services {
		saved, e := s.store.Password(ids[i])
		require.NoError(t, e)
		assert.Equal(t, remote, saved)
		assert.False(t, s.store.HasPendingPasswordRotation(ids[i]))
	}
	again, e := services[0].ExecuteManagedRotation(t.Context(), in, func() error { return nil })
	require.NoError(t, e)
	assert.Equal(t, out, again)
	assert.Equal(t, 1, resets)
}

func TestPAMAutomaticSevenDayOptinRunsOnlyOnceWhenDue(t *testing.T) {
	s, st, a, p, _ := pamService(t, ProtocolPostgreSQL)
	in := PAMImportInput{Principal: p, Version: accountVersion(a), Password: "initial-credential", Automatic: true, RequestID: "pam-weekly-enroll"}
	preview, e := s.PreviewPAMImport(t.Context(), a.ID, in, importActor(), func() error { return nil })
	require.NoError(t, e)
	require.Empty(t, preview.Issues)
	in.PreviewToken = preview.Token
	receipt, e := s.CommitPAMImport(t.Context(), a.ID, in, importActor())
	require.NoError(t, e)
	id := receipt.Rows[0].AccountID
	st.mu.Lock()
	r := st.assets[id]
	r.PasswordRotatedAt = time.Now().Add(-8 * 24 * time.Hour)
	r.Asset.PasswordRotatedAt = r.PasswordRotatedAt
	st.assets[id] = r
	st.mu.Unlock()
	remote := "initial-credential"
	resets := 0
	s.pamReset = func(_ context.Context, target, collector Asset, _ sshclient.Target, _ sshclient.Credentials, next string, guard pamtypes.Guard) error {
		require.NoError(t, guard())
		assert.Equal(t, id, target.ID)
		assert.Equal(t, id, collector.ID)
		resets++
		remote = next
		return nil
	}
	s.pamVerify = func(_ context.Context, _ Asset, _ sshclient.Target, c sshclient.Credentials) error {
		if c.Password != remote {
			return pamtypes.ErrUnavailable
		}
		return nil
	}
	s.RotateDuePasswords(t.Context())
	s.RotateDuePasswords(t.Context())
	assert.Equal(t, 1, resets)
	stored, e := st.Password(id)
	require.NoError(t, e)
	assert.Equal(t, remote, stored)
	fresh, e := s.Get(id)
	require.NoError(t, e)
	assert.Equal(t, "scheduled", baseRotationStatus(fresh, time.Now()).State)
}

func TestPAMConfirmedOldCredentialCreatesFailedReceiptWithoutResetReplay(t *testing.T) {
	s, st, a, p, _ := pamService(t, ProtocolPostgreSQL)
	_, receipt := enrollPAM(t, s, a, p, "pam-old-enroll")
	id := receipt.Rows[0].AccountID
	attachManagedCoordinator(t, s)
	resets := 0
	s.pamReset = func(context.Context, Asset, Asset, sshclient.Target, sshclient.Credentials, string, pamtypes.Guard) error {
		resets++
		return pamtypes.ErrUnavailable
	}
	s.pamVerify = func(_ context.Context, _ Asset, _ sshclient.Target, c sshclient.Credentials) error {
		if c.Password != "initial-credential" {
			return pamtypes.ErrUnavailable
		}
		return nil
	}
	in := managedIntent(t, s, id, a.ID, "pam-confirm-old")
	out, e := s.ExecuteManagedRotation(t.Context(), in, func() error { return nil })
	require.Error(t, e)
	assert.Equal(t, "failed", out.State)
	assert.False(t, st.HasPendingPasswordRotation(id))
	again, e := s.ExecuteManagedRotation(t.Context(), in, func() error { return nil })
	require.NoError(t, e)
	assert.Equal(t, "failed", again.State)
	assert.Equal(t, 1, resets)
	saved, e := st.Password(id)
	require.NoError(t, e)
	assert.Equal(t, "initial-credential", saved)
}
