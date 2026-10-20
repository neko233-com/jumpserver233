package sshclient

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/neko233-com/jumpserver233/server/internal/connector/pamtypes"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestWindowsPAMFixedPowerShellAndPrivateUnicodeStdin(t *testing.T) {
	server, target := startRotationServer(t, "0", "collector-secret")
	defer server.listener.Close()
	p := pamtypes.Principal{Username: "Operator", ID: "S-1-5-21-11-22-33-1001", Scope: "local", Enabled: true}
	next := `Synthetic-密码-'\233!`
	calls := 0
	server.mu.Lock()
	server.windows = func(command string, input []byte) ([]byte, uint32) {
		calls++
		assert.NotContains(t, command, next)
		assert.NotContains(t, command, p.Username)
		switch calls {
		case 1:
			assert.Equal(t, fixedPowerShell(windowsPAMCollect), command)
			assert.Empty(t, input)
			raw, _ := json.Marshal([]pamtypes.Principal{p})
			return raw, 0
		default:
			decoded, e := base64.StdEncoding.DecodeString(string(input))
			require.NoError(t, e)
			var payload struct {
				Username string `json:"username"`
				SID      string `json:"principal_id"`
				Password string `json:"password"`
			}
			require.NoError(t, json.Unmarshal(decoded, &payload))
			assert.Equal(t, p.Username, payload.Username)
			assert.Equal(t, p.ID, payload.SID)
			assert.Equal(t, next, payload.Password)
			if calls == 2 {
				assert.Equal(t, fixedPowerShell(windowsPAMReset), command)
			}
			return nil, 0
		}
	}
	server.mu.Unlock()
	c := Credentials{Password: "collector-secret"}
	guard := func() error { return nil }
	rows, e := DiscoverWindowsPAM(t.Context(), target, c, guard)
	require.NoError(t, e)
	assert.Equal(t, []pamtypes.Principal{p}, rows)
	require.NoError(t, ResetWindowsPAMPassword(t.Context(), target, c, p, next, guard))
	require.NoError(t, VerifyWindowsPAMViaCollector(t.Context(), target, c, p, next, guard))
	assert.Equal(t, 3, calls)
	denied := errors.New("revoked")
	_, e = DiscoverWindowsPAM(t.Context(), target, c, func() error { return denied })
	assert.ErrorIs(t, e, denied)
	assert.Equal(t, 3, calls)
	wrong := target
	wrong.HostKeyFingerprint = "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	_, e = DiscoverWindowsPAM(t.Context(), wrong, c, guard)
	assert.Error(t, e)
	assert.Equal(t, 3, calls)
	for _, name := range []string{"DOMAIN\\user", "user@example.com", "bad;name", strings.Repeat("x", 21)} {
		assert.False(t, ValidWindowsAccount(name))
	}
	for _, sid := range []string{"S-1-5-21-", "S-1-5-18", "S-1-5-21-1-2-3-4;exit"} {
		assert.False(t, ValidWindowsSID(sid))
	}
}
func TestWindowsPAMRejectsMalformedInventoryAndOutputOverflow(t *testing.T) {
	for _, output := range []string{`[{"username":"Operator","principal_id":"S-1-5-18","scope":"local","enabled":true}]`, `{"unexpected":true}`, strings.Repeat("x", 256*1024+1)} {
		t.Run(fmt.Sprint(len(output)), func(t *testing.T) {
			server, target := startRotationServer(t, "0", "collector-secret")
			defer server.listener.Close()
			server.mu.Lock()
			server.windows = func(string, []byte) ([]byte, uint32) { return []byte(output), 0 }
			server.mu.Unlock()
			_, e := DiscoverWindowsPAM(t.Context(), target, Credentials{Password: "collector-secret"}, func() error { return nil })
			assert.Error(t, e)
		})
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	_, e := runWindowsPAM(ctx, Target{}, Credentials{}, windowsPAMCollect, nil, func() error { t.Fatal("cancelled guard"); return nil })
	assert.ErrorIs(t, e, context.Canceled)
}

// Optional native fixture: it must be an explicitly opted-in disposable Windows
// OpenSSH machine. Only a unique account created by this test is mutated/deleted.
func TestRealWindowsPAMLocalSAMAndCollectorCredentialProof(t *testing.T) {
	if os.Getenv("JMS_TEST_WINDOWS_PAM_DISPOSABLE") != "true" {
		t.Skip("requires an opted-in disposable Windows OpenSSH fixture")
	}
	port, e := strconv.Atoi(os.Getenv("JMS_TEST_WINDOWS_PAM_PORT"))
	require.NoError(t, e)
	target := Target{Host: os.Getenv("JMS_TEST_WINDOWS_PAM_HOST"), Port: port, Username: os.Getenv("JMS_TEST_WINDOWS_PAM_USER"), HostKeyFingerprint: os.Getenv("JMS_TEST_WINDOWS_PAM_FINGERPRINT")}
	credentials := Credentials{Password: os.Getenv("JMS_TEST_WINDOWS_PAM_PASSWORD")}
	require.NotEmpty(t, credentials.Password)
	require.NotEmpty(t, target.HostKeyFingerprint)
	name := fmt.Sprintf("pamqa_%012x", uint64(time.Now().UnixNano())&0xffffffffffff)
	require.True(t, ValidWindowsAccount(name))
	initial := "Synthetic-PAM-Initial-233!"
	guard := func() error { return nil }
	const create = windowsPAMPreamble + `$r=ConvertFrom-Json ([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String([Console]::In.ReadToEnd())));if($r.username -notmatch '^pamqa_[a-f0-9]{1,16}$'){exit 48};$p=ConvertTo-SecureString $r.password -AsPlainText -Force;$u=New-LocalUser -Name $r.username -Password $p;[Console]::Write($u.SID.Value);exit 0}catch{exit 45}`
	raw, _ := json.Marshal(map[string]string{"username": name, "password": initial})
	sid, e := runWindowsPAM(t.Context(), target, credentials, create, raw, guard)
	require.NoError(t, e)
	p := pamtypes.Principal{Username: name, ID: strings.TrimSpace(string(sid)), Scope: "local", Enabled: true}
	require.True(t, ValidWindowsSID(p.ID))
	t.Cleanup(func() {
		const remove = windowsPAMPreamble + `$r=ConvertFrom-Json ([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String([Console]::In.ReadToEnd())));if($r.username -notmatch '^pamqa_[a-f0-9]{1,16}$'){exit 48};$u=Get-LocalUser -Name $r.username -ErrorAction SilentlyContinue;if($null -ne $u){if($u.SID.Value -ne $r.principal_id){exit 46};Remove-LocalUser -SID $u.SID -Confirm:$false};exit 0}catch{exit 45}`
		data, _ := json.Marshal(p)
		for range 2 {
			_, err := runWindowsPAM(context.Background(), target, credentials, remove, data, guard)
			assert.NoError(t, err)
		}
	})
	rows, e := DiscoverWindowsPAM(t.Context(), target, credentials, guard)
	require.NoError(t, e)
	assert.Contains(t, rows, p)
	require.NoError(t, VerifyWindowsPAMViaCollector(t.Context(), target, credentials, p, initial, guard))
	next := "Synthetic-PAM-Next-密码233!"
	require.NoError(t, ResetWindowsPAMPassword(t.Context(), target, credentials, p, next, guard))
	require.NoError(t, VerifyWindowsPAMViaCollector(t.Context(), target, credentials, p, next, guard))
	assert.Error(t, VerifyWindowsPAMViaCollector(t.Context(), target, credentials, p, initial, guard))
	bad := p
	bad.ID = "S-1-5-21-11-22-33-9999"
	assert.Error(t, ResetWindowsPAMPassword(t.Context(), target, credentials, bad, "unapplied-password", guard))
	require.NoError(t, VerifyWindowsPAMViaCollector(t.Context(), target, credentials, p, next, guard))
}
