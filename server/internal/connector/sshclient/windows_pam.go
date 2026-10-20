package sshclient

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"regexp"
	"strings"
	"time"
	"unicode/utf16"

	"github.com/neko233-com/jumpserver233/server/internal/connector/pamtypes"
)

var windowsSID = regexp.MustCompile(`^S-1-5-21-[0-9]+-[0-9]+-[0-9]+-[0-9]+$`)

func ValidWindowsSID(v string) bool { return len(v) <= 184 && windowsSID.MatchString(v) }

func ValidWindowsAccount(v string) bool {
	return pamtypes.Text(v, 80) && len([]rune(v)) <= 20 && !strings.ContainsAny(v, `"/\[]:;|=,+*?<>@`) && strings.TrimSpace(v) == v
}
func fixedPowerShell(script string) string {
	words := utf16.Encode([]rune(script))
	raw := make([]byte, len(words)*2)
	for i, v := range words {
		binary.LittleEndian.PutUint16(raw[i*2:], v)
	}
	return "powershell.exe -NoLogo -NoProfile -NonInteractive -EncodedCommand " + base64.StdEncoding.EncodeToString(raw)
}

const windowsPAMPreamble = `$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue';[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false);try{`
const windowsPAMCollect = windowsPAMPreamble + `$rows=@(Get-LocalUser | Sort-Object SID | ForEach-Object { [pscustomobject]@{username=$_.Name;principal_id=$_.SID.Value;scope='local';enabled=[bool]$_.Enabled} });if($rows.Count -gt 1000){exit 44};[Console]::Write((ConvertTo-Json -InputObject $rows -Depth 4 -Compress));exit 0}catch{exit 45}`
const windowsPAMReset = windowsPAMPreamble + `$json=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String([Console]::In.ReadToEnd()));$request=ConvertFrom-Json -InputObject $json;$user=Get-LocalUser -Name $request.username;if($user.SID.Value -ne $request.principal_id -or -not $user.Enabled){exit 46};$password=ConvertTo-SecureString -String $request.password -AsPlainText -Force;Set-LocalUser -SID $user.SID -Password $password -Confirm:$false;exit 0}catch{exit 45}`

func runWindowsPAM(ctx context.Context, target Target, credentials Credentials, script string, input []byte, guard pamtypes.Guard) ([]byte, error) {
	if len(input) > 16<<10 {
		return nil, pamtypes.ErrInvalid
	}
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	if e := pamtypes.Check(ctx, guard); e != nil {
		return nil, e
	}
	client, _, e := dial(ctx, target, credentials, 10*time.Second)
	if e != nil {
		return nil, pamtypes.ErrUnavailable
	}
	defer client.Close()
	stop := context.AfterFunc(ctx, func() { _ = client.Close() })
	defer stop()
	session, e := client.NewSession()
	if e != nil {
		return nil, pamtypes.ErrUnavailable
	}
	defer session.Close()
	budget := &outputBudget{remaining: 256 * 1024}
	out, stderr := &limitedOutput{budget: budget}, &limitedOutput{budget: budget}
	session.Stdout = out
	session.Stderr = stderr
	// stdin is ASCII base64 of UTF-8 JSON so Windows console code pages cannot
	// alter Unicode names/passwords. No value enters the encoded command.
	if len(input) > 0 {
		session.Stdin = bytes.NewBufferString(base64.StdEncoding.EncodeToString(input))
	}
	if e = pamtypes.Check(ctx, guard); e != nil {
		return nil, e
	}
	if e = session.Run(fixedPowerShell(script)); e != nil || budget.truncated {
		return nil, pamtypes.ErrUnavailable
	}
	return out.data, nil
}
func DiscoverWindowsPAM(ctx context.Context, target Target, credentials Credentials, guard pamtypes.Guard) ([]pamtypes.Principal, error) {
	raw, e := runWindowsPAM(ctx, target, credentials, windowsPAMCollect, nil, guard)
	if e != nil {
		return nil, e
	}
	var rows []pamtypes.Principal
	if json.Unmarshal(raw, &rows) != nil || len(rows) > pamtypes.MaxPrincipals {
		return nil, pamtypes.ErrUnavailable
	}
	seen := map[string]bool{}
	for _, p := range rows {
		if !ValidWindowsAccount(p.Username) || !ValidWindowsSID(p.ID) || p.Scope != "local" || p.Host != "" || p.Plugin != "" || seen[p.ID] {
			return nil, pamtypes.ErrUnavailable
		}
		seen[p.ID] = true
	}
	return rows, nil
}
func ResetWindowsPAMPassword(ctx context.Context, target Target, credentials Credentials, p pamtypes.Principal, password string, guard pamtypes.Guard) error {
	if !p.Enabled || !ValidWindowsAccount(p.Username) || !ValidWindowsSID(p.ID) || p.Scope != "local" || p.Host != "" || p.Plugin != "" || !pamtypes.ValidPassword(password) {
		return pamtypes.ErrInvalid
	}
	raw, e := json.Marshal(struct {
		Username string `json:"username"`
		ID       string `json:"principal_id"`
		Password string `json:"password"`
	}{p.Username, p.ID, password})
	if e != nil {
		return pamtypes.ErrInvalid
	}
	_, e = runWindowsPAM(ctx, target, credentials, windowsPAMReset, raw, guard)
	return e
}
func VerifyWindowsPAMViaCollector(ctx context.Context, target Target, credentials Credentials, p pamtypes.Principal, password string, guard pamtypes.Guard) error {
	if !ValidWindowsAccount(p.Username) || !ValidWindowsSID(p.ID) || p.Scope != "local" || p.Host != "" || p.Plugin != "" || !pamtypes.ValidPassword(password) {
		return pamtypes.ErrInvalid
	}
	const script = windowsPAMPreamble + `$json=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String([Console]::In.ReadToEnd()));$request=ConvertFrom-Json -InputObject $json;Add-Type -AssemblyName System.DirectoryServices.AccountManagement;$context=[DirectoryServices.AccountManagement.PrincipalContext]::new([DirectoryServices.AccountManagement.ContextType]::Machine,$env:COMPUTERNAME);try{if(-not $context.ValidateCredentials($request.username,$request.password,[DirectoryServices.AccountManagement.ContextOptions]::Negotiate)){exit 47};$user=[DirectoryServices.AccountManagement.UserPrincipal]::FindByIdentity($context,[DirectoryServices.AccountManagement.IdentityType]::SamAccountName,$request.username);if($null -eq $user -or $user.Sid.Value -ne $request.principal_id){exit 46};$user.Dispose();exit 0}finally{$context.Dispose()}}catch{exit 45}`
	raw, e := json.Marshal(struct {
		Username string `json:"username"`
		ID       string `json:"principal_id"`
		Password string `json:"password"`
	}{p.Username, p.ID, password})
	if e != nil {
		return pamtypes.ErrInvalid
	}
	_, e = runWindowsPAM(ctx, target, credentials, script, raw, guard)
	return e
}
func VerifyWindowsPAMPassword(ctx context.Context, target Target, credentials Credentials, p pamtypes.Principal) error {
	const script = windowsPAMPreamble + `[Console]::Write([Security.Principal.WindowsIdentity]::GetCurrent().User.Value);exit 0}catch{exit 45}`
	raw, e := runWindowsPAM(ctx, target, credentials, script, nil, func() error { return ctx.Err() })
	if e != nil {
		return e
	}
	if strings.TrimSpace(string(raw)) != p.ID {
		return pamtypes.ErrChanged
	}
	return nil
}
