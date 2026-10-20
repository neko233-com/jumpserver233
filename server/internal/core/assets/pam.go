package assets

import (
	"context"
	"encoding/hex"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/neko233-com/jumpserver233/server/internal/connector/pamclient"
	"github.com/neko233-com/jumpserver233/server/internal/connector/pamtypes"
	"github.com/neko233-com/jumpserver233/server/internal/connector/sqlclient"
	"github.com/neko233-com/jumpserver233/server/internal/connector/sshclient"
	"github.com/neko233-com/jumpserver233/server/internal/core/rotationplans"
)

// PAMSettings contains metadata only. Actual passwords remain in the existing
// account vault and staged credential transaction, including across tenants.
type PAMSettings struct {
	Platform  string             `json:"platform"`
	Enabled   bool               `json:"enabled"`
	Principal pamtypes.Principal `json:"principal"`
}

func clonePAM(p *PAMSettings) *PAMSettings {
	if p == nil {
		return nil
	}
	v := *p
	return &v
}
func WindowsPAM(a Asset) bool               { return IsSSH(a) && a.PAM != nil && a.PAM.Platform == "windows" }
func ManagedAccountsSupported(a Asset) bool { return IsSSH(a) || pamclient.Supports(Protocol(a)) }
func SupportsPasswordRotation(a Asset) bool {
	if IsSSH(a) && !WindowsPAM(a) {
		return true
	}
	return a.PAM != nil && a.PAM.Enabled && (WindowsPAM(a) || pamclient.Supports(Protocol(a)))
}
func validatePAM(a Asset) error {
	if a.PAM == nil {
		return nil
	}
	p := a.PAM
	if p.Platform == "linux" {
		if !IsSSH(a) || p.Enabled || p.Principal != (pamtypes.Principal{}) {
			return ErrInvalidInput
		}
		return nil
	}
	if p.Platform != "windows" && p.Platform != "database" || p.Platform == "windows" && !IsSSH(a) || p.Platform == "database" && !pamclient.Supports(Protocol(a)) {
		return ErrInvalidInput
	}
	if p.Platform == "windows" && (a.SSHWorkspace != "" || a.KeyRotationEnabled) {
		return ErrInvalidInput
	}
	if !p.Enabled && p.Principal == (pamtypes.Principal{}) {
		return nil
	}
	principal := p.Principal
	nameMatches := principal.Username == a.Username
	if p.Platform == "windows" {
		nameMatches = strings.EqualFold(principal.Username, a.Username)
	}
	if !nameMatches || !principal.Enabled || !pamtypes.Text(principal.Username, 128) {
		return ErrInvalidInput
	}
	switch {
	case p.Platform == "windows":
		if !sshclient.ValidWindowsAccount(principal.Username) || !sshclient.ValidWindowsSID(principal.ID) || principal.Scope != "local" || principal.Host != "" || principal.Plugin != "" {
			return ErrInvalidInput
		}
	case Protocol(a) == ProtocolPostgreSQL:
		id, e := strconv.ParseUint(principal.ID, 10, 32)
		if e != nil || id == 0 || principal.Host != "" || principal.Plugin != "" || principal.Scope != "cluster" {
			return ErrInvalidInput
		}
	case Protocol(a) == ProtocolMySQL || Protocol(a) == ProtocolMariaDB:
		if !pamtypes.Text(principal.Host, 255) || principal.ID != pamtypes.MySQLID(principal.Username, principal.Host) || principal.Scope != "server" || principal.Plugin != "mysql_native_password" && principal.Plugin != "caching_sha2_password" && principal.Plugin != "sha256_password" || Protocol(a) == ProtocolMariaDB && principal.Plugin != "mysql_native_password" {
			return ErrInvalidInput
		}
	case Protocol(a) == ProtocolSQLServer:
		sid, e := hex.DecodeString(principal.ID)
		if e != nil || len(sid) == 0 || len(sid) > 86 || principal.Scope != "instance" || principal.Host != "" || principal.Plugin != "" {
			return ErrInvalidInput
		}
	}
	if p.Enabled && credentialType(a.CredentialType) != CredentialPassword {
		return ErrCredentialType
	}
	if p.Platform == "database" {
		cfg := DatabaseSettings(a)
		if cfg == nil || cfg.TLSMode != "verify-full" {
			return ErrInvalidInput
		}
	}
	return nil
}
func accountNameKey(a Asset) string {
	name := a.Username
	if WindowsPAM(a) {
		name = windowsAccountKey(name)
	}
	key := ResourceID(a) + "\x00" + name
	if (Protocol(a) == ProtocolMySQL || Protocol(a) == ProtocolMariaDB) && a.PAM != nil && a.PAM.Principal.Host != "" {
		key += "\x00" + a.PAM.Principal.Host
	}
	return key
}
func windowsAccountKey(name string) string {
	return strings.Map(func(r rune) rune {
		canonical := r
		for next := unicode.SimpleFold(r); next != r; next = unicode.SimpleFold(next) {
			if next < canonical {
				canonical = next
			}
		}
		return canonical
	}, name)
}
func (s *Store) passwordConnection(id string) (Asset, sshclient.Target, sshclient.Credentials, error) {
	return s.connectionForProtocol(id, false)
}
func pamSQLTarget(a Asset, route sshclient.Target) (sqlclient.Target, error) {
	cfg := DatabaseSettings(a)
	if cfg == nil || !pamclient.Supports(Protocol(a)) || cfg.TLSMode != "verify-full" {
		return sqlclient.Target{}, ErrUnsupportedProtocol
	}
	return sqlclient.Target{Settings: *cfg, Host: a.Host, Port: a.Port, Username: a.Username, Gateways: route.Gateways}, nil
}
func (s *Service) verifyAssetPassword(ctx context.Context, a Asset, route sshclient.Target, c sshclient.Credentials, timeout time.Duration) error {
	if s.pamVerify != nil && (WindowsPAM(a) || !IsSSH(a)) {
		return s.pamVerify(ctx, a, route, c)
	}
	if WindowsPAM(a) {
		collectorID, binding := "", ""
		guard := func() error { return ctx.Err() }
		if v := managedContext(ctx); v != nil {
			collectorID = v.Intent.Target.CollectorID
			binding = v.Intent.Target.Binding
			guard = v.Guard
		}
		if collectorID == "" {
			s.store.mu.RLock()
			r := s.store.assets[a.ID]
			if r.PendingRotation != nil && r.PendingRotation.Planned != nil {
				collectorID = r.PendingRotation.Planned.PAMCollector
				binding = r.PendingRotation.Planned.PAMBinding
			}
			s.store.mu.RUnlock()
		}
		if collectorID != "" && collectorID != a.ID {
			s.store.mu.RLock()
			fresh, e := s.store.prepareManagedRotationLocked(rotationplans.Selection{AccountID: a.ID, CollectorID: collectorID})
			s.store.mu.RUnlock()
			if e != nil || fresh.Binding != binding {
				return ErrCredentialChanged
			}
			collector, target, credentials, e := s.store.passwordConnection(collectorID)
			if e != nil {
				return e
			}
			if !sameRotationHost(a, collector) {
				return ErrCredentialChanged
			}
			return sshclient.VerifyWindowsPAMViaCollector(ctx, target, credentials, a.PAM.Principal, c.Password, guard)
		}
		return sshclient.VerifyWindowsPAMViaCollector(ctx, route, c, a.PAM.Principal, c.Password, guard)
	}
	if IsSSH(a) {
		return s.verifyPassword(ctx, route, c, timeout)
	}
	t, e := pamSQLTarget(a, route)
	if e != nil {
		return e
	}
	if a.PAM == nil {
		return ErrUnsupportedProtocol
	}
	return pamclient.Verify(ctx, Protocol(a), t, sqlclient.Credentials{Password: c.Password}, a.PAM.Principal)
}
func (s *Service) changePAMPassword(ctx context.Context, a Asset, next string, guard pamtypes.Guard, collectorID string) error {
	if a.PAM == nil || !a.PAM.Enabled || validatePAM(a) != nil {
		return ErrUnsupportedProtocol
	}
	if collectorID == "" {
		collectorID = a.ID
	}
	collector, route, credentials, e := s.store.passwordConnection(collectorID)
	if e != nil {
		return e
	}
	if !sameRotationHost(a, collector) {
		return ErrCredentialChanged
	}
	if s.pamReset != nil {
		return s.pamReset(ctx, a, collector, route, credentials, next, guard)
	}
	if WindowsPAM(a) {
		return sshclient.ResetWindowsPAMPassword(ctx, route, credentials, a.PAM.Principal, next, guard)
	}
	t, e := pamSQLTarget(collector, route)
	if e != nil {
		return e
	}
	return pamclient.Reset(ctx, Protocol(a), t, sqlclient.Credentials{Password: credentials.Password}, a.PAM.Principal, next, guard)
}

type PAMDiscovery struct {
	AssetID    string               `json:"asset_id"`
	Version    string               `json:"version"`
	Protocol   string               `json:"protocol"`
	Platform   string               `json:"platform"`
	Principals []pamtypes.Principal `json:"principals"`
}

func (s *Service) DiscoverPAM(ctx context.Context, id string, guard pamtypes.Guard) (PAMDiscovery, error) {
	a, route, c, e := s.store.passwordConnection(id)
	if e != nil {
		return PAMDiscovery{}, e
	}
	if e = pamtypes.Check(ctx, guard); e != nil {
		return PAMDiscovery{}, e
	}
	var rows []pamtypes.Principal
	platform := "database"
	if s.pamDiscover != nil {
		rows, e = s.pamDiscover(ctx, a, route, c)
		if WindowsPAM(a) {
			platform = "windows"
		}
	} else if WindowsPAM(a) {
		platform = "windows"
		rows, e = sshclient.DiscoverWindowsPAM(ctx, route, c, guard)
	} else if pamclient.Supports(Protocol(a)) {
		var t sqlclient.Target
		t, e = pamSQLTarget(a, route)
		if e == nil {
			rows, e = pamclient.Discover(ctx, Protocol(a), t, sqlclient.Credentials{Password: c.Password})
		}
	} else {
		return PAMDiscovery{}, ErrUnsupportedProtocol
	}
	if e != nil {
		return PAMDiscovery{}, e
	}
	if e = pamtypes.Check(ctx, guard); e != nil {
		return PAMDiscovery{}, e
	}
	fresh, e := s.Get(id)
	if e != nil || accountVersion(fresh) != accountVersion(a) {
		return PAMDiscovery{}, ErrCredentialChanged
	}
	return PAMDiscovery{AssetID: id, Version: accountVersion(a), Protocol: Protocol(a), Platform: platform, Principals: rows}, nil
}

type PAMImportInput struct {
	Principal    pamtypes.Principal `json:"principal"`
	Version      string             `json:"version"`
	Update       bool               `json:"update"`
	Name         *string            `json:"name,omitempty"`
	Password     string             `json:"password,omitempty"`
	Automatic    bool               `json:"automatic"`
	RequestID    string             `json:"request_id"`
	PreviewToken string             `json:"preview_token,omitempty"`
}

func (s *Service) pamImportRows(parentID string, in PAMImportInput) ([]AccountImportRow, error) {
	a, e := s.Get(parentID)
	if e != nil {
		return nil, e
	}
	if a.ParentAssetID != "" || !ManagedAccountsSupported(a) || !pamtypes.Text(in.Principal.Username, 128) {
		return nil, ErrInvalidInput
	}
	platform := "database"
	if WindowsPAM(a) {
		platform = "windows"
	} else if IsSSH(a) {
		return nil, ErrUnsupportedProtocol
	}
	action := "create"
	if in.Update {
		action = "update"
	}
	username := in.Principal.Username
	if platform == "windows" && in.Update {
		for _, current := range s.store.List() {
			if ResourceID(current) == parentID && strings.EqualFold(current.Username, username) {
				username = current.Username
				break
			}
		}
	}
	return []AccountImportRow{{Line: 1, AssetID: parentID, Action: action, Input: AccountInput{Username: username, CredentialType: CredentialPassword, Password: in.Password, Version: in.Version, Name: in.Name, PasswordRotationEnabled: &in.Automatic, PAM: &PAMSettings{Enabled: true, Platform: platform, Principal: in.Principal}}}}, nil
}
func (s *Service) PreviewPAMImport(ctx context.Context, parentID string, in PAMImportInput, actor AccountActor, guard pamtypes.Guard) (AccountImportPreview, error) {
	rows, e := s.pamImportRows(parentID, in)
	if e != nil {
		return AccountImportPreview{}, e
	}
	scope := "pam-" + parentID
	// The existing import receipt is authoritative. A lost response must not
	// trigger another remote inventory read, let alone another mutation.
	s.store.mu.RLock()
	digest := s.store.importInputDigest(rows, actor.ID, scope, in.RequestID)
	prior, e := s.store.importRecordLocked(actor.ID, scope, in.RequestID, digest)
	s.store.mu.RUnlock()
	if e != nil {
		return AccountImportPreview{}, e
	}
	if prior == nil {
		discovery, e := s.DiscoverPAM(ctx, parentID, guard)
		if e != nil {
			return AccountImportPreview{}, e
		}
		found := false
		for _, p := range discovery.Principals {
			if p == in.Principal {
				found = true
				break
			}
		}
		if !found {
			return AccountImportPreview{}, ErrCredentialChanged
		}
	}
	if e = pamtypes.Check(ctx, guard); e != nil {
		return AccountImportPreview{}, e
	}
	return s.PreviewAccountImport(ctx, rows, actor, scope, in.RequestID)
}
func (s *Service) CommitPAMImport(ctx context.Context, parentID string, in PAMImportInput, actor AccountActor) (AccountImportReceipt, error) {
	rows, e := s.pamImportRows(parentID, in)
	if e != nil {
		return AccountImportReceipt{}, e
	}
	return s.CommitAccountImport(ctx, rows, actor, "pam-"+parentID, in.RequestID, in.PreviewToken)
}
func (s *Service) ConfigurePAMPlatform(ctx context.Context, parentID, platform, version, requestID string, actor AccountActor) (AccountImportReceipt, error) {
	a, e := s.Get(parentID)
	if e != nil {
		return AccountImportReceipt{}, e
	}
	if a.ParentAssetID != "" || platform != "windows" && platform != "database" && platform != "linux" || (platform == "windows" || platform == "linux") && !IsSSH(a) || platform == "database" && !pamclient.Supports(Protocol(a)) {
		return AccountImportReceipt{}, ErrInvalidInput
	}
	p := &PAMSettings{Platform: platform}
	rows := []AccountImportRow{{Line: 1, AssetID: a.ID, Action: "update", Input: AccountInput{Username: a.Username, Version: version, PAM: p}}}
	scope := "pam-platform-" + parentID
	// Keep the mode request canonical so a lost-response replay after later
	// enrollment returns its receipt without deriving a new input from that pin.
	s.store.mu.RLock()
	digest := s.store.importInputDigest(rows, actor.ID, scope, requestID)
	prior, e := s.store.importRecordLocked(actor.ID, scope, requestID, digest)
	s.store.mu.RUnlock()
	if e != nil {
		return AccountImportReceipt{}, e
	}
	if prior == nil && a.PAM != nil && (a.PAM.Enabled || a.PAM.Principal != (pamtypes.Principal{})) {
		return AccountImportReceipt{}, ErrCredentialChanged
	}
	preview, e := s.PreviewAccountImport(ctx, rows, actor, scope, requestID)
	if e != nil {
		return AccountImportReceipt{}, e
	}
	if len(preview.Issues) > 0 || preview.Token == "" {
		return AccountImportReceipt{}, ErrCredentialChanged
	}
	return s.CommitAccountImport(ctx, rows, actor, scope, requestID, preview.Token)
}
