package assets

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"strings"
	"time"

	"github.com/neko233-com/jumpserver233/server/internal/connector/sshclient"
)

// DiscoveryOrigin tracks only metadata owned by a sync source. Secret changes
// are deliberately outside ManagedHash and never get overwritten by a sync.
type DiscoveryOrigin struct {
	SourceID       string    `json:"source_id"`
	PolicyID       string    `json:"policy_id,omitempty"`
	FindingID      string    `json:"finding_id"`
	ManagedHash    string    `json:"managed_hash"`
	LastSynced     time.Time `json:"last_synced"`
	DisabledBySync bool      `json:"disabled_by_sync,omitempty"`
}

var ErrDiscoveryUncertain = errors.New("asset sync persistence requires reconciliation")

func (s *Store) refreshDiscoveryLocked() error {
	if !s.discoveryUncertain {
		return nil
	}
	next, e := openStoreWithCipher(s.path, s.aead, s.importKey, s.documents)
	if e != nil {
		return e
	}
	if len(s.assets) > 0 && len(next.assets) == 0 {
		return ErrDiscoveryUncertain
	}
	s.assets = next.assets
	s.imports = next.imports
	s.discoveryUncertain = false
	return nil
}
func (s *Store) persistDiscoveryLocked() error {
	if e := s.persistLocked(); e != nil {
		s.discoveryUncertain = true
		if refreshError := s.refreshDiscoveryLocked(); refreshError != nil {
			return ErrDiscoveryUncertain
		}
		return e
	}
	return nil
}

func NormalizeDiscoveryTemplate(in Input, allowEmpty ...bool) (Input, string, error) {
	in.Name = "discovery-template"
	in.Host = "127.0.0.1"
	in.Port = 22
	in.NodeID = ""
	in.Group = "Ungrouped"
	in.Remark = ""
	in.GatewayID = nil
	in.Protocol = Protocol(Asset{Protocol: in.Protocol})
	in.Username = strings.TrimSpace(in.Username)
	if in.Protocol == ProtocolSSH {
		in.HostKeyFingerprint = "SHA256:" + base64.RawStdEncoding.EncodeToString(make([]byte, 32))
	}
	optional := len(allowEmpty) == 1 && allowEmpty[0]
	empty := in.Password == "" && in.PrivateKey == ""
	if optional && empty {
		if !IsSSH(Asset{Protocol: in.Protocol}) && !IsDatabase(Asset{Protocol: in.Protocol}) && in.Protocol != ProtocolRDP && in.Protocol != ProtocolTelnet && in.Protocol != ProtocolKubernetes {
			return Input{}, "", ErrUnsupportedProtocol
		}
		if len(in.Username) > 128 || strings.ContainsAny(in.Username, "\x00\r\n") || in.PrivateKeyPassphrase != "" {
			return Input{}, "", ErrInvalidInput
		}
		if in.CredentialType == "" {
			in.CredentialType = CredentialPassword
		}
		if in.CredentialType != CredentialPassword && in.CredentialType != CredentialSSHKey || in.CredentialType == CredentialSSHKey && in.Protocol != ProtocolSSH {
			return Input{}, "", ErrCredentialType
		}
		if in.KeyRotationEnabled != nil && *in.KeyRotationEnabled && in.CredentialType != CredentialSSHKey {
			return Input{}, "", ErrCredentialType
		}
		if in.Protocol != ProtocolRDP && in.RDP != nil || in.Protocol != ProtocolTelnet && in.Telnet != nil || in.Protocol != ProtocolKubernetes && in.Kubernetes != nil || !IsDatabase(Asset{Protocol: in.Protocol}) && inputConfigCount(in) > 0 || IsDatabase(Asset{Protocol: in.Protocol}) && (inputConfigCount(in) > 1 || inputConfigCount(in) == 1 && inputSettings(in, in.Protocol) == nil) {
			return Input{}, "", ErrInvalidInput
		}
		certificates := []string{}
		if in.RDP != nil {
			certificates = append(certificates, in.RDP.RootCAPEM)
		}
		if in.Telnet != nil {
			certificates = append(certificates, in.Telnet.RootCAPEM)
		}
		if in.Kubernetes != nil {
			certificates = append(certificates, in.Kubernetes.RootCAPEM)
		}
		if p := inputSettings(in, in.Protocol); p != nil {
			certificates = append(certificates, p.RootCAPEM)
		}
		for _, pem := range certificates {
			if len(pem) > 64<<10 || pem != "" && (strings.Contains(pem, "PRIVATE KEY") || !x509.NewCertPool().AppendCertsFromPEM([]byte(pem))) {
				return Input{}, "", ErrInvalidInput
			}
		}
		return in, "", nil
	}
	a, e := normalizeInput(in, "")
	if e != nil {
		return Input{}, "", e
	}
	kind, pin, c, e := inputCredential(in, nil)
	if e != nil {
		return Input{}, "", e
	}
	in.Protocol = Protocol(a)
	in.CredentialType = kind
	a.CredentialType = kind
	if e = applyKeyRotationPolicy(&a, in, nil); e != nil {
		return Input{}, "", e
	}
	if kind == CredentialSSHKey {
		in.PrivateKey = string(c.PrivateKey)
		in.PrivateKeyPassphrase = ""
	}
	return in, pin, nil
}

func discoveryManagedHash(a Asset) string {
	data, _ := json.Marshal(struct {
		Name, Host, Protocol, Group, Node, Remark, Username, Pin, Gateway string
		Port                                                              int
		Disabled                                                          bool
	}{a.Name, a.Host, Protocol(a), a.Group, a.NodeID, a.Remark, a.Username, a.HostKeyFingerprint, a.GatewayID, a.Port, a.AccountDisabled})
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
func DiscoveryAssetID(source, finding string) string {
	sum := sha256.Sum256([]byte(source + "\x00" + finding))
	return "asset-" + hex.EncodeToString(sum[:16])
}

// SyncDiscovery never adopts another source's asset and refuses to overwrite
// metadata edited independently since the preceding successful sync.
type DiscoverySyncOptions struct {
	PolicyID  string
	Overwrite bool
}

func (s *Service) SyncDiscovery(source, finding string, in Input, update, missing bool, now time.Time, options ...DiscoverySyncOptions) (Asset, string, error) {
	var option DiscoverySyncOptions
	if len(options) > 1 {
		return Asset{}, "", ErrInvalidInput
	}
	if len(options) == 1 {
		option = options[0]
	}
	if !strings.HasPrefix(source, "source-") || len(source) != 39 || len(finding) != 64 {
		return Asset{}, "", ErrInvalidInput
	}
	if _, e := hex.DecodeString(source[7:]); e != nil {
		return Asset{}, "", ErrInvalidInput
	}
	if _, e := hex.DecodeString(finding); e != nil {
		return Asset{}, "", ErrInvalidInput
	}
	if s.passwordCoordinator != nil {
		s.passwordCoordinator.mu.Lock()
		defer s.passwordCoordinator.mu.Unlock()
		defer s.passwordCoordinator.refreshSharedLocked()
	}
	s.store.mu.Lock()
	e := s.store.refreshDiscoveryLocked()
	s.store.mu.Unlock()
	if e != nil {
		return Asset{}, "", e
	}
	id := DiscoveryAssetID(source, finding)
	existingAsset, known := s.find(id)
	if !known {
		var existing []Asset
		for _, a := range s.store.List() {
			if a.ParentAssetID == "" && a.Host == strings.TrimSpace(in.Host) && a.Port == in.Port && Protocol(a) == Protocol(Asset{Protocol: in.Protocol}) && a.GatewayID == normalizeGateway(in.GatewayID) {
				existing = append(existing, a)
			}
		}
		if len(existing) > 1 {
			return Asset{}, "", ErrCredentialChanged
		}
		if len(existing) == 1 {
			return cloneAsset(existing[0]), "existing", nil
		}
	}
	if known {
		in.Password = ""
		in.PrivateKey = ""
		in.PrivateKeyPassphrase = ""
		in.CredentialType = existingAsset.CredentialType
		in.KeyRotationEnabled = nil
		in.RDP = existingAsset.RDP
		in.Telnet = existingAsset.Telnet
		in.Kubernetes = existingAsset.Kubernetes
		in.PostgreSQL = nil
		in.MySQL = nil
		in.SQLServer = nil
		in.ClickHouse = nil
		in.Redis = nil
		in.MongoDB = nil
		if p := DatabaseSettings(existingAsset); p != nil {
			ro := p.ReadOnly
			setInputSettings(&in, Protocol(existingAsset), &PostgreSQLInput{Database: p.Database, AuthDatabase: p.AuthDatabase, TLSMode: p.TLSMode, ServerName: p.ServerName, RootCAPEM: p.RootCAPEM, ReadOnly: &ro})
		}
	}
	if known && in.Username == "" {
		in.Username = existingAsset.Username
	}
	desired, e := normalizeInput(in, id)
	if e != nil {
		return Asset{}, "", e
	}
	var credentials *sshclient.Credentials
	kind, pin := existingAsset.CredentialType, existingAsset.KeyFingerprint
	if !known {
		kind, pin, credentials, e = inputCredential(in, nil)
		if e != nil {
			return Asset{}, "", e
		}
	}
	desired.CredentialType, desired.KeyFingerprint = kind, pin
	if !known && s.passwordCoordinator != nil {
		if e = s.passwordCoordinator.validateMutation(s.passwordScope, desired, credentials); e != nil {
			return Asset{}, "", e
		}
	}
	s.store.mu.Lock()
	defer s.store.mu.Unlock()
	old, exists := s.store.assets[id]
	if exists {
		origin := old.Discovery
		if origin == nil || origin.SourceID != source || origin.FindingID != finding || old.ParentAssetID != "" || !option.Overwrite && (discoveryManagedHash(old.Asset) != origin.ManagedHash || origin.PolicyID != option.PolicyID) {
			return Asset{}, "", ErrCredentialChanged
		}
		if old.Host != desired.Host || old.Port != desired.Port || Protocol(old.Asset) != Protocol(desired) || old.HostKeyFingerprint != desired.HostKeyFingerprint || old.Username != desired.Username || old.GatewayID != desired.GatewayID {
			return Asset{}, "", ErrCredentialChanged
		}
		if !update && !missing && !origin.DisabledBySync {
			return cloneAsset(old.Asset), "unchanged", nil
		}
		desired = cloneAsset(old.Asset)
		if update {
			desired.Name = in.Name
			desired.NodeID = in.NodeID
			desired.Group = strings.TrimSpace(in.Group)
			if desired.Group == "" {
				desired.Group = "Ungrouped"
			}
			desired.Remark = strings.TrimSpace(in.Remark)
		}
		if missing {
			desired.AccountDisabled = true
		} else if origin.DisabledBySync {
			desired.AccountDisabled = false
		}
		if discoveryManagedHash(desired) == discoveryManagedHash(old.Asset) && origin.PolicyID == option.PolicyID {
			return cloneAsset(old.Asset), "unchanged", nil
		}
		copyOrigin := *origin
		copyOrigin.PolicyID = option.PolicyID
		copyOrigin.ManagedHash = discoveryManagedHash(desired)
		copyOrigin.LastSynced = now
		copyOrigin.DisabledBySync = missing
		desired.Discovery = &copyOrigin
		desired.UpdatedAt = now
		next := old
		next.Asset = desired
		s.store.assets[id] = next
		if e = s.store.materializeAccountsLocked(); e != nil {
			s.store.assets[id] = old
			return Asset{}, "", e
		}
		if e = s.store.persistDiscoveryLocked(); e != nil {
			if !s.store.discoveryUncertain {
				if restored, ok := s.store.assets[id]; ok && restored.Discovery != nil && restored.Discovery.ManagedHash == copyOrigin.ManagedHash {
					return cloneAsset(restored.Asset), "updated", nil
				}
			}
			if s.store.discoveryUncertain {
				s.store.assets[id] = old
			}
			return Asset{}, "", e
		}
		return cloneAsset(desired), "updated", nil
	}
	if missing {
		return Asset{}, "", ErrNotFound
	}
	desired.CreatedAt = now
	desired.UpdatedAt = now
	desired.PasswordRotatedAt = now
	desired.CredentialRevision = 1
	if e = applyKeyRotationPolicy(&desired, in, nil); e != nil {
		return Asset{}, "", e
	}
	if kind == CredentialSSHKey {
		desired.KeyRotatedAt = now
	}
	desired.Discovery = &DiscoveryOrigin{SourceID: source, PolicyID: option.PolicyID, FindingID: finding, ManagedHash: discoveryManagedHash(desired), LastSynced: now}
	secret, e := s.store.sealCredentials(&desired, *credentials)
	if e != nil {
		return Asset{}, "", e
	}
	s.store.assets[id] = storedAsset{Asset: desired, Credential: secret, PasswordRotatedAt: now}
	if e = s.store.materializeAccountsLocked(); e != nil {
		delete(s.store.assets, id)
		return Asset{}, "", e
	}
	if e = s.store.validateGatewaysLocked(); e != nil {
		delete(s.store.assets, id)
		return Asset{}, "", e
	}
	if e = s.store.persistDiscoveryLocked(); e != nil {
		if !s.store.discoveryUncertain {
			if restored, ok := s.store.assets[id]; ok && restored.Discovery != nil && restored.Discovery.ManagedHash == desired.Discovery.ManagedHash {
				return cloneAsset(restored.Asset), "created", nil
			}
		} else {
			delete(s.store.assets, id)
		}
		return Asset{}, "", e
	}
	return cloneAsset(desired), "created", nil
}

// PrepareDiscoveryGateway snapshots credentials while the caller holds its access
// lock. Opening performs network I/O after that lock has been released.
type DiscoveryGatewayOpen func(context.Context) (func(context.Context, string) (net.Conn, error), func() error, func() bool, error)

func (s *Service) PrepareDiscoveryGateway(id string) (DiscoveryGatewayOpen, string, error) {
	snapshot := func() (sshclient.Target, sshclient.Credentials, string, error) {
		s.store.mu.RLock()
		r, ok := s.store.assets[id]
		pending := ok && (r.PendingRotation != nil || r.PendingKeyChange != nil)
		s.store.mu.RUnlock()
		if pending {
			return sshclient.Target{}, sshclient.Credentials{}, "", ErrRotationPending
		}
		a, target, credentials, e := s.store.connection(id)
		if e != nil {
			return target, credentials, "", e
		}
		chain := []Asset{a}
		for _, hop := range a.GatewayIDs {
			g, e := s.Get(hop)
			if e != nil {
				return target, credentials, "", e
			}
			chain = append(chain, g)
		}
		data, _ := json.Marshal(struct {
			Route      []Asset
			Target     sshclient.Target
			Credential sshclient.Credentials
		}{chain, target, credentials})
		mac := hmac.New(sha256.New, s.store.importKey)
		_, _ = mac.Write(data)
		return target, credentials, hex.EncodeToString(mac.Sum(nil)), nil
	}
	target, credentials, binding, e := snapshot()
	if e != nil {
		return nil, "", e
	}
	current := func() bool { _, _, now, e := snapshot(); return e == nil && hmac.Equal([]byte(binding), []byte(now)) }
	open := func(ctx context.Context) (func(context.Context, string) (net.Conn, error), func() error, func() bool, error) {
		if !current() {
			return nil, nil, nil, ErrCredentialChanged
		}
		forwarder, e := sshclient.OpenForwarder(ctx, target, credentials, 5*time.Second)
		if e != nil {
			return nil, nil, nil, e
		}
		return forwarder.Dial, forwarder.Close, current, nil
	}
	return open, binding, nil
}
func (s *Service) DiscoveryGateway(ctx context.Context, id string) (func(context.Context, string) (net.Conn, error), func() error, func() bool, error) {
	if id == "" {
		return nil, func() error { return nil }, func() bool { return true }, nil
	}
	open, _, e := s.PrepareDiscoveryGateway(id)
	if e != nil {
		return nil, nil, nil, e
	}
	return open(ctx)
}

func DiscoveryConflict(e error) bool {
	return errors.Is(e, ErrCredentialChanged) || errors.Is(e, ErrRotationPending)
}

func validateDiscoveryOrigin(a Asset) error {
	if a.Discovery == nil {
		return nil
	}
	d := a.Discovery
	if d.PolicyID != "" {
		if !strings.HasPrefix(d.PolicyID, "policy-") || len(d.PolicyID) != 39 {
			return ErrInvalidInput
		}
		if _, e := hex.DecodeString(d.PolicyID[7:]); e != nil || d.PolicyID != strings.ToLower(d.PolicyID) {
			return ErrInvalidInput
		}
	}
	if !strings.HasPrefix(d.SourceID, "source-") || len(d.SourceID) != 39 || len(d.FindingID) != 64 || len(d.ManagedHash) != 64 || d.LastSynced.IsZero() || a.ParentAssetID != "" || a.ID != DiscoveryAssetID(d.SourceID, d.FindingID) {
		return ErrInvalidInput
	}
	for _, v := range []string{d.SourceID[7:], d.FindingID, d.ManagedHash} {
		if v != strings.ToLower(v) {
			return ErrInvalidInput
		}
		if _, e := hex.DecodeString(v); e != nil {
			return ErrInvalidInput
		}
	}
	return nil
}
func (s *Service) DiscoveryBound(source, finding string) (string, bool) {
	id := DiscoveryAssetID(source, finding)
	a, ok := s.find(id)
	return id, ok && a.Discovery != nil && a.Discovery.SourceID == source && a.Discovery.FindingID == finding
}
func (s *Service) DiscoveryGatewayRoute(id string) ([]Asset, error) {
	a, _, _, e := s.store.connection(id)
	if e != nil {
		return nil, e
	}
	if len(a.GatewayIDs)+1 > sshclient.MaxGatewayHops {
		return nil, ErrInvalidInput
	}
	out := []Asset{}
	for _, hop := range a.GatewayIDs {
		g, e := s.Get(hop)
		if e != nil {
			return nil, e
		}
		out = append(out, g)
	}
	return append(out, a), nil
}

func (s *Service) DiscoveryExisting(host string, port int, gateway string) []Asset {
	s.store.mu.RLock()
	defer s.store.mu.RUnlock()
	out := []Asset{}
	for _, r := range s.store.assets {
		if r.ParentAssetID == "" && r.Host == host && r.Port == port && r.GatewayID == gateway {
			out = append(out, cloneAsset(r.Asset))
		}
	}
	return out
}
