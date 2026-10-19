package assets

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/neko233-com/jumpserver233/server/internal/connector/kubeclient"
	"github.com/neko233-com/jumpserver233/server/internal/connector/rdpclient"
	"github.com/neko233-com/jumpserver233/server/internal/connector/sqlclient"
	"github.com/neko233-com/jumpserver233/server/internal/connector/sshclient"
	"github.com/neko233-com/jumpserver233/server/internal/connector/telnetclient"
	"github.com/neko233-com/jumpserver233/server/internal/core/monitorhistory"
	"github.com/neko233-com/jumpserver233/server/internal/hostagent"
)

var hostLabelPattern = regexp.MustCompile(`^[a-zA-Z0-9-]+$`)

var ErrInvalidInput = errors.New("invalid asset input")

// MonitorStatus is the latest SSH probe result. ErrorCode is a stable code for
// localization and never includes server output or credential material.
type MonitorStatus struct {
	binding                       string
	networkReady                  bool
	LatencyMS                     *float64           `json:"latency_ms,omitempty"`
	State                         string             `json:"state"`
	ErrorCode                     string             `json:"error_code,omitempty"`
	LastChecked                   *time.Time         `json:"last_checked,omitempty"`
	Metrics                       *sshclient.Metrics `json:"metrics,omitempty"`
	NetworkReceivedBytesPerSecond float64            `json:"network_received_bytes_per_second"`
	NetworkSentBytesPerSecond     float64            `json:"network_sent_bytes_per_second"`
}

// ListItem combines an asset's public inventory fields with its current status.
type ListItem struct {
	Asset
	Accounts          []AccountChoice         `json:"accounts,omitempty"`
	SelectedAccountID string                  `json:"selected_account_id,omitempty"`
	Monitor           MonitorStatus           `json:"monitor"`
	Permissions       []string                `json:"permissions"`
	PasswordRotation  *PasswordRotationStatus `json:"password_rotation,omitempty"`
	SSHKeyRotation    *SSHKeyRotationStatus   `json:"ssh_key_rotation,omitempty"`
}

type ProbeFunc func(context.Context, sshclient.Target, sshclient.Credentials, time.Duration) (sshclient.Metrics, error)

type previousSample struct {
	binding string
	metrics sshclient.Metrics
	at      time.Time
}

// Service owns the asset inventory and serializes status updates from scheduled
// and manually requested probes.
type Service struct {
	passwordCoordinator *PasswordCoordinator
	passwordScope       string
	keyUpdater          KeyUpdaterFunc
	keyPreflight        func(context.Context, sshclient.Target, sshclient.Credentials, []byte, []byte) error
	store               *Store
	probe               ProbeFunc
	changePassword      PasswordChangeFunc
	changePasswordFor   func(context.Context, sshclient.Target, sshclient.Credentials, string, string, time.Duration) error
	verifyPassword      PasswordVerifyFunc
	mu                  sync.RWMutex
	status              map[string]MonitorStatus
	last                map[string]previousSample
	rotationStatus      map[string]PasswordRotationStatus
	rotationRunning     map[string]bool
	rotationAuditMux    sync.Mutex
	monitorHistory      *monitorhistory.Store
}

func NewService(store *Store, probe ProbeFunc) *Service {
	return NewServiceWithPasswordRotation(store, probe, nil, nil)
}

func (s *Service) List() []ListItem {
	assets := s.store.List()
	s.mu.RLock()
	items := make([]ListItem, 0, len(assets))
	for _, asset := range assets {
		if asset.ParentAssetID != "" {
			continue
		}
		status, exists := s.status[asset.ID]
		if !exists {
			status.State = "unknown"
		}
		items = append(items, ListItem{Asset: asset, Monitor: status, Permissions: []string{}})
	}
	s.mu.RUnlock()
	for i := range items {
		items[i].PasswordRotation = s.passwordRotationStatus(items[i].Asset)
		items[i].SSHKeyRotation = s.sshKeyRotationStatus(items[i].Asset)
	}
	return items
}

func (s *Service) Create(input Input) (Asset, error) {
	if s.passwordCoordinator != nil {
		s.passwordCoordinator.mu.Lock()
		defer s.passwordCoordinator.mu.Unlock()
		defer s.passwordCoordinator.refreshSharedLocked()
	}
	asset, err := normalizeInput(input, "")
	if err != nil {
		return Asset{}, err
	}
	kind, pin, credentials, err := inputCredential(input, nil)
	if err != nil {
		return Asset{}, err
	}
	asset.CredentialType = kind
	asset.KeyFingerprint = pin
	if e := applyKeyRotationPolicy(&asset, input, nil); e != nil {
		return Asset{}, e
	}
	asset.ID, err = newID()
	if err != nil {
		return Asset{}, err
	}
	now := time.Now().UTC()
	asset.CreatedAt = now
	asset.UpdatedAt = now
	asset.PasswordRotatedAt = now
	if s.passwordCoordinator != nil {
		if e := s.passwordCoordinator.validateMutation(s.passwordScope, asset, credentials); e != nil {
			return Asset{}, e
		}
	}
	return s.store.CreateCredentials(asset, *credentials)
}

func (s *Service) Update(id string, input Input) (Asset, error) {
	if s.passwordCoordinator != nil {
		s.passwordCoordinator.mu.Lock()
		defer s.passwordCoordinator.mu.Unlock()
		defer s.passwordCoordinator.refreshSharedLocked()
		if s.passwordCoordinator.blocked(s.passwordScope, id) {
			return Asset{}, ErrRotationPending
		}
	}
	current, exists := s.find(id)
	if !exists {
		return Asset{}, ErrNotFound
	}
	if current.ParentAssetID != "" {
		return Asset{}, ErrInvalidInput
	}
	if e := s.accountChildrenBlocked(id); e != nil {
		return Asset{}, e
	}
	if input.Protocol == "" {
		input.Protocol = current.Protocol
	}
	candidateProtocol := Protocol(Asset{Protocol: input.Protocol})
	if candidateProtocol != Protocol(current) {
		return Asset{}, ErrUnsupportedProtocol
	}
	if IsKubernetes(current) && input.Kubernetes == nil {
		copy := cloneAsset(current)
		input.Kubernetes = copy.Kubernetes
	}
	if IsRDP(current) && input.RDP == nil {
		copy := cloneAsset(current)
		input.RDP = copy.RDP
	}
	if IsTelnet(current) && input.Telnet == nil {
		copy := cloneAsset(current)
		input.Telnet = copy.Telnet
	}
	if IsDatabase(current) && DatabaseSettings(current) != nil {
		p := DatabaseSettings(current)
		source := inputSettings(input, candidateProtocol)
		if source == nil {
			ro := p.ReadOnly
			source = &PostgreSQLInput{AuthDatabase: p.AuthDatabase, Database: p.Database, TLSMode: p.TLSMode, ServerName: p.ServerName, RootCAPEM: p.RootCAPEM, ReadOnly: &ro}
		} else if source.ReadOnly == nil {
			ro := p.ReadOnly
			copy := *source
			copy.ReadOnly = &ro
			source = &copy
		}
		setInputSettings(&input, candidateProtocol, source)
	}

	asset, err := normalizeInput(input, id)
	if err != nil {
		return Asset{}, err
	}
	if input.GatewayID == nil {
		asset.GatewayID = current.GatewayID
	}
	if input.LoginReviewRequired == nil {
		asset.LoginReviewRequired = current.LoginReviewRequired
	}
	if input.SSHWorkspace == nil {
		asset.SSHWorkspace = current.SSHWorkspace
	}
	asset.UpdatedAt = time.Now().UTC()
	kind, pin, credentials, err := inputCredential(input, &current)
	if err != nil {
		return Asset{}, err
	}
	asset.CredentialType = kind
	asset.KeyFingerprint = pin
	asset.AccountName, asset.AccountRemark = current.AccountName, current.AccountRemark
	asset.AccountDiscoveryID = current.AccountDiscoveryID
	asset.Discovery = cloneAsset(current).Discovery
	if asset.Username != current.Username || asset.Host != current.Host || asset.Port != current.Port || asset.HostKeyFingerprint != current.HostKeyFingerprint {
		asset.AccountDiscoveryID = ""
	}
	asset.AccountDisabled, asset.PasswordRotationDisabled = current.AccountDisabled, current.PasswordRotationDisabled
	if e := applyKeyRotationPolicy(&asset, input, &current); e != nil {
		return Asset{}, e
	}
	if s.passwordCoordinator != nil {
		if e := s.passwordCoordinator.validateMutation(s.passwordScope, asset, credentials); e != nil {
			return Asset{}, e
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.rotationRunning[id] {
		return Asset{}, ErrRotationInProgress
	}
	updated, err := s.store.UpdateCredentials(asset, credentials)
	if err != nil {
		return Asset{}, err
	}
	if credentials != nil {
		delete(s.rotationStatus, id)
	}
	return updated, nil
}

func (s *Service) Delete(id string) error {
	if a, ok := s.find(id); ok && a.ParentAssetID != "" {
		return ErrInvalidInput
	}
	if s.passwordCoordinator != nil {
		s.passwordCoordinator.mu.Lock()
		defer s.passwordCoordinator.mu.Unlock()
		defer s.passwordCoordinator.refreshSharedLocked()
		if s.passwordCoordinator.blocked(s.passwordScope, id) {
			return ErrRotationPending
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.rotationRunning[id] {
		return ErrRotationInProgress
	}
	if err := s.store.Delete(id); err != nil {
		return err
	}
	delete(s.status, id)
	delete(s.last, id)
	delete(s.rotationStatus, id)
	return nil
}

func (s *Service) Get(id string) (Asset, error) {
	asset, exists := s.find(id)
	if !exists {
		return Asset{}, ErrNotFound
	}
	if asset.AccountDisabled {
		return Asset{}, ErrAccountDisabled
	}
	return asset, nil
}

func (s *Service) currentMonitorStatus(id string) MonitorStatus {
	s.mu.RLock()
	status, exists := s.status[id]
	s.mu.RUnlock()
	if !exists {
		return MonitorStatus{State: "unknown"}
	}
	return status
}

func (s *Service) Probe(ctx context.Context, id string) (ListItem, error) {
	if a, e := s.Get(id); e == nil && IsRDP(a) {
		started := time.Now()
		e = s.ProbeRDP(ctx, id)
		at := time.Now().UTC()
		latency := float64(time.Since(started)) / float64(time.Millisecond)
		state, code := "online", ""
		if e != nil {
			state, code = "offline", "rdp_connection_failed"
		}
		status := MonitorStatus{State: state, ErrorCode: code, LastChecked: &at, LatencyMS: &latency}
		s.mu.Lock()
		s.status[id] = status
		s.mu.Unlock()
		return ListItem{Asset: a, Monitor: status}, e
	}
	if a, e := s.Get(id); e == nil && IsTelnet(a) {
		started := time.Now()
		_, shell, e := s.OpenTelnetShell(ctx, id, 80, 24)
		if shell != nil {
			shell.Close()
		}
		at := time.Now().UTC()
		latency := float64(time.Since(started)) / float64(time.Millisecond)
		state, code := "online", ""
		if e != nil {
			state, code = "offline", "telnet_connection_failed"
		}
		status := MonitorStatus{State: state, ErrorCode: code, LastChecked: &at, LatencyMS: &latency}
		s.mu.Lock()
		s.status[id] = status
		s.mu.Unlock()
		return ListItem{Asset: a, Monitor: status}, e
	}
	if a, e := s.Get(id); e == nil && IsKubernetes(a) {
		started := time.Now()
		_, e := s.KubernetesPods(ctx, id, a.Kubernetes.Namespaces[0])
		at := time.Now().UTC()
		state, code := "online", ""
		if e != nil {
			state, code = "offline", "kubernetes_connection_failed"
		}
		latency := float64(time.Since(started)) / float64(time.Millisecond)
		status := MonitorStatus{State: state, ErrorCode: code, LastChecked: &at, LatencyMS: &latency}
		s.mu.Lock()
		s.status[id] = status
		s.mu.Unlock()
		return ListItem{Asset: a, Monitor: status}, e
	}

	if a, e := s.Get(id); e == nil && IsDatabase(a) {
		started := time.Now()
		e := s.PingDatabase(ctx, id)
		at := time.Now().UTC()
		state, code := "online", ""
		if e != nil {
			state, code = "offline", "database_connection_failed"
		}
		latency := float64(time.Since(started)) / float64(time.Millisecond)
		status := MonitorStatus{State: state, ErrorCode: code, LastChecked: &at, LatencyMS: &latency}
		s.mu.Lock()
		s.status[id] = status
		s.mu.Unlock()
		return ListItem{Asset: a, Monitor: status}, e
	}
	asset, target, credentials, err := s.store.connection(id)
	if err != nil {
		asset, e := s.Get(id)
		if e != nil {
			return ListItem{}, e
		}
		at := time.Now().UTC()
		code := "ssh_failed"
		if asset.GatewayID != "" {
			code = "gateway_failed"
		}
		status := MonitorStatus{State: "offline", ErrorCode: code, LastChecked: &at}
		s.mu.Lock()
		s.status[id] = status
		s.mu.Unlock()
		return ListItem{Asset: asset, Monitor: status}, err
	}
	metrics, probeErr := s.probe(ctx, target, credentials, 8*time.Second)
	checkedAt := time.Now().UTC()
	if probeErr != nil {
		status := MonitorStatus{State: "offline", ErrorCode: classifyProbeError(probeErr), LastChecked: &checkedAt, binding: monitorTargetBinding(asset, target)}
		s.mu.Lock()
		s.status[id] = status
		s.mu.Unlock()
		s.recordHistory(id, status)
		return ListItem{Asset: asset, Monitor: status}, fmt.Errorf("SSH host probe failed")
	}
	status := s.recordMetrics(id, metrics, checkedAt, monitorTargetBinding(asset, target))
	s.recordHistory(id, status)
	return ListItem{Asset: asset, Monitor: status}, nil
}

// OpenShell starts a server-side SSH PTY using the encrypted asset credential.
// The returned terminal exposes only stream I/O, never the decrypted secret.
func (s *Service) OpenShell(ctx context.Context, id string, cols, rows int) (Asset, *sshclient.Shell, error) {
	asset, target, credentials, err := s.store.connection(id)
	if err != nil {
		return Asset{}, nil, err
	}
	if asset.SSHWorkspace != "" {
		startup, e := s.workspaceStartup(ctx, target, credentials, asset.SSHWorkspace, false)
		if e != nil {
			return Asset{}, nil, e
		}
		shell, e := sshclient.OpenShellCommand(ctx, target, credentials, 12*time.Second, cols, rows, startup)
		return asset, shell, e
	}
	shell, err := sshclient.OpenShell(ctx, target, credentials, 12*time.Second, cols, rows)
	if err != nil {
		return Asset{}, nil, err
	}
	return asset, shell, nil
}

// OpenSFTP opens a server-side SFTP channel using the asset's encrypted
// credential and pinned host key. Only the file-channel abstraction escapes.
func (s *Service) OpenSFTP(ctx context.Context, id string) (Asset, *sshclient.SFTP, error) {
	asset, target, credentials, err := s.store.connection(id)
	if err != nil {
		return Asset{}, nil, err
	}
	if asset.SSHWorkspace != "" {
		remote, e := s.openWorkspaceSFTP(ctx, target, credentials, asset.SSHWorkspace)
		return asset, remote, e
	}
	remote, err := sshclient.OpenSFTP(ctx, target, credentials, 12*time.Second)
	if err != nil {
		return Asset{}, nil, err
	}
	return asset, remote, nil
}

func (s *Service) RefreshAll(ctx context.Context) {
	assets := s.store.List()
	limit := make(chan struct{}, 8)
	var workers sync.WaitGroup
	for _, asset := range assets {
		if asset.ParentAssetID != "" || asset.AccountDisabled {
			continue
		}
		select {
		case <-ctx.Done():
			workers.Wait()
			return
		case limit <- struct{}{}:
		}
		workers.Add(1)
		go func(asset Asset) {
			defer workers.Done()
			defer func() { <-limit }()
			probeCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
			defer cancel()
			_, _ = s.Probe(probeCtx, asset.ID)
		}(asset)
	}
	workers.Wait()
}

func (s *Service) Run(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = time.Minute
	}
	s.RecoverPendingSSHKeyChanges(ctx)
	s.RecoverPendingPasswordRotations(ctx)
	for {
		s.pruneHistory()
		s.RefreshAll(ctx)
		s.RecoverPendingSSHKeyChanges(ctx)
		s.RecoverPendingPasswordRotations(ctx)
		s.RotateDuePasswords(ctx)
		s.RotateDueSSHKeys(ctx)
		timer := time.NewTimer(interval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
	}
}

func (s *Service) find(id string) (Asset, bool) {
	return s.store.lookup(id)
}

func (s *Service) recordMetrics(id string, metrics sshclient.Metrics, at time.Time, bindings ...string) MonitorStatus {
	metrics.CollectedAt = at
	status := MonitorStatus{State: "online", LastChecked: &at, Metrics: &metrics}
	if len(bindings) > 0 {
		status.binding = bindings[0]
	}
	s.mu.Lock()
	if previous, exists := s.last[id]; exists {
		seconds := at.Sub(previous.at).Seconds()
		if previous.binding == status.binding && seconds > 0 && metrics.NetworkReceivedBytes >= previous.metrics.NetworkReceivedBytes && metrics.NetworkSentBytes >= previous.metrics.NetworkSentBytes {
			status.NetworkReceivedBytesPerSecond = float64(metrics.NetworkReceivedBytes-previous.metrics.NetworkReceivedBytes) / seconds
			status.NetworkSentBytesPerSecond = float64(metrics.NetworkSentBytes-previous.metrics.NetworkSentBytes) / seconds
			status.networkReady = true
		}
	}
	s.status[id] = status
	s.last[id] = previousSample{metrics: metrics, at: at, binding: status.binding}
	s.mu.Unlock()
	return status
}

func normalizeInput(input Input, id string) (Asset, error) {
	protocol := Protocol(Asset{Protocol: input.Protocol})
	if !IsSSH(Asset{Protocol: protocol}) && !IsDatabase(Asset{Protocol: protocol}) && protocol != ProtocolKubernetes && protocol != ProtocolTelnet && protocol != ProtocolRDP {
		return Asset{}, ErrUnsupportedProtocol
	}
	name := strings.TrimSpace(input.Name)
	host := strings.TrimSpace(input.Host)
	username := strings.TrimSpace(input.Username)
	fingerprint := strings.TrimSpace(input.HostKeyFingerprint)
	group := strings.TrimSpace(input.Group)
	nodeID := strings.TrimSpace(input.NodeID)
	remark := strings.TrimSpace(input.Remark)
	if name == "" || len(name) > 120 {
		return Asset{}, fmt.Errorf("%w: asset name must contain 1 to 120 characters", ErrInvalidInput)
	}
	if !validHost(host) {
		return Asset{}, fmt.Errorf("%w: SSH host must be an IP address or DNS name", ErrInvalidInput)
	}
	if input.Port == 0 {
		input.Port = databasePort(protocol)
		if protocol == ProtocolRDP {
			input.Port = 3389
		}
		if protocol == ProtocolKubernetes {
			input.Port = 6443
		}
		if protocol == ProtocolTelnet {
			input.Port = 992
			if input.Telnet != nil && input.Telnet.TLSMode == "disable" {
				input.Port = 23
			}
		}
	}
	if input.Port < 1 || input.Port > 65535 {
		return Asset{}, fmt.Errorf("%w: SSH port must be between 1 and 65535", ErrInvalidInput)
	}
	if username == "" || len(username) > 128 {
		return Asset{}, fmt.Errorf("%w: SSH username must contain 1 to 128 characters", ErrInvalidInput)
	}
	if protocol == ProtocolSSH && !validFingerprint(fingerprint) {
		return Asset{}, fmt.Errorf("%w: a SHA256 SSH host-key fingerprint is required", ErrInvalidInput)
	}
	if len(normalizeGateway(input.GatewayID)) > 128 || len(group) > 120 || len(nodeID) > 128 || len(remark) > 500 {
		return Asset{}, fmt.Errorf("%w: group or remark is too long", ErrInvalidInput)
	}
	if len(input.Password) > 4096 {
		return Asset{}, fmt.Errorf("%w: SSH password is too long", ErrInvalidInput)
	}
	if group == "" {
		group = "Ungrouped"
	}
	var rdp *rdpclient.Settings
	if protocol == ProtocolRDP {
		if input.RDP == nil || input.Telnet != nil || input.Kubernetes != nil || inputConfigCount(input) != 0 || input.PrivateKey != "" || input.PrivateKeyPassphrase != "" || input.CredentialType == CredentialSSHKey || input.KeyRotationEnabled != nil && *input.KeyRotationEnabled || !rdpclient.ValidCredential(username) || input.Password != "" && !rdpclient.ValidCredential(input.Password) {
			return Asset{}, ErrInvalidInput
		}
		normalized, e := rdpclient.Normalize(*input.RDP)
		if e != nil {
			return Asset{}, ErrInvalidInput
		}
		rdp = &normalized
		fingerprint = ""
	} else if input.RDP != nil {
		return Asset{}, ErrInvalidInput
	}
	var kube *kubeclient.Settings
	var telnet *telnetclient.Settings
	if protocol == ProtocolTelnet {
		if input.Telnet == nil || input.Kubernetes != nil || inputConfigCount(input) != 0 || input.PrivateKey != "" || input.PrivateKeyPassphrase != "" || input.CredentialType == CredentialSSHKey || input.KeyRotationEnabled != nil && *input.KeyRotationEnabled || !telnetclient.ValidCredential(username) || input.Password != "" && !telnetclient.ValidCredential(input.Password) {
			return Asset{}, ErrInvalidInput
		}
		normalized, e := telnetclient.Normalize(*input.Telnet)
		if e != nil {
			return Asset{}, ErrInvalidInput
		}
		telnet = &normalized
		fingerprint = ""
	} else if input.Telnet != nil {
		return Asset{}, ErrInvalidInput
	}
	if protocol == ProtocolKubernetes {
		if input.Password != "" && !kubeclient.ValidToken(input.Password) {
			return Asset{}, ErrInvalidInput
		}
		if input.Kubernetes == nil || inputConfigCount(input) != 0 || input.CredentialType == CredentialSSHKey || input.PrivateKey != "" || input.PrivateKeyPassphrase != "" || input.KeyRotationEnabled != nil && *input.KeyRotationEnabled {
			return Asset{}, ErrInvalidInput
		}
		normalized, e := kubeclient.Normalize(*input.Kubernetes)
		if e != nil {
			return Asset{}, ErrInvalidInput
		}
		kube = &normalized
		fingerprint = ""
	} else if input.Kubernetes != nil {
		return Asset{}, ErrInvalidInput
	}
	var pg *sqlclient.Settings
	if IsDatabase(Asset{Protocol: protocol}) {
		p := inputSettings(input, protocol)
		if inputConfigCount(input) != 1 {
			return Asset{}, ErrInvalidInput
		}
		if p == nil || input.PrivateKey != "" || input.PrivateKeyPassphrase != "" || input.CredentialType == CredentialSSHKey || input.KeyRotationEnabled != nil && *input.KeyRotationEnabled {
			return Asset{}, ErrInvalidInput
		}
		ro := true
		if p.ReadOnly != nil {
			ro = *p.ReadOnly
		}
		mode := p.TLSMode
		if mode == "" {
			mode = "verify-full"
		}
		pg = &sqlclient.Settings{AuthDatabase: p.AuthDatabase, Database: p.Database, TLSMode: mode, ServerName: p.ServerName, RootCAPEM: p.RootCAPEM, ReadOnly: ro}
		if validateDatabaseSettings(protocol, *pg) != nil {
			return Asset{}, ErrInvalidInput
		}
		fingerprint = ""
	} else if inputConfigCount(input) != 0 {
		return Asset{}, ErrInvalidInput
	}
	asset := Asset{Protocol: input.Protocol, Kubernetes: kube, Telnet: telnet, RDP: rdp,
		ID:                  id,
		GatewayID:           normalizeGateway(input.GatewayID),
		Name:                name,
		Host:                host,
		Group:               group,
		NodeID:              nodeID,
		Username:            username,
		HostKeyFingerprint:  fingerprint,
		Port:                input.Port,
		Remark:              remark,
		LoginReviewRequired: input.LoginReviewRequired != nil && *input.LoginReviewRequired,
	}
	if input.SSHWorkspace != nil {
		asset.SSHWorkspace = *input.SSHWorkspace
		if asset.SSHWorkspace != "" && (protocol != ProtocolSSH || hostagent.ValidateWorkspace(asset.SSHWorkspace) != nil) {
			return Asset{}, ErrInvalidInput
		}
	}
	setAssetSettings(&asset, protocol, pg)
	return asset, nil
}

func validHost(host string) bool {
	if host == "" || len(host) > 253 || strings.ContainsAny(host, " \t\r\n/\\@") {
		return false
	}
	if net.ParseIP(host) != nil {
		return true
	}
	for _, label := range strings.Split(strings.TrimSuffix(host, "."), ".") {
		if len(label) == 0 || len(label) > 63 || !hostLabelPattern.MatchString(label) || strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return false
		}
	}
	return true
}

func validFingerprint(fingerprint string) bool {
	if !strings.HasPrefix(fingerprint, "SHA256:") {
		return false
	}
	decoded, err := base64.RawStdEncoding.DecodeString(strings.TrimPrefix(fingerprint, "SHA256:"))
	return err == nil && len(decoded) == 32
}

func newID() (string, error) {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", fmt.Errorf("generate asset ID: %w", err)
	}
	return "asset-" + hex.EncodeToString(raw[:]), nil
}

func classifyProbeError(err error) string {
	var gateway *sshclient.GatewayError
	if errors.As(err, &gateway) {
		return "gateway_failed"
	}
	message := strings.ToLower(err.Error())
	switch {
	case strings.Contains(message, "fingerprint mismatch"):
		return "host_key_mismatch"
	case strings.Contains(message, "unable to authenticate"), strings.Contains(message, "authentication failed"):
		return "authentication_failed"
	case errors.Is(err, context.DeadlineExceeded), strings.Contains(message, "timeout"):
		return "connection_timeout"
	default:
		return "probe_failed"
	}
}

func applyKeyRotationPolicy(asset *Asset, input Input, current *Asset) error {
	if current != nil {
		asset.KeyRotationEnabled = current.KeyRotationEnabled
	}
	if input.KeyRotationEnabled != nil {
		asset.KeyRotationEnabled = *input.KeyRotationEnabled
	}
	if asset.CredentialType != CredentialSSHKey {
		if input.KeyRotationEnabled != nil && *input.KeyRotationEnabled {
			return fmt.Errorf("%w: SSH key rotation requires key authentication", ErrInvalidInput)
		}
		asset.KeyRotationEnabled = false
	}
	return nil
}
