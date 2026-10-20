package assets

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"
)

var ErrConnectionChanged = errors.New("SSH connection authorization changed")

type connectionBindingKey struct{}
type workspaceIdentityKey struct{}
type workingDirectoryKey struct{}
type executionCheckKey struct{}
type workingDirectoryProof struct{ directory, identity string }

type connectionSnapshot struct {
	ID, ParentID, Host, Username, Protocol, Fingerprint, Workspace, Gateway, Node string
	Port                                                                          int
	CredentialRevision                                                            uint64
	Disabled, ReviewRequired                                                      bool
	UpdatedAt                                                                     time.Time
	PAMDetails                                                                    string `json:",omitempty"`
}

func snapshotConnection(a Asset) connectionSnapshot {
	details := ""
	if a.PAM != nil {
		raw, _ := json.Marshal(struct {
			PAM      *PAMSettings
			Database any
		}{a.PAM, DatabaseSettings(a)})
		sum := sha256.Sum256(raw)
		details = hex.EncodeToString(sum[:])
	}
	return connectionSnapshot{a.ID, a.ParentAssetID, a.Host, a.Username, Protocol(a), a.HostKeyFingerprint, a.SSHWorkspace, a.GatewayID, a.NodeID, a.Port, a.CredentialRevision, a.AccountDisabled, a.LoginReviewRequired, a.UpdatedAt, details}
}

// These values originate only from authenticated server authorization. They
// are not accepted from request bodies, headers or remote terminal output.
func WithConnectionBinding(ctx context.Context, binding string) context.Context {
	return context.WithValue(ctx, connectionBindingKey{}, binding)
}
func WithWorkspaceIdentity(ctx context.Context, identity string) context.Context {
	return context.WithValue(ctx, workspaceIdentityKey{}, identity)
}
func WithWorkingDirectory(ctx context.Context, directory, identity string) context.Context {
	return context.WithValue(ctx, workingDirectoryKey{}, workingDirectoryProof{directory, identity})
}
func expectedWorkingDirectory(ctx context.Context) workingDirectoryProof {
	value, _ := ctx.Value(workingDirectoryKey{}).(workingDirectoryProof)
	return value
}
func WithExecutionCheck(ctx context.Context, check func() error) context.Context {
	return context.WithValue(ctx, executionCheckKey{}, check)
}
func checkExecution(ctx context.Context) error {
	if check, ok := ctx.Value(executionCheckKey{}).(func() error); ok && check != nil {
		return check()
	}
	return nil
}

func (s *Service) BindConnection(asset Asset) (string, error) {
	s.store.mu.RLock()
	defer s.store.mu.RUnlock()
	current, ok := s.store.assets[asset.ID]
	if !ok {
		return "", ErrNotFound
	}
	if snapshotConnection(current.Asset) != snapshotConnection(asset) {
		return "", ErrConnectionChanged
	}
	return s.store.connectionBindingLocked(asset.ID)
}

func (s *Store) connectionBindingLocked(id string) (string, error) {
	route := []connectionSnapshot{}
	certificates := []string{}
	hasCertificatePolicy := false
	seen := map[string]bool{}
	for id != "" {
		if seen[id] || len(route) > 3 {
			return "", ErrInvalidInput
		}
		seen[id] = true
		row, ok := s.assets[id]
		if !ok {
			return "", ErrNotFound
		}
		if (!IsSSH(row.Asset) && (len(route) > 0 || !SupportsPasswordRotation(row.Asset))) || row.AccountDisabled || remoteAccountPending(row.Asset) {
			return "", ErrConnectionChanged
		}
		certificate := ""
		if s.certificates != nil {
			var e error
			certificate, e = s.certificates.ConnectionIdentity(id)
			if e != nil {
				return "", e
			}
		}
		route = append(route, snapshotConnection(row.Asset))
		certificates = append(certificates, certificate)
		hasCertificatePolicy = hasCertificatePolicy || certificate != ""
		id = row.GatewayID
	}
	if hasCertificatePolicy {
		return s.importMAC("connection-authorization/certificates/v1", struct {
			Route        []connectionSnapshot
			Certificates []string
		}{route, certificates}), nil
	}
	return s.importMAC("connection-authorization/v1", route), nil
}

func (s *Store) checkConnectionBindingLocked(id, binding string) error {
	if binding == "" {
		return nil
	}
	current, err := s.connectionBindingLocked(id)
	if err != nil || subtle.ConstantTimeCompare([]byte(current), []byte(binding)) != 1 {
		return ErrConnectionChanged
	}
	return nil
}

func expectedConnectionBinding(ctx context.Context) string {
	value, _ := ctx.Value(connectionBindingKey{}).(string)
	return value
}

func expectedWorkspaceIdentity(ctx context.Context) string {
	value, _ := ctx.Value(workspaceIdentityKey{}).(string)
	return value
}
