package assets

import (
	"fmt"
	"strings"

	"github.com/neko233-com/jumpserver233/server/internal/connector/sshclient"
)

var ErrGatewayInUse = fmt.Errorf("SSH gateway is referenced by another asset")

func (s *Store) validateGatewaysLocked() error {
	for id := range s.assets {
		seen := map[string]bool{id: true}
		current := s.assets[id]
		hops := 0
		for current.GatewayID != "" {
			hops++
			if hops > sshclient.MaxGatewayHops || seen[current.GatewayID] {
				return fmt.Errorf("%w: SSH gateway route contains a cycle or exceeds three hops", ErrInvalidInput)
			}
			seen[current.GatewayID] = true
			next, ok := s.assets[current.GatewayID]
			if !ok {
				return fmt.Errorf("%w: SSH gateway does not exist", ErrInvalidInput)
			}
			current = next
			if !IsSSH(current.Asset) {
				return ErrUnsupportedProtocol
			}
		}
	}
	return nil
}

// connection snapshots the full route and vault credentials under one read lock.
// A gateway's pending password change blocks new routes through that gateway.
func (s *Store) connection(id string) (Asset, sshclient.Target, sshclient.Credentials, error) {
	return s.connectionForProtocol(id, true)
}
func (s *Store) connectionForProtocol(id string, requireSSH bool) (Asset, sshclient.Target, sshclient.Credentials, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	record, ok := s.assets[id]
	if !ok {
		return Asset{}, sshclient.Target{}, sshclient.Credentials{}, ErrNotFound
	}
	if requireSSH && !IsSSH(record.Asset) {
		return Asset{}, sshclient.Target{}, sshclient.Credentials{}, ErrUnsupportedProtocol
	}
	password, e := s.aead.Open(nil, record.Credential.Nonce, record.Credential.Ciphertext, credentialAAD(record.ID, record.CredentialType, ""))
	if e != nil {
		return Asset{}, sshclient.Target{}, sshclient.Credentials{}, e
	}
	target := sshTarget(record.Asset)
	current := record
	hops := []sshclient.Hop{}
	ids := []string{}
	seen := map[string]bool{id: true}
	for current.GatewayID != "" {
		if len(hops) >= sshclient.MaxGatewayHops || seen[current.GatewayID] {
			return Asset{}, sshclient.Target{}, sshclient.Credentials{}, ErrInvalidInput
		}
		seen[current.GatewayID] = true
		gateway, exists := s.assets[current.GatewayID]
		if !exists {
			return Asset{}, sshclient.Target{}, sshclient.Credentials{}, ErrInvalidInput
		}
		if !IsSSH(gateway.Asset) {
			return Asset{}, sshclient.Target{}, sshclient.Credentials{}, ErrUnsupportedProtocol
		}
		if gateway.PendingRotation != nil || gateway.PendingKeyChange != nil {
			return Asset{}, sshclient.Target{}, sshclient.Credentials{}, ErrRotationPending
		}
		secret, e := s.aead.Open(nil, gateway.Credential.Nonce, gateway.Credential.Ciphertext, credentialAAD(gateway.ID, gateway.CredentialType, ""))
		if e != nil {
			return Asset{}, sshclient.Target{}, sshclient.Credentials{}, e
		}
		hops = append(hops, sshclient.Hop{Target: sshTarget(gateway.Asset), Credentials: decodeCredentials(gateway.CredentialType, secret)})
		ids = append(ids, gateway.ID)
		current = gateway
	}
	for i, j := 0, len(hops)-1; i < j; i, j = i+1, j-1 {
		hops[i], hops[j] = hops[j], hops[i]
		ids[i], ids[j] = ids[j], ids[i]
	}
	target.Gateways = hops
	asset := record.Asset
	asset.GatewayIDs = ids
	return asset, target, decodeCredentials(record.CredentialType, password), nil
}
func normalizeGateway(input *string) string {
	if input == nil {
		return ""
	}
	return strings.TrimSpace(*input)
}
