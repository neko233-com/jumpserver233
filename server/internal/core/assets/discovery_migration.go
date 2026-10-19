package assets

import (
	"crypto/sha256"
	"encoding/hex"
	"net/netip"
	"strconv"
	"strings"
)

// Only a stable cloud-resource finding can move an SSH endpoint. A matching
// observed host key preserves the existing trust; credentials are never sent
// during discovery and remain encrypted under the same asset/account IDs.
func (s *Service) validateDiscoveryAddressMigrationLocked(old storedAsset, next Asset, source, finding string, option DiscoverySyncOptions, update, missing bool) error {
	if !option.MigrateCloudSSHAddress || !update || missing || old.Host == next.Host || !IsSSH(old.Asset) || !IsSSH(next) || option.CloudResourceKey == "" || len(option.CloudResourceKey) > 256 || strings.ContainsRune(option.CloudResourceKey, '\x00') {
		return ErrCredentialChanged
	}
	identity := sha256.Sum256([]byte(source + "\x00" + Protocol(next) + "\x00" + option.CloudResourceKey + "\x00" + strconv.Itoa(next.Port)))
	if hex.EncodeToString(identity[:]) != finding || old.Discovery == nil || old.Discovery.PolicyID != option.PolicyID || discoveryManagedHash(old.Asset) != old.Discovery.ManagedHash {
		return ErrCredentialChanged
	}
	address, e := netip.ParseAddr(next.Host)
	previous, e2 := netip.ParseAddr(old.Host)
	if e != nil || e2 != nil || address == previous || address.Zone() != "" || previous.Zone() != "" || address.Is4In6() || previous.Is4In6() || !address.IsGlobalUnicast() || !previous.IsGlobalUnicast() {
		return ErrCredentialChanged
	}
	if old.Port != next.Port || old.HostKeyFingerprint == "" || old.HostKeyFingerprint != next.HostKeyFingerprint || old.Username != next.Username || old.GatewayID != next.GatewayID {
		return ErrCredentialChanged
	}
	for _, record := range s.store.assets {
		if record.ID == old.ID || record.ParentAssetID == old.ID {
			if s.rotationRunning[record.ID] {
				return ErrRotationInProgress
			}
			if record.PendingRotation != nil || record.PendingKeyChange != nil {
				return ErrRotationPending
			}
			if remoteAccountPending(record.Asset) {
				return ErrRemoteAccountPending
			}
			if s.passwordCoordinator != nil && s.passwordCoordinator.blocked(s.passwordScope, record.ID) {
				return ErrRotationPending
			}
		}
		if record.ParentAssetID == "" && record.ID != old.ID && record.Host == next.Host && record.Port == next.Port && Protocol(record.Asset) == Protocol(next) && record.GatewayID == next.GatewayID {
			return ErrCredentialChanged
		}
	}
	if s.passwordCoordinator != nil {
		rows := []importPrepared{}
		for _, record := range s.store.assets {
			if record.ID != old.ID && record.ParentAssetID != old.ID {
				continue
			}
			candidate := next
			if record.ParentAssetID == old.ID {
				candidate = inheritAccount(next, record.Asset)
			}
			current := record
			rows = append(rows, importPrepared{asset: candidate, current: &current})
		}
		if e := s.validateDiscoveryMigrationOperationsLocked(rows); e != nil {
			return e
		}
		return s.validateAccountImportAliasesLocked(rows)
	}
	return nil
}

func (s *Service) validateDiscoveryMigrationOperationsLocked(rows []importPrepared) error {
	if c := s.passwordCoordinator; c != nil {
		for _, row := range rows {
			if row.current != nil && (c.blocked(s.passwordScope, row.asset.ID) || c.ops[passwordIdentity(row.asset)] != nil || c.sharedKeyMutation(row.asset)) {
				return ErrRotationPending
			}
		}
	}
	return nil
}
