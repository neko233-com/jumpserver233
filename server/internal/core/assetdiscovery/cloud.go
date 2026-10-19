package assetdiscovery

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"slices"
	"strconv"

	"github.com/neko233-com/jumpserver233/server/internal/connector/cloudinventory"
	"github.com/neko233-com/jumpserver233/server/internal/connector/inventoryprobe"
)

func normalizeCloudSource(in *SourceInput, old *sourceRecord) error {
	if old != nil && old.Input.Provider != in.Provider {
		return ErrInvalid
	}
	if in.Provider == "lan" {
		if in.Cloud != nil || in.CloudCredential != nil {
			return ErrInvalid
		}
		return nil
	}
	if in.Cloud == nil || len(in.Targets) != 0 || len(in.Exclude) != 0 {
		return ErrInvalid
	}
	if old != nil && (old.Input.Cloud == nil || in.Cloud.AccountID != old.Input.Cloud.AccountID) {
		return ErrInvalid
	}
	if in.CloudCredential == nil && old != nil {
		in.CloudCredential = copyJSON(old.Input.CloudCredential)
	}
	if in.CloudCredential == nil {
		return ErrInvalid
	}
	config, e := cloudinventory.Validate(in.Provider, *in.Cloud, *in.CloudCredential)
	if e != nil {
		return ErrInvalid
	}
	in.Cloud = &config
	in.Targets, in.Exclude = []string{}, []string{}
	return nil
}

func cloudFindingID(source, protocol string, instance cloudinventory.Instance, port int) string {
	sum := sha256.Sum256([]byte(source + "\x00" + protocol + "\x00" + instance.ResourceKey() + "\x00" + strconv.Itoa(port)))
	return hex.EncodeToString(sum[:])
}

func cloudError(e error) string {
	if errors.Is(e, ErrDenied) {
		return "scan_permission_revoked"
	}
	if errors.Is(e, cloudinventory.ErrIdentity) {
		return "scan_cloud_identity_mismatch"
	}
	if errors.Is(e, cloudinventory.ErrPermission) {
		return "scan_cloud_permission_denied"
	}
	if errors.Is(e, cloudinventory.ErrCapacity) || errors.Is(e, ErrCapacity) {
		return "scan_cloud_capacity"
	}
	if errors.Is(e, context.Canceled) {
		return "scan_cancelled"
	}
	if errors.Is(e, context.DeadlineExceeded) {
		return "scan_timeout"
	}
	return "scan_cloud_unavailable"
}

func (s *Service) cloudTargets(ctx context.Context, source sourceRecord, actor Actor) ([]observation, error) {
	if e := s.authorize(ctx, actor, publicSource(source), "execute"); e != nil {
		return nil, ErrDenied
	}
	list := s.hooks.CloudList
	if list == nil {
		client := cloudinventory.NewClient()
		defer client.Close()
		list = client.List
	}
	instances, e := list(ctx, source.Input.Provider, *source.Input.Cloud, *source.Input.CloudCredential)
	if e != nil {
		return nil, e
	}
	if len(instances) > cloudinventory.MaxInstances || len(instances)*len(source.Input.Ports) > MaxEndpoints {
		return nil, ErrCapacity
	}
	out := []observation{}
	metadataBytes := 0
	seen := map[string]bool{}
	for _, instance := range instances {
		metadataBytes += instance.EncodedSize() * len(source.Input.Ports)
		if metadataBytes > cloudinventory.MaxMetadataBytes {
			return nil, ErrCapacity
		}
		if instance.Provider != source.Input.Provider || instance.AccountID != source.Input.Cloud.AccountID || !slices.Contains(source.Input.Cloud.Regions, instance.Region) || instance.Missing {
			return nil, cloudinventory.ErrIdentity
		}
		for _, port := range source.Input.Ports {
			id := cloudFindingID(source.ID, source.Input.Template.Protocol, instance, port)
			if seen[id] {
				return nil, ErrConflict
			}
			seen[id] = true
			v := instance
			host := v.Address(source.Input.Cloud.AddressMode)
			result := inventoryprobe.Result{}
			if host == "" {
				result.ErrorCode = "scan_cloud_no_address"
			} else if v.State != "running" {
				result.ErrorCode = "scan_cloud_not_running"
			}
			out = append(out, observation{host: host, port: port, result: result, cloud: &v})
		}
	}
	// Only a complete successful inventory can mark a resource missing. Removed
	// regions/protocols/ports are outside this scan's scope and remain untouched.
	s.store.mu.Lock()
	defer s.store.mu.Unlock()
	if e = s.store.refreshLocked(); e != nil {
		return nil, e
	}
	for id, old := range s.store.data.Findings {
		if old.SourceID != source.ID || old.Cloud == nil || seen[id] || old.Protocol != source.Input.Template.Protocol || !slices.Contains(source.Input.Ports, old.Port) || !slices.Contains(source.Input.Cloud.Regions, old.Cloud.Region) {
			continue
		}
		v := *old.Cloud
		v.Missing = true
		metadataBytes += v.EncodedSize()
		if metadataBytes > cloudinventory.MaxMetadataBytes {
			return nil, ErrCapacity
		}
		out = append(out, observation{host: old.Host, port: old.Port, cloud: &v, result: inventoryprobe.Result{ErrorCode: "scan_cloud_missing"}})
	}
	if len(out) > MaxEndpoints {
		return nil, ErrCapacity
	}
	return out, nil
}
