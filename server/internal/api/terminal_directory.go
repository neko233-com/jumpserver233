package api

import (
	"github.com/neko233-com/jumpserver233/server/internal/core/assets"
	coreauth "github.com/neko233-com/jumpserver233/server/internal/core/auth"
	"github.com/neko233-com/jumpserver233/server/internal/core/commandfilters"
	"github.com/neko233-com/jumpserver233/server/internal/gateway"
	"github.com/neko233-com/jumpserver233/server/internal/terminalwire"
	"time"
)

func terminalDirectoryPolicy(d Dependencies, principal coreauth.User, assetID string) gateway.DirectoryCommandPolicy {
	if d.Assets == nil || d.CommandFilters == nil {
		return nil
	}
	return func(command string, supported bool, at time.Time, proof terminalwire.Proof) gateway.CommandPolicyDecision {
		asset, e := d.Assets.Get(assetID)
		if e != nil {
			return gateway.CommandPolicyDecision{}
		}
		var groups, nodes []string
		if d.Groups != nil {
			groups = d.Groups.GroupIDsForUser(principal.ID)
		}
		if d.Nodes != nil {
			nodes = d.Nodes.AncestorIDs(asset.NodeID)
		}
		scope := commandfilters.Scope{UserID: principal.ID, GroupIDs: groups, AssetID: assets.ResourceID(asset), NodeIDs: nodes, Account: asset.Username}
		if assets.IsSSH(asset) && proof.Valid() && asset.SSHWorkspace == proof.Root {
			scope.Directory = proof.Directory
			scope.DirectoryVerified = true
		}
		v := d.CommandFilters.Decide(scope, command, supported, at)
		return gateway.CommandPolicyDecision{Allowed: v.Allowed, RequireReview: v.Action == commandfilters.ActionReview, RuleName: v.RuleName, PolicyKey: v.PolicyKey, DirectoryRequired: v.DirectoryRequired}
	}
}
