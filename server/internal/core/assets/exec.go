package assets

import (
	"context"
	"github.com/neko233-com/jumpserver233/server/internal/connector/sshclient"
)

// Exec keeps decrypted SSH credentials inside the asset/connector boundary.
func (s *Service) Exec(ctx context.Context, id, command string) (sshclient.ExecResult, error) {
	asset, target, credentials, err := s.store.connectionForProtocolBound(id, true, expectedConnectionBinding(ctx))
	if err != nil {
		return sshclient.ExecResult{ExitCode: -1}, err
	}
	if asset.SSHWorkspace != "" {
		return s.execWorkspace(ctx, target, credentials, asset.SSHWorkspace, command)
	}
	return sshclient.Exec(ctx, target, credentials, command)
}
