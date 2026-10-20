package assets

import (
	"context"
	"github.com/neko233-com/jumpserver233/server/internal/connector/sshclient"
)

func (s *Service) OpenManagedHost(ctx context.Context, id string) (*sshclient.ManagedHost, error) {
	a, target, credentials, e := s.store.connection(id)
	if e != nil {
		return nil, e
	}
	if WindowsPAM(a) {
		return nil, ErrUnsupportedProtocol
	}
	return sshclient.OpenManagedHost(ctx, target, credentials)
}
