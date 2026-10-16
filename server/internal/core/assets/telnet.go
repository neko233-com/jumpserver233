package assets

import (
	"context"
	"github.com/neko233-com/jumpserver233/server/internal/connector/telnetclient"
)

const ProtocolTelnet = "telnet"

func IsTelnet(a Asset) bool { return Protocol(a) == ProtocolTelnet }
func (s *Service) OpenTelnetShell(ctx context.Context, id string, cols, rows int) (Asset, *telnetclient.Shell, error) {
	a, t, c, e := s.store.connectionForProtocol(id, false)
	if e != nil {
		return Asset{}, nil, e
	}
	if !IsTelnet(a) || a.Telnet == nil {
		return Asset{}, nil, ErrUnsupportedProtocol
	}
	shell, e := telnetclient.OpenShell(ctx, telnetclient.Target{Host: a.Host, Port: a.Port, Settings: *a.Telnet, Gateways: t.Gateways}, a.Username, c.Password, cols, rows)
	return a, shell, e
}
