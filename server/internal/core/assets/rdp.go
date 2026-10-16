package assets

import (
	"context"
	"github.com/neko233-com/jumpserver233/server/internal/connector/rdpclient"
)

const ProtocolRDP = "rdp"

func IsRDP(a Asset) bool { return Protocol(a) == ProtocolRDP }
func (s *Service) rdpTarget(id string) (Asset, rdpclient.Target, string, error) {
	a, route, secret, e := s.store.connectionForProtocol(id, false)
	if e != nil {
		return Asset{}, rdpclient.Target{}, "", e
	}
	if !IsRDP(a) || a.RDP == nil {
		return Asset{}, rdpclient.Target{}, "", ErrUnsupportedProtocol
	}
	return a, rdpclient.Target{Host: a.Host, Port: a.Port, Settings: *a.RDP, Gateways: route.Gateways}, secret.Password, nil
}
func (s *Service) OpenRDP(ctx context.Context, id string) (Asset, *rdpclient.Client, error) {
	a, target, password, e := s.rdpTarget(id)
	if e != nil {
		return a, nil, e
	}
	client, e := rdpclient.Open(ctx, target, a.Username, password)
	return a, client, e
}
func (s *Service) ProbeRDP(ctx context.Context, id string) error {
	_, target, _, e := s.rdpTarget(id)
	if e != nil {
		return e
	}
	return rdpclient.Probe(ctx, target)
}
