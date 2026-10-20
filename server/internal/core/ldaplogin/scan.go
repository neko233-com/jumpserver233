package ldaplogin

import (
	"context"
	"github.com/neko233-com/jumpserver233/server/internal/connector/ldapclient"
)

type ScanResult struct {
	ldapclient.DirectorySnapshot
	Issuer   string `json:"-"`
	Revision int    `json:"revision"`
}

func (s *Service) Scan(ctx context.Context, o ldapclient.ScanOptions) (ScanResult, error) {
	scanner, ok := s.directory.(ldapclient.Scanner)
	if !ok {
		return ScanResult{}, ldapclient.ErrUnavailable
	}
	c, password := s.current()
	if !c.Enabled {
		return ScanResult{}, ErrDisabled
	}
	select {
	case s.slots <- struct{}{}:
		defer func() { <-s.slots }()
	default:
		return ScanResult{}, ErrCapacity
	}
	result, e := scanner.Scan(ctx, c.Config, password, o)
	if e != nil {
		return ScanResult{}, e
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.data.Config.Revision != c.Revision || !s.data.Config.Enabled {
		return ScanResult{}, ErrConflict
	}
	return ScanResult{result, issuer(c), c.Revision}, nil
}
