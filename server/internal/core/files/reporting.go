package files

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"github.com/neko233-com/jumpserver233/server/internal/core/reporting"
	"os"
)

func (s *Service) ReportMetadata(ctx context.Context, actor string, all bool, emit func(reporting.Entry) error) error {
	if s.audit == nil {
		return errors.New("file audit unavailable")
	}
	a := s.audit
	a.mu.Lock()
	defer a.mu.Unlock()
	f, e := os.Open(a.path)
	if errors.Is(e, os.ErrNotExist) {
		return nil
	}
	if e != nil {
		return e
	}
	defer f.Close()
	info, e := f.Stat()
	if e != nil {
		return e
	}
	if info.Size() > 64<<20 {
		return reporting.ErrLimit
	}
	scan := bufio.NewScanner(f)
	scan.Buffer(make([]byte, 4096), 1<<20)
	for scan.Scan() {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		var v Transfer
		if json.Unmarshal(scan.Bytes(), &v) != nil {
			return reporting.ErrInvalid
		}
		if !all && (actor == "" || v.Actor != actor) {
			continue
		}
		state := "failed"
		if v.Success {
			state = "succeeded"
		}
		if e = emit(reporting.Entry{At: v.At, State: state}); e != nil {
			return e
		}
	}
	return scan.Err()
}
