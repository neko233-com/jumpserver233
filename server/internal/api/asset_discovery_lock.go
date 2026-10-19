package api

import (
	"context"
	"time"
)

// Runtime workers must be cancellable while an organization lifecycle writer
// holds authority locks and waits for those same workers to stop.
func lockDiscoveryRuntime(ctx context.Context, d Dependencies, write bool) (func(), error) {
	global := d.GlobalAccessMu
	separate := global != nil && global != d.AccessMu
	timer := time.NewTicker(time.Millisecond)
	defer timer.Stop()
	for {
		if e := ctx.Err(); e != nil {
			return nil, e
		}
		acquired := true
		if separate {
			if write {
				acquired = global.TryLock()
			} else {
				acquired = global.TryRLock()
			}
		}
		if acquired {
			local := false
			if write {
				local = d.AccessMu.TryLock()
			} else {
				local = d.AccessMu.TryRLock()
			}
			if local {
				return func() {
					if write {
						d.AccessMu.Unlock()
					} else {
						d.AccessMu.RUnlock()
					}
					if separate {
						if write {
							global.Unlock()
						} else {
							global.RUnlock()
						}
					}
				}, nil
			}
			if separate {
				if write {
					global.Unlock()
				} else {
					global.RUnlock()
				}
			}
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-timer.C:
		}
	}
}
