package desktop

import (
	"context"
	"os"

	"github.com/neko233-com/jumpserver233/server/internal/core/replayarchive"
)

func (b *Broker) SetReplayArchive(store *replayarchive.Store) { b.archive.Store(store) }
func (b *Broker) replayArchive() *replayarchive.Store         { return b.archive.Load() }
func (b *Broker) ReplayRecords(ctx context.Context) ([]Record, error) {
	entries, e := os.ReadDir(b.root)
	if e != nil {
		return nil, e
	}
	out := []Record{}
	for _, entry := range entries {
		if e := ctx.Err(); e != nil {
			return nil, e
		}
		if !entry.IsDir() || !idPattern.MatchString(entry.Name()) {
			continue
		}
		r, e := b.readIndex(entry.Name())
		if e == nil && r.Status == "ended" {
			r.Frames = nil
			out = append(out, r)
		}
	}
	return out, nil
}
