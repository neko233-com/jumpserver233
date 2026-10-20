package gateway

import (
	"context"
	"io"

	"github.com/neko233-com/jumpserver233/server/internal/core/replayarchive"
)

func (b *Broker) SetReplayArchive(store *replayarchive.Store) { b.archive.Store(store) }
func (b *Broker) replayArchive() *replayarchive.Store         { return b.archive.Load() }

// ReplayRecords supplies finalized audit identities for authorized listing and
// explicit historical enqueue. The archive never substitutes for this index.
func (b *Broker) ReplayRecords() ([]SessionRecord, error) {
	rows, e := b.readSessionRecords()
	if e != nil {
		return nil, e
	}
	out := []SessionRecord{}
	for _, r := range rows {
		if r.Status == "ended" {
			out = append(out, r)
		}
	}
	return out, nil
}
func (b *Broker) ReplayRecord(id, operator string, all bool) (SessionRecord, error) {
	if !validSessionID(id) {
		return SessionRecord{}, ErrSessionNotFound
	}
	rows, e := b.ReplayRecords()
	if e != nil {
		return SessionRecord{}, e
	}
	for _, r := range rows {
		if r.SessionID == id && (all || operator != "" && r.OperatorID == operator) {
			return r, nil
		}
	}
	return SessionRecord{}, ErrSessionNotFound
}
func (b *Broker) OpenReplayForOperatorContext(ctx context.Context, id, operator string) (io.ReadCloser, error) {
	if e := b.requireSessionOperator(id, operator); e != nil {
		return nil, e
	}
	return b.OpenReplayContext(ctx, id)
}
