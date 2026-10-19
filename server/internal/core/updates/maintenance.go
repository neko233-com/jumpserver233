package updates

import (
	"github.com/neko233-com/jumpserver233/server/internal/core/servicemaintenance"
	"time"
)

// RecordMaintenance persists the event before the admission state changes.
func (s *Store) RecordMaintenance(event servicemaintenance.Event) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	next := s.data
	withAudit(&next, Audit{At: time.Now().UTC(), ActorID: event.ActorID, Actor: event.Actor, Action: "maintenance", Maintenance: &event})
	if e := s.persist(next); e != nil {
		return e
	}
	s.data = next
	return nil
}
