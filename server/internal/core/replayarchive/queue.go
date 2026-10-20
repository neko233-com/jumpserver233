package replayarchive

// Queue records an explicitly authorized historical archive request. Replays of
// a request return its original receipt even after the worker changes status.
func (s *Store) Queue(ref Ref, actor, request string) (Record, error) {
	if !ValidRef(ref) || !validActor(actor) || !requestPattern.MatchString(request) {
		return Record{}, ErrInvalid
	}
	hash := s.requestHash([]any{"archive", ref})
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return Record{}, ErrClosed
	}
	if r, yes, e := s.replay(actor, request, hash); yes {
		if e != nil {
			return Record{}, e
		}
		if r.Record == nil {
			return Record{}, ErrConflict
		}
		return *r.Record, nil
	}
	r, ok := s.data.Records[refKey(ref)]
	if !ok {
		c := s.data.History[s.data.Revision]
		if !c.Enabled || c.Provider == "local" {
			return Record{}, ErrConflict
		}
		if len(s.data.Records) >= maxRecords {
			return Record{}, ErrCapacity
		}
		at := s.now().UTC()
		r = storedRecord{Record: Record{Ref: ref, ConfigRevision: c.Revision, Status: "queued", QueuedAt: at, NextAttempt: at}}
	}
	st := s.copy()
	st.Records[refKey(ref)] = r
	out := r.Record
	if e := s.commit(st, receipt{Actor: actor, Request: request, Hash: hash, Record: &out}, Audit{At: s.now().UTC(), ActorID: actor, Action: "archive", Ref: &ref, Revision: s.data.Revision}); e != nil {
		return Record{}, e
	}
	s.notify()
	return out, nil
}
