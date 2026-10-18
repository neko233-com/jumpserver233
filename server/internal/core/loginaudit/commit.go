package loginaudit

import (
	"fmt"
	"github.com/neko233-com/jumpserver233/server/internal/core/eventfeed"
	"slices"
	"time"
)

func (s *Store) commitRows(rows []Record, cursor *SourceBatch) error {
	total := s.data.Total
	for i := 0; i < len(rows); {
		if s.ctx.Err() != nil {
			return ErrClosed
		}
		n := total / SegmentSize
		tail := []Record{}
		if total%SegmentSize != 0 {
			var e error
			tail, e = s.segment(n)
			if e != nil {
				return e
			}
		}
		for i < len(rows) && len(tail) < SegmentSize {
			tail = append(tail, rows[i])
			i++
			total++
		}
		if e := s.save(fmt.Sprintf("segment-%012d", n), tail); e != nil {
			return e
		}
	}
	next := s.data
	next.Total = total
	// Retain whole segments, keeping the count bound strict.
	for next.Total-next.Floor+1 > MaxRecords {
		next.Floor += SegmentSize
	}
	cutoff := s.now().Add(-Retention)
	for next.Floor+SegmentSize-1 <= s.data.Total {
		start := int(next.Floor - s.data.Floor)
		if start < 0 || start+SegmentSize > len(s.rows) {
			break
		}
		old := s.rows[start : start+SegmentSize]
		expired := true
		for _, r := range old {
			if !r.At.Before(cutoff) {
				expired = false
				break
			}
		}
		if !expired {
			break
		}
		next.Floor += SegmentSize
	}
	if cursor != nil {
		next.ReviewCursor = cursor.Cursor
		next.ReviewGap = next.ReviewGap || cursor.Gap
	}
	if s.ctx.Err() != nil {
		return ErrClosed
	}
	if e := s.save("index", next); e != nil {
		return e
	}
	s.data = next
	s.rows = append(s.rows, rows...)
	for _, r := range rows {
		s.publish(r)
	}
	drop := 0
	for drop < len(s.rows) && s.rows[drop].Sequence < next.Floor {
		r := s.rows[drop]
		delete(s.byID, r.ID)
		if s.lastIP[r.UserID].Sequence == r.Sequence {
			delete(s.lastIP, r.UserID)
		}
		drop++
	}
	if drop > 0 {
		s.rows = slices.Clone(s.rows[drop:])
		s.events = slices.DeleteFunc(s.events, func(e eventfeed.Event) bool { _, ok := s.byID[e.ResourceID]; return !ok })
	}
	// Bound old failure buckets even when many source IPs are used.
	if s.now().Sub(s.lastPrune) >= time.Minute {
		for ip, b := range s.failures {
			b.At = slices.DeleteFunc(b.At, func(at time.Time) bool { return at.Before(s.now().Add(-5 * time.Minute)) })
			if len(b.At) == 0 && b.Notified.Before(s.now().Add(-15*time.Minute)) {
				delete(s.failures, ip)
			} else {
				s.failures[ip] = b
			}
		}
		s.lastPrune = s.now()
		s.health.AggregationLimited = len(s.failures) >= 8192
	}
	s.gc()
	return nil
}
