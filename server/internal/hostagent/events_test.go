package hostagent

import (
	"encoding/json"
	"fmt"
	"github.com/stretchr/testify/require"
	"testing"
	"time"
)

func sampleSnapshot() EventSnapshot {
	e := Event{Sequence: 1, ID: fmt.Sprintf("%032x", 1), Attempt: fmt.Sprintf("%032x", 2), At: time.Now().UTC(), Kind: "repair_completed", Trigger: "supervisor", ConfigSHA: SHA([]byte("qa")), PreviousHash: SHA(nil)}
	e.Hash = EventHash(e)
	return EventSnapshot{Format: EventFormat, Stream: fmt.Sprintf("%032x", 3), FirstSequence: 1, LastSequence: 1, AnchorHash: SHA(nil), Events: []Event{e}}
}
func TestNativeEventSnapshotRejectsForgedAndUnboundedChains(t *testing.T) {
	s := sampleSnapshot()
	raw, _ := json.Marshal(s)
	_, e := DecodeEventSnapshot(raw)
	require.NoError(t, e)
	for name, mutate := range map[string]func(*EventSnapshot){"hash": func(v *EventSnapshot) { v.Events[0].Hash = SHA(nil) }, "identity": func(v *EventSnapshot) { v.Events[0].ID = "x" }, "chain": func(v *EventSnapshot) { v.AnchorHash = SHA([]byte("foreign")) }, "sequence": func(v *EventSnapshot) { v.FirstSequence = 2 }, "more": func(v *EventSnapshot) { v.More = true }, "empty": func(v *EventSnapshot) { v.Events = nil }, "cursor": func(v *EventSnapshot) { v.Requested.Sequence = 1 }, "limit": func(v *EventSnapshot) {
		for range 65 {
			v.Events = append(v.Events, v.Events[0])
		}
	}, "missing": func(v *EventSnapshot) { v.Missing = true }} {
		t.Run(name, func(t *testing.T) {
			v := sampleSnapshot()
			mutate(&v)
			raw, _ := json.Marshal(v)
			_, e := DecodeEventSnapshot(raw)
			require.ErrorIs(t, e, ErrJournal)
		})
	}
	raw = []byte(`{"format":"jms233/agent-events/v1","format":"duplicate"}`)
	_, e = DecodeEventSnapshot(raw)
	require.ErrorIs(t, e, ErrJournal)
}
