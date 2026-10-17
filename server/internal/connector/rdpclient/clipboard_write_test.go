package rdpclient

import (
	"encoding/binary"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func clipboardAck(flags byte) []byte { return []byte{3, 0, flags, 0, 0, 0, 0, 0} }
func noClipboardResult(t *testing.T, result <-chan error) {
	t.Helper()
	select {
	case e := <-result:
		t.Fatalf("clipboard completed before matching acknowledgement: %v", e)
	case <-time.After(20 * time.Millisecond):
	}
}
func TestClipboardWriteWaitsForItsOwnFormatAcknowledgement(t *testing.T) {
	c := newTestClient(t)
	defer c.Close()
	c.SetClipboardGuard(func(string) error { return nil })
	sent := make(chan struct{}, 2)
	sink := &channelSink{onFormat: func() { sent <- struct{}{} }}
	c.clip = newClipboard(c, sink)
	require.NoError(t, c.clip.process([]byte{1, 0, 0, 0, 0, 0, 0, 0}))
	<-sent // startup format announcement remains outstanding
	result := make(chan error, 1)
	go func() { result <- c.clip.set("new clipboard text") }()
	<-sent
	noClipboardResult(t, result)
	require.NoError(t, c.clip.process(clipboardAck(1))) // startup response cannot complete the new write
	noClipboardResult(t, result)
	require.NoError(t, c.clip.process(clipboardAck(1)))
	select {
	case e := <-result:
		require.NoError(t, e)
	case <-time.After(time.Second):
		t.Fatal("matching format acknowledgement was ignored")
	}
}

func TestClipboardInitializationDoesNotAdvertiseUnprovidedText(t *testing.T) {
	c := newTestClient(t)
	defer c.Close()
	c.SetClipboardGuard(func(string) error { return nil })
	sink := &channelSink{}
	c.clip = newClipboard(c, sink)
	require.NoError(t, c.clip.process([]byte{1, 0, 0, 0, 0, 0, 0, 0}))
	packet := sink.messages[len(sink.messages)-1]
	assert.Equal(t, uint16(2), binary.LittleEndian.Uint16(packet[8:]))
	assert.Zero(t, binary.LittleEndian.Uint32(packet[12:]), "no local clipboard format exists before an explicit write")
	require.NoError(t, c.clip.process(clipboardAck(1)))
	assert.False(t, c.clip.localAccepted)
	require.NoError(t, c.clip.process([]byte{4, 0, 0, 0, 4, 0, 0, 0, 13, 0, 0, 0}))
	packet = sink.messages[len(sink.messages)-1]
	assert.Equal(t, uint16(2), binary.LittleEndian.Uint16(packet[10:]))
}
func TestClipboardRejectedFormatAndRevocationCannotServeLocalText(t *testing.T) {
	for _, revoked := range []bool{false, true} {
		t.Run(map[bool]string{false: "rejected", true: "revoked"}[revoked], func(t *testing.T) {
			c := newTestClient(t)
			defer c.Close()
			var allowed atomic.Bool
			allowed.Store(true)
			c.SetClipboardGuard(func(string) error {
				if !allowed.Load() {
					return ErrClipboard
				}
				return nil
			})
			sent := make(chan struct{}, 1)
			sink := &channelSink{onFormat: func() { sent <- struct{}{} }}
			c.clip = newClipboard(c, sink)
			c.clip.ready = true
			result := make(chan error, 1)
			go func() { result <- c.clip.set("synthetic confidential text") }()
			<-sent
			flags := byte(2)
			if revoked {
				allowed.Store(false)
				flags = 1
			}
			require.NoError(t, c.clip.process(clipboardAck(flags)))
			require.ErrorIs(t, <-result, ErrClipboard)
			require.NoError(t, c.clip.process([]byte{4, 0, 0, 0, 4, 0, 0, 0, 13, 0, 0, 0}))
			packet := sink.messages[len(sink.messages)-1]
			assert.Equal(t, uint16(2), binary.LittleEndian.Uint16(packet[10:]))
			assert.Len(t, packet, 16)
		})
	}
}
func TestClipboardCloseUnblocksPendingWrite(t *testing.T) {
	c := newTestClient(t)
	defer c.Close()
	c.SetClipboardGuard(func(string) error { return nil })
	sent := make(chan struct{}, 1)
	c.clip = newClipboard(c, &channelSink{onFormat: func() { sent <- struct{}{} }})
	c.clip.ready = true
	result := make(chan error, 1)
	go func() { result <- c.clip.set("pending") }()
	<-sent
	c.Close()
	select {
	case e := <-result:
		assert.ErrorIs(t, e, ErrUnavailable)
	case <-time.After(time.Second):
		t.Fatal("closed desktop retained pending clipboard write")
	}
}

func TestClipboardUnacknowledgedWriteFailsClosedAndCannotServeLateData(t *testing.T) {
	c := newTestClient(t)
	defer c.Close()
	c.SetClipboardGuard(func(string) error { return nil })
	sink := &channelSink{}
	c.clip = newClipboard(c, sink)
	c.clip.ready = true
	c.clip.writeTimeout = 20 * time.Millisecond
	require.ErrorIs(t, c.clip.set("synthetic confidential text"), ErrClipboard)
	require.NoError(t, c.clip.process(clipboardAck(1)))
	require.NoError(t, c.clip.process([]byte{4, 0, 0, 0, 4, 0, 0, 0, 13, 0, 0, 0}))
	packet := sink.messages[len(sink.messages)-1]
	assert.Equal(t, uint16(2), binary.LittleEndian.Uint16(packet[10:]))
	require.ErrorIs(t, c.clip.set("another value"), ErrClipboard)
}
