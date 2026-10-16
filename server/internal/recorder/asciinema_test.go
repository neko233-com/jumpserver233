package recorder

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestEncryptedRecordingReplaysAsAsciinemaGzip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "session.json.gz.enc")
	key := []byte("0123456789abcdef0123456789abcdef")
	started := time.Now().UTC()
	recording, err := NewAsciinema(path, "session-1", "asset-1", 120, 40, started, key)
	if err != nil {
		t.Fatal(err)
	}
	if err := recording.Record('i', []byte("sudo -S password123\n")); err != nil {
		t.Fatal(err)
	}
	if err := recording.Record('o', []byte("ready\r\n")); err != nil {
		t.Fatal(err)
	}
	if err := recording.Close(); err != nil {
		t.Fatal(err)
	}

	stored, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(stored), "password123") || strings.Contains(string(stored), "ready") {
		t.Fatal("recording contains unencrypted terminal data")
	}

	replay, err := OpenReplay(path, "session-1", key)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := io.ReadAll(replay)
	closeErr := replay.Close()
	if err != nil {
		t.Fatalf("read asciinema replay: %v", err)
	}
	if closeErr != nil {
		t.Fatalf("close asciinema replay: %v", closeErr)
	}
	text := string(decoded)
	for _, expected := range []string{`"version":2`, `"width":120`, `"height":40`, `"i","sudo -S password123\n"`, `"o","ready\r\n"`} {
		if !strings.Contains(text, expected) {
			t.Errorf("asciinema stream does not contain %q: %s", expected, text)
		}
	}
}

func TestOpenReplayRejectsWrongVaultKey(t *testing.T) {
	path := filepath.Join(t.TempDir(), "session.json.gz.enc")
	key := []byte("0123456789abcdef0123456789abcdef")
	recording, err := NewAsciinema(path, "session-2", "asset-1", 80, 24, time.Now(), key)
	if err != nil {
		t.Fatal(err)
	}
	if err := recording.Close(); err != nil {
		t.Fatal(err)
	}
	wrong := []byte("abcdef0123456789abcdef0123456789")
	replay, err := OpenReplay(path, "session-2", wrong)
	if err == nil {
		defer replay.Close()
		if _, readErr := io.ReadAll(replay); readErr == nil {
			t.Fatal("replay accepted a different vault key")
		}
	}
}
