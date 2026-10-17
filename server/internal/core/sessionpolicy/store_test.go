package sessionpolicy

import (
	"bytes"
	"context"
	"image"
	"image/color"
	"image/png"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/neko233-com/jumpserver233/server/internal/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPolicyPersistenceRevisionAuditAndFailedWrite(t *testing.T) {
	path := filepath.Join(t.TempDir(), "session-security.json")
	s, e := Open(path, nil)
	require.NoError(t, e)
	assert.Equal(t, Defaults(), s.Snapshot())
	in := s.Snapshot()
	in.IdleMinutes = 15
	out, e := s.Save(in, "admin-id", "admin")
	require.NoError(t, e)
	assert.Equal(t, 2, out.Revision)
	_, e = s.Save(in, "admin-id", "admin")
	assert.ErrorIs(t, e, ErrConflict)
	reopened, e := Open(path, nil)
	require.NoError(t, e)
	assert.Equal(t, out, reopened.Snapshot())
	require.Len(t, reopened.Audit(), 1)
	assert.Equal(t, Defaults(), reopened.Audit()[0].Before)
	bad := out
	bad.IdleMinutes = -1
	_, e = s.Save(bad, "admin-id", "admin")
	assert.ErrorIs(t, e, ErrInvalid)
	bad = out
	bad.MaxHours = 169
	_, e = s.Save(bad, "admin-id", "admin")
	assert.ErrorIs(t, e, ErrInvalid)
	block := filepath.Join(filepath.Dir(path), "file")
	require.NoError(t, os.WriteFile(block, []byte("file"), 0600))
	s.path = filepath.Join(block, "settings.json")
	_, e = s.Save(out, "admin-id", "admin")
	require.Error(t, e)
	assert.Equal(t, out, s.Snapshot())
	require.Len(t, s.Audit(), 1)
}

func TestPolicyConcurrentWritersAndAuditBound(t *testing.T) {
	s, e := Open(filepath.Join(t.TempDir(), "policy.json"), nil)
	require.NoError(t, e)
	in := s.Snapshot()
	var wins atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, e := s.Save(in, "id", "actor")
			if e == nil {
				wins.Add(1)
			} else {
				assert.ErrorIs(t, e, ErrConflict)
			}
		}()
	}
	wg.Wait()
	assert.Equal(t, int32(1), wins.Load())
	for i := 0; i < 201; i++ {
		_, e = s.Save(s.Snapshot(), "id", "actor")
		require.NoError(t, e)
	}
	assert.Len(t, s.Audit(), 200)
}

func TestPolicyTimeBoundariesAndWatermarkPNG(t *testing.T) {
	now := time.Now()
	p := Settings{IdleMinutes: 1, MaxHours: 1}
	assert.Empty(t, p.EndReason(now, now, now.Add(59*time.Second)))
	assert.Equal(t, "idle_timeout", p.EndReason(now, now, now.Add(time.Minute)))
	assert.Equal(t, "duration_limit", p.EndReason(now.Add(-time.Hour), now, now))
	assert.Empty(t, (Settings{}).EndReason(now.Add(-time.Hour), now.Add(-time.Hour), now))
	im := image.NewRGBA(image.Rect(0, 0, 640, 200))
	im.Set(50, 50, color.RGBA{255, 0, 0, 255})
	var input bytes.Buffer
	require.NoError(t, png.Encode(&input, im))
	stamped, e := StampPNG(input.Bytes(), Label("user-123", "session-456", now))
	require.NoError(t, e)
	assert.NotEqual(t, input.Bytes(), stamped)
	decoded, e := png.Decode(bytes.NewReader(stamped))
	require.NoError(t, e)
	assert.Equal(t, im.Bounds(), decoded.Bounds())
	r, g, b, a := im.At(50, 50).RGBA()
	rr, gg, bb, aa := decoded.At(50, 50).RGBA()
	assert.Equal(t, []uint32{r, g, b, a}, []uint32{rr, gg, bb, aa})
	unchanged, e := StampPNG(input.Bytes(), "")
	require.NoError(t, e)
	assert.Equal(t, input.Bytes(), unchanged)
	_, e = StampPNG([]byte("invalid"), "marker")
	require.Error(t, e)
}

func TestPolicyPostgresTakeover(t *testing.T) {
	url := os.Getenv("JMS_TEST_DATABASE_URL")
	if url == "" {
		t.Skip("set JMS_TEST_DATABASE_URL for shared policy takeover")
	}
	namespace := "session-security-" + time.Now().Format("20060102150405.000000000")
	d, e := storage.OpenPostgres(context.Background(), url, namespace)
	require.NoError(t, e)
	defer d.Close()
	defer func() { require.NoError(t, d.Delete("session-security")) }()
	path := filepath.Join(t.TempDir(), "policy.json")
	s, e := Open(path, d)
	require.NoError(t, e)
	in := s.Snapshot()
	in.MaxHours = 2
	_, e = s.Save(in, "actor", "admin")
	require.NoError(t, e)
	second, e := storage.OpenPostgres(context.Background(), url, namespace)
	require.NoError(t, e)
	defer second.Close()
	takeover, e := Open(filepath.Join(t.TempDir(), "policy.json"), second)
	require.NoError(t, e)
	assert.Equal(t, s.Snapshot(), takeover.Snapshot())
	assert.Equal(t, s.Audit(), takeover.Audit())
}
