package recorder

import (
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"os"
	"path/filepath"
	"testing"
)

func TestDesktopEncryptionTamperAndMetadataBinding(t *testing.T) {
	root := t.TempDir()
	r, e := NewDesktop(root, "session", make([]byte, 32))
	require.NoError(t, e)
	frame := DesktopFrame{Index: 0, AtMS: 123, Sequence: 1, Width: 1280, Height: 720}
	png := []byte("synthetic PNG payload")
	require.NoError(t, r.Record(frame, png))
	raw, e := os.ReadFile(filepath.Join(root, "000000.png.enc"))
	require.NoError(t, e)
	assert.NotContains(t, string(raw), string(png))
	decoded, e := r.Read(frame)
	require.NoError(t, e)
	assert.Equal(t, png, decoded)
	altered := frame
	altered.AtMS++
	_, e = r.Read(altered)
	assert.Error(t, e)
	wrong, e := NewDesktop(root, "other", make([]byte, 32))
	require.NoError(t, e)
	_, e = wrong.Read(frame)
	assert.Error(t, e)
	raw[len(raw)-1] ^= 1
	require.NoError(t, os.WriteFile(filepath.Join(root, "000000.png.enc"), raw, 0600))
	_, e = r.Read(frame)
	assert.Error(t, e)
	assert.Error(t, r.Record(frame, png))
	assert.Error(t, r.Record(DesktopFrame{Index: MaxDesktopFrames}, png))
	_, e = r.Read(DesktopFrame{Index: -1})
	assert.Error(t, e)
}
