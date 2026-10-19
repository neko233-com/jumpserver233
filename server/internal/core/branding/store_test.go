package branding

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"image"
	"image/color"
	"image/jpeg"
	"image/png"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/neko233-com/jumpserver233/server/internal/core/rbac"
	"github.com/neko233-com/jumpserver233/server/internal/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func brandInput(s Settings) Input { return AsInput(s) }
func brandImage(t *testing.T, w, h int, jpg bool) []byte {
	t.Helper()
	im := image.NewNRGBA(image.Rect(0, 0, w, h))
	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			im.Set(x, y, color.NRGBA{50, 200, 150, 255})
		}
	}
	var output bytes.Buffer
	var e error
	if jpg {
		e = jpeg.Encode(&output, im, nil)
	} else {
		e = png.Encode(&output, im)
	}
	require.NoError(t, e)
	return output.Bytes()
}
func brandEnv(t *testing.T) (*Store, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "branding.json")
	s, e := Open(path, nil)
	require.NoError(t, e)
	return s, path
}

func TestBrandingControlledPalettesAndInputs(t *testing.T) {
	assert.NotContains(t, rbac.OrganizationCatalog(), "branding.manage")
	assert.Contains(t, rbac.Catalog(), "branding.manage")
	for _, theme := range Themes() {
		in := brandInput(Defaults())
		in.Theme = theme.ID
		out, e := Prepare(in)
		require.NoError(t, e, theme.ID)
		colors := (Settings{Revision: 1, NameEN: out.NameEN, NameZH: out.NameZH, Theme: out.Theme, Accent: out.Accent}).Public().Colors
		assert.GreaterOrEqual(t, contrast(colors.Accent, colors.Panel), 4.5)
		assert.GreaterOrEqual(t, contrast(colors.Accent, colors.AccentText), 4.5)
	}
	for _, change := range []func(*Input){func(in *Input) { in.NameEN = "" }, func(in *Input) { in.NameEN = "line\nname" }, func(in *Input) { in.NameZH = "\u202ehost" }, func(in *Input) { in.Theme = "custom-css" }, func(in *Input) { in.Accent = "url(https://invalid.example/)" }, func(in *Input) { in.Revision = 0 }} {
		in := brandInput(Defaults())
		change(&in)
		_, e := Prepare(in)
		assert.ErrorIs(t, e, ErrInvalid)
	}
	in := brandInput(Defaults())
	in.Accent = "#0d1117"
	_, e := Prepare(in)
	assert.ErrorIs(t, e, ErrContrast)
	in = brandInput(Defaults())
	in.NameEN = "  Operations Vault  "
	in.NameZH = " 运维平台 "
	in.Accent = "#65D8A1"
	out, e := Prepare(in)
	require.NoError(t, e)
	assert.Equal(t, "Operations Vault", out.NameEN)
	assert.Equal(t, "运维平台", out.NameZH)
	assert.Equal(t, "#65d8a1", out.Accent)
}
func TestBrandingImagesAreBoundedCanonicalRasters(t *testing.T) {
	raw := append(brandImage(t, 32, 16, false), []byte("synthetic-private-metadata")...)
	out, e := PrepareImage(raw, false)
	require.NoError(t, e)
	assert.NotContains(t, string(out), "synthetic-private-metadata")
	cfg, e := png.DecodeConfig(bytes.NewReader(out))
	require.NoError(t, e)
	assert.Equal(t, 32, cfg.Width)
	jpegImage, e := PrepareImage(brandImage(t, 16, 16, true), true)
	require.NoError(t, e)
	assert.True(t, bytes.HasPrefix(jpegImage, []byte("\x89PNG")))
	for _, bad := range [][]byte{[]byte(`<svg onload="alert(1)"></svg>`), []byte("https://invalid.example/logo.png"), bytes.Repeat([]byte("x"), MaxImageBytes+1), brandImage(t, 2049, 1, false), brandImage(t, 1024, 1024, false), []byte("\x89PNG\r\n\x1a\ntruncated")} {
		_, e := PrepareImage(bad, false)
		assert.ErrorIs(t, e, ErrImage)
	}
	_, e = PrepareImage(brandImage(t, 32, 16, false), true)
	assert.ErrorIs(t, e, ErrImage)
}
func TestBrandingRetriesConflictsImagesAndReopening(t *testing.T) {
	s, path := brandEnv(t)
	in := brandInput(s.Snapshot().Settings)
	in.NameEN = "Operations Vault"
	in.NameZH = "运维平台"
	in.Theme = "forest"
	in.Accent = "#65d8a1"
	logo := brandImage(t, 64, 32, false)
	icon := brandImage(t, 16, 16, false)
	in.Logo = &logo
	in.Icon = &icon
	writes := 0
	s.saveHook = func([]byte) error { writes++; return nil }
	out, e := s.Save(in, "admin-id", "admin")
	require.NoError(t, e)
	assert.Equal(t, 2, out.Revision)
	assert.NotEmpty(t, out.LogoDigest)
	assert.NotEmpty(t, out.IconDigest)
	// A lost-response retry with the original revision performs no second write.
	retry, e := s.Save(in, "admin-id", "admin")
	require.NoError(t, e)
	assert.Equal(t, out, retry)
	assert.Equal(t, 1, writes)
	changed := in
	changed.NameEN = "Different"
	_, e = s.Save(changed, "admin-id", "admin")
	assert.ErrorIs(t, e, ErrConflict)
	changed = brandInput(out.Settings)
	changed.Revision++
	_, e = s.Save(changed, "admin-id", "admin")
	assert.ErrorIs(t, e, ErrConflict)
	rows, total, e := s.Audit(0, 10)
	require.NoError(t, e)
	assert.Equal(t, 1, total)
	require.Len(t, rows, 1)
	assert.Equal(t, "admin", rows[0].Actor)
	imageData, ok := s.Image(out.LogoDigest)
	require.True(t, ok)
	imageData[0] = 0
	again, ok := s.Image(out.LogoDigest)
	require.True(t, ok)
	assert.Equal(t, byte(0x89), again[0])
	reopened, e := Open(path, nil)
	require.NoError(t, e)
	assert.Equal(t, out, reopened.Snapshot())
	_, ok = reopened.Image(out.IconDigest)
	assert.True(t, ok)
	public, e := json.Marshal(out)
	require.NoError(t, e)
	assert.NotContains(t, string(public), "actor")
	assert.NotContains(t, string(public), "data:image")
	clear := brandInput(out.Settings)
	empty := []byte{}
	clear.Logo = &empty
	clear.Icon = &empty
	out, e = s.Save(clear, "admin-id", "admin")
	require.NoError(t, e)
	assert.Empty(t, out.LogoDigest)
	_, ok = s.Image(retry.LogoDigest)
	assert.False(t, ok)
	reopened, e = Open(path, nil)
	require.NoError(t, e)
	assert.Equal(t, out, reopened.Snapshot())
	if runtime.GOOS != "windows" {
		info, e := os.Stat(path)
		require.NoError(t, e)
		assert.Equal(t, os.FileMode(0600), info.Mode().Perm())
	}
}
func TestBrandingPersistenceFailureRollsBackAndConcurrentRevisionWinsOnce(t *testing.T) {
	s, path := brandEnv(t)
	in := brandInput(s.Snapshot().Settings)
	in.NameEN = "First"
	first, e := s.Save(in, "admin", "admin")
	require.NoError(t, e)
	disk, e := os.ReadFile(path)
	require.NoError(t, e)
	in = brandInput(first.Settings)
	in.NameEN = "Second"
	s.saveHook = func([]byte) error { return errors.New("synthetic write failure") }
	_, e = s.Save(in, "admin", "admin")
	require.Error(t, e)
	assert.Equal(t, first, s.Snapshot())
	after, e := os.ReadFile(path)
	require.NoError(t, e)
	assert.Equal(t, disk, after)
	s.saveHook = nil
	var wg sync.WaitGroup
	out := make(chan error, 32)
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			local := in
			local.NameEN = fmt.Sprintf("Concurrent %d", i)
			_, e := s.Save(local, "admin", "admin")
			out <- e
		}(i)
	}
	wg.Wait()
	close(out)
	wins, conflicts := 0, 0
	for e := range out {
		if e == nil {
			wins++
		} else {
			require.ErrorIs(t, e, ErrConflict)
			conflicts++
		}
	}
	assert.Equal(t, 1, wins)
	assert.Equal(t, 31, conflicts)
	assert.Equal(t, first.Revision+1, s.Snapshot().Revision)
}
func TestBrandingAuditRetentionAndCorruptionFailClosed(t *testing.T) {
	s, path := brandEnv(t)
	for i := 0; i < 205; i++ {
		in := brandInput(s.Snapshot().Settings)
		in.NameEN = fmt.Sprintf("Revision %d", i)
		_, e := s.Save(in, "admin", "admin")
		require.NoError(t, e)
	}
	rows, total, e := s.Audit(190, 10)
	require.NoError(t, e)
	assert.Equal(t, 200, total)
	assert.Len(t, rows, 10)
	_, _, e = s.Audit(-1, 10)
	assert.ErrorIs(t, e, ErrInvalid)
	reopened, e := Open(path, nil)
	require.NoError(t, e)
	assert.Equal(t, s.Snapshot(), reopened.Snapshot())
	data, e := os.ReadFile(path)
	require.NoError(t, e)
	var stored map[string]any
	require.NoError(t, json.Unmarshal(data, &stored))
	stored["version"] = 99
	data, e = json.Marshal(stored)
	require.NoError(t, e)
	require.NoError(t, os.WriteFile(path, data, 0600))
	_, e = Open(path, nil)
	assert.ErrorIs(t, e, ErrInvalid)
}
func TestBrandingSharedPostgresReopening(t *testing.T) {
	dbURL := os.Getenv("JMS_TEST_DATABASE_URL")
	if dbURL == "" {
		t.Skip("set JMS_TEST_DATABASE_URL for real branding storage")
	}
	docs, e := storage.OpenPostgres(context.Background(), dbURL, fmt.Sprintf("branding-%d", time.Now().UnixNano()))
	require.NoError(t, e)
	t.Cleanup(func() { require.NoError(t, docs.Delete("branding")); require.NoError(t, docs.Close()) })
	path := filepath.Join(t.TempDir(), "branding.json")
	s, e := Open(path, docs)
	require.NoError(t, e)
	in := brandInput(s.Snapshot().Settings)
	in.NameEN = "Shared operations"
	logo := brandImage(t, 16, 16, false)
	in.Logo = &logo
	saved, e := s.Save(in, "admin", "admin")
	require.NoError(t, e)
	_, e = os.Stat(path)
	assert.True(t, os.IsNotExist(e))
	next, e := Open(filepath.Join(t.TempDir(), "branding.json"), docs)
	require.NoError(t, e)
	assert.Equal(t, saved, next.Snapshot())
	imageData, ok := next.Image(saved.LogoDigest)
	require.True(t, ok)
	assert.NotEmpty(t, imageData)
	retry, e := next.Save(in, "admin", "admin")
	require.NoError(t, e)
	assert.Equal(t, saved, retry)
	_, total, e := next.Audit(0, 10)
	require.NoError(t, e)
	assert.Equal(t, 1, total)
}
func TestBrandingUncertainSharedWriteReconcilesOriginalActor(t *testing.T) {
	dbURL := os.Getenv("JMS_TEST_DATABASE_URL")
	if dbURL == "" {
		t.Skip("set JMS_TEST_DATABASE_URL for real branding storage")
	}
	namespace := fmt.Sprintf("branding-ack-%d", time.Now().UnixNano())
	docs, e := storage.OpenPostgres(context.Background(), dbURL, namespace)
	require.NoError(t, e)
	path := filepath.Join(t.TempDir(), "branding.json")
	s, e := Open(path, docs)
	require.NoError(t, e)
	in := AsInput(s.Snapshot().Settings)
	in.NameEN = "Committed before acknowledgement"
	writer, e := Open(path, docs)
	require.NoError(t, e)
	committed, e := writer.Save(in, "original-id", "original-actor")
	require.NoError(t, e)
	require.NoError(t, docs.Close())
	_, e = s.Save(in, "retry-id", "retry-actor")
	require.Error(t, e)
	require.Error(t, s.Refresh())
	reconnected, e := storage.OpenPostgres(context.Background(), dbURL, namespace)
	require.NoError(t, e)
	t.Cleanup(func() { require.NoError(t, reconnected.Delete("branding")); require.NoError(t, reconnected.Close()) })
	s.docs = reconnected
	retried, e := s.Save(in, "retry-id", "retry-actor")
	require.NoError(t, e)
	assert.Equal(t, committed, retried)
	rows, total, e := s.Audit(0, 10)
	require.NoError(t, e)
	require.Equal(t, 1, total)
	assert.Equal(t, "original-actor", rows[0].Actor)
}
func TestBrandingCompleteAppearanceFieldsAndSafeRegistration(t *testing.T) {
	s, path := brandEnv(t)
	in := AsInput(Defaults())
	in.NameEN = "Operations"
	in.LoginTitleEN = "Welcome to operations"
	in.LoginTitleZH = "欢迎进入运维平台"
	in.FooterEN = "Operations access"
	in.FooterZH = "运维访问入口"
	in.RegistrationLabel = "QA registration"
	in.RegistrationURL = "https://registration.example.invalid/entry"
	in.Theme = "crimson"
	in.Accent = "#ff8a93"
	mark := brandImage(t, 32, 32, false)
	illustration := brandImage(t, 1024, 1024, false)
	in.Mark = &mark
	in.LoginImage = &illustration
	out, e := s.Save(in, "admin", "admin")
	require.NoError(t, e)
	assert.Equal(t, in.FooterZH, out.FooterZH)
	assert.Equal(t, in.LoginTitleEN, out.LoginTitleEN)
	assert.NotEmpty(t, out.MarkDigest)
	assert.NotEmpty(t, out.LoginDigest)
	opened, e := Open(path, nil)
	require.NoError(t, e)
	assert.Equal(t, out, opened.Snapshot())
	for _, digest := range []string{out.MarkDigest, out.LoginDigest} {
		data, ok := opened.Image(digest)
		require.True(t, ok)
		_, e := png.Decode(bytes.NewReader(data))
		require.NoError(t, e)
	}
	for _, target := range []string{"javascript:alert(1)", "http://registration.example.invalid/", "https://user:synthetic-password@registration.example.invalid/"} {
		bad := AsInput(out.Settings)
		bad.RegistrationURL = target
		_, e := opened.Save(bad, "admin", "admin")
		assert.ErrorIs(t, e, ErrInvalid)
	}
	clear := AsInput(out.Settings)
	empty := []byte{}
	clear.Mark = &empty
	clear.LoginImage = &empty
	cleared, e := opened.Save(clear, "admin", "admin")
	require.NoError(t, e)
	assert.Empty(t, cleared.MarkDigest)
	assert.Empty(t, cleared.LoginDigest)
	_, ok := opened.Image(out.LoginDigest)
	assert.False(t, ok)
}
