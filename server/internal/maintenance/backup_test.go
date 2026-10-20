package maintenance

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/neko233-com/jumpserver233/server/internal/connector/aichat"
	"github.com/neko233-com/jumpserver233/server/internal/core/assets"
	"github.com/neko233-com/jumpserver233/server/internal/core/assistant"
	"github.com/neko233-com/jumpserver233/server/internal/core/auth"
	"github.com/neko233-com/jumpserver233/server/internal/core/labels"
	"github.com/neko233-com/jumpserver233/server/testsupport/enterpriseprovider"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var testPassword = []byte("synthetic-backup-passphrase-233")

func fixture(t *testing.T) Options {
	t.Helper()
	parent := t.TempDir()
	data := filepath.Join(parent, "data")
	require.NoError(t, RecordMode(data, false))
	key := bytes.Repeat([]byte{37}, 32)
	require.NoError(t, os.WriteFile(filepath.Join(data, "vault.key"), key, 0600))
	require.NoError(t, RecordVaultKey(data, key))
	require.NoError(t, os.MkdirAll(filepath.Join(data, "organizations", "org-test", "recordings"), 0700))
	require.NoError(t, os.WriteFile(filepath.Join(data, "organizations", "org-test", "recordings", "replay.json.gz"), []byte("synthetic-encrypted-recording"), 0600))
	require.NoError(t, os.WriteFile(filepath.Join(data, "audit.jsonl"), []byte("synthetic-encrypted-audit"), 0600))
	return Options{DataDir: data, File: filepath.Join(parent, "backup.jmsbackup"), Version: "v0.1.0-test", Passphrase: testPassword}
}
func TestBackupPreservesIdentityVaultCiphertextOrganizationsAndAudit(t *testing.T) {
	opt := fixture(t)
	key, e := os.ReadFile(filepath.Join(opt.DataDir, "vault.key"))
	require.NoError(t, e)
	store, e := assets.OpenStore(filepath.Join(opt.DataDir, "assets.json"), key)
	require.NoError(t, e)
	_, e = store.Create(assets.Asset{ID: "asset-backup", Name: "SSH backup fixture", Host: "192.0.2.20", Port: 22, Username: "ops"}, "synthetic-remote-password")
	require.NoError(t, e)
	identity, e := auth.OpenServiceWithVaultKey(filepath.Join(opt.DataDir, "users.json"), key)
	require.NoError(t, e)
	user, e := identity.Bootstrap("backup.admin", "synthetic-admin-password-233")
	require.NoError(t, e)
	labelStore, e := labels.Open(filepath.Join(opt.DataDir, "labels.json"), key, nil)
	require.NoError(t, e)
	labelInput := labels.Input{Name: "Recovery", Value: "preserved", RequestID: "backup-label-001"}
	label, e := labelStore.Save("", user.ID, labelInput)
	require.NoError(t, e)
	labelResource := labels.Resource{Type: "asset", ID: "asset-backup"}
	labelBindingInput := labels.BindingInput{LabelIDs: []string{label.ID}, RequestID: "backup-bind-001"}
	labelBinding, e := labelStore.Bind(labelResource, user.ID, labelBindingInput)
	require.NoError(t, e)
	labelStore.Close()
	labelBytes, e := os.ReadFile(filepath.Join(opt.DataDir, "labels.json"))
	require.NoError(t, e)
	assistantProvider, e := enterpriseprovider.New()
	require.NoError(t, e)
	defer assistantProvider.Close()
	assistantStore, e := assistant.Open(filepath.Join(opt.DataDir, "assistant.json"), key, nil)
	require.NoError(t, e)
	assistantSecret := enterpriseprovider.AssistantSecret
	_, e = assistantStore.SaveSettings(user.ID, assistant.SettingsInput{Settings: aichat.Settings{Endpoint: assistantProvider.TLS.URL + "/v1/chat/completions", Model: "synthetic-assistant-model", RootCAPEM: assistantProvider.CAPEM, MaxTokens: 512}, Enabled: true, Secret: &assistantSecret, RequestID: "backup-assistant-settings"})
	require.NoError(t, e)
	assistantInput := assistant.Input{Message: "Explain pwd", Locale: "en", Consent: true, RequestID: "backup-assistant-question"}
	assistantResult, e := assistantStore.Submit(t.Context(), user.ID, assistantInput, func(context.Context) error { return nil })
	require.NoError(t, e)
	require.Equal(t, "completed", assistantResult.Turn.Status)
	assistantStore.Close()
	assistantBytes, e := os.ReadFile(filepath.Join(opt.DataDir, "assistant.json"))
	require.NoError(t, e)
	original, e := os.ReadFile(filepath.Join(opt.DataDir, "assets.json"))
	require.NoError(t, e)
	created, e := Create(context.Background(), opt)
	require.NoError(t, e)
	assert.Greater(t, created.Files, 4)
	assert.Len(t, created.ArchiveSHA256, 64)
	raw, e := os.ReadFile(opt.File)
	require.NoError(t, e)
	assert.NotContains(t, string(raw), "synthetic-remote-password")
	assert.NotContains(t, string(raw), "synthetic-admin-password-233")
	assert.NotContains(t, string(raw), "replay.json.gz")
	assert.NotContains(t, string(raw), string(key))
	verified, e := Verify(context.Background(), opt)
	require.NoError(t, e)
	assert.Equal(t, created, verified)
	opt.DataDir = filepath.Join(filepath.Dir(opt.DataDir), "restored")
	restored, e := Restore(context.Background(), opt)
	require.NoError(t, e)
	assert.Equal(t, created.BackupID, restored.BackupID)
	copy, e := os.ReadFile(filepath.Join(opt.DataDir, "assets.json"))
	require.NoError(t, e)
	assert.Equal(t, original, copy)
	key2, e := assets.LoadOrCreateVaultKey(opt.DataDir, "")
	require.NoError(t, e)
	assert.Equal(t, key, key2)
	assistantCopy, e := os.ReadFile(filepath.Join(opt.DataDir, "assistant.json"))
	require.NoError(t, e)
	assert.Equal(t, assistantBytes, assistantCopy)
	assistantRecovered, e := assistant.Open(filepath.Join(opt.DataDir, "assistant.json"), key2, nil)
	require.NoError(t, e)
	assistantReplay, e := assistantRecovered.Submit(t.Context(), user.ID, assistantInput, func(context.Context) error { return nil })
	require.NoError(t, e)
	assert.Equal(t, assistantResult, assistantReplay)
	assert.EqualValues(t, 1, assistantProvider.AssistantCalls.Load())
	assistantRecovered.Close()
	labelCopy, e := os.ReadFile(filepath.Join(opt.DataDir, "labels.json"))
	require.NoError(t, e)
	assert.Equal(t, labelBytes, labelCopy)
	labelRecovered, e := labels.Open(filepath.Join(opt.DataDir, "labels.json"), key2, nil)
	require.NoError(t, e)
	replayedLabel, e := labelRecovered.Save("", user.ID, labelInput)
	require.NoError(t, e)
	assert.Equal(t, label, replayedLabel)
	replayedBinding, e := labelRecovered.Bind(labelResource, user.ID, labelBindingInput)
	require.NoError(t, e)
	assert.Equal(t, labelBinding, replayedBinding)
	labelRecovered.Close()
	reopened, e := assets.OpenStore(filepath.Join(opt.DataDir, "assets.json"), key2)
	require.NoError(t, e)
	password, e := reopened.Password("asset-backup")
	require.NoError(t, e)
	assert.Equal(t, "synthetic-remote-password", password)
	users, e := auth.OpenServiceWithVaultKey(filepath.Join(opt.DataDir, "users.json"), key2)
	require.NoError(t, e)
	login, e := users.Authenticate("backup.admin", "synthetic-admin-password-233")
	require.NoError(t, e)
	assert.Equal(t, user.ID, login.User.ID)
	require.FileExists(t, filepath.Join(opt.DataDir, "organizations", "org-test", "recordings", "replay.json.gz"))
	require.FileExists(t, filepath.Join(opt.DataDir, "audit.jsonl"))
	// A network retry must not overwrite new data written since the first import.
	require.NoError(t, os.WriteFile(filepath.Join(opt.DataDir, "new-after-restore"), []byte("preserve-new-data"), 0600))
	again, e := Restore(context.Background(), opt)
	require.NoError(t, e)
	assert.True(t, again.Unchanged)
	require.FileExists(t, filepath.Join(opt.DataDir, "new-after-restore"))
	opt.Replace = true
	again, e = Restore(context.Background(), opt)
	require.NoError(t, e)
	assert.True(t, again.Unchanged)
	assert.NoFileExists(t, journalPath(opt.DataDir))
	assert.NoFileExists(t, filepath.Join(opt.DataDir, manifestName))
}
func TestBackupReplacementPreservesCompletePreviousData(t *testing.T) {
	opt := fixture(t)
	_, e := Create(context.Background(), opt)
	require.NoError(t, e)
	target := filepath.Join(filepath.Dir(opt.DataDir), "target")
	require.NoError(t, os.Mkdir(target, 0700))
	sentinel := filepath.Join(target, "existing")
	require.NoError(t, os.WriteFile(sentinel, []byte("keep-entire-old-state"), 0600))
	opt.DataDir = target
	_, e = Restore(context.Background(), opt)
	assert.ErrorIs(t, e, ErrConflict)
	assert.FileExists(t, sentinel)
	opt.Replace = true
	restored, e := Restore(context.Background(), opt)
	require.NoError(t, e)
	assert.NotEmpty(t, restored.PreviousDataDir)
	b, e := os.ReadFile(filepath.Join(restored.PreviousDataDir, "existing"))
	require.NoError(t, e)
	assert.Equal(t, "keep-entire-old-state", string(b))
	assert.NoFileExists(t, sentinel)
	again, e := Restore(context.Background(), opt)
	require.NoError(t, e)
	assert.True(t, again.Unchanged)
	require.FileExists(t, filepath.Join(restored.PreviousDataDir, "existing"))
}
func TestBackupExternalKeyIsWrappedAndWrongKeyNeverExports(t *testing.T) {
	opt := fixture(t)
	key, e := os.ReadFile(filepath.Join(opt.DataDir, "vault.key"))
	require.NoError(t, e)
	opt.ExternalVaultKey = base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{9}, 32))
	_, e = Create(context.Background(), opt)
	assert.ErrorIs(t, e, ErrInvalid)
	assert.NoFileExists(t, opt.File)
	opt.ExternalVaultKey = base64.StdEncoding.EncodeToString(key)
	require.NoError(t, os.Remove(filepath.Join(opt.DataDir, "vault.key")))
	result, e := Create(context.Background(), opt)
	require.NoError(t, e)
	assert.True(t, result.ExternalKeyIncluded)
	opt.DataDir = filepath.Join(filepath.Dir(opt.DataDir), "external-key-restored")
	_, e = Restore(context.Background(), opt)
	require.NoError(t, e)
	restored, e := os.ReadFile(filepath.Join(opt.DataDir, "vault.key"))
	require.NoError(t, e)
	assert.Equal(t, key, restored)
}
func TestBackupUsesExclusiveStoppedStateAndRejectsCluster(t *testing.T) {
	opt := fixture(t)
	lock, e := Acquire(opt.DataDir)
	require.NoError(t, e)
	_, e = Create(context.Background(), opt)
	assert.ErrorIs(t, e, ErrBusy)
	_, e = Restore(context.Background(), opt)
	assert.ErrorIs(t, e, ErrBusy)
	require.NoError(t, lock.Close())
	require.NoError(t, lock.Close())
	require.NoError(t, RecordMode(opt.DataDir, true))
	_, e = Create(context.Background(), opt)
	assert.ErrorIs(t, e, ErrCluster)
	assert.ErrorIs(t, RecordMode(opt.DataDir, false), ErrCluster)
}
func TestBackupRejectsSymlinksAliasesAndExistingOutputs(t *testing.T) {
	opt := fixture(t)
	insideOpt := opt
	insideOpt.File = filepath.Join(opt.DataDir, "bad-backup")
	_, e := Create(context.Background(), insideOpt)
	assert.ErrorIs(t, e, ErrInvalid)
	require.NoError(t, os.WriteFile(opt.File, []byte("existing-output"), 0600))
	_, e = Create(context.Background(), opt)
	assert.ErrorIs(t, e, os.ErrExist)
	b, e := os.ReadFile(opt.File)
	require.NoError(t, e)
	assert.Equal(t, "existing-output", string(b))
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation may require Windows developer mode")
	}
	opt.File += ".new"
	outside := filepath.Join(filepath.Dir(opt.DataDir), "outside")
	require.NoError(t, os.WriteFile(outside, []byte("outside-secret"), 0600))
	require.NoError(t, os.Symlink(outside, filepath.Join(opt.DataDir, "link")))
	_, e = Create(context.Background(), opt)
	assert.ErrorIs(t, e, ErrInvalid)
	assert.NoFileExists(t, opt.File)
}
func TestBackupEncryptionRejectsTamperTruncationReplayAndAppend(t *testing.T) {
	payload := make([]byte, chunkSize*2+501)
	_, e := rand.Read(payload)
	require.NoError(t, e)
	var output bytes.Buffer
	writer, e := newEncryptedWriter(&output, testPassword)
	require.NoError(t, e)
	_, e = writer.Write(payload)
	require.NoError(t, e)
	require.NoError(t, writer.Close())
	original := append([]byte{}, output.Bytes()...)
	reader, e := newEncryptedReader(bytes.NewReader(original), testPassword)
	require.NoError(t, e)
	got, e := io.ReadAll(reader)
	require.NoError(t, e)
	assert.Equal(t, payload, got)
	for _, kind := range []string{"header", "ciphertext", "final", "truncate-header", "truncate-data", "truncate-final", "append", "replay", "reorder"} {
		t.Run(kind, func(t *testing.T) {
			raw := append([]byte{}, original...)
			frame := 4 + chunkSize + 16
			switch kind {
			case "header":
				raw[len(magic)] ^= 1
			case "ciphertext":
				raw[headerSize+17] ^= 1
			case "final":
				raw[len(raw)-1] ^= 1
			case "truncate-header":
				raw = raw[:headerSize-1]
			case "truncate-data":
				raw = raw[:headerSize+frame-3]
			case "truncate-final":
				raw = raw[:len(raw)-20]
			case "append":
				raw = append(raw, 1)
			case "replay":
				copy(raw[headerSize+frame:headerSize+2*frame], raw[headerSize:headerSize+frame])
			case "reorder":
				first := append([]byte{}, raw[headerSize:headerSize+frame]...)
				copy(raw[headerSize:headerSize+frame], raw[headerSize+frame:headerSize+2*frame])
				copy(raw[headerSize+frame:headerSize+2*frame], first)
			}
			r, e := newEncryptedReader(bytes.NewReader(raw), testPassword)
			if e == nil {
				_, e = io.ReadAll(r)
			}
			assert.ErrorIs(t, e, ErrIntegrity)
		})
	}
}

type forgedEntry struct {
	Header tar.Header
	Body   []byte
}

func forgeArchive(t *testing.T, file string, entries []forgedEntry, m manifest, extra ...[]byte) {
	t.Helper()
	f, e := os.Create(file)
	require.NoError(t, e)
	w, e := newEncryptedWriter(f, testPassword)
	require.NoError(t, e)
	z := gzip.NewWriter(w)
	tarball := tar.NewWriter(z)
	for _, item := range entries {
		h := item.Header
		h.Size = int64(len(item.Body))
		require.NoError(t, tarball.WriteHeader(&h))
		if len(item.Body) > 0 {
			_, e = tarball.Write(item.Body)
			require.NoError(t, e)
		}
	}
	body, e := json.Marshal(m)
	require.NoError(t, e)
	require.NoError(t, tarball.WriteHeader(&tar.Header{Name: manifestName, Mode: 0600, Size: int64(len(body)), Typeflag: tar.TypeReg}))
	_, e = tarball.Write(body)
	require.NoError(t, e)
	require.NoError(t, tarball.Close())
	require.NoError(t, z.Close())
	for _, body := range extra {
		_, e = w.Write(body)
		require.NoError(t, e)
	}
	require.NoError(t, w.Close())
	require.NoError(t, f.Close())
}
func TestBackupImportPreflightRejectsUnsafeNamesVersionsAndManifest(t *testing.T) {
	for _, kind := range []string{"../escape", "/absolute", "C:stream", "dir\\escape", "CON", "a/../../b", "trailing.", "symlink", "hardlink", "duplicate-case", "missing-parent"} {
		t.Run(kind, func(t *testing.T) {
			opt := fixture(t)
			file := opt.File
			opt.DataDir = filepath.Join(filepath.Dir(opt.DataDir), "existing-target")
			require.NoError(t, os.Mkdir(opt.DataDir, 0700))
			require.NoError(t, os.WriteFile(filepath.Join(opt.DataDir, "sentinel"), []byte("unchanged"), 0600))
			opt.Replace = true
			m := manifest{Format: 1, Result: Result{BackupID: strings.Repeat("a", 32), Version: "v0.1", CreatedAt: time.Now().UTC()}, Entries: []entry{}}
			name := kind
			typ := byte(tar.TypeReg)
			link := ""
			switch kind {
			case "symlink":
				name = "link"
				typ = tar.TypeSymlink
				link = "../outside"
			case "hardlink":
				name = "hard"
				typ = tar.TypeLink
				link = "outside"
			case "missing-parent":
				name = "parent/file"
			case "duplicate-case":
				name = "Same"
			}
			data := []byte("data")
			if typ != tar.TypeReg {
				data = nil
			}
			records := []forgedEntry{{Header: tar.Header{Name: name, Mode: 0600, Typeflag: typ, Linkname: link}, Body: data}}
			if kind == "duplicate-case" {
				records = append(records, forgedEntry{Header: tar.Header{Name: "same", Mode: 0600, Typeflag: tar.TypeReg}, Body: data})
			}
			forgeArchive(t, file, records, m)
			_, e := Verify(context.Background(), opt)
			assert.Error(t, e)
			_, e = Restore(context.Background(), opt)
			assert.Error(t, e)
			b, e := os.ReadFile(filepath.Join(opt.DataDir, "sentinel"))
			require.NoError(t, e)
			assert.Equal(t, "unchanged", string(b))
			assert.NoFileExists(t, journalPath(opt.DataDir))
			matches, e := filepath.Glob(filepath.Join(controlDir(opt.DataDir), "stage-*"))
			require.NoError(t, e)
			assert.Empty(t, matches)
		})
	}
}
func TestBackupWrongPasswordCancellationAndEmptyDirectoryRestore(t *testing.T) {
	opt := fixture(t)
	_, e := Create(context.Background(), opt)
	require.NoError(t, e)
	good := opt.Passphrase
	opt.Passphrase = []byte("synthetic-wrong-password-233")
	_, e = Verify(context.Background(), opt)
	assert.ErrorIs(t, e, ErrIntegrity)
	opt.DataDir = filepath.Join(filepath.Dir(opt.DataDir), "empty")
	require.NoError(t, os.Mkdir(opt.DataDir, 0700))
	_, e = Restore(context.Background(), opt)
	assert.ErrorIs(t, e, ErrIntegrity)
	entries, e := topEntries(opt.DataDir)
	require.NoError(t, e)
	assert.Empty(t, entries)
	opt.Passphrase = good
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, e = Restore(ctx, opt)
	assert.ErrorIs(t, e, context.Canceled)
	entries, e = topEntries(opt.DataDir)
	require.NoError(t, e)
	assert.Empty(t, entries)
	_, e = Restore(context.Background(), opt)
	require.NoError(t, e)
	require.FileExists(t, filepath.Join(opt.DataDir, "vault.key"))
}

func TestBackupValidEnvelopeRejectsFutureFormatHashKeyAndCompressedTrailingData(t *testing.T) {
	for _, kind := range []string{"future-format", "entry-hash", "missing-key", "key-mismatch", "gzip-trailing", "entry-count", "control-case", "receipt-case", "manifest-case"} {
		t.Run(kind, func(t *testing.T) {
			opt := fixture(t)
			_, e := Create(context.Background(), opt)
			require.NoError(t, e)
			m, _, e := readArchive(context.Background(), opt, nil)
			require.NoError(t, e)
			m.Result.ArchiveSHA256 = ""
			entries := []forgedEntry{}
			kept := []entry{}
			for _, item := range m.Entries {
				if item.Name == "vault.key" && kind == "missing-key" {
					m.Result.Files--
					m.Result.Bytes -= item.Size
					continue
				}
				h := tar.Header{Name: item.Name, Mode: item.Mode, Typeflag: tar.TypeReg}
				var body []byte
				if item.Directory {
					h.Typeflag = tar.TypeDir
				} else {
					body, e = os.ReadFile(filepath.Join(opt.DataDir, filepath.FromSlash(item.Name)))
					require.NoError(t, e)
				}
				if item.Name == "vault.key" && kind == "key-mismatch" {
					body = bytes.Repeat([]byte{90}, 32)
					sum := sha256.Sum256(body)
					item.SHA256 = hex.EncodeToString(sum[:])
				}
				entries = append(entries, forgedEntry{Header: h, Body: body})
				kept = append(kept, item)
			}
			m.Entries = kept
			switch kind {
			case "future-format":
				m.Format = 2
			case "entry-hash":
				m.Entries[0].SHA256 = strings.Repeat("0", 64)
			case "entry-count":
				m.Result.Files++
			case "control-case", "receipt-case", "manifest-case":
				name := strings.ToUpper(receiptName)
				if kind == "manifest-case" {
					name = strings.ToUpper(manifestName)
				} else if kind == "control-case" {
					name = strings.ToUpper(controlName)
					entries = append(entries, forgedEntry{Header: tar.Header{Name: name, Mode: 0700, Typeflag: tar.TypeDir}})
					m.Entries = append(m.Entries, entry{Name: name, Mode: 0700, Directory: true})
					name += "/lock"
				}
				body := []byte("reserved-case-alias")
				sum := sha256.Sum256(body)
				entries = append(entries, forgedEntry{Header: tar.Header{Name: name, Mode: 0600, Typeflag: tar.TypeReg}, Body: body})
				m.Entries = append(m.Entries, entry{Name: name, Mode: 0600, Size: int64(len(body)), SHA256: hex.EncodeToString(sum[:])})
				m.Result.Files++
				m.Result.Bytes += int64(len(body))
			}
			bad := opt.File + ".bad"
			var extra [][]byte
			if kind == "gzip-trailing" {
				extra = append(extra, []byte("unconsumed-plaintext"))
			}
			forgeArchive(t, bad, entries, m, extra...)
			opt.File = bad
			_, e = Verify(context.Background(), opt)
			require.ErrorIs(t, e, ErrIntegrity)
			opt.DataDir = filepath.Join(filepath.Dir(opt.DataDir), "preserved")
			require.NoError(t, os.Mkdir(opt.DataDir, 0700))
			require.NoError(t, os.WriteFile(filepath.Join(opt.DataDir, "keep"), []byte("original"), 0600))
			opt.Replace = true
			_, e = Restore(context.Background(), opt)
			assert.Error(t, e)
			require.FileExists(t, filepath.Join(opt.DataDir, "keep"))
			assert.NoFileExists(t, journalPath(opt.DataDir))
		})
	}
}

func TestBackupControlNamespaceCaseAliasIsPortable(t *testing.T) {
	opt := fixture(t)
	alias := strings.ToUpper(controlName)
	require.NoError(t, os.MkdirAll(filepath.Join(opt.DataDir, alias), 0700))
	lock, e := Acquire(opt.DataDir)
	require.NoError(t, e)
	dataDir := lock.DataDir
	require.NoError(t, lock.Close())
	_, e = Create(context.Background(), opt)
	if actualControl(dataDir, alias) {
		require.NoError(t, e)
		_, e = Verify(context.Background(), opt)
		require.NoError(t, e)
	} else {
		require.ErrorIs(t, e, ErrInvalid)
	}
	assert.False(t, validTopList([]string{alias}))
	assert.False(t, validTopList([]string{"safe", alias}))
}

func TestBackupReservedNamesUseUnicodeCaseFolding(t *testing.T) {
	for _, name := range []string{strings.ToUpper(controlName), ".jmſ233-maintenance/lock", ".jmſ233-restore-receipt.json", ".jmſ233-backup-manifest.json"} {
		assert.True(t, reserved(name), name)
	}
	assert.False(t, reserved("organizations/customer/receipt.json"))
}

func TestBackupSameIDWithDifferentManifestCannotReplaceAppliedData(t *testing.T) {
	opt := fixture(t)
	source := opt.DataDir
	_, e := Create(context.Background(), opt)
	require.NoError(t, e)
	m, _, e := readArchive(context.Background(), opt, nil)
	require.NoError(t, e)
	m.Result.ArchiveSHA256 = ""
	m.Result.Version = "same-id-different-manifest"
	entries := []forgedEntry{}
	for _, item := range m.Entries {
		header := tar.Header{Name: item.Name, Mode: item.Mode, Typeflag: tar.TypeReg}
		var body []byte
		if item.Directory {
			header.Typeflag = tar.TypeDir
		} else {
			body, e = os.ReadFile(filepath.Join(source, filepath.FromSlash(item.Name)))
			require.NoError(t, e)
		}
		entries = append(entries, forgedEntry{Header: header, Body: body})
	}
	changed := opt.File + ".changed"
	forgeArchive(t, changed, entries, m)
	check := opt
	check.File = changed
	_, e = Verify(context.Background(), check)
	require.NoError(t, e, "the alternate archive must be structurally valid")
	opt.DataDir = filepath.Join(filepath.Dir(source), "target")
	_, e = Restore(context.Background(), opt)
	require.NoError(t, e)
	require.NoError(t, os.WriteFile(filepath.Join(opt.DataDir, "after-import"), []byte("retain-new-data"), 0600))
	opt.File = changed
	opt.Replace = true
	_, e = Restore(context.Background(), opt)
	assert.ErrorIs(t, e, ErrConflict)
	assert.FileExists(t, filepath.Join(opt.DataDir, "after-import"))
	assert.NoFileExists(t, journalPath(opt.DataDir))
}
