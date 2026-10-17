package assets

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/neko233-com/jumpserver233/server/internal/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func importActor() AccountActor { return AccountActor{ID: "import-owner", Name: "Importer"} }
func importRow(parent, username string, line int) AccountImportRow {
	return AccountImportRow{Line: line, AssetID: parent, Action: "create", Input: AccountInput{Username: username, Password: "synthetic-import-password"}}
}

func TestAccountImportBoundsCapacityCancellationAndCorruptReceipts(t *testing.T) {
	s, st, parent, _ := newRotationServiceTest(t)
	rows := []AccountImportRow{importRow(parent.ID, "capacity-user", 2)}
	p, e := s.PreviewAccountImport(context.Background(), rows, importActor(), "default", "capacity-import")
	require.NoError(t, e)
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	_, e = s.CommitAccountImport(cancelled, rows, importActor(), "default", "capacity-import", p.Token)
	require.Error(t, e)
	assert.Len(t, st.List(), 1)
	require.Empty(t, s.AccountImportReceipts(""))
	for i := range maxAccountImportReceipts {
		st.imports = append(st.imports, accountImportRecord{AccountImportReceipt: AccountImportReceipt{RequestID: fmt.Sprintf("occupied-%d", i), Actor: importActor(), CreatedAt: time.Now().UTC()}})
	}
	full, e := s.PreviewAccountImport(context.Background(), rows, importActor(), "default", "capacity-import")
	require.NoError(t, e)
	assert.Empty(t, full.Token)
	require.NotEmpty(t, full.Issues)
	_, e = s.CommitAccountImport(context.Background(), rows, importActor(), "default", "capacity-import", p.Token)
	assert.ErrorIs(t, e, ErrAccountImportCapacity)
	for i := range st.imports {
		st.imports[i].CreatedAt = time.Now().Add(-25 * time.Hour)
	}
	receipt, e := s.CommitAccountImport(context.Background(), rows, importActor(), "default", "capacity-import", p.Token)
	require.NoError(t, e)
	require.Len(t, st.imports, 1)
	assert.Equal(t, receipt, st.imports[0].AccountImportReceipt)
	require.NoError(t, validateImportRecords(st.imports))
	st.imports[0].InputDigest = strings.Repeat("g", 64)
	assert.Error(t, validateImportRecords(st.imports))
	var csvRows bytes.Buffer
	w := csv.NewWriter(&csvRows)
	require.NoError(t, w.Write([]string{"action", "asset_id", "username"}))
	for range MaxAccountImportRows {
		require.NoError(t, w.Write([]string{"create", "host", "user"}))
	}
	w.Flush()
	parsed, issues := ParseAccountImport("csv", csvRows.Bytes())
	require.Empty(t, issues)
	require.Len(t, parsed, 500)
	_, issues = ParseAccountImport("csv", append(csvRows.Bytes(), []byte("create,host,overflow\n")...))
	require.Len(t, issues, 1)
	assert.Equal(t, "row_limit", issues[0].Code)
	_, issues = ParseAccountImport("csv", make([]byte, MaxAccountImportBytes+1))
	assert.Equal(t, "file_size", issues[0].Code)
}

func TestAccountImportXLSXRejectsDocumentDirectivesAndUnusedExternalRelationships(t *testing.T) {
	original, e := AccountImportTemplate("xlsx")
	require.NoError(t, e)
	for _, kind := range []string{"directive", "unused-external", "sparse-rows", "extra-column"} {
		t.Run(kind, func(t *testing.T) {
			reader, e := zip.NewReader(bytes.NewReader(original), int64(len(original)))
			require.NoError(t, e)
			var out bytes.Buffer
			z := zip.NewWriter(&out)
			for _, f := range reader.File {
				r, e := f.Open()
				require.NoError(t, e)
				data, e := io.ReadAll(r)
				require.NoError(t, e)
				r.Close()
				if f.Name == "xl/worksheets/sheet1.xml" {
					switch kind {
					case "directive":
						data = bytes.Replace(data, []byte("?><worksheet"), []byte("?><!DOCTYPE x [<!ENTITY sample 'unsafe'>]><worksheet"), 1)
					case "sparse-rows":
						data = bytes.Replace(data, []byte("</sheetData>"), []byte(`<row r="1000"><c r="A1000" t="inlineStr"><is><t></t></is></c></row></sheetData>`), 1)
					case "extra-column":
						data = bytes.Replace(data, []byte(`r="M2"`), []byte(`r="N2"`), 1)
					}
				}
				entry, e := z.Create(f.Name)
				require.NoError(t, e)
				_, e = entry.Write(data)
				require.NoError(t, e)
			}
			if kind == "unused-external" {
				entry, e := z.Create("xl/worksheets/_rels/sheet1.xml.rels")
				require.NoError(t, e)
				_, e = entry.Write([]byte(`<Relationships><Relationship Id="rId9" TargetMode="External" Target="https://example.invalid"/></Relationships>`))
				require.NoError(t, e)
			}
			require.NoError(t, z.Close())
			rows, issues := ParseAccountImport("xlsx", out.Bytes())
			if kind == "sparse-rows" {
				require.Empty(t, issues)
				require.Len(t, rows, 1)
			} else {
				require.NotEmpty(t, issues)
			}
		})
	}
}
func TestAccountImportAtomicMixedCredentialsAuditAndVersionedReload(t *testing.T) {
	s, st, parent, path := newRotationServiceTest(t)
	ctx := context.Background()
	actor := importActor()
	second, e := st.Create(Asset{ID: "second-host", Name: "Second", Host: "192.0.2.99", Port: 22, Username: "primary", HostKeyFingerprint: "SHA256:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"}, "synthetic-second-password")
	require.NoError(t, e)
	key, _, e := generateSSHKey()
	require.NoError(t, e)
	rows := []AccountImportRow{importRow(parent.ID, "csv-user", 2), importRow(second.ID, "key-user", 3), {Line: 4, AssetID: parent.ID, Action: "update", Input: AccountInput{Username: parent.Username, Name: ptrImport("Updated primary")}}}
	rows[1].Input = AccountInput{Username: "key-user", CredentialType: CredentialSSHKey, PrivateKey: string(key.PrivateKey)}
	preview, e := s.PreviewAccountImport(ctx, rows, actor, "default", "mixed-import")
	require.NoError(t, e)
	require.Empty(t, preview.Issues)
	require.Len(t, preview.Rows, 3)
	require.NotEmpty(t, preview.Token)
	assert.Len(t, st.List(), 2, "preview never writes credentials")
	safe, _ := json.Marshal(preview)
	assert.False(t, bytes.Contains(safe, key.PrivateKey))
	assert.False(t, bytes.Contains(safe, []byte(rows[0].Input.Password)))
	receipt, e := s.CommitAccountImport(ctx, rows, actor, "default", "mixed-import", preview.Token)
	require.NoError(t, e)
	require.Len(t, receipt.Rows, 3)
	for _, row := range receipt.Rows {
		a, e := s.ManagedAccount(row.AssetID, row.AccountID)
		require.NoError(t, e)
		assert.Equal(t, row.Version, a.Version)
		events, total, e := s.AccountActivity(row.AssetID, row.AccountID, 0, 20)
		require.NoError(t, e)
		assert.Equal(t, 1, total)
		assert.Equal(t, "mixed-import", events[0].ImportID)
	}
	assert.True(t, receipt.Rows[0].Active)
	duplicate, e := s.CommitAccountImport(ctx, rows, actor, "default", "mixed-import", preview.Token)
	require.NoError(t, e)
	assert.Equal(t, receipt, duplicate)
	raw, e := os.ReadFile(path)
	require.NoError(t, e)
	assert.Contains(t, string(raw), `"format": 3`)
	assert.False(t, bytes.Contains(raw, key.PrivateKey))
	assert.False(t, bytes.Contains(raw, []byte(rows[0].Input.Password)))
	var old []storedAsset
	assert.Error(t, json.Unmarshal(raw, &old))
	_, e = OpenStore(path, []byte("0123456789abcdef0123456789abcdef"))
	require.NoError(t, e)
	peer, e := OpenStore(path, []byte("0123456789abcdef0123456789abcdef"))
	require.NoError(t, e)
	reopened := NewService(peer, nil)
	repeated, e := reopened.CommitAccountImport(ctx, rows, actor, "default", "mixed-import", preview.Token)
	require.NoError(t, e)
	assert.Equal(t, receipt, repeated)
	rows[0].Input.Password = "synthetic-changed-input"
	_, e = reopened.CommitAccountImport(ctx, rows, actor, "default", "mixed-import", preview.Token)
	assert.ErrorIs(t, e, ErrAccountImportConflict)
}
func ptrImport(s string) *string { return &s }

func TestAccountImportMaximumBatchCreatesAndUpdatesEveryRowTogether(t *testing.T) {
	s, st, parent, _ := newRotationServiceTest(t)
	rows := make([]AccountImportRow, MaxAccountImportRows)
	for i := range rows {
		rows[i] = importRow(parent.ID, fmt.Sprintf("bulk-%03d", i), i+2)
	}
	p, e := s.PreviewAccountImport(context.Background(), rows, importActor(), "default", "maximum-create")
	require.NoError(t, e)
	require.Empty(t, p.Issues)
	require.Len(t, p.Rows, 500)
	created, e := s.CommitAccountImport(context.Background(), rows, importActor(), "default", "maximum-create", p.Token)
	require.NoError(t, e)
	require.Len(t, created.Rows, 500)
	require.Len(t, st.List(), 501)
	for i := range rows {
		rows[i].Action = "update"
		rows[i].Input.Password = "synthetic-bulk-updated-password"
		rows[i].Input.Version = created.Rows[i].Version
	}
	p, e = s.PreviewAccountImport(context.Background(), rows, importActor(), "default", "maximum-update")
	require.NoError(t, e)
	require.Empty(t, p.Issues)
	updated, e := s.CommitAccountImport(context.Background(), rows, importActor(), "default", "maximum-update", p.Token)
	require.NoError(t, e)
	require.Len(t, updated.Rows, 500)
	require.Len(t, st.List(), 501)
	for _, row := range updated.Rows {
		_, _, credential, e := st.connection(row.AccountID)
		require.NoError(t, e)
		assert.True(t, credential.Password == "synthetic-bulk-updated-password")
		backups, e := s.ListCredentialBackups(row.AccountID)
		require.NoError(t, e)
		require.Len(t, backups, 1)
	}
	assert.Len(t, s.AccountImportReceipts(importActor().ID), 2)
}

func BenchmarkAccountImportPreview500Passwords(b *testing.B) {
	st, e := OpenStore(filepath.Join(b.TempDir(), "assets.json"), make([]byte, 32))
	if e != nil {
		b.Fatal(e)
	}
	parent, e := st.Create(Asset{ID: "bench-host", Name: "Benchmark", Host: "192.0.2.90", Port: 22, Username: "primary"}, "synthetic-benchmark-password")
	if e != nil {
		b.Fatal(e)
	}
	s := NewService(st, nil)
	rows := make([]AccountImportRow, MaxAccountImportRows)
	for i := range rows {
		rows[i] = importRow(parent.ID, fmt.Sprintf("bulk-%03d", i), i+2)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		p, e := s.PreviewAccountImport(context.Background(), rows, importActor(), "default", "benchmark-import")
		if e != nil || len(p.Issues) != 0 || len(p.Rows) != MaxAccountImportRows {
			b.Fatal("preview did not validate the complete batch")
		}
	}
}

func TestAccountImportRejectsStaleExpiredAlteredAndCrossIdentityProofsWithoutPartialWrites(t *testing.T) {
	s, st, parent, _ := newRotationServiceTest(t)
	rows := []AccountImportRow{importRow(parent.ID, "first-user", 2), importRow(parent.ID, "second-user", 3)}
	actor := importActor()
	ctx := context.Background()
	p, e := s.PreviewAccountImport(ctx, rows, actor, "default", "proof-import")
	require.NoError(t, e)
	require.Empty(t, p.Issues)
	for _, v := range []struct {
		actor        AccountActor
		scope, token string
	}{{AccountActor{ID: "other", Name: "Other"}, "default", p.Token}, {actor, "other-org", p.Token}, {actor, "default", p.Token + "x"}} {
		_, e = s.CommitAccountImport(ctx, rows, v.actor, v.scope, "proof-import", v.token)
		assert.ErrorIs(t, e, ErrAccountImportConflict)
	}
	proof, e := st.decodeImportToken(p.Token)
	require.NoError(t, e)
	proof.Expires = time.Now().Add(-time.Second).Unix()
	_, e = s.CommitAccountImport(ctx, rows, actor, "default", "proof-import", st.signImportToken(proof))
	assert.ErrorIs(t, e, ErrAccountImportExpired)
	a, e := s.ManagedAccount(parent.ID, parent.ID)
	require.NoError(t, e)
	_, e = s.UpdateManagedAccount(parent.ID, parent.ID, AccountInput{Version: a.Version, Name: ptrImport("New name")}, actor)
	require.NoError(t, e)
	_, e = s.CommitAccountImport(ctx, rows, actor, "default", "proof-import", p.Token)
	assert.ErrorIs(t, e, ErrAccountImportConflict)
	assert.Len(t, st.List(), 1)
	rows[1].Input.CredentialType = "unknown"
	p, e = s.PreviewAccountImport(ctx, rows, actor, "default", "invalid-import")
	require.NoError(t, e)
	require.NotEmpty(t, p.Issues)
	assert.Empty(t, p.Token)
	assert.Len(t, st.List(), 1)
}
func TestAccountImportPersistenceFailureRollsBackAllRowsAndConcurrentRetryCreatesOnce(t *testing.T) {
	s, st, parent, path := newRotationServiceTest(t)
	rows := []AccountImportRow{importRow(parent.ID, "first-user", 2), importRow(parent.ID, "second-user", 3)}
	actor := importActor()
	ctx := context.Background()
	p, e := s.PreviewAccountImport(ctx, rows, actor, "default", "atomic-import")
	require.NoError(t, e)
	blocked := filepath.Join(t.TempDir(), "blocked")
	require.NoError(t, os.WriteFile(blocked, []byte("owned fault"), 0600))
	st.path = filepath.Join(blocked, "assets.json")
	_, e = s.CommitAccountImport(ctx, rows, actor, "default", "atomic-import", p.Token)
	require.Error(t, e)
	assert.Len(t, st.List(), 1)
	assert.Empty(t, s.AccountImportReceipts(actor.ID))
	st.path = path
	var wg sync.WaitGroup
	results := make(chan error, 4)
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, e := s.CommitAccountImport(ctx, rows, actor, "default", "atomic-import", p.Token)
			results <- e
		}()
	}
	wg.Wait()
	close(results)
	for e := range results {
		require.NoError(t, e)
	}
	assert.Len(t, st.List(), 3)
	assert.Len(t, s.AccountImportReceipts(actor.ID), 1)
}
func TestAccountImportPreservesBackupAndStopsPendingRemoteAccount(t *testing.T) {
	s, st, parent, _ := newRotationServiceTest(t)
	a := addManagedTestAccount(t, s, parent.ID)
	actor := importActor()
	ctx := context.Background()
	rows := []AccountImportRow{{Line: 2, AssetID: parent.ID, Action: "update", Input: AccountInput{Username: a.Username, Password: "synthetic-replaced-password", Version: a.Version}}}
	p, e := s.PreviewAccountImport(ctx, rows, actor, "default", "update-import")
	require.NoError(t, e)
	require.Empty(t, p.Issues)
	r, e := s.CommitAccountImport(ctx, rows, actor, "default", "update-import", p.Token)
	require.NoError(t, e)
	assert.True(t, r.Rows[0].CredentialReplaced)
	backups, e := s.ListCredentialBackups(a.ID)
	require.NoError(t, e)
	require.Len(t, backups, 1)
	_, secret, e := st.backupCredentialsLocked(a.ID, backups[0].ID)
	require.NoError(t, e)
	assert.True(t, secret.Password == "synthetic-managed-password")
	pending := prepareRemoteTest(t, s, parent, "pending-native-import")
	rows = []AccountImportRow{{Line: 2, AssetID: parent.ID, Action: "update", Input: AccountInput{Username: pending.Operation.Task.Username, Password: "synthetic-replaced-password"}}}
	p, e = s.PreviewAccountImport(ctx, rows, actor, "default", "pending-import")
	require.NoError(t, e)
	assert.Empty(t, p.Token)
	assert.Equal(t, "pending", p.Issues[0].Code)
}

func TestAccountImportCSVAndXLSXTemplatesAndStrictParsing(t *testing.T) {
	for _, format := range []string{"csv", "xlsx"} {
		raw, e := AccountImportTemplate(format)
		require.NoError(t, e)
		rows, issues := ParseAccountImport(format, raw)
		require.Empty(t, issues)
		require.Len(t, rows, 1)
		assert.Equal(t, "ASSET_ID", rows[0].AssetID)
		assert.Equal(t, "LOGIN_USER", rows[0].Input.Username)
	}
	var b bytes.Buffer
	w := csv.NewWriter(&b)
	require.NoError(t, w.Write([]string{"action", "asset_id", "username", "private_key", "active"}))
	require.NoError(t, w.Write([]string{"create", "host", "deploy", "multiline\nkey\nvalue", "false"}))
	w.Flush()
	rows, issues := ParseAccountImport("csv", b.Bytes())
	require.Empty(t, issues)
	assert.Equal(t, "multiline\nkey\nvalue", rows[0].Input.PrivateKey)
	assert.False(t, *rows[0].Input.Active)
	rows, issues = ParseAccountImport("csv", []byte("\ufeff\"action\",\"asset_id\",\"username\"\r\n\"create\",\"host\",\"quoted-bom\"\r\n"))
	require.Empty(t, issues)
	require.Len(t, rows, 1)
	assert.Equal(t, "quoted-bom", rows[0].Input.Username)
	for _, raw := range []string{"action,asset_id,username,password,password\ncreate,host,user,secret,secret", "action,asset_id,username,active\ncreate,host,user,yes", "wrong,asset_id,username\ncreate,host,user", "action,asset_id,username\n\"unterminated"} {
		_, issues = ParseAccountImport("csv", []byte(raw))
		require.NotEmpty(t, issues)
		safe, _ := json.Marshal(issues)
		assert.NotContains(t, string(safe), "secret")
	}
	original, e := AccountImportTemplate("xlsx")
	require.NoError(t, e)
	for _, kind := range []string{"formula", "macro", "external", "duplicate", "symlink-path"} {
		t.Run(kind, func(t *testing.T) {
			r, e := zip.NewReader(bytes.NewReader(original), int64(len(original)))
			require.NoError(t, e)
			var out bytes.Buffer
			z := zip.NewWriter(&out)
			for _, f := range r.File {
				reader, e := f.Open()
				require.NoError(t, e)
				data, e := io.ReadAll(reader)
				require.NoError(t, e)
				reader.Close()
				if kind == "formula" && strings.Contains(f.Name, "sheet1.xml") {
					data = bytes.Replace(data, []byte("</is></c>"), []byte("</is><f>HYPERLINK(\"bad\")</f></c>"), 1)
				}
				if kind == "external" && f.Name == "xl/_rels/workbook.xml.rels" {
					data = bytes.Replace(data, []byte(`Target="worksheets/sheet1.xml"`), []byte(`TargetMode="External" Target="https://example.invalid/sheet.xml"`), 1)
				}
				entry, e := z.Create(f.Name)
				require.NoError(t, e)
				_, e = entry.Write(data)
				require.NoError(t, e)
			}
			switch kind {
			case "macro":
				_, e = z.Create("xl/vbaProject.bin")
			case "duplicate":
				_, e = z.Create("xl/WORKBOOK.xml")
			case "symlink-path":
				_, e = z.Create("../outside.xml")
			}
			require.NoError(t, e)
			require.NoError(t, z.Close())
			_, issues := ParseAccountImport("xlsx", out.Bytes())
			require.NotEmpty(t, issues)
		})
	}
}

func TestAccountImportFinalAliasSetAndLateCrossOrganizationReferenceStayConsistent(t *testing.T) {
	s, st, parent, _ := newRotationServiceTest(t)
	coordinator, e := OpenPasswordCoordinator(filepath.Join(t.TempDir(), "shared.json"), make([]byte, 32), nil)
	require.NoError(t, e)
	require.NoError(t, s.CoordinatePasswords(coordinator, "default"))
	alias := parent
	alias.ID = "same-host-alias"
	alias.Name = "Alias"
	_, e = st.Create(alias, "initial-credential")
	require.NoError(t, e)
	rows := []AccountImportRow{{Line: 2, Action: "update", AssetID: parent.ID, Input: AccountInput{Username: parent.Username, Password: "synthetic-next-password"}}, {Line: 3, Action: "update", AssetID: alias.ID, Input: AccountInput{Username: alias.Username, Password: "synthetic-next-password"}}}
	p, e := s.PreviewAccountImport(context.Background(), rows[:1], importActor(), "default", "one-alias-import")
	require.NoError(t, e)
	require.NotEmpty(t, p.Issues)
	assert.Equal(t, "shared_conflict", p.Issues[0].Code)
	p, e = s.PreviewAccountImport(context.Background(), rows, importActor(), "default", "both-alias-import")
	require.NoError(t, e)
	require.Empty(t, p.Issues)
	other, _, _, _ := newRotationServiceTest(t)
	require.NoError(t, other.CoordinatePasswords(coordinator, "other"))
	_, e = s.CommitAccountImport(context.Background(), rows, importActor(), "default", "both-alias-import", p.Token)
	assert.ErrorIs(t, e, ErrAccountImportConflict)
	assert.Empty(t, s.AccountImportReceipts(importActor().ID))
	coordinator.mu.Lock()
	delete(coordinator.stores, "other")
	delete(coordinator.services, "other")
	coordinator.mu.Unlock()
	_, e = s.CommitAccountImport(context.Background(), rows, importActor(), "default", "both-alias-import", p.Token)
	require.NoError(t, e)
	for _, id := range []string{parent.ID, alias.ID} {
		_, _, cred, e := st.connection(id)
		require.NoError(t, e)
		assert.True(t, cred.Password == "synthetic-next-password")
	}
}
func TestAccountImportPostgresTakeoverAndExpiredAcknowledgementReturnOneReceipt(t *testing.T) {
	dsn := os.Getenv("JMS_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("requires PostgreSQL state fixture")
	}
	docs, e := storage.OpenPostgres(context.Background(), dsn, fmt.Sprintf("account-import-%d", time.Now().UnixNano()))
	require.NoError(t, e)
	t.Cleanup(func() { _ = docs.Delete("assets"); _ = docs.Close() })
	key := []byte("0123456789abcdef0123456789abcdef")
	st, e := OpenStoreWithDocuments(filepath.Join(t.TempDir(), "assets.json"), key, docs)
	require.NoError(t, e)
	parent, e := st.Create(Asset{ID: "host-ha", Name: "HA", Host: "192.0.2.8", Port: 22, Username: "primary"}, "synthetic-primary")
	require.NoError(t, e)
	rows := []AccountImportRow{importRow(parent.ID, "import-ha", 2)}
	s := NewService(st, nil)
	p, e := s.PreviewAccountImport(context.Background(), rows, importActor(), "org-ha", "ha-import-request")
	require.NoError(t, e)
	peer, e := OpenStoreWithDocuments(filepath.Join(t.TempDir(), "unused.json"), key, docs)
	require.NoError(t, e)
	next := NewService(peer, nil)
	receipt, e := next.CommitAccountImport(context.Background(), rows, importActor(), "org-ha", "ha-import-request", p.Token)
	require.NoError(t, e)
	reopened, e := OpenStoreWithDocuments(filepath.Join(t.TempDir(), "unused.json"), key, docs)
	require.NoError(t, e)
	proof, e := st.decodeImportToken(p.Token)
	require.NoError(t, e)
	proof.Expires = time.Now().Add(-time.Hour).Unix()
	again, e := NewService(reopened, nil).CommitAccountImport(context.Background(), rows, importActor(), "org-ha", "ha-import-request", st.signImportToken(proof))
	require.NoError(t, e)
	assert.Equal(t, receipt, again)
	_, e = next.CommitAccountImport(context.Background(), rows, importActor(), "different-org", "ha-import-request", p.Token)
	assert.ErrorIs(t, e, ErrAccountImportConflict)
	raw, e := docs.Load("assets")
	require.NoError(t, e)
	assert.False(t, bytes.Contains(raw, []byte(rows[0].Input.Password)))
}
