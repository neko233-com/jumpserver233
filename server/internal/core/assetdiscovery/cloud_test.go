package assetdiscovery

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/neko233-com/jumpserver233/server/internal/connector/cloudinventory"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func cloudSourceInput() SourceInput {
	in := sourceInput()
	in.RequestID = "cloud-source-request-001"
	in.Name = "AWS inventory"
	in.Provider = "aws"
	in.Targets = nil
	in.Cloud = &cloudinventory.Config{AccountID: "123456789012", Regions: []string{"us-east-1", "us-west-2"}, AddressMode: "private"}
	in.CloudCredential = &cloudinventory.Credential{AccessKeyID: "AKIAIOSFODNN7EXAMPLE", SecretAccessKey: "synthetic-secret-cloud-key", SessionToken: "synthetic-secret-cloud-session"}
	return in
}

func TestCloudSourceSecretsIdentityRevisionAndRestart(t *testing.T) {
	st, _, _, _ := fixture(t, Hooks{})
	in := cloudSourceInput()
	src, e := st.SaveSource("", in, actor(), time.Now())
	require.NoError(t, e)
	assert.True(t, src.CloudCredentialConfigured)
	public, e := json.Marshal(src)
	require.NoError(t, e)
	for _, secret := range []string{in.CloudCredential.AccessKeyID, in.CloudCredential.SecretAccessKey, in.CloudCredential.SessionToken, in.Credential.Password} {
		assert.NotContains(t, string(public), secret)
	}
	raw, e := os.ReadFile(st.path)
	require.NoError(t, e)
	assert.NotContains(t, string(raw), in.CloudCredential.SecretAccessKey)
	retry, e := st.SaveSource("", in, actor(), time.Now())
	require.NoError(t, e)
	assert.Equal(t, src, retry)
	edit := sourceEdit(src)
	edit.Cloud = copyJSON(src.Cloud)
	edit.Description = "metadata edit"
	updated, e := st.SaveSource(src.ID, edit, actor(), time.Now())
	require.NoError(t, e)
	assert.True(t, updated.CloudCredentialConfigured)
	edit.Revision = updated.Revision
	edit.Cloud.AccountID = "999999999999"
	_, e = st.SaveSource(src.ID, edit, actor(), time.Now())
	assert.ErrorIs(t, e, ErrInvalid)
	edit.Cloud.AccountID = src.Cloud.AccountID
	edit.Provider = "aws_cn"
	_, e = st.SaveSource(src.ID, edit, actor(), time.Now())
	assert.ErrorIs(t, e, ErrInvalid)
	reopened, e := Open(st.path, fixtureKey, nil)
	require.NoError(t, e)
	private, e := reopened.source(src.ID)
	require.NoError(t, e)
	assert.Equal(t, in.CloudCredential, private.Input.CloudCredential)
	public, _ = json.Marshal(reopened.data.Audit)
	assert.NotContains(t, string(public), in.CloudCredential.SecretAccessKey)
	assert.NotContains(t, string(public), in.CloudCredential.AccessKeyID)
}

func TestCloudSyncStableIdentityPartialFailureAndScopedMissing(t *testing.T) {
	var mu sync.Mutex
	instance := cloudinventory.Instance{Provider: "aws", AccountID: "123456789012", Region: "us-east-1", ID: "i-0123456789abcdef0", Name: "cloud-node", State: "running", PrivateIP: "192.0.2.7"}
	rows := []cloudinventory.Instance{instance}
	var listError error
	st, s, _, inventory := fixture(t, Hooks{CloudList: func(context.Context, string, cloudinventory.Config, cloudinventory.Credential) ([]cloudinventory.Instance, error) {
		mu.Lock()
		defer mu.Unlock()
		return copyJSON(rows), listError
	}})
	src, e := st.SaveSource("", cloudSourceInput(), actor(), time.Now())
	require.NoError(t, e)
	p := policyFor(t, st, src, true)
	r := runScan(t, s, src, &p, "cloud-run-request-001")
	assert.Equal(t, "completed", r.State)
	assert.Equal(t, 1, r.Imported)
	findings, total, e := st.Findings(src.ID, 0, 100)
	require.NoError(t, e)
	require.Equal(t, 1, total)
	findingID := findings[0].ID
	assetID := findings[0].AssetID
	assert.Equal(t, "cloud-node-22", inventory.List()[0].Name)
	r = runScan(t, s, src, &p, "cloud-run-request-002")
	assert.Equal(t, 0, r.Imported)
	require.Len(t, inventory.List(), 1)
	mu.Lock()
	listError = errors.New("synthetic partial region failure")
	mu.Unlock()
	r = runScan(t, s, src, &p, "cloud-run-request-003")
	assert.Equal(t, "failed", r.State)
	assert.Equal(t, "scan_cloud_unavailable", r.ErrorCode)
	findings, _, e = st.Findings(src.ID, 0, 100)
	require.NoError(t, e)
	assert.Zero(t, findings[0].ConsecutiveMisses)
	mu.Lock()
	listError = nil
	rows[0].PrivateIP = "192.0.2.8"
	mu.Unlock()
	r = runScan(t, s, src, &p, "cloud-run-request-004")
	assert.Equal(t, 1, r.Conflicts)
	findings, _, e = st.Findings(src.ID, 0, 100)
	require.NoError(t, e)
	assert.Equal(t, findingID, findings[0].ID)
	assert.Equal(t, assetID, findings[0].AssetID)
	assert.Equal(t, "192.0.2.7", inventory.List()[0].Host)
	mu.Lock()
	rows[0].PrivateIP = ""
	rows[0].State = "stopped"
	mu.Unlock()
	for _, request := range []string{"cloud-run-request-005", "cloud-run-request-006"} {
		r = runScan(t, s, src, &p, request)
		assert.Equal(t, "completed", r.State)
	}
	findings, _, e = st.Findings(src.ID, 0, 100)
	require.NoError(t, e)
	assert.Zero(t, findings[0].ConsecutiveMisses)
	assert.False(t, inventory.List()[0].AccountDisabled)
	mu.Lock()
	rows = nil
	mu.Unlock()
	r = runScan(t, s, src, &p, "cloud-run-request-007")
	assert.False(t, inventory.List()[0].AccountDisabled)
	// The preserved observed address may differ from the inventory after an
	// unresolved IP move: endpoint conflicts also protect missing-host writes.
	r = runScan(t, s, src, &p, "cloud-run-request-008")
	assert.Equal(t, 1, r.Conflicts)
	assert.False(t, inventory.List()[0].AccountDisabled)
	mu.Lock()
	rows = []cloudinventory.Instance{instance}
	mu.Unlock()
	r = runScan(t, s, src, &p, "cloud-run-request-009")
	assert.Equal(t, "completed", r.State)
	mu.Lock()
	rows = nil
	mu.Unlock()
	_ = runScan(t, s, src, &p, "cloud-run-request-010")
	_ = runScan(t, s, src, &p, "cloud-run-request-011")
	assert.True(t, inventory.List()[0].AccountDisabled)
	mu.Lock()
	rows = []cloudinventory.Instance{instance}
	mu.Unlock()
	_ = runScan(t, s, src, &p, "cloud-run-request-012")
	assert.False(t, inventory.List()[0].AccountDisabled)
	edit := sourceEdit(src)
	edit.Cloud = copyJSON(src.Cloud)
	edit.Cloud.Regions = []string{"us-west-2"}
	src, e = st.SaveSource(src.ID, edit, actor(), time.Now())
	require.NoError(t, e)
	mu.Lock()
	rows = nil
	mu.Unlock()
	r = runScan(t, s, src, nil, "cloud-run-request-013")
	assert.Equal(t, "completed", r.State)
	findings, _, e = st.Findings(src.ID, 0, 100)
	require.NoError(t, e)
	assert.False(t, findings[0].Cloud.Missing)
	assert.Zero(t, findings[0].ConsecutiveMisses)
}

func TestCloudSourceRejectsLANRangesAndUnboundCredential(t *testing.T) {
	for _, mode := range []string{"targets", "excludes", "credential", "provider", "regions", "account"} {
		t.Run(mode, func(t *testing.T) {
			in := cloudSourceInput()
			switch mode {
			case "targets":
				in.Targets = []string{"192.0.2.1"}
			case "excludes":
				in.Exclude = []string{"192.0.2.1"}
			case "credential":
				in.CloudCredential = nil
			case "provider":
				in.Provider = "fake-cloud"
			case "regions":
				in.Cloud.Regions = []string{"evil.example"}
			case "account":
				in.Cloud.AccountID = "other"
			}
			_, _, e := normalizeSource(in, nil)
			assert.ErrorIs(t, e, ErrInvalid)
		})
	}
}

func TestCloudMetadataBudgetIncludesEveryPortBeforeProbing(t *testing.T) {
	rows := []cloudinventory.Instance{}
	for n := 0; n < 400; n++ {
		rows = append(rows, cloudinventory.Instance{Provider: "aws", AccountID: "123456789012", Region: "us-east-1", ID: fmt.Sprintf("i-%017x", n), Name: "node", State: "running", PrivateIP: "192.0.2.7", Tags: map[string]string{"large": strings.Repeat("&", 1024)}})
	}
	st, s, _, _ := fixture(t, Hooks{CloudList: func(context.Context, string, cloudinventory.Config, cloudinventory.Credential) ([]cloudinventory.Instance, error) {
		return rows, nil
	}})
	in := cloudSourceInput()
	in.Ports = []int{22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37}
	source, e := st.SaveSource("", in, actor(), time.Now())
	require.NoError(t, e)
	run := runScan(t, s, source, nil, "cloud-metadata-budget-001")
	assert.Equal(t, "failed", run.State)
	assert.Equal(t, "scan_cloud_capacity", run.ErrorCode)
	assert.Zero(t, run.Completed)
	_, total, e := st.Findings(source.ID, 0, 100)
	require.NoError(t, e)
	assert.Zero(t, total)
}
