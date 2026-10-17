package hostagent

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAccountsMetadataDiscardsPasswordsAndGECOSBeforeDigestOrEncoding(t *testing.T) {
	rows, e := ParseAccounts([]byte("root:SYNTHETIC-HASH-NEVER-EXPORT:0:0:private full name:/root:/bin/bash\nops:x:1000:1000:Private:/home/ops:/bin/sh\n"))
	require.NoError(t, e)
	require.Len(t, rows, 2)
	assert.Equal(t, "ops", rows[0].Username)
	raw, _ := json.Marshal(rows)
	assert.NotContains(t, string(raw), "SYNTHETIC-HASH")
	assert.NotContains(t, string(raw), "Private")
	assert.NotContains(t, string(raw), "private full name")
	other, e := ParseAccounts([]byte("root:DIFFERENT-HASH:0:0:Different:/root:/bin/bash\nops:another:1000:1000:Else:/home/ops:/bin/sh\n"))
	require.NoError(t, e)
	assert.Equal(t, AccountDigest(rows), AccountDigest(other))
	for _, input := range []string{"", "a:x:-1:0::/a:/bin/sh\n", "a:x:4294967296:0::/a:/bin/sh\n", "a:x:1:1::/a:/bin/sh\na:x:2:2::/b:/bin/sh\n", "a:x:1:1::relative:/bin/sh\n", "a:x:1:1::/a:/bin/sh:unexpected\n"} {
		_, e = ParseAccounts([]byte(input))
		require.Error(t, e)
	}
	var many strings.Builder
	for i := 0; i <= MaxAccounts; i++ {
		fmt.Fprintf(&many, "qa%d:x:%d:1::/home/qa:/bin/sh\n", i, i)
	}
	_, e = ParseAccounts([]byte(many.String()))
	require.Error(t, e)
}
func TestAccountPagesRejectIncompleteDuplicateOrUnboundedReports(t *testing.T) {
	rows := []Account{{Username: "ops", UID: 1000, GID: 1000, Home: "/home/ops", Shell: "/bin/sh"}}
	page := AccountPage{Format: AccountFormat, Digest: AccountDigest(rows), Total: 1, Accounts: rows}
	raw, _ := json.Marshal(page)
	parsed, e := DecodeAccountPage(raw)
	require.NoError(t, e)
	assert.Equal(t, page, parsed)
	for _, bad := range [][]byte{append(raw, []byte(" {}")...), []byte(`{"format":"x","format":"y"}`), []byte(strings.Repeat("x", MaxAccountPageBytes+1))} {
		_, e = DecodeAccountPage(bad)
		require.Error(t, e)
	}
	for _, mutate := range []func(*AccountPage){func(p *AccountPage) { p.Total = MaxAccounts + 1 }, func(p *AccountPage) { p.Offset = 1 }, func(p *AccountPage) { p.Accounts = nil }, func(p *AccountPage) { p.Digest = "invalid" }, func(p *AccountPage) { p.Accounts = []Account{{Username: "a", Home: "bad"}} }} {
		copy := page
		mutate(&copy)
		raw, _ = json.Marshal(copy)
		_, e = DecodeAccountPage(raw)
		require.Error(t, e)
	}
}
