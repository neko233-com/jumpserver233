package sqlclient

import (
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestClickHouseAuditTypedParametersHeredocsAndOverrides(t *testing.T) {
	s, e := ScanClickHouse("/*private-comment*/ SELECT {p1:String}, {p2:Nullable(UInt64)}, 'private-literal' AS `private-alias`, $tag$private-heredoc$tag$, 0xDEADBEEF, 1.23e-42 --private-tail\n")
	require.NoError(t, e)
	assert.Equal(t, "SELECT", s.Verb)
	assert.Equal(t, map[int]string{1: "String", 2: "Nullable(UInt64)"}, s.Parameters)
	assert.NotContains(t, s.Audit, "private")
	assert.NotContains(t, s.Audit, "DEADBEEF")
	assert.NotContains(t, s.Audit, "42")
	assert.Contains(t, s.Audit, "{p1:?}")
	for _, sql := range []string{"SELECT 1 SETTINGS readonly=0", "SELECT 1 FORMAT CSV", "SELECT 1 INTO OUTFILE '/tmp/a'", "SET readonly=0", "USE other", "KILL QUERY WHERE 1", "BEGIN", "SELECT {x:String}", "SELECT {p01:String}", "SELECT {p101:String}", "SELECT {p1:Identifier}", "SELECT {p1:String}, {p1:UInt8}", "SELECT 'unfinished", "SELECT /*unfinished", "SELECT $tag$unfinished"} {
		t.Run(sql, func(t *testing.T) { _, e := ScanClickHouse(sql); assert.ErrorIs(t, e, ErrInvalid) })
	}
	for _, sql := range []string{"SELECT format('{}', {p1:String})", "SELECT 'SETTINGS FORMAT OUTFILE'", "SELECT \"format\" FROM table_name", "SELECT 1 /* /* nested */ comment */"} {
		_, e := ScanClickHouse(sql)
		assert.NoError(t, e)
	}
}
