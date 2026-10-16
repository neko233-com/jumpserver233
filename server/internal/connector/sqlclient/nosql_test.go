package sqlclient

import (
	"encoding/json"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"strings"
	"testing"
)

func TestNoSQLStrictDocumentsAndAuditExcludeArgumentsAndFieldNames(t *testing.T) {
	for _, raw := range []string{`{"find":"private-collection","filter":{"password":"private-value"}}`, `["ECHO","private-argument"]`} {
		dialect := "mongodb"
		if raw[0] == '[' {
			dialect = "redis"
		}
		in := Input{SQL: raw, Dialect: dialect, ReadOnly: true, RowLimit: 1, TimeoutSeconds: 1}
		require.NoError(t, ValidateInput(in))
		audit, e := AuditSQL(raw, dialect)
		require.NoError(t, e)
		assert.NotContains(t, audit, "private")
		assert.NotContains(t, audit, "password")
		in.Parameters = []json.RawMessage{json.RawMessage(`"extra"`)}
		assert.ErrorIs(t, ValidateInput(in), ErrInvalid)
	}
	for _, raw := range []string{`{"find":"x","find":"y"}`, `{"find":"x","filter":{"a":1,"a":2}}`, `["GET","x"] []`, strings.Repeat("[", 35) + strings.Repeat("]", 35)} {
		assert.Error(t, StrictJSON([]byte(raw)), "strict structural test for %s", raw)
	}
}
func TestRedisBinaryArgumentsAndMongoCommandOrder(t *testing.T) {
	args, e := RedisCommand(`["set",{"base64":"AP8="},"值\n"]`)
	require.NoError(t, e)
	assert.Equal(t, "SET", string(args[0]))
	assert.Equal(t, []byte{0, 255}, args[1])
	assert.Equal(t, "值\n", string(args[2]))
	for _, raw := range []string{`["GET",12]`, `["GET",{"base64":"%%%"}]`, `["GET",{"base64":"eA==","extra":1}]`, `["auth\r\nset","x"]`} {
		_, e := RedisCommand(raw)
		assert.Error(t, e)
	}
	fields, e := JSONFields([]byte(`{"find":"items","filter":{"id":1}}`))
	require.NoError(t, e)
	assert.Equal(t, "find", fields[0].Key)
	assert.Equal(t, "filter", fields[1].Key)
}

func TestMissingResultCoordinatesAreDeepCopied(t *testing.T) {
	source := Result{MissingCells: [][2]int{{0, 0}}, Columns: []Column{{Name: "value"}}, Rows: [][]*string{{nil}}}
	clone := CloneResult(source)
	clone.MissingCells[0][0] = 123
	assert.Equal(t, [2]int{0, 0}, source.MissingCells[0])
}
