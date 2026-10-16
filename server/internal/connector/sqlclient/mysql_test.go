package sqlclient

import (
	"encoding/json"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestMySQLRedactionAndDialectValidation(t *testing.T) {
	for _, sql := range []string{"SELECT 'private-value', `private-identifier`, 0xAABB, ? # private-comment", `SELECT "private-value", 'private-\'value' /* private-comment */`, "SELECT 'private-value' -- private-comment\n", "CREATE PROCEDURE p() BEGIN SELECT 'private-value'; END"} {
		redacted, e := AuditMySQL(sql)
		require.NoError(t, e, sql)
		assert.NotContains(t, redacted, "private-")
		assert.NotContains(t, redacted, "AABB")
	}
	for _, sql := range []string{"/*!50000 SELECT 1 */", "/*M! SELECT 1 */", "/*m! SELECT 1 */", "SET autocommit=0", "START TRANSACTION", "COMMIT", "LOAD DATA LOCAL INFILE 'secret' INTO TABLE x", "USE mysql", "SELECT 'unterminated", "/* no end", "-- only comment"} {
		_, e := AuditMySQL(sql)
		assert.ErrorIs(t, e, ErrInvalid, sql)
	}
	in := Input{SQL: "SELECT ?", Dialect: "mysql", Parameters: []json.RawMessage{json.RawMessage(`"text"`)}, TimeoutSeconds: 5, RowLimit: 5}
	require.NoError(t, ValidateInput(in))
	in.Dialect = "mariadb"
	require.NoError(t, ValidateInput(in))
	in.Dialect = "unknown"
	require.ErrorIs(t, ValidateInput(in), ErrInvalid)
	in.Dialect = "mysql"
	in.Parameters = []json.RawMessage{json.RawMessage(`"\u0000"`)}
	require.ErrorIs(t, ValidateInput(in), ErrInvalid)
}
