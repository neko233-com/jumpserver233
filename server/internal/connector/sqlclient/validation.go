package sqlclient

import (
	"bytes"
	"encoding/json"
	"strings"
	"unicode/utf8"
)

func ValidateShape(in Input) error {
	if strings.TrimSpace(in.SQL) == "" || len(in.SQL) > MaxSQLBytes || !utf8.ValidString(in.SQL) || strings.ContainsRune(in.SQL, 0) || in.RowLimit < 1 || in.RowLimit > MaxRows || in.TimeoutSeconds < 1 || in.TimeoutSeconds > 300 || len(in.Parameters) > 100 {
		return ErrInvalid
	}
	total := 0
	for _, p := range in.Parameters {
		p = bytes.TrimSpace(p)
		if !json.Valid(p) || len(p) > 65536 {
			return ErrInvalid
		}
		total += len(p)
		if total > MaxParameterBytes {
			return ErrInvalid
		}
		var s string
		if len(p) > 0 && p[0] == '"' {
			if json.Unmarshal(p, &s) != nil || strings.ContainsRune(s, 0) {
				return ErrInvalid
			}
		}
	}
	return nil
}
func ValidateInput(in Input) error {
	if (in.Dialect == "redis" || in.Dialect == "mongodb") && len(in.Parameters) != 0 {
		return ErrInvalid
	}
	if e := ValidateShape(in); e != nil {
		return e
	}
	_, e := AuditSQL(in.SQL, in.Dialect)
	return e
}
func AuditSQL(sql, dialect string) (string, error) {
	switch dialect {
	case "", "postgresql":
		return AuditPostgres(sql)
	case "mysql", "mariadb":
		return AuditMySQL(sql)
	case "sqlserver":
		return AuditSQLServer(sql)
	case "redis":
		return AuditRedis(sql)
	case "mongodb":
		return AuditMongoDB(sql)
	case "clickhouse":
		return AuditClickHouse(sql)
	default:
		return "", ErrInvalid
	}
}
