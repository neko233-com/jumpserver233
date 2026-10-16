package sqlclient

import (
	"strings"
	"unicode"
	"unicode/utf8"
)

// AuditMySQL removes literal, identifier and comment contents. Executable
// comments and transaction/session controls are rejected rather than audited
// as harmless comments. Execution keeps server multiple-statement support disabled.
func AuditMySQL(sql string) (string, error) {
	var out strings.Builder
	first := ""

	for i := 0; i < len(sql); {
		if strings.HasPrefix(sql[i:], "/*") {
			if strings.HasPrefix(sql[i:], "/*!") || strings.HasPrefix(sql[i:], "/*M!") || strings.HasPrefix(sql[i:], "/*m!") {
				return "", ErrInvalid
			}
			end := strings.Index(sql[i+2:], "*/")
			if end < 0 {
				return "", ErrInvalid
			}
			i += end + 4
			out.WriteByte(' ')
			continue
		}
		if sql[i] == '#' || strings.HasPrefix(sql[i:], "--") && (i+2 == len(sql) || sql[i+2] <= 32) {
			end := strings.IndexByte(sql[i:], '\n')
			if end < 0 {
				break
			}
			i += end
			out.WriteByte(' ')
			continue
		}
		if sql[i] <= 32 {
			r, n := utf8.DecodeRuneInString(sql[i:])
			if unicode.IsControl(r) && !strings.ContainsRune("\r\n\t", r) {
				return "", ErrInvalid
			}
			out.WriteRune(r)
			i += n
			continue
		}

		if sql[i] == ';' {
			out.WriteByte(';')
			i++
			continue
		}
		if sql[i] == '\'' || sql[i] == '"' || sql[i] == '`' {
			quote := sql[i]
			i++
			closed := false
			for i < len(sql) {
				if sql[i] == quote {
					if i+1 < len(sql) && sql[i+1] == quote {
						i += 2
						continue
					}
					i++
					closed = true
					break
				}
				if sql[i] == '\\' && quote != '`' && i+1 < len(sql) {
					i += 2
				} else {
					i++
				}
			}
			if !closed {
				return "", ErrInvalid
			}
			out.WriteByte('?')
			continue
		}
		r, n := utf8.DecodeRuneInString(sql[i:])
		if r == utf8.RuneError && n == 1 || unicode.IsControl(r) {
			return "", ErrInvalid
		}
		if r >= '0' && r <= '9' {
			out.WriteByte('?')
			i += n
			for i < len(sql) && identifierByte(sql[i]) {
				i++
			}
			continue
		}
		if identifierByte(sql[i]) {
			j := i + 1
			for j < len(sql) && identifierByte(sql[j]) {
				j++
			}
			word := sql[i:j]
			if first == "" {
				first = strings.ToUpper(word)
			}
			out.WriteString(word)
			i = j
			continue
		}
		out.WriteRune(r)
		i += n
	}
	switch first {
	case "", "BEGIN", "START", "COMMIT", "ROLLBACK", "ABORT", "SAVEPOINT", "RELEASE", "SET", "RESET", "PREPARE", "EXECUTE", "DEALLOCATE", "XA", "USE", "LOAD", "LOCK", "UNLOCK", "KILL", "DELIMITER", "HANDLER":
		return "", ErrInvalid
	}
	return strings.TrimSpace(out.String()), nil
}
