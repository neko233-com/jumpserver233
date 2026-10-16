package sqlclient

import (
	"strings"
	"unicode"
	"unicode/utf8"
)

// AuditSQL omits literal and comment contents. Execution uses the original SQL
// and separately bound parameters; this representation is only for history.
func AuditPostgres(sql string) (string, error) {
	var out strings.Builder
	first := ""
	depth := 0
	for i := 0; i < len(sql); {
		if strings.HasPrefix(sql[i:], "--") {
			j := strings.IndexByte(sql[i:], '\n')
			if j < 0 {
				break
			}
			out.WriteByte(' ')
			i += j
			continue
		}
		if strings.HasPrefix(sql[i:], "/*") {
			i += 2
			depth = 1
			for i < len(sql) && depth > 0 {
				if strings.HasPrefix(sql[i:], "/*") {
					depth++
					if depth > 100 {
						return "", ErrInvalid
					}
					i += 2
				} else if strings.HasPrefix(sql[i:], "*/") {
					depth--
					i += 2
				} else {
					i++
				}
			}
			if depth != 0 {
				return "", ErrInvalid
			}
			out.WriteByte(' ')
			continue
		}
		if sql[i] == '\'' || sql[i] == '"' {
			quote := sql[i]
			escape := quote == '\'' && i > 0 && (sql[i-1] == 'e' || sql[i-1] == 'E') && (i < 2 || !identifierByte(sql[i-2]))
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
				if sql[i] == '\\' && escape && i+1 < len(sql) {
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
		if sql[i] == '$' {
			j := i + 1
			for j < len(sql) && ((sql[j] >= 'a' && sql[j] <= 'z') || (sql[j] >= 'A' && sql[j] <= 'Z') || sql[j] == '_' || (j > i+1 && sql[j] >= '0' && sql[j] <= '9')) {
				j++
			}
			if j < len(sql) && sql[j] == '$' {
				delimiter := sql[i : j+1]
				end := strings.Index(sql[j+1:], delimiter)
				if end < 0 {
					return "", ErrInvalid
				}
				out.WriteByte('?')
				i = j + 1 + end + len(delimiter)
				continue
			}
			if j == i+1 && j < len(sql) && sql[j] >= '0' && sql[j] <= '9' {
				out.WriteByte('$')
				i++
				for i < len(sql) && sql[i] >= '0' && sql[i] <= '9' {
					out.WriteByte(sql[i])
					i++
				}
				continue
			}
		}
		if sql[i] >= '0' && sql[i] <= '9' {
			out.WriteByte('?')
			i++
			for i < len(sql) && ((sql[i] >= '0' && sql[i] <= '9') || strings.ContainsRune(".eExXaAbBcCdDfF_+-", rune(sql[i]))) {
				i++
			}
			continue
		}
		r, n := utf8.DecodeRuneInString(sql[i:])
		if r == utf8.RuneError && n == 1 {
			return "", ErrInvalid
		}
		if unicode.IsControl(r) && !strings.ContainsRune("\r\n\t", r) {
			return "", ErrInvalid
		}
		if first == "" && ((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z')) {
			j := i
			for j < len(sql) && ((sql[j] >= 'a' && sql[j] <= 'z') || (sql[j] >= 'A' && sql[j] <= 'Z') || sql[j] == '_') {
				j++
			}
			first = strings.ToUpper(sql[i:j])
		}
		out.WriteRune(r)
		i += n
	}
	if first == "" {
		return "", ErrInvalid
	}
	switch first {
	case "BEGIN", "START", "COMMIT", "END", "ROLLBACK", "ABORT", "SAVEPOINT", "RELEASE", "PREPARE", "EXECUTE", "DEALLOCATE", "DISCARD", "SET", "RESET", "COPY":
		return "", ErrInvalid
	}
	return strings.TrimSpace(out.String()), nil
}

func identifierByte(c byte) bool {
	return c == '_' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c >= 128
}
