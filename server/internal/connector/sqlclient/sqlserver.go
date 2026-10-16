package sqlclient

import (
	"strings"
	"unicode"
	"unicode/utf8"
)

// AuditSQLServer handles T-SQL strings, delimited identifiers and nested comments.
// Quoted content never participates in the read-only keyword check.
func AuditSQLServer(input string) (string, error) {
	var out strings.Builder
	for i := 0; i < len(input); {
		if strings.HasPrefix(input[i:], "--") {
			end := strings.IndexByte(input[i:], '\n')
			if end < 0 {
				break
			}
			i += end
			out.WriteByte(' ')
			continue
		}
		if strings.HasPrefix(input[i:], "/*") {
			i += 2
			depth := 1
			for i < len(input) && depth > 0 {
				switch {
				case strings.HasPrefix(input[i:], "/*"):
					depth++
					i += 2
				case strings.HasPrefix(input[i:], "*/"):
					depth--
					i += 2
				default:
					i++
				}
				if depth > 100 {
					return "", ErrInvalid
				}
			}
			if depth != 0 {
				return "", ErrInvalid
			}
			out.WriteByte(' ')
			continue
		}
		if input[i] == '\'' || input[i] == '"' || input[i] == '[' {
			end := input[i]
			if end == '[' {
				end = ']'
			}
			i++
			closed := false
			for i < len(input) {
				if input[i] == end {
					if i+1 < len(input) && input[i+1] == end {
						i += 2
						continue
					}
					i++
					closed = true
					break
				}
				i++
			}
			if !closed {
				return "", ErrInvalid
			}
			out.WriteByte('?')
			continue
		}
		r, n := utf8.DecodeRuneInString(input[i:])
		if r == utf8.RuneError && n == 1 || unicode.IsControl(r) && !strings.ContainsRune("\r\n\t", r) {
			return "", ErrInvalid
		}
		if unicode.IsLetter(r) || r == '_' || r == '@' || r == '#' {
			start := i
			i += n
			for i < len(input) && (identifierByte(input[i]) || input[i] == '@' || input[i] == '#') {
				i++
			}
			out.WriteString(input[start:i])
			continue
		}
		if unicode.IsDigit(r) {
			out.WriteByte('?')
			i += n
			if r == '0' && i < len(input) && (input[i] == 'x' || input[i] == 'X') {
				i++
				for i < len(input) && (input[i] >= '0' && input[i] <= '9' || input[i] >= 'a' && input[i] <= 'f' || input[i] >= 'A' && input[i] <= 'F') {
					i++
				}
			} else {
				for i < len(input) {
					next, size := utf8.DecodeRuneInString(input[i:])
					if !unicode.IsDigit(next) && next != '.' {
						break
					}
					i += size
				}
				if i < len(input) && (input[i] == 'e' || input[i] == 'E') {
					end := i + 1
					if end < len(input) && (input[end] == '+' || input[end] == '-') {
						end++
					}
					start := end
					for end < len(input) && input[end] >= '0' && input[end] <= '9' {
						end++
					}
					if end > start {
						i = end
					}
				}
			}
			continue
		}
		out.WriteRune(r)
		i += n
	}
	text := strings.TrimSpace(out.String())
	if text == "" {
		return "", ErrInvalid
	}
	return text, nil
}

// SQL Server has no read-only transaction flag. Restrict this entry point to
// SELECT/CTE reads and reject every mutation/control token, including batches.
// Database account permissions remain an additional authorization boundary.
func ReadOnlySQLServer(redacted string) bool {
	words := strings.FieldsFunc(redacted, func(r rune) bool {
		return !unicode.IsLetter(r) && !unicode.IsDigit(r) && r != '_' && r != '@' && r != '#' && r != '$'
	})
	if len(words) == 0 {
		return false
	}
	first := strings.ToUpper(words[0])
	if first != "SELECT" && first != "WITH" {
		return false
	}
	for _, word := range words {
		switch strings.ToUpper(word) {
		case "INTO", "INSERT", "UPDATE", "DELETE", "MERGE", "CREATE", "ALTER", "DROP", "TRUNCATE", "EXEC", "EXECUTE", "BEGIN", "COMMIT", "ROLLBACK", "SAVE", "SET", "SETUSER", "REVERT", "USE", "DECLARE", "GRANT", "DENY", "REVOKE", "DBCC", "BULK", "BACKUP", "RESTORE", "WAITFOR", "KILL", "SHUTDOWN", "RECONFIGURE", "NEXT", "OPENQUERY", "OPENROWSET", "OPENDATASOURCE", "SEND", "RECEIVE", "ENABLE", "DISABLE", "CHECKPOINT", "WRITETEXT", "UPDATETEXT", "READTEXT", "PRINT", "RAISERROR", "THROW", "IF", "WHILE", "GOTO", "RETURN", "BREAK", "CONTINUE", "OPEN", "CLOSE", "DEALLOCATE", "CONVERSATION", "MOVE", "DISK":
			return false
		}
	}
	return true
}
