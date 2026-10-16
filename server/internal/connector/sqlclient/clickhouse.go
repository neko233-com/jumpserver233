package sqlclient

import (
	"regexp"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

type ClickHouseStatement struct {
	Audit      string
	Verb       string
	Parameters map[int]string
}

var clickHouseNumber = regexp.MustCompile(`^(?:0[xX][0-9a-fA-F_]+|0[bB][01_]+|[0-9][0-9_]*(?:\.[0-9_]*)?(?:[eE][+-]?[0-9_]+)?)`)

func AuditClickHouse(sql string) (string, error) { s, e := ScanClickHouse(sql); return s.Audit, e }

// ScanClickHouse redacts quoted values/identifiers, numbers and heredocs while
// retaining separately bound parameter names. Transport settings belong to the
// connector; SQL cannot override the result format or execution limits.
func ScanClickHouse(input string) (ClickHouseStatement, error) {
	s := ClickHouseStatement{Parameters: map[int]string{}}
	var out strings.Builder
	for i := 0; i < len(input); {
		if input[i] == '#' || strings.HasPrefix(input[i:], "--") {
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
					return s, ErrInvalid
				}
			}
			if depth != 0 {
				return s, ErrInvalid
			}
			out.WriteByte(' ')
			continue
		}
		if input[i] == '\'' || input[i] == '"' || input[i] == '`' {
			end, e := clickHouseQuoteEnd(input, i)
			if e != nil {
				return s, e
			}
			i = end
			out.WriteByte('?')
			continue
		}
		if input[i] == '$' {
			j := i + 1
			for j < len(input) && ((input[j] >= 'a' && input[j] <= 'z') || (input[j] >= 'A' && input[j] <= 'Z') || (input[j] >= '0' && input[j] <= '9') || input[j] == '_') {
				j++
			}
			if j < len(input) && input[j] == '$' {
				delimiter := input[i : j+1]
				end := strings.Index(input[j+1:], delimiter)
				if end < 0 {
					return s, ErrInvalid
				}
				i = j + 1 + end + len(delimiter)
				out.WriteByte('?')
				continue
			}
		}
		if input[i] == '{' {
			j := i + 1
			for j < len(input) && (input[j] >= 'a' && input[j] <= 'z' || input[j] >= 'A' && input[j] <= 'Z' || input[j] >= '0' && input[j] <= '9' || input[j] == '_') {
				j++
			}
			name := input[i+1 : j]
			if j < len(input) && input[j] == ':' && name != "" {
				if len(name) < 2 || name[0] != 'p' {
					return s, ErrInvalid
				}
				n, e := strconv.Atoi(name[1:])
				if e != nil || n < 1 || n > 100 || name != "p"+strconv.Itoa(n) {
					return s, ErrInvalid
				}
				start := j + 1
				j = start
				for j < len(input) && input[j] != '}' {
					if input[j] == '\'' || input[j] == '"' || input[j] == '`' {
						end, e := clickHouseQuoteEnd(input, j)
						if e != nil {
							return s, e
						}
						j = end
					} else {
						j++
					}
				}
				if j == len(input) {
					return s, ErrInvalid
				}
				kind := strings.TrimSpace(input[start:j])
				if kind == "" || strings.ContainsAny(kind, "\x00\r\n") || strings.EqualFold(kind, "Identifier") {
					return s, ErrInvalid
				}
				if old, ok := s.Parameters[n]; ok && old != kind {
					return s, ErrInvalid
				}
				s.Parameters[n] = kind
				out.WriteString("{" + name + ":?}")
				i = j + 1
				continue
			}
		}
		r, n := utf8.DecodeRuneInString(input[i:])
		if r == utf8.RuneError && n == 1 || unicode.IsControl(r) && !strings.ContainsRune("\r\n\t", r) {
			return s, ErrInvalid
		}
		if unicode.IsLetter(r) || r == '_' {
			start := i
			i += n
			for i < len(input) && identifierByte(input[i]) {
				i++
			}
			word := input[start:i]
			upper := strings.ToUpper(word)
			if s.Verb == "" {
				s.Verb = upper
			}
			if upper == "SETTINGS" || upper == "OUTFILE" || upper == "TOTALS" {
				return s, ErrInvalid
			}
			if upper == "FORMAT" {
				j := i
				for j < len(input) && input[j] <= 32 {
					j++
				}
				if j == len(input) || input[j] != '(' {
					return s, ErrInvalid
				}
			}
			out.WriteString(word)
			continue
		}
		if unicode.IsDigit(r) {
			out.WriteByte('?')
			if number := clickHouseNumber.FindString(input[i:]); number != "" {
				i += len(number)
			} else {
				i += n
			}
			continue
		}
		out.WriteRune(r)
		i += n
	}
	s.Audit = strings.TrimSpace(out.String())
	switch s.Verb {
	case "", "SET", "USE", "BEGIN", "START", "COMMIT", "ROLLBACK", "SAVEPOINT", "KILL":
		return s, ErrInvalid
	}
	return s, nil
}
func clickHouseQuoteEnd(input string, i int) (int, error) {
	quote := input[i]
	i++
	for i < len(input) {
		if input[i] == '\\' && i+1 < len(input) {
			i += 2
			continue
		}
		if input[i] == quote {
			if i+1 < len(input) && input[i+1] == quote {
				i += 2
				continue
			}
			return i + 1, nil
		}
		i++
	}
	return i, ErrInvalid
}
