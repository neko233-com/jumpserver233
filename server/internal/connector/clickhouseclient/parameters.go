package clickhouseclient

import (
	"encoding/json"
	"github.com/neko233-com/jumpserver233/server/internal/connector/sqlclient"
	"sort"
	"strconv"
	"strings"
)

func bind(parameters []json.RawMessage, types map[int]string) (map[string]string, error) {
	values := map[string]string{}
	for index, kind := range types {
		if index > len(parameters) {
			return nil, sqlclient.ErrInvalid
		}
		var value any
		decoder := json.NewDecoder(strings.NewReader(string(parameters[index-1])))
		decoder.UseNumber()
		if decoder.Decode(&value) != nil {
			return nil, sqlclient.ErrInvalid
		}
		text, e := parameterValue(value, kind, false, 0)
		if e != nil {
			return nil, e
		}
		values["param_p"+strconv.Itoa(index)] = text
	}
	return values, nil
}

var escaped = strings.NewReplacer("\\", "\\\\", "\n", "\\n", "\r", "\\r", "\t", "\\t", "\b", "\\b", "\f", "\\f")

func quoted(value string) string {
	return "'" + strings.ReplaceAll(escaped.Replace(value), "'", "\\'") + "'"
}
func parameterValue(value any, kind string, nested bool, depth int) (string, error) {
	if depth > 32 {
		return "", sqlclient.ErrInvalid
	}
	name, args := typeParts(kind)
	if (strings.EqualFold(name, "Nullable") || strings.EqualFold(name, "LowCardinality")) && len(args) == 1 && value != nil {
		return parameterValue(value, args[0], nested, depth+1)
	}
	switch v := value.(type) {
	case nil:
		if nested {
			return "NULL", nil
		}
		return "\\N", nil
	case string:
		if strings.ContainsRune(v, 0) {
			return "", sqlclient.ErrInvalid
		}
		if nested {
			return quoted(v), nil
		}
		return escaped.Replace(v), nil
	case json.Number:
		return string(v), nil
	case bool:
		if v {
			return "1", nil
		}
		return "0", nil
	case []any:
		tuple := strings.EqualFold(name, "Tuple")
		parts := make([]string, len(v))
		if tuple && len(args) != len(v) {
			return "", sqlclient.ErrInvalid
		}
		for i, item := range v {
			elementType := ""
			if tuple {
				elementType = unnamed(args[i])
			} else if len(args) == 1 {
				elementType = args[0]
			}
			text, e := parameterValue(item, elementType, true, depth+1)
			if e != nil {
				return "", e
			}
			parts[i] = text
		}
		if tuple {
			return "(" + strings.Join(parts, ",") + ")", nil
		}
		return "[" + strings.Join(parts, ",") + "]", nil
	case map[string]any:
		keys := make([]string, 0, len(v))
		for key := range v {
			if strings.ContainsRune(key, 0) {
				return "", sqlclient.ErrInvalid
			}
			keys = append(keys, key)
		}
		sort.Strings(keys)
		parts := make([]string, 0, len(keys))
		elementType := ""
		if len(args) == 2 {
			elementType = args[1]
		}
		for _, key := range keys {
			text, e := parameterValue(v[key], elementType, true, depth+1)
			if e != nil {
				return "", e
			}
			parts = append(parts, quoted(key)+":"+text)
		}
		return "{" + strings.Join(parts, ",") + "}", nil
	}
	return "", sqlclient.ErrInvalid
}
func unnamed(kind string) string {
	if i := strings.IndexByte(kind, ' '); i >= 0 && !strings.ContainsAny(kind[:i], "(,'\"") {
		return strings.TrimSpace(kind[i+1:])
	}
	return kind
}
func typeParts(kind string) (string, []string) {
	kind = strings.TrimSpace(kind)
	open := strings.IndexByte(kind, '(')
	if open < 0 || !strings.HasSuffix(kind, ")") {
		return kind, nil
	}
	name := strings.TrimSpace(kind[:open])
	body := kind[open+1 : len(kind)-1]
	args := []string{}
	start, depth := 0, 0
	quote := byte(0)
	for i := 0; i < len(body); i++ {
		c := body[i]
		if quote != 0 {
			if c == '\\' {
				i++
			} else if c == quote {
				quote = 0
			}
			continue
		}
		switch c {
		case '\'', '"', '`':
			quote = c
		case '(':
			depth++
		case ')':
			depth--
		case ',':
			if depth == 0 {
				args = append(args, strings.TrimSpace(body[start:i]))
				start = i + 1
			}
		}
	}
	if start < len(body) {
		args = append(args, strings.TrimSpace(body[start:]))
	}
	return name, args
}
