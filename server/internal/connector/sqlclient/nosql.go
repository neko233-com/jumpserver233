package sqlclient

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"strconv"
	"strings"
)

// JSONFields preserves MongoDB command order and rejects duplicate keys at every
// depth, ambiguous documents and excessively nested input before BSON decoding.
type JSONField struct {
	Key   string
	Value json.RawMessage
}

func StrictJSON(raw []byte) error {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	count := 0
	var value func(int) error
	value = func(depth int) error {
		if depth > 32 || count > MaxResultCells {
			return ErrInvalid
		}
		count++
		v, e := d.Token()
		if e != nil {
			return ErrInvalid
		}
		delimiter, ok := v.(json.Delim)
		if !ok {
			return nil
		}
		switch delimiter {
		case '{':
			seen := map[string]bool{}
			for d.More() {
				token, e := d.Token()
				if e != nil {
					return ErrInvalid
				}
				key, ok := token.(string)
				if !ok || seen[key] || strings.ContainsRune(key, 0) {
					return ErrInvalid
				}
				seen[key] = true
				if e = value(depth + 1); e != nil {
					return e
				}
			}
			end, e := d.Token()
			if e != nil || end != json.Delim('}') {
				return ErrInvalid
			}
		case '[':
			for d.More() {
				if e = value(depth + 1); e != nil {
					return e
				}
			}
			end, e := d.Token()
			if e != nil || end != json.Delim(']') {
				return ErrInvalid
			}
		default:
			return ErrInvalid
		}
		return nil
	}
	if value(0) != nil {
		return ErrInvalid
	}
	if _, e := d.Token(); e != io.EOF {
		return ErrInvalid
	}
	return nil
}
func JSONFields(raw []byte) ([]JSONField, error) {
	if StrictJSON(raw) != nil {
		return nil, ErrInvalid
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	v, e := d.Token()
	if e != nil || v != json.Delim('{') {
		return nil, ErrInvalid
	}
	fields := []JSONField{}
	for d.More() {
		key, e := d.Token()
		if e != nil {
			return nil, ErrInvalid
		}
		var raw json.RawMessage
		if d.Decode(&raw) != nil {
			return nil, ErrInvalid
		}
		fields = append(fields, JSONField{key.(string), raw})
	}
	return fields, nil
}
func commandName(name string) bool {
	if len(name) == 0 || len(name) > 64 {
		return false
	}
	for _, c := range name {
		if c != '_' && c != '.' && c != '-' && (c < 'A' || c > 'Z') && (c < 'a' || c > 'z') && (c < '0' || c > '9') {
			return false
		}
	}
	return true
}
func RedisCommand(raw string) ([][]byte, error) {
	if StrictJSON([]byte(raw)) != nil {
		return nil, ErrInvalid
	}
	var items []json.RawMessage
	if json.Unmarshal([]byte(raw), &items) != nil || len(items) < 1 || len(items) > 1001 {
		return nil, ErrInvalid
	}
	out := make([][]byte, len(items))
	total := 0
	for i, item := range items {
		var text string
		if json.Unmarshal(item, &text) == nil {
			out[i] = []byte(text)
		} else {
			var bin struct {
				Base64 *string `json:"base64"`
			}
			fields, e := JSONFields(item)
			if e != nil || len(fields) != 1 || fields[0].Key != "base64" || json.Unmarshal(item, &bin) != nil || bin.Base64 == nil {
				return nil, ErrInvalid
			}
			decoded, e := base64.StdEncoding.Strict().DecodeString(*bin.Base64)
			if e != nil {
				return nil, ErrInvalid
			}
			out[i] = decoded
		}
		total += len(out[i])
		if total > MaxParameterBytes {
			return nil, ErrInvalid
		}
	}
	if !commandName(string(out[0])) {
		return nil, ErrInvalid
	}
	out[0] = []byte(strings.ToUpper(string(out[0])))
	return out, nil
}
func AuditRedis(raw string) (string, error) {
	args, e := RedisCommand(raw)
	if e != nil {
		return "", e
	}
	parts := []string{strconv.Quote(string(args[0]))}
	for range args[1:] {
		parts = append(parts, `"?"`)
	}
	return "[" + strings.Join(parts, ",") + "]", nil
}
func AuditMongoDB(raw string) (string, error) {
	fields, e := JSONFields([]byte(raw))
	if e != nil || len(fields) == 0 || !commandName(fields[0].Key) {
		return "", ErrInvalid
	}
	return `{"command":` + strconv.Quote(fields[0].Key) + `,"arguments":"?"}`, nil
}
