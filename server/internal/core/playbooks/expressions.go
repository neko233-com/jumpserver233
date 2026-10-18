package playbooks

import (
	"encoding/json"
	"fmt"
	"math"
	"path"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"unicode"
)

var variablePath = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*|\[[0-9]{1,3}\])*$`)
var interpolation = regexp.MustCompile(`\{\{\s*([^{}]{1,512}?)\s*\}\}`)

type undefined struct{}
type expression struct {
	kind, value string
	left, right *expression
}
type expressionParser struct {
	tokens        []string
	offset, depth int
}

func tokenize(s string) ([]string, error) {
	if len(s) > 512 {
		return nil, ErrInvalid
	}
	out := []string{}
	for i := 0; i < len(s); {
		c := s[i]
		if c == ' ' || c == '\t' {
			i++
			continue
		}
		start := i
		if c == '\'' || c == '"' {
			quote := c
			i++
			for i < len(s) && s[i] != quote {
				if s[i] == '\\' {
					i++
					if i >= len(s) {
						return nil, ErrInvalid
					}
				}
				i++
			}
			if i >= len(s) {
				return nil, ErrInvalid
			}
			i++
			out = append(out, s[start:i])
			continue
		}
		if strings.ContainsRune("()", rune(c)) {
			i++
			out = append(out, string(c))
			continue
		}
		if strings.ContainsRune("=!<>", rune(c)) {
			i++
			if i < len(s) && s[i] == '=' {
				i++
			}
			op := s[start:i]
			if op == "=" || op == "!" {
				return nil, ErrInvalid
			}
			out = append(out, op)
			continue
		}
		for i < len(s) && !strings.ContainsRune(" \t()=!<>", rune(s[i])) {
			i++
		}
		if i == start {
			return nil, ErrInvalid
		}
		token := s[start:i]
		if !variablePath.MatchString(token) && !slicesWord(token) && !numeric(token) {
			return nil, ErrInvalid
		}
		out = append(out, token)
		if len(out) > 128 {
			return nil, ErrInvalid
		}
	}
	return out, nil
}
func slicesWord(s string) bool {
	switch s {
	case "and", "or", "not", "in", "is", "defined", "undefined", "failed", "succeeded", "changed", "skipped", "true", "false", "True", "False", "none", "None", "null":
		return true
	}
	return false
}
func numeric(s string) bool {
	if s == "" || !strings.ContainsRune("-+0123456789", rune(s[0])) {
		return false
	}
	n, e := strconv.ParseFloat(s, 64)
	return e == nil && !math.IsInf(n, 0) && !math.IsNaN(n)
}
func (p *expressionParser) take(s string) bool {
	if p.offset < len(p.tokens) && p.tokens[p.offset] == s {
		p.offset++
		return true
	}
	return false
}
func (p *expressionParser) parse(min int) (*expression, error) {
	p.depth++
	defer func() { p.depth-- }()
	if p.depth > 32 || p.offset >= len(p.tokens) {
		return nil, ErrInvalid
	}
	var left *expression
	if p.take("not") {
		x, e := p.parse(3)
		if e != nil {
			return nil, e
		}
		left = &expression{kind: "not", left: x}
	} else if p.take("(") {
		x, e := p.parse(0)
		if e != nil || !p.take(")") {
			return nil, ErrInvalid
		}
		left = x
	} else {
		token := p.tokens[p.offset]
		p.offset++
		if slicesWord(token) && !strings.Contains(" true false True False none None null ", " "+token+" ") {
			return nil, ErrInvalid
		}
		left = &expression{kind: "value", value: token}
	}
	for p.offset < len(p.tokens) {
		op := p.tokens[p.offset]
		prec := 0
		switch op {
		case "or":
			prec = 1
		case "and":
			prec = 2
		case "==", "!=", "<", ">", "<=", ">=", "in", "is", "not":
			prec = 3
		default:
			return left, nil
		}
		if prec < min {
			return left, nil
		}
		p.offset++
		if op == "is" {
			neg := p.take("not")
			if p.offset >= len(p.tokens) {
				return nil, ErrInvalid
			}
			test := p.tokens[p.offset]
			p.offset++
			if !strings.Contains(" defined undefined failed succeeded changed skipped ", " "+test+" ") {
				return nil, ErrInvalid
			}
			if neg {
				test = "not " + test
			}
			left = &expression{kind: "is", value: test, left: left}
			continue
		}
		if op == "not" {
			if !p.take("in") {
				return nil, ErrInvalid
			}
			op = "not in"
		}
		right, e := p.parse(prec + 1)
		if e != nil {
			return nil, e
		}
		left = &expression{kind: op, left: left, right: right}
	}
	return left, nil
}
func parseExpression(s string) (*expression, error) {
	t, e := tokenize(strings.TrimSpace(s))
	if e != nil || len(t) == 0 {
		return nil, ErrInvalid
	}
	p := expressionParser{tokens: t}
	x, e := p.parse(0)
	if e != nil || p.offset != len(t) {
		return nil, ErrInvalid
	}
	return x, nil
}
func ValidateExpression(s string) error { _, e := parseExpression(s); return e }
func truth(v any) (bool, error) {
	switch x := v.(type) {
	case undefined:
		return false, ErrInvalid
	case nil:
		return false, nil
	case bool:
		return x, nil
	case string:
		return x != "", nil
	case float64:
		return x != 0, nil
	case int:
		return x != 0, nil
	case int64:
		return x != 0, nil
	case []any:
		return len(x) > 0, nil
	case []string:
		return len(x) > 0, nil
	case map[string]any:
		return len(x) > 0, nil
	}
	return false, ErrInvalid
}
func resolve(name string, values map[string]any) any {
	if !variablePath.MatchString(name) {
		return undefined{}
	}
	parts := strings.FieldsFunc(strings.ReplaceAll(strings.ReplaceAll(name, "[", "."), "]", ""), func(r rune) bool { return r == '.' })
	var current any = values
	for _, part := range parts {
		switch v := current.(type) {
		case map[string]any:
			x, ok := v[part]
			if !ok {
				return undefined{}
			}
			current = x
		case []any:
			i, e := strconv.Atoi(part)
			if e != nil || i < 0 || i >= len(v) {
				return undefined{}
			}
			current = v[i]
		case []string:
			i, e := strconv.Atoi(part)
			if e != nil || i < 0 || i >= len(v) {
				return undefined{}
			}
			current = v[i]
		default:
			return undefined{}
		}
	}
	return current
}
func (x *expression) evaluate(values map[string]any) (any, error) {
	if x.kind == "value" {
		s := x.value
		if strings.HasPrefix(s, "'") || strings.HasPrefix(s, "\"") {
			if s[0] == '\'' {
				return strings.ReplaceAll(strings.ReplaceAll(s[1:len(s)-1], `\'`, `'`), `\\`, `\`), nil
			}
			v, e := strconv.Unquote(s)
			return v, e
		}
		switch s {
		case "true", "True":
			return true, nil
		case "false", "False":
			return false, nil
		case "none", "None", "null":
			return nil, nil
		}
		if numeric(s) {
			n, e := strconv.ParseFloat(s, 64)
			return n, e
		}
		return resolve(s, values), nil
	}
	a, e := x.left.evaluate(values)
	if e != nil {
		return nil, e
	}
	if x.kind == "is" {
		_, missing := a.(undefined)
		test := strings.TrimPrefix(x.value, "not ")
		out := false
		switch test {
		case "defined":
			out = !missing
		case "undefined":
			out = missing
		default:
			if missing {
				return nil, ErrInvalid
			}
			m, ok := a.(map[string]any)
			if !ok {
				return nil, ErrInvalid
			}
			if test == "succeeded" {
				out = m["failed"] == false && m["skipped"] != true
			} else {
				out = m[test] == true
			}
		}
		if strings.HasPrefix(x.value, "not ") {
			out = !out
		}
		return out, nil
	}
	if x.kind == "not" {
		v, e := truth(a)
		return !v, e
	}
	if x.kind == "and" || x.kind == "or" {
		v, e := truth(a)
		if e != nil {
			return nil, e
		}
		if x.kind == "and" && !v || x.kind == "or" && v {
			return v, nil
		}
		b, e := x.right.evaluate(values)
		if e != nil {
			return nil, e
		}
		return truth(b)
	}
	b, e := x.right.evaluate(values)
	if e != nil {
		return nil, e
	}
	if _, ok := a.(undefined); ok {
		return nil, ErrInvalid
	}
	if _, ok := b.(undefined); ok {
		return nil, ErrInvalid
	}
	switch x.kind {
	case "==", "!=":
		same := equal(a, b)
		if x.kind == "!=" {
			same = !same
		}
		return same, nil
	case "in", "not in":
		found := false
		switch list := b.(type) {
		case string:
			s, ok := a.(string)
			if !ok {
				return nil, ErrInvalid
			}
			found = strings.Contains(list, s)
		case []any:
			for _, v := range list {
				if equal(a, v) {
					found = true
					break
				}
			}
		case []string:
			for _, v := range list {
				if equal(a, v) {
					found = true
					break
				}
			}
		case map[string]any:
			s, ok := a.(string)
			if !ok {
				return nil, ErrInvalid
			}
			_, found = list[s]
		default:
			return nil, ErrInvalid
		}
		if x.kind == "not in" {
			found = !found
		}
		return found, nil
	}
	var cmp int
	if af, ok := asNumber(a); ok {
		bf, ok := asNumber(b)
		if !ok {
			return nil, ErrInvalid
		}
		if af < bf {
			cmp = -1
		} else if af > bf {
			cmp = 1
		}
	} else {
		av, ok := a.(string)
		bv, ok2 := b.(string)
		if !ok || !ok2 {
			return nil, ErrInvalid
		}
		cmp = strings.Compare(av, bv)
	}
	switch x.kind {
	case "<":
		return cmp < 0, nil
	case ">":
		return cmp > 0, nil
	case "<=":
		return cmp <= 0, nil
	case ">=":
		return cmp >= 0, nil
	}
	return nil, ErrInvalid
}
func asNumber(v any) (float64, bool) {
	switch n := v.(type) {
	case float64:
		return n, true
	case int:
		return float64(n), true
	case int64:
		return float64(n), true
	case uint64:
		return float64(n), true
	case json.Number:
		f, e := n.Float64()
		return f, e == nil
	}
	return 0, false
}
func equal(a, b any) bool {
	if af, ok := asNumber(a); ok {
		if bf, ok := asNumber(b); ok {
			return af == bf
		}
	}
	return reflect.DeepEqual(a, b)
}
func All(conditions []string, values map[string]any) (bool, error) {
	for _, condition := range conditions {
		x, e := parseExpression(condition)
		if e != nil {
			return false, e
		}
		v, e := x.evaluate(values)
		if e != nil {
			return false, e
		}
		ok, e := truth(v)
		if e != nil || !ok {
			return ok, e
		}
	}
	return true, nil
}
func quote(s string) string { return "'" + strings.ReplaceAll(s, "'", "'\"'\"'") + "'" }
func scalar(v any) (string, error) {
	switch x := v.(type) {
	case string:
		return x, nil
	case bool:
		return strconv.FormatBool(x), nil
	case nil:
		return "", nil
	case int:
		return strconv.Itoa(x), nil
	case int64:
		return strconv.FormatInt(x, 10), nil
	case float64:
		return strconv.FormatFloat(x, 'g', -1, 64), nil
	}
	return "", ErrInvalid
}
func templateValue(source string, values map[string]any) (any, error) {
	fields := strings.Split(source, "|")
	if len(fields) > 8 {
		return nil, ErrInvalid
	}
	key := strings.TrimSpace(fields[0])
	if !variablePath.MatchString(key) {
		return nil, ErrInvalid
	}
	v := resolve(key, values)
	for _, raw := range fields[1:] {
		f := strings.TrimSpace(raw)
		switch {
		case strings.HasPrefix(f, "default(") && strings.HasSuffix(f, ")"):
			if _, missing := v.(undefined); missing || v == nil {
				literal := strings.TrimSpace(f[8 : len(f)-1])
				x, e := parseExpression(literal)
				if e != nil || x.kind != "value" {
					return nil, ErrInvalid
				}
				v, e = x.evaluate(map[string]any{})
				if e != nil {
					return nil, e
				}
			}
		case f == "length":
			switch x := v.(type) {
			case string:
				v = len(x)
			case []any:
				v = len(x)
			case []string:
				v = len(x)
			case map[string]any:
				v = len(x)
			default:
				return nil, ErrInvalid
			}
		case f == "bool":
			s, e := scalar(v)
			if e != nil {
				return nil, e
			}
			switch strings.ToLower(s) {
			case "true", "yes", "1", "on":
				v = true
			case "false", "no", "0", "off", "":
				v = false
			default:
				return nil, ErrInvalid
			}
		case f == "int":
			s, e := scalar(v)
			if e != nil {
				return nil, e
			}
			n, e := strconv.ParseInt(s, 10, 64)
			if e != nil {
				return nil, e
			}
			v = n
		case f == "from_json":
			s, ok := v.(string)
			if !ok || len(s) > 4096 || json.Unmarshal([]byte(s), &v) != nil {
				return nil, ErrInvalid
			}
		case f == "to_json":
			if _, missing := v.(undefined); missing {
				return nil, ErrInvalid
			}
			raw, e := json.Marshal(v)
			if e != nil {
				return nil, e
			}
			v = string(raw)
		case strings.HasPrefix(f, "join(") && strings.HasSuffix(f, ")"):
			x, e := parseExpression(strings.TrimSpace(f[5 : len(f)-1]))
			if e != nil || x.kind != "value" {
				return nil, ErrInvalid
			}
			sep, e := x.evaluate(map[string]any{})
			if e != nil {
				return nil, e
			}
			s, ok := sep.(string)
			if !ok {
				return nil, ErrInvalid
			}
			var list []string
			switch a := v.(type) {
			case []string:
				list = a
			case []any:
				for _, item := range a {
					str, e := scalar(item)
					if e != nil {
						return nil, e
					}
					list = append(list, str)
				}
			default:
				return nil, ErrInvalid
			}
			v = strings.Join(list, s)
		default:
			s, e := scalar(v)
			if e != nil {
				return nil, e
			}
			switch f {
			case "quote":
				v = quote(s)
			case "lower":
				v = strings.ToLower(s)
			case "upper":
				v = strings.ToUpper(s)
			case "trim":
				v = strings.TrimSpace(s)
			case "string":
				v = s
			case "basename":
				v = path.Base(s)
			case "dirname":
				v = path.Dir(s)
			default:
				return nil, ErrInvalid
			}
		}
	}
	if _, missing := v.(undefined); missing {
		return nil, ErrInvalid
	}
	return v, nil
}
func Render(source string, values map[string]any) (string, error) {
	if strings.Contains(source, "{%") || strings.Contains(source, "{#") {
		return "", ErrInvalid
	}
	var problem error
	out := interpolation.ReplaceAllStringFunc(source, func(found string) string {
		v, e := templateValue(found[2:len(found)-2], values)
		if e != nil {
			problem = e
			return ""
		}
		s, e := scalar(v)
		if e != nil {
			problem = e
		}
		return s
	})
	if problem != nil || len(out) > 16<<10 || strings.Contains(out, "{{") || strings.Contains(out, "}}") || strings.ContainsRune(out, 0) {
		return "", ErrInvalid
	}
	return out, nil
}
func RenderValue(in any, values map[string]any) (any, error) {
	switch v := in.(type) {
	case string:
		trim := strings.TrimSpace(v)
		matches := interpolation.FindStringIndex(trim)
		if matches != nil && matches[0] == 0 && matches[1] == len(trim) {
			return templateValue(trim[2:len(trim)-2], values)
		}
		return Render(v, values)
	case []any:
		out := make([]any, len(v))
		for i, x := range v {
			r, e := RenderValue(x, values)
			if e != nil {
				return nil, e
			}
			out[i] = r
		}
		return out, nil
	case map[string]any:
		out := map[string]any{}
		for k, x := range v {
			r, e := RenderValue(x, values)
			if e != nil {
				return nil, e
			}
			out[k] = r
		}
		return out, nil
	default:
		return in, nil
	}
}
func LoopValues(loop any, values map[string]any) ([]any, error) {
	if loop == nil {
		return []any{nil}, nil
	}
	v, e := RenderValue(loop, values)
	if e != nil {
		return nil, e
	}
	out, ok := v.([]any)
	if !ok || len(out) > 50 {
		return nil, ErrInvalid
	}
	raw, e := json.Marshal(out)
	if e != nil || len(raw) > 8192 {
		return nil, ErrInvalid
	}
	return out, nil
}

func ResolveVariables(base, defaults, bindings map[string]any, allowMissing bool) (map[string]any, error) {
	vars := Overlay(defaults, bindings)
	for key := range vars {
		if _, exists := base[key]; exists {
			if _, bound := bindings[key]; !bound {
				delete(vars, key)
			}
		}
	}
	env := Overlay(base, vars)
	for range 8 {
		changed := false
		for key, value := range vars {
			rendered, e := RenderValue(value, env)
			if e != nil {
				if !allowMissing {
					continue
				}
				continue
			}
			if !reflect.DeepEqual(rendered, vars[key]) {
				vars[key] = rendered
				env[key] = rendered
				changed = true
			}
		}
		if !changed {
			break
		}
	}
	if !allowMissing {
		for _, value := range vars {
			if unresolved(value) {
				return nil, ErrInvalid
			}
		}
	}
	raw, e := json.Marshal(env)
	if e != nil || len(raw) > 80<<10 {
		return nil, ErrInvalid
	}
	return env, nil
}
func unresolved(v any) bool {
	switch x := v.(type) {
	case string:
		return strings.Contains(x, "{{") || strings.Contains(x, "}}") || strings.Contains(x, "{%")
	case []any:
		for _, v := range x {
			if unresolved(v) {
				return true
			}
		}
	case map[string]any:
		for _, v := range x {
			if unresolved(v) {
				return true
			}
		}
	}
	return false
}
func splitLines(s string) []string { return strings.Split(strings.TrimSuffix(s, "\n"), "\n") }
func validAccount(s string) bool {
	if s == "" || len(s) > 64 {
		return false
	}
	for i, c := range s {
		if !(unicode.IsLetter(c) && c < 128 || c == '_' || c == '-' || i > 0 && unicode.IsDigit(c)) {
			return false
		}
	}
	return true
}
func argument(values map[string]any, key string, defaultValue string) (string, error) {
	v, ok := values[key]
	if !ok {
		return defaultValue, nil
	}
	return scalar(v)
}
func invalidTask(t Task, field string) error {
	return &Issue{Code: "module_invalid", File: t.File, Line: t.Line, Field: field}
}
func checkArgs(args map[string]any, allowed []string) error {
	for key := range args {
		found := false
		for _, v := range allowed {
			if key == v {
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("unsupported module argument")
		}
	}
	return nil
}
