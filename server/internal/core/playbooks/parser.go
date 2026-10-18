package playbooks

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"go.yaml.in/yaml/v3"
	"io"
	"math"
	"path"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

var identifier = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,63}$`)
var modules = []string{"shell", "command", "copy", "template", "file", "service", "systemd_service", "package", "user", "stat", "assert", "debug", "set_fact", "pause", "setup", "fail"}
var taskFields = []string{"name", "vars", "when", "register", "loop", "notify", "become", "become_user", "ignore_errors", "timeout", "until", "retries", "delay", "changed_when", "failed_when", "args", "include_tasks", "import_tasks", "tags", "check_mode"}

func Modules() []string { return slices.Clone(modules) }
func ValidVariable(name string) bool {
	return identifier.MatchString(name) && !slices.Contains([]string{"inventory_hostname", "jms_asset_id", "ansible_facts", "item", "result", "hostvars", "lookup", "query"}, name)
}
func ValidFile(name string) bool {
	return name != "" && len(name) <= 128 && path.Clean(name) == name && !strings.HasPrefix(name, "/") && name != ".." && !strings.HasPrefix(name, "../") && !strings.ContainsAny(name, "\\:\x00\r\n") && utf8.ValidString(name)
}
func WorkspaceID(files map[string]string) string {
	raw, _ := json.Marshal(files)
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}
func Compile(in Workspace) (Program, error) {
	p := Program{Version: 1, Files: map[string]string{}, Tasks: []Task{}}
	if len(in.Files) < 1 || len(in.Files) > MaxFiles {
		return p, &Issue{Code: "workspace_size"}
	}
	total := 0
	for name, content := range in.Files {
		if !ValidFile(name) || !utf8.ValidString(content) || strings.ContainsRune(content, 0) || len(content) > MaxFileBytes {
			return p, &Issue{Code: "file_invalid", File: name}
		}
		total += len(content)
		p.Files[name] = content
	}
	if total > MaxWorkspaceBytes {
		return p, &Issue{Code: "workspace_size"}
	}
	if _, ok := p.Files["main.yml"]; !ok {
		return p, &Issue{Code: "main_missing", File: "main.yml"}
	}
	root, e := readYAML("main.yml", p.Files["main.yml"])
	if e != nil {
		return p, e
	}
	if root.Kind != yaml.SequenceNode || len(root.Content) < 1 || len(root.Content) > 8 {
		return p, &Issue{Code: "plays_invalid", File: "main.yml", Line: root.Line}
	}
	for index, node := range root.Content {
		values, e := nodeMap(node, []string{"name", "hosts", "gather_facts", "vars", "become", "become_user", "pre_tasks", "tasks", "post_tasks", "handlers"}, "main.yml")
		if e != nil {
			return p, e
		}
		hosts, e := text(values["hosts"], "all")
		if e != nil || hosts != "all" && hosts != "*" {
			return p, issue(node, "main.yml", "hosts_invalid", "hosts")
		}
		inherited := Task{Play: index, Vars: map[string]any{}}
		if v := values["vars"]; v != nil {
			inherited.Vars, e = variables(v, "main.yml")
			if e != nil {
				return p, e
			}
		}
		inherited.Become, e = boolean(values["become"], false)
		if e != nil {
			return p, issue(node, "main.yml", "type_invalid", "become")
		}
		inherited.BecomeUser, e = text(values["become_user"], "root")
		if e != nil || !validAccount(inherited.BecomeUser) {
			return p, issue(node, "main.yml", "account_invalid", "become_user")
		}
		facts, e := boolean(values["gather_facts"], false)
		if e != nil {
			return p, issue(node, "main.yml", "type_invalid", "gather_facts")
		}
		if facts {
			t := inherited
			t.Module = "setup"
			t.Name = "setup"
			t.File = "main.yml"
			t.Line = node.Line
			t.Args = map[string]any{}
			p.Tasks = append(p.Tasks, t)
		}
		start := len(p.Tasks)
		for _, section := range []string{"pre_tasks", "tasks", "post_tasks", "handlers"} {
			if v := values[section]; v != nil {
				base := inherited
				base.Handler = section == "handlers"
				if e = appendTasks(&p, v, "main.yml", base, []string{"main.yml"}); e != nil {
					return p, e
				}
			}
		}
		if len(p.Tasks) == start && !facts {
			return p, issue(node, "main.yml", "tasks_missing", "tasks")
		}
	}
	handlers := map[string]bool{}
	for i := range p.Tasks {
		t := &p.Tasks[i]
		t.ID = fmt.Sprintf("task-%d", i)
		n := 1
		if list, ok := t.Loop.([]any); ok {
			n = max(1, len(list))
		} else if t.Loop != nil {
			n = 50
		}
		p.MaxSteps += n * (t.Retries + 1)
		if t.Handler {
			key := fmt.Sprintf("%d:%s", t.Play, t.Name)
			if handlers[key] {
				return p, &Issue{Code: "handler_duplicate", File: t.File, Line: t.Line}
			}
			handlers[key] = true
		}
	}
	if len(p.Tasks) > MaxTasks || p.MaxSteps > MaxExpandedTasks {
		return p, &Issue{Code: "tasks_limit"}
	}
	for _, t := range p.Tasks {
		for _, name := range t.Notify {
			if !handlers[fmt.Sprintf("%d:%s", t.Play, name)] {
				return p, &Issue{Code: "handler_missing", File: t.File, Line: t.Line}
			}
		}
	}
	return p, nil
}
func appendTasks(p *Program, node *yaml.Node, file string, base Task, stack []string) error {
	if node.Kind != yaml.SequenceNode || len(stack) > 8 {
		return issue(node, file, "tasks_invalid", "")
	}
	for _, n := range node.Content {
		if len(p.Tasks) >= MaxTasks {
			return issue(n, file, "tasks_limit", "")
		}
		allowed := append(slices.Clone(taskFields), modules...)
		for _, m := range modules {
			allowed = append(allowed, "ansible.builtin."+m)
		}
		allowed = append(allowed, "ansible.builtin.include_tasks", "ansible.builtin.import_tasks", "systemd", "ansible.builtin.systemd")
		v, e := nodeMap(n, allowed, file)
		if e != nil {
			return e
		}
		t := base
		t.Args = map[string]any{}
		t.File = file
		t.Line = n.Line
		t.Name, e = text(v["name"], "")
		if e != nil || len(t.Name) > 100 || strings.IndexFunc(t.Name, unicode.IsControl) >= 0 {
			return issue(n, file, "name_invalid", "name")
		}
		if values := v["vars"]; values != nil {
			extra, e := variables(values, file)
			if e != nil {
				return e
			}
			t.Vars = Overlay(t.Vars, extra)
		}
		ownWhen, whenErr := conditions(v["when"])
		if whenErr != nil {
			return issue(n, file, "condition_invalid", "when")
		}
		t.When = append(slices.Clone(base.When), ownWhen...)
		if t.ChangedWhen, e = conditions(v["changed_when"]); e != nil {
			return issue(n, file, "condition_invalid", "changed_when")
		}
		if t.FailedWhen, e = conditions(v["failed_when"]); e != nil {
			return issue(n, file, "condition_invalid", "failed_when")
		}
		if t.Until, e = conditions(v["until"]); e != nil {
			return issue(n, file, "condition_invalid", "until")
		}
		if t.Register, e = text(v["register"], ""); e != nil || t.Register != "" && !ValidVariable(t.Register) {
			return issue(n, file, "variable_invalid", "register")
		}
		if t.Notify, e = texts(v["notify"]); e != nil || len(t.Notify) > 16 {
			return issue(n, file, "notify_invalid", "notify")
		}
		if t.Become, e = boolean(v["become"], t.Become); e != nil {
			return issue(n, file, "type_invalid", "become")
		}
		if t.BecomeUser, e = text(v["become_user"], t.BecomeUser); e != nil || !validAccount(t.BecomeUser) {
			return issue(n, file, "account_invalid", "become_user")
		}
		if t.IgnoreErrors, e = boolean(v["ignore_errors"], base.IgnoreErrors); e != nil {
			return issue(n, file, "type_invalid", "ignore_errors")
		}
		if t.Timeout, e = number(v["timeout"], base.Timeout, 0, 300); e != nil {
			return issue(n, file, "timeout_invalid", "timeout")
		}
		if t.Retries, e = number(v["retries"], 0, 0, 5); e != nil {
			return issue(n, file, "retry_invalid", "retries")
		}
		if t.Delay, e = number(v["delay"], 1, 1, 60); e != nil {
			return issue(n, file, "retry_invalid", "delay")
		}
		if len(t.Until) > 0 && v["retries"] == nil {
			t.Retries = 3
		}
		if t.Retries > 0 && len(t.Until) == 0 || len(t.Until) > 0 && t.Retries == 0 {
			return issue(n, file, "retry_invalid", "until")
		}
		if check := v["check_mode"]; check != nil {
			mode, e := boolean(check, false)
			if e != nil || mode {
				return issue(n, file, "check_mode_unsupported", "check_mode")
			}
		}
		if tags := v["tags"]; tags != nil {
			if _, e = texts(tags); e != nil {
				return issue(n, file, "type_invalid", "tags")
			}
		}
		if loop := v["loop"]; loop != nil {
			t.Loop, e = value(loop)
			if e != nil {
				return issue(n, file, "loop_invalid", "loop")
			}
			switch x := t.Loop.(type) {
			case []any:
				if len(x) > 50 {
					return issue(n, file, "loop_invalid", "loop")
				}
			case string:
				if !strings.HasPrefix(x, "{{") || !strings.HasSuffix(x, "}}") {
					return issue(n, file, "loop_invalid", "loop")
				}
			default:
				return issue(n, file, "loop_invalid", "loop")
			}
		}
		included := ""
		moduleCount := 0
		for key, node := range v {
			module := strings.TrimPrefix(key, "ansible.builtin.")
			if module == "systemd" {
				module = "systemd_service"
			}
			if module == "include_tasks" || module == "import_tasks" {
				included, e = text(node, "")
				if e != nil || included == "" {
					return issue(n, file, "include_invalid", key)
				}
				moduleCount++
				continue
			}
			if !slices.Contains(modules, module) {
				continue
			}
			t.Module = module
			moduleCount++
			arg, e := value(node)
			if e != nil {
				return issue(n, file, "module_invalid", key)
			}
			switch x := arg.(type) {
			case map[string]any:
				t.Args = x
			case string:
				t.Args["_raw"] = x
			case nil:
			default:
				return issue(n, file, "module_invalid", key)
			}
		}
		if moduleCount != 1 {
			return issue(n, file, "module_count", "")
		}
		if args := v["args"]; args != nil {
			a, e := value(args)
			if e != nil {
				return issue(n, file, "args_invalid", "args")
			}
			m, ok := a.(map[string]any)
			if !ok {
				return issue(n, file, "args_invalid", "args")
			}
			for k, x := range m {
				if _, exists := t.Args[k]; exists {
					return issue(n, file, "duplicate_key", k)
				}
				t.Args[k] = x
			}
		}
		if included != "" {
			target := path.Join(path.Dir(file), included)
			if !ValidFile(included) || !ValidFile(target) || slices.Contains(stack, target) || t.Loop != nil || t.Register != "" || len(t.Notify) > 0 || len(t.Until) > 0 {
				return issue(n, file, "include_invalid", "")
			}
			content, ok := p.Files[target]
			if !ok {
				return issue(n, file, "include_missing", target)
			}
			root, e := readYAML(target, content)
			if e != nil {
				return e
			}
			if e = appendTasks(p, root, target, t, append(slices.Clone(stack), target)); e != nil {
				return e
			}
			continue
		}
		if t.Name == "" {
			t.Name = t.Module
		}
		if e = validateArgs(t); e != nil {
			return e
		}
		p.Tasks = append(p.Tasks, t)
	}
	return nil
}
func readYAML(file, source string) (*yaml.Node, error) {
	decoder := yaml.NewDecoder(strings.NewReader(source))
	var doc yaml.Node
	if decoder.Decode(&doc) != nil || len(doc.Content) != 1 {
		return nil, &Issue{Code: "yaml_invalid", File: file}
	}
	var second yaml.Node
	if decoder.Decode(&second) != io.EOF {
		return nil, &Issue{Code: "yaml_multiple", File: file}
	}
	count := 0
	var walk func(*yaml.Node, int) bool
	walk = func(n *yaml.Node, depth int) bool {
		count++
		if depth > 32 || count > 10000 || n.Kind == yaml.AliasNode || n.Anchor != "" || n.Alias != nil {
			return false
		}
		if n.Tag != "" && !slices.Contains([]string{"!!map", "!!seq", "!!str", "!!bool", "!!int", "!!float", "!!null"}, n.ShortTag()) {
			return false
		}
		if n.Kind == yaml.MappingNode {
			seen := map[string]bool{}
			for i := 0; i < len(n.Content); i += 2 {
				k := n.Content[i]
				if k.Kind != yaml.ScalarNode || k.ShortTag() != "!!str" || seen[k.Value] {
					return false
				}
				seen[k.Value] = true
			}
		}
		for _, c := range n.Content {
			if !walk(c, depth+1) {
				return false
			}
		}
		return true
	}
	if !walk(doc.Content[0], 0) {
		return nil, &Issue{Code: "yaml_structure", File: file}
	}
	return doc.Content[0], nil
}
func nodeMap(n *yaml.Node, allowed []string, file string) (map[string]*yaml.Node, error) {
	if n.Kind != yaml.MappingNode {
		return nil, issue(n, file, "mapping_required", "")
	}
	out := map[string]*yaml.Node{}
	for i := 0; i < len(n.Content); i += 2 {
		k := n.Content[i].Value
		if !slices.Contains(allowed, k) {
			return nil, issue(n.Content[i], file, "field_unsupported", k)
		}
		out[k] = n.Content[i+1]
	}
	return out, nil
}
func issue(n *yaml.Node, file, code, field string) *Issue {
	return &Issue{Code: code, File: file, Line: n.Line, Column: n.Column, Field: field}
}
func text(n *yaml.Node, fallback string) (string, error) {
	if n == nil {
		return fallback, nil
	}
	if n.Kind != yaml.ScalarNode || n.ShortTag() != "!!str" {
		return "", ErrInvalid
	}
	return n.Value, nil
}
func boolean(n *yaml.Node, fallback bool) (bool, error) {
	if n == nil {
		return fallback, nil
	}
	if n.Kind != yaml.ScalarNode || n.ShortTag() != "!!bool" {
		return false, ErrInvalid
	}
	return strconv.ParseBool(n.Value)
}
func number(n *yaml.Node, fallback, min, max int) (int, error) {
	if n == nil {
		return fallback, nil
	}
	v, e := strconv.Atoi(n.Value)
	if n.Kind != yaml.ScalarNode || n.ShortTag() != "!!int" || e != nil || v < min || v > max {
		return 0, ErrInvalid
	}
	return v, nil
}
func texts(n *yaml.Node) ([]string, error) {
	if n == nil {
		return nil, nil
	}
	if n.Kind == yaml.ScalarNode {
		x, e := text(n, "")
		return []string{x}, e
	}
	if n.Kind != yaml.SequenceNode || len(n.Content) > 50 {
		return nil, ErrInvalid
	}
	out := []string{}
	for _, v := range n.Content {
		x, e := text(v, "")
		if e != nil {
			return nil, e
		}
		out = append(out, x)
	}
	return out, nil
}
func conditions(n *yaml.Node) ([]string, error) {
	if n != nil && n.Kind == yaml.ScalarNode && n.ShortTag() == "!!bool" {
		return []string{n.Value}, nil
	}
	list, e := texts(n)
	if e != nil || len(list) > 16 {
		return nil, ErrInvalid
	}
	for _, x := range list {
		if len(x) > 512 || strings.ContainsAny(x, "\x00\r\n") {
			return nil, ErrInvalid
		}
	}
	return list, nil
}
func value(n *yaml.Node) (any, error) {
	switch n.Kind {
	case yaml.SequenceNode:
		out := []any{}
		for _, c := range n.Content {
			x, e := value(c)
			if e != nil {
				return nil, e
			}
			out = append(out, x)
		}
		return out, nil
	case yaml.MappingNode:
		out := map[string]any{}
		for i := 0; i < len(n.Content); i += 2 {
			x, e := value(n.Content[i+1])
			if e != nil {
				return nil, e
			}
			out[n.Content[i].Value] = x
		}
		return out, nil
	case yaml.ScalarNode:
		var out any
		if n.Decode(&out) != nil {
			return nil, ErrInvalid
		}
		switch x := out.(type) {
		case int:
			if x > 1<<53-1 || x < -(1<<53-1) {
				return nil, ErrInvalid
			}
		case uint64:
			if x > 1<<53-1 {
				return nil, ErrInvalid
			}
		case float64:
			if math.IsInf(x, 0) || math.IsNaN(x) || math.Abs(x) > 1<<53-1 {
				return nil, ErrInvalid
			}
		}
		return out, nil
	}
	return nil, ErrInvalid
}
func variables(n *yaml.Node, file string) (map[string]any, error) {
	v, e := value(n)
	if e != nil {
		return nil, e
	}
	out, ok := v.(map[string]any)
	if !ok || len(out) > 64 {
		return nil, issue(n, file, "variables_invalid", "")
	}
	for k := range out {
		if !ValidVariable(k) {
			return nil, issue(n, file, "variable_invalid", k)
		}
	}
	raw, e := json.Marshal(out)
	if e != nil || len(raw) > 8192 {
		return nil, issue(n, file, "variables_invalid", "")
	}
	return out, nil
}
