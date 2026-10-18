package playbooks

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"path"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

type Action struct {
	Command      string `json:"command,omitempty"`
	Local        string `json:"local,omitempty"`
	Value        any    `json:"value,omitempty"`
	PauseSeconds int    `json:"pause_seconds,omitempty"`
}

var packageName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9+_.:-]{0,127}$`)
var serviceName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.@:-]{0,127}$`)
var modeValue = regexp.MustCompile(`^0?[0-7]{3}$`)
var moduleArgs = map[string][]string{
	"shell":           {"_raw", "cmd", "chdir", "creates", "removes", "executable"},
	"command":         {"_raw", "cmd", "argv", "chdir", "creates", "removes"},
	"copy":            {"src", "content", "dest", "mode", "owner", "group"},
	"template":        {"src", "dest", "mode", "owner", "group"},
	"file":            {"path", "dest", "state", "mode", "owner", "group"},
	"service":         {"name", "state", "enabled", "scope"},
	"systemd_service": {"name", "state", "enabled", "scope", "daemon_reload"},
	"package":         {"name", "state", "update_cache"},
	"user":            {"name", "state", "uid", "shell", "home", "create_home", "groups", "append", "remove"},
	"stat":            {"path"}, "assert": {"that", "fail_msg", "success_msg"}, "debug": {"msg", "var"}, "set_fact": {}, "pause": {"seconds"}, "setup": {}, "fail": {"msg"},
}

func validateArgs(t Task) error {
	allowed, ok := moduleArgs[t.Module]
	if !ok {
		return invalidTask(t, "module")
	}
	if t.Module == "set_fact" {
		if len(t.Args) < 1 || len(t.Args) > 32 {
			return invalidTask(t, "set_fact")
		}
		for key := range t.Args {
			if !ValidVariable(key) {
				return invalidTask(t, key)
			}
		}
	} else if checkArgs(t.Args, allowed) != nil {
		return invalidTask(t, "args")
	}
	for _, group := range [][]string{t.When, t.ChangedWhen, t.FailedWhen, t.Until} {
		for _, condition := range group {
			if ValidateExpression(condition) != nil {
				return invalidTask(t, "condition")
			}
		}
	}
	raw, e := json.Marshal(t.Args)
	if e != nil || len(raw) > MaxFileBytes {
		return invalidTask(t, "args")
	}
	return nil
}
func Prepare(p Program, t Task, values map[string]any) (Action, error) {
	rendered, e := RenderValue(t.Args, values)
	if e != nil {
		return Action{}, e
	}
	args, ok := rendered.(map[string]any)
	if !ok {
		return Action{}, ErrInvalid
	}
	action, e := prepareModule(p, t, args, values)
	if e != nil {
		return action, e
	}
	if action.Command != "" {
		command := action.Command
		if t.Become {
			user, e := Render(t.BecomeUser, values)
			if e != nil || !validAccount(user) {
				return Action{}, ErrInvalid
			}
			command = "sudo -n -H -u " + quote(user) + " -- /bin/sh -c " + quote(command)
		}
		if len(command) > MaxCommandBytes || strings.ContainsRune(command, 0) {
			return Action{}, ErrInvalid
		}
		action.Command = command
	}
	return action, nil
}
func absolute(s string) bool {
	return len(s) > 1 && len(s) <= 512 && path.IsAbs(s) && path.Clean(s) == s && !strings.ContainsAny(s, "\x00\r\n")
}
func pathArg(args map[string]any, key string) (string, error) {
	s, e := argument(args, key, "")
	if e != nil || !absolute(s) {
		return "", ErrInvalid
	}
	return s, nil
}
func boolArg(args map[string]any, key string, defaultValue bool) (bool, error) {
	v, ok := args[key]
	if !ok {
		return defaultValue, nil
	}
	b, ok := v.(bool)
	if !ok {
		return false, ErrInvalid
	}
	return b, nil
}
func intArg(args map[string]any, key string, defaultValue, min, max int) (int, error) {
	v, ok := args[key]
	if !ok {
		return defaultValue, nil
	}
	n, ok := asNumber(v)
	if !ok || n < float64(min) || n > float64(max) || float64(int(n)) != n {
		return 0, ErrInvalid
	}
	return int(n), nil
}
func listArg(v any) ([]string, error) {
	switch a := v.(type) {
	case string:
		if a == "" {
			return nil, ErrInvalid
		}
		return []string{a}, nil
	case []any:
		if len(a) < 1 || len(a) > 50 {
			return nil, ErrInvalid
		}
		out := []string{}
		for _, item := range a {
			s, e := scalar(item)
			if e != nil || s == "" {
				return nil, ErrInvalid
			}
			out = append(out, s)
		}
		return out, nil
	}
	return nil, ErrInvalid
}
func statusScript(script, status string) string {
	return "set -e\n" + script + "\nprintf '\\nJMS233_NATIVE_STATUS=" + status + "\\n'"
}
func skippedScript() string { return "printf '\\nJMS233_NATIVE_STATUS=skipped\\n'; exit 0" }
func prepareModule(p Program, t Task, args, values map[string]any) (Action, error) {
	var script string
	switch t.Module {
	case "shell", "command":
		raw, _ := argument(args, "_raw", "")
		cmd, _ := argument(args, "cmd", "")
		if raw != "" && cmd != "" {
			return Action{}, ErrInvalid
		}
		if cmd == "" {
			cmd = raw
		}
		if t.Module == "command" {
			var argv []string
			var e error
			if supplied, ok := args["argv"]; ok {
				if cmd != "" {
					return Action{}, ErrInvalid
				}
				argv, e = listArg(supplied)
			} else {
				argv, e = splitCommand(cmd)
			}
			if e != nil || len(argv) == 0 || len(argv) > 128 {
				return Action{}, ErrInvalid
			}
			for i := range argv {
				argv[i] = quote(argv[i])
			}
			script = strings.Join(argv, " ")
		} else {
			if strings.TrimSpace(cmd) == "" {
				return Action{}, ErrInvalid
			}
			exe, e := argument(args, "executable", "/bin/sh")
			if e != nil || !slices.Contains([]string{"/bin/sh", "/bin/bash"}, exe) {
				return Action{}, ErrInvalid
			}
			script = quote(exe) + " -c " + quote(cmd)
		}
		prefix := ""
		for _, key := range []string{"creates", "removes"} {
			if _, ok := args[key]; !ok {
				continue
			}
			file, e := pathArg(args, key)
			if e != nil {
				return Action{}, e
			}
			test := "-e"
			if key == "removes" {
				test = "! -e"
			}
			prefix += "if [ " + test + " " + quote(file) + " ]; then " + skippedScript() + "; fi\n"
		}
		if _, ok := args["chdir"]; ok {
			dir, e := pathArg(args, "chdir")
			if e != nil {
				return Action{}, e
			}
			prefix += "cd -- " + quote(dir) + "\n"
		}
		return Action{Command: statusScript(prefix+script, "changed")}, nil
	case "copy", "template":
		dest, e := pathArg(args, "dest")
		if e != nil {
			return Action{}, e
		}
		content, hasContent := args["content"]
		src, hasSrc := args["src"]
		if hasContent == hasSrc || t.Module == "template" && !hasSrc {
			return Action{}, ErrInvalid
		}
		var data string
		if hasContent {
			var ok bool
			data, ok = content.(string)
			if !ok {
				return Action{}, ErrInvalid
			}
		} else {
			source, ok := src.(string)
			if !ok || !ValidFile(source) {
				return Action{}, ErrInvalid
			}
			filename := path.Join(path.Dir(t.File), source)
			var exists bool
			data, exists = p.Files[filename]
			if !exists {
				return Action{}, ErrInvalid
			}
			if t.Module == "template" {
				data, e = Render(data, values)
				if e != nil {
					return Action{}, e
				}
			}
		}
		if len(data) > 4096 {
			return Action{}, ErrInvalid
		}
		metadata, e := fileMetadata(args, dest)
		if e != nil {
			return Action{}, e
		}
		encoded := base64.StdEncoding.EncodeToString([]byte(data))
		script = "test ! -L " + quote(dest) + "\ntest ! -d " + quote(dest) + "\ntmp=$(mktemp " + quote(path.Join(path.Dir(dest), ".jms233-playbook.XXXXXX")) + ")\ntrap 'rm -f -- \"$tmp\"' EXIT HUP INT TERM\nprintf '%s' " + quote(encoded) + " | base64 -d > \"$tmp\"\nchanged=0\nif ! cmp -s -- \"$tmp\" " + quote(dest) + "; then mv -f -- \"$tmp\" " + quote(dest) + "; changed=1; fi\n" + metadata + "\nprintf '\\nJMS233_NATIVE_STATUS=%s\\n' \"$(if [ \"$changed\" = 1 ]; then printf changed; else printf ok; fi)\""
	case "file":
		if _, ok := args["path"]; !ok {
			args["path"] = args["dest"]
		} else if _, exists := args["dest"]; exists {
			return Action{}, ErrInvalid
		}
		dest, e := pathArg(args, "path")
		if e != nil {
			return Action{}, e
		}
		state, e := argument(args, "state", "file")
		if e != nil {
			return Action{}, e
		}
		script = "changed=0\n"
		switch state {
		case "directory":
			script += "test ! -L " + quote(dest) + "\nif [ ! -d " + quote(dest) + " ]; then mkdir -p -- " + quote(dest) + "; changed=1; fi\n"
		case "touch":
			script += "test ! -L " + quote(dest) + "\ntouch -- " + quote(dest) + "\nchanged=1\n"
		case "file":
			script += "test -f " + quote(dest) + "\ntest ! -L " + quote(dest) + "\n"
		case "absent":
			if dest == "/" {
				return Action{}, ErrInvalid
			}
			script += "if [ -e " + quote(dest) + " ] || [ -L " + quote(dest) + " ]; then rm -rf -- " + quote(dest) + "; changed=1; fi\n"
		default:
			return Action{}, ErrInvalid
		}
		if state != "absent" {
			meta, e := fileMetadata(args, dest)
			if e != nil {
				return Action{}, e
			}
			script += meta
		} else {
			for _, k := range []string{"mode", "owner", "group"} {
				if _, ok := args[k]; ok {
					return Action{}, ErrInvalid
				}
			}
		}
		script += "printf '\\nJMS233_NATIVE_STATUS=%s\\n' \"$(if [ \"$changed\" = 1 ]; then printf changed; else printf ok; fi)\""
	case "service", "systemd_service":
		name, e := argument(args, "name", "")
		if e != nil || !serviceName.MatchString(name) {
			return Action{}, ErrInvalid
		}
		scope, e := argument(args, "scope", "system")
		if e != nil || scope != "system" && scope != "user" {
			return Action{}, ErrInvalid
		}
		tool := "systemctl"
		if scope == "user" {
			tool += " --user"
		}
		script = "changed=0\n"
		if reload, e := boolArg(args, "daemon_reload", false); e != nil {
			return Action{}, e
		} else if reload {
			script += tool + " daemon-reload\nchanged=1\n"
		}
		if _, ok := args["enabled"]; ok {
			enabled, e := boolArg(args, "enabled", false)
			if e != nil {
				return Action{}, e
			}
			verb := "enable"
			test := "!"
			if !enabled {
				verb = "disable"
				test = ""
			}
			script += "if " + test + " " + tool + " is-enabled --quiet -- " + quote(name) + "; then " + tool + " " + verb + " -- " + quote(name) + "; changed=1; fi\n"
		}
		state, e := argument(args, "state", "")
		if e != nil {
			return Action{}, e
		}
		switch state {
		case "started":
			script += "if ! " + tool + " is-active --quiet -- " + quote(name) + "; then " + tool + " start -- " + quote(name) + "; changed=1; fi\n"
		case "stopped":
			script += "if " + tool + " is-active --quiet -- " + quote(name) + "; then " + tool + " stop -- " + quote(name) + "; changed=1; fi\n"
		case "restarted", "reloaded":
			verb := "restart"
			if state == "reloaded" {
				verb = "reload"
			}
			script += tool + " " + verb + " -- " + quote(name) + "\nchanged=1\n"
		case "":
			if _, ok := args["enabled"]; !ok {
				return Action{}, ErrInvalid
			}
		default:
			return Action{}, ErrInvalid
		}
		script += "printf '\\nJMS233_NATIVE_STATUS=%s\\n' \"$(if [ \"$changed\" = 1 ]; then printf changed; else printf ok; fi)\""
	case "package":
		names, e := listArg(args["name"])
		if e != nil {
			return Action{}, e
		}
		for i, name := range names {
			if !packageName.MatchString(name) {
				return Action{}, ErrInvalid
			}
			names[i] = quote(name)
		}
		state, e := argument(args, "state", "present")
		if e != nil || !slices.Contains([]string{"present", "latest", "absent"}, state) {
			return Action{}, ErrInvalid
		}
		update, e := boolArg(args, "update_cache", false)
		if e != nil {
			return Action{}, e
		}
		script = "changed=0\n"
		script += "if command -v apt-get >/dev/null 2>&1; then\n"
		if update {
			script += "DEBIAN_FRONTEND=noninteractive apt-get update -q\nchanged=1\n"
		}
		for _, name := range names {
			switch state {
			case "present":
				script += "if ! dpkg-query -W -f='${Status}' -- " + name + " 2>/dev/null | grep -qx 'install ok installed'; then DEBIAN_FRONTEND=noninteractive apt-get install -y -q -- " + name + "; changed=1; fi\n"
			case "absent":
				script += "if dpkg-query -W -f='${Status}' -- " + name + " 2>/dev/null | grep -qx 'install ok installed'; then DEBIAN_FRONTEND=noninteractive apt-get remove -y -q -- " + name + "; changed=1; fi\n"
			case "latest":
				script += "DEBIAN_FRONTEND=noninteractive apt-get install -y -q -- " + name + "\nchanged=1\n"
			}
		}
		script += "elif command -v apk >/dev/null 2>&1; then\n"
		if update {
			script += "apk update\nchanged=1\n"
		}
		for _, name := range names {
			if state == "absent" {
				script += "if apk info -e -- " + name + " >/dev/null 2>&1; then apk del -- " + name + "; changed=1; fi\n"
			} else if state == "latest" {
				script += "apk add --upgrade -- " + name + "\nchanged=1\n"
			} else {
				script += "if ! apk info -e -- " + name + " >/dev/null 2>&1; then apk add -- " + name + "; changed=1; fi\n"
			}
		}
		script += "elif command -v dnf >/dev/null 2>&1 || command -v yum >/dev/null 2>&1; then\nmanager=dnf\ncommand -v dnf >/dev/null 2>&1 || manager=yum\n"
		if update {
			script += "$manager makecache -y\nchanged=1\n"
		}
		for _, name := range names {
			if state == "absent" {
				script += "if rpm -q -- " + name + " >/dev/null 2>&1; then $manager remove -y -- " + name + "; changed=1; fi\n"
			} else if state == "latest" {
				script += "$manager install -y -- " + name + "\nchanged=1\n"
			} else {
				script += "if ! rpm -q -- " + name + " >/dev/null 2>&1; then $manager install -y -- " + name + "; changed=1; fi\n"
			}
		}
		script += "else printf '%s\\n' 'No supported package manager' >&2; exit 2; fi\nprintf '\\nJMS233_NATIVE_STATUS=%s\\n' \"$(if [ \"$changed\" = 1 ]; then printf changed; else printf ok; fi)\""
	case "user":
		name, e := argument(args, "name", "")
		if e != nil || !validAccount(name) || name == "root" {
			return Action{}, ErrInvalid
		}
		state, e := argument(args, "state", "present")
		if e != nil || state != "present" && state != "absent" {
			return Action{}, ErrInvalid
		}
		script = "changed=0\n"
		if state == "absent" {
			remove, e := boolArg(args, "remove", false)
			if e != nil {
				return Action{}, e
			}
			flag := ""
			if remove {
				flag = " -r"
			}
			script += "if id -u -- " + quote(name) + " >/dev/null 2>&1; then userdel" + flag + " -- " + quote(name) + "; changed=1; fi\n"
		} else {
			create, e := boolArg(args, "create_home", true)
			if e != nil {
				return Action{}, e
			}
			flags := " -m"
			updates := ""
			if !create {
				flags = " -M"
			}
			for _, key := range []string{"shell", "home"} {
				if _, ok := args[key]; !ok {
					continue
				}
				v, e := pathArg(args, key)
				if e != nil {
					return Action{}, e
				}
				flag := "-s"
				if key == "home" {
					flag = "-d"
				}
				flags += " " + flag + " " + quote(v)
				field := "7"
				if key == "home" {
					field = "6"
				}
				updates += "if [ \"$(getent passwd " + quote(name) + " | cut -d: -f" + field + ")\" != " + quote(v) + " ]; then usermod " + flag + " " + quote(v) + " -- " + quote(name) + "; changed=1; fi\n"
			}
			if _, ok := args["uid"]; ok {
				uid, e := intArg(args, "uid", 0, 1000, 60000)
				if e != nil {
					return Action{}, e
				}
				flags += " -u " + strconv.Itoa(uid)
				updates += "if [ \"$(id -u -- " + quote(name) + ")\" != " + quote(strconv.Itoa(uid)) + " ]; then usermod -u " + strconv.Itoa(uid) + " -- " + quote(name) + "; changed=1; fi\n"
			}
			script += "if ! id -u -- " + quote(name) + " >/dev/null 2>&1; then useradd" + flags + " -- " + quote(name) + "; changed=1; fi\n"
			script += updates
			if g, ok := args["groups"]; ok {
				groups, e := listArg(g)
				if e != nil {
					return Action{}, e
				}
				for _, group := range groups {
					if !validAccount(group) {
						return Action{}, ErrInvalid
					}
				}
				appendGroups, e := boolArg(args, "append", false)
				if e != nil {
					return Action{}, e
				}
				flag := "-G"
				if appendGroups {
					flag = "-aG"
				}
				if appendGroups {
					for _, group := range groups {
						script += "if ! id -nG -- " + quote(name) + " | tr ' ' '\\n' | grep -Fxq -- " + quote(group) + "; then usermod -aG " + quote(group) + " -- " + quote(name) + "; changed=1; fi\n"
					}
				} else {
					script += "primary=$(id -gn -- " + quote(name) + ")\ncurrent=$(id -nG -- " + quote(name) + " | tr ' ' '\\n' | grep -Fxv -- \"$primary\" | sort -u || :)\nwanted=$(printf '%s\\n' " + strings.Join(func() []string {
						out := make([]string, len(groups))
						for i, g := range groups {
							out[i] = quote(g)
						}
						return out
					}(), " ") + " | grep -Fxv -- \"$primary\" | sort -u || :)\nif [ \"$current\" != \"$wanted\" ]; then usermod " + flag + " " + quote(strings.Join(groups, ",")) + " -- " + quote(name) + "; changed=1; fi\n"
				}
			}
		}
		script += "printf '\\nJMS233_NATIVE_STATUS=%s\\n' \"$(if [ \"$changed\" = 1 ]; then printf changed; else printf ok; fi)\""
	case "stat":
		file, e := pathArg(args, "path")
		if e != nil {
			return Action{}, e
		}
		script = "if [ -e " + quote(file) + " ] || [ -L " + quote(file) + " ]; then\nprintf 'exists=true\\nisdir=%s\\nisreg=%s\\nislnk=%s\\n' \"$(if [ -d " + quote(file) + " ]; then printf true; else printf false; fi)\" \"$(if [ -f " + quote(file) + " ]; then printf true; else printf false; fi)\" \"$(if [ -L " + quote(file) + " ]; then printf true; else printf false; fi)\"\nprintf 'mode=%s\\nsize=%s\\n' \"$(stat -c '%a' -- " + quote(file) + ")\" \"$(stat -c '%s' -- " + quote(file) + ")\"\nelse printf 'exists=false\\n'; fi"
		return Action{Command: statusScript(script, "ok")}, nil
	case "setup":
		script = "printf 'system='; uname -s | tr -d '\\n' | base64 | tr -d '\\n'; printf '\\narchitecture='; uname -m | tr -d '\\n' | base64 | tr -d '\\n'; printf '\\nuser_id='; id -un | tr -d '\\n' | base64 | tr -d '\\n'; printf '\\nuser_dir='; printf '%s' \"$HOME\" | base64 | tr -d '\\n'; printf '\\n'"
		return Action{Command: statusScript(script, "ok")}, nil
	case "debug":
		if _, ok := args["msg"]; ok {
			if _, also := args["var"]; also {
				return Action{}, ErrInvalid
			}
			return Action{Local: "debug", Value: args["msg"]}, nil
		}
		if v, ok := args["var"]; ok {
			name, ok := v.(string)
			if !ok {
				return Action{}, ErrInvalid
			}
			out := resolve(name, values)
			if _, missing := out.(undefined); missing {
				return Action{}, ErrInvalid
			}
			return Action{Local: "debug", Value: out}, nil
		}
		return Action{Local: "debug", Value: ""}, nil
	case "set_fact":
		return Action{Local: "set_fact", Value: args}, nil
	case "assert":
		list, e := listArg(args["that"])
		if e != nil {
			return Action{}, ErrInvalid
		}
		ok, e := All(list, values)
		if e != nil {
			return Action{}, e
		}
		key := "success_msg"
		local := "assert"
		if !ok {
			key = "fail_msg"
			local = "fail"
		}
		msg, e := argument(args, key, "")
		if e != nil {
			return Action{}, e
		}
		return Action{Local: local, Value: msg}, nil
	case "fail":
		msg, e := argument(args, "msg", "")
		return Action{Local: "fail", Value: msg}, e
	case "pause":
		seconds, e := intArg(args, "seconds", 1, 1, 60)
		return Action{Local: "pause", PauseSeconds: seconds}, e
	default:
		return Action{}, ErrInvalid
	}
	return Action{Command: "set -e\n" + script}, nil
}
func fileMetadata(args map[string]any, dest string) (string, error) {
	script := ""
	for _, key := range []string{"mode", "owner", "group"} {
		v, ok := args[key]
		if !ok {
			continue
		}
		s, e := scalar(v)
		if e != nil {
			return "", e
		}
		format, tool := "%a", "chmod"
		switch key {
		case "mode":
			if _, ok := v.(string); !ok {
				return "", ErrInvalid
			}
			if !modeValue.MatchString(s) {
				return "", ErrInvalid
			}
			mode, e := strconv.ParseUint(s, 8, 12)
			if e != nil {
				return "", ErrInvalid
			}
			s = strconv.FormatUint(mode, 8)
		case "owner":
			if !validAccount(s) {
				return "", ErrInvalid
			}
			format, tool = "%U", "chown"
		case "group":
			if !validAccount(s) {
				return "", ErrInvalid
			}
			format, tool = "%G", "chgrp"
		}
		script += "if [ \"$(stat -c " + quote(format) + " -- " + quote(dest) + ")\" != " + quote(s) + " ]; then " + tool + " " + quote(s) + " -- " + quote(dest) + "; changed=1; fi\n"
	}
	return script, nil
}
func splitCommand(command string) ([]string, error) {
	var out []string
	var word strings.Builder
	quoted := byte(0)
	started := false
	for i := 0; i < len(command); i++ {
		c := command[i]
		if quoted != 0 {
			if c == quoted {
				quoted = 0
			} else if c == '\\' && quoted == '"' {
				i++
				if i >= len(command) {
					return nil, ErrInvalid
				}
				word.WriteByte(command[i])
			} else {
				word.WriteByte(c)
			}
			started = true
			continue
		}
		switch c {
		case '\'', '"':
			quoted = c
			started = true
		case '\\':
			i++
			if i >= len(command) {
				return nil, ErrInvalid
			}
			word.WriteByte(command[i])
			started = true
		case ' ', '\t', '\n':
			if started {
				out = append(out, word.String())
				word.Reset()
				started = false
			}
		default:
			word.WriteByte(c)
			started = true
		}
	}
	if quoted != 0 {
		return nil, ErrInvalid
	}
	if started {
		out = append(out, word.String())
	}
	return out, nil
}
func Output(module, stdout, stderr string, code int) (Result, map[string]any, error) {
	result := Result{RC: code, Stdout: stdout, Stderr: stderr, Failed: code != 0}
	extra := map[string]any{}
	if code != 0 {
		return result, extra, nil
	}
	found := false
	for _, state := range []string{"changed", "ok", "skipped"} {
		suffix := "\nJMS233_NATIVE_STATUS=" + state + "\n"
		if strings.HasSuffix(stdout, suffix) {
			result.Stdout = strings.TrimSuffix(stdout, suffix)
			result.Changed = state == "changed"
			result.Skipped = state == "skipped"
			found = true
			break
		}
	}
	if !found {
		return result, nil, ErrInvalid
	}
	if module == "stat" {
		stat := map[string]any{}
		for _, line := range splitLines(result.Stdout) {
			k, v, ok := strings.Cut(line, "=")
			if !ok {
				return result, nil, ErrInvalid
			}
			switch k {
			case "exists", "isdir", "isreg", "islnk":
				b, e := strconv.ParseBool(v)
				if e != nil {
					return result, nil, e
				}
				stat[k] = b
			case "mode":
				if !regexp.MustCompile(`^[0-7]{3,4}$`).MatchString(v) {
					return result, nil, ErrInvalid
				}
				stat[k] = v
			case "size":
				n, e := strconv.ParseInt(v, 10, 64)
				if e != nil || n < 0 {
					return result, nil, ErrInvalid
				}
				stat[k] = n
			default:
				return result, nil, ErrInvalid
			}
		}
		if _, ok := stat["exists"]; !ok {
			return result, nil, ErrInvalid
		}
		extra["stat"] = stat
	}
	if module == "setup" {
		facts := map[string]any{}
		for _, line := range splitLines(result.Stdout) {
			k, v, ok := strings.Cut(line, "=")
			if !ok || !slices.Contains([]string{"system", "architecture", "user_id", "user_dir"}, k) {
				return result, nil, ErrInvalid
			}
			raw, e := base64.StdEncoding.DecodeString(v)
			if e != nil || len(raw) > 1024 {
				return result, nil, ErrInvalid
			}
			facts[k] = string(raw)
		}
		if len(facts) != 4 {
			return result, nil, ErrInvalid
		}
		extra["ansible_facts"] = facts
	}
	return result, extra, nil
}
func LocalResult(action Action) (Result, map[string]any, error) {
	result := Result{RC: 0}
	extra := map[string]any{}
	switch action.Local {
	case "debug", "assert":
		raw, e := json.Marshal(action.Value)
		if e != nil || len(raw) > 4096 {
			return result, nil, ErrInvalid
		}
		result.Stdout = string(raw)
	case "set_fact":
		v, ok := action.Value.(map[string]any)
		if !ok {
			return result, nil, ErrInvalid
		}
		raw, e := json.Marshal(v)
		if e != nil || len(raw) > 4096 {
			return result, nil, ErrInvalid
		}
		extra["facts"] = v
	case "fail":
		result.Failed = true
		result.RC = 1
		msg, _ := scalar(action.Value)
		if len(msg) > 4096 {
			return result, nil, ErrInvalid
		}
		result.Stderr = msg
	case "pause":
	default:
		return result, nil, fmt.Errorf("unknown local module")
	}
	return result, extra, nil
}
