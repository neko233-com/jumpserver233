package playbooks

import (
	"fmt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"strings"
	"testing"
)

func workspace(source string) Workspace {
	return Workspace{Files: map[string]string{"main.yml": source}}
}
func TestCompileWorkspaceIncludesAndSafeLimits(t *testing.T) {
	in := workspace("- hosts: all\n  gather_facts: true\n  vars: {message: ready}\n  tasks:\n    - include_tasks: tasks/check.yml\n      when: message == 'ready'\n      timeout: 12\n  handlers:\n    - name: changed\n      debug: {msg: done}\n")
	in.Files["tasks/check.yml"] = "- name: Print\n  command: {argv: [printf, '%s', '{{ message }}']}\n  register: printed\n  notify: changed\n- assert: {that: printed.stdout == message}\n"
	p, e := Compile(in)
	require.NoError(t, e)
	require.Len(t, p.Tasks, 4)
	assert.Equal(t, "setup", p.Tasks[0].Module)
	assert.Equal(t, 12, p.Tasks[1].Timeout)
	assert.Equal(t, []string{"message == 'ready'"}, p.Tasks[1].When)
	assert.True(t, p.Tasks[3].Handler)
	id := WorkspaceID(p.Files)
	in.Files["tasks/check.yml"] = "changed"
	assert.NotEqual(t, WorkspaceID(in.Files), id)
	assert.NotEqual(t, in.Files, p.Files)
	clone := CloneProgram(p)
	clone.Files["main.yml"] = "other"
	assert.NotEqual(t, p.Files, clone.Files)
	for name, source := range map[string]string{
		"alias":     "- hosts: all\n  vars: &x {x: 1}\n  tasks: [{debug: {msg: *x}}]",
		"duplicate": "- hosts: all\n  hosts: all\n  tasks: [{debug: {msg: ok}}]",
		"tag":       "- hosts: all\n  tasks: [{debug: {msg: !custom hi}}]",
		"multi":     "- tasks: [{debug: {msg: ok}}]\n---\n[]",
		"module":    "- tasks: [{fetch: {src: /etc/passwd}}]",
		"lookup":    "- tasks: [{debug: {msg: ok}, delegate_to: localhost}]",
		"check":     "- tasks: [{debug: {msg: ok}, check_mode: true}]",
		"hosts":     "- hosts: controller\n  tasks: [{debug: {msg: ok}}]",
		"cycle":     "- tasks: [{include_tasks: main.yml}]",
		"escape":    "- tasks: [{include_tasks: ../outside.yml}]",
		"missing":   "- tasks: [{include_tasks: absent.yml}]",
		"notify":    "- tasks: [{debug: {msg: ok}, notify: missing}]",
		"reserved":  "- vars: {inventory_hostname: forged}\n  tasks: [{debug: {msg: ok}}]",
		"infinite":  "- vars: {n: .inf}\n  tasks: [{debug: {msg: ok}}]",
		"largeint":  "- vars: {n: 9007199254740992}\n  tasks: [{debug: {msg: ok}}]",
		"retry":     "- tasks: [{debug: {msg: ok}, retries: 2}]",
		"tooMany":   "- tasks:\n" + strings.Repeat("    - debug: {msg: ok}\n", MaxTasks+1),
	} {
		t.Run(name, func(t *testing.T) {
			_, e := Compile(workspace(source))
			require.ErrorIs(t, e, ErrInvalid)
			assert.NotContains(t, e.Error(), source)
		})
	}
	for _, file := range []string{"../x", "/etc/passwd", "x\\y", "x/../y", "a:b", "a\n"} {
		in := workspace("- tasks: [{debug: {msg: ok}}]")
		in.Files[file] = "x"
		_, e := Compile(in)
		assert.Error(t, e, file)
	}
	in = workspace(strings.Repeat("x", MaxFileBytes+1))
	_, e = Compile(in)
	assert.Error(t, e)
	p, e = Compile(workspace("- tasks: [{debug: {msg: ok}, loop: []}, {debug: {msg: ok}, until: result.rc == 0}]"))
	require.NoError(t, e)
	assert.Equal(t, 5, p.MaxSteps)
	assert.Equal(t, 3, p.Tasks[1].Retries)
}
func TestExpressionsTypedVariablesAndNoControllerEvaluation(t *testing.T) {
	env := map[string]any{"message": "it's $(unsafe)", "items": []any{"a", "b"}, "n": float64(2), "health": map[string]any{"rc": float64(0), "failed": false}}
	for _, expr := range []string{"health.rc == 0", "n >= 2 and n < 3", "not n == 3", "missing is undefined or missing.rc == 9", "'a' in items", "health is succeeded"} {
		v, e := All([]string{expr}, env)
		require.NoError(t, e, expr)
		assert.True(t, v, expr)
	}
	for _, expr := range []string{"lookup('env','HOME')", "health.__class__()", "x + 1", "n ==", "n; id"} {
		require.Error(t, ValidateExpression(expr), expr)
	}
	s, e := Render("{{ message | quote }}", env)
	require.NoError(t, e)
	assert.Equal(t, "'it'\"'\"'s $(unsafe)'", s)
	v, e := RenderValue("{{ items }}", env)
	require.NoError(t, e)
	assert.Equal(t, env["items"], v)
	s, e = Render("{{ missing | default('fallback') }}", env)
	require.NoError(t, e)
	assert.Equal(t, "fallback", s)
	for _, source := range []string{"{{ lookup('file','/etc/passwd') }}", "{% for x in items %}", "{{ missing }}", "{{ missing | to_json }}"} {
		_, e := Render(source, env)
		assert.Error(t, e, source)
	}
	resolved, e := ResolveVariables(map[string]any{"message": "fact"}, map[string]any{"message": "default", "a": "{{ b }}", "b": "{{ c }}"}, map[string]any{"c": "ready"}, false)
	require.NoError(t, e)
	assert.Equal(t, "ready", resolved["a"])
	assert.Equal(t, "fact", resolved["message"])
	_, e = ResolveVariables(nil, map[string]any{"a": "{{ b }}", "b": "{{ a }}"}, nil, false)
	assert.Error(t, e)
	loop, e := LoopValues("{{ items }}", env)
	require.NoError(t, e)
	require.Len(t, loop, 2)
	vars := (Result{Stdout: strings.Repeat("x", 5000)}).Variables()
	assert.True(t, vars["stdout_truncated"].(bool))
	assert.Len(t, vars["stdout"], 4096)
}
func TestModulesPrepareRejectUnsafeArgumentsAndParseEvidence(t *testing.T) {
	examples := map[string]map[string]any{
		"command": {"argv": []any{"printf", "%s", "'; touch /tmp/never; #"}}, "shell": {"cmd": "printf ok"}, "copy": {"content": "hello", "dest": "/tmp/test", "mode": "0644"}, "template": {"src": "data.j2", "dest": "/tmp/test"}, "file": {"path": "/tmp/test", "state": "directory"}, "service": {"name": "sshd", "state": "started"}, "systemd_service": {"name": "sshd", "enabled": true}, "package": {"name": "curl"}, "user": {"name": "syntheticqa", "uid": float64(24001), "shell": "/bin/sh", "home": "/home/syntheticqa", "groups": []any{"users"}}, "stat": {"path": "/tmp/test"}, "setup": {}, "assert": {"that": "true"}, "debug": {"msg": "hello"}, "set_fact": {"hello": "world"}, "pause": {"seconds": float64(1)}, "fail": {"msg": "expected"}}
	for _, module := range Modules() {
		t.Run(module, func(t *testing.T) {
			task := Task{Module: module, Args: examples[module], File: "main.yml", BecomeUser: "root"}
			require.NoError(t, validateArgs(task))
			a, e := Prepare(Program{Files: map[string]string{"data.j2": "hello {{ name }}"}}, task, map[string]any{"name": "world"})
			require.NoError(t, e)
			if a.Command != "" {
				assert.LessOrEqual(t, len(a.Command), MaxCommandBytes)
				assert.Contains(t, a.Command, "JMS233_NATIVE_STATUS")
			} else {
				_, _, e := LocalResult(a)
				require.NoError(t, e)
			}
		})
	}
	for _, args := range []map[string]any{{"path": "/", "state": "absent"}, {"path": "/tmp/../root", "state": "absent"}, {"path": "/tmp/x", "mode": float64(420)}, {"path": "/tmp/x", "owner": "root;id"}} {
		_, e := Prepare(Program{}, Task{Module: "file", Args: args}, nil)
		assert.Error(t, e)
	}
	_, e := Prepare(Program{}, Task{Module: "command", Args: map[string]any{"cmd": "echo ok", "argv": []any{"id"}}}, nil)
	assert.Error(t, e)
	_, e = splitCommand("echo 'unterminated")
	assert.Error(t, e)
	r, extra, e := Output("stat", "exists=true\nisdir=false\nisreg=true\nislnk=false\nmode=644\nsize=5\n\nJMS233_NATIVE_STATUS=ok\n", "", 0)
	require.NoError(t, e)
	assert.False(t, r.Changed)
	assert.Equal(t, int64(5), extra["stat"].(map[string]any)["size"])
	_, _, e = Output("command", "forged", "", 0)
	assert.Error(t, e)
	r, _, e = Output("command", "", "failure", 7)
	require.NoError(t, e)
	assert.True(t, r.Failed)
	task := Task{Module: "command", Args: map[string]any{"argv": []any{"id"}}, Become: true, BecomeUser: "root"}
	a, e := Prepare(Program{}, task, nil)
	require.NoError(t, e)
	assert.True(t, strings.HasPrefix(a.Command, "sudo -n -H -u 'root'"))
	meta := Execution{RunID: "run-" + strings.Repeat("a", 32), StepID: "step-" + strings.Repeat("b", 32), ProgramID: strings.Repeat("c", 64), TaskIndex: 0}
	require.NoError(t, meta.Validate())
	meta.StepID = "step-escape"
	assert.Error(t, meta.Validate())
}
func BenchmarkCompileNativeWorkspace(b *testing.B) {
	in := workspace("- tasks:\n" + strings.Repeat("    - command: {argv: [printf, '%s', ok]}\n", 32))
	b.ReportAllocs()
	for b.Loop() {
		if _, e := Compile(in); e != nil {
			b.Fatal(fmt.Sprint(e))
		}
	}
}
