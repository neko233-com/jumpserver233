package playbooks

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"maps"
	"slices"
	"strings"
)

const (
	MaxFiles          = 32
	MaxFileBytes      = 16 << 10
	MaxWorkspaceBytes = 64 << 10
	MaxTasks          = 64
	MaxExpandedTasks  = 128
	MaxCommandBytes   = 8192
)

var ErrInvalid = errors.New("invalid native playbook")

type Issue struct {
	Code   string `json:"code"`
	File   string `json:"file,omitempty"`
	Line   int    `json:"line,omitempty"`
	Column int    `json:"column,omitempty"`
	Field  string `json:"field,omitempty"`
}

func (i *Issue) Error() string { return "invalid native playbook: " + i.Code }
func (i *Issue) Unwrap() error { return ErrInvalid }

type Workspace struct {
	Files map[string]string `json:"files"`
}

// Execution identifies a server-created step. Public job JSON cannot provide it.
type Execution struct {
	RunID     string `json:"run_id"`
	StepID    string `json:"step_id"`
	ProgramID string `json:"program_id"`
	TaskIndex int    `json:"task_index"`
}

func (e Execution) Validate() error {
	for _, v := range []struct {
		value, prefix string
		size          int
	}{{e.RunID, "run-", 32}, {e.StepID, "step-", 32}, {e.ProgramID, "", 64}} {
		if len(v.value) != len(v.prefix)+v.size || !strings.HasPrefix(v.value, v.prefix) {
			return ErrInvalid
		}
		if _, err := hex.DecodeString(strings.TrimPrefix(v.value, v.prefix)); err != nil {
			return ErrInvalid
		}
	}
	if e.TaskIndex < 0 || e.TaskIndex >= MaxTasks {
		return ErrInvalid
	}
	return nil
}

type Program struct {
	Version  int               `json:"version"`
	Files    map[string]string `json:"files"`
	Tasks    []Task            `json:"tasks"`
	MaxSteps int               `json:"max_steps"`
}
type Task struct {
	ID           string         `json:"id"`
	Name         string         `json:"name"`
	Play         int            `json:"play"`
	File         string         `json:"file"`
	Line         int            `json:"line"`
	Module       string         `json:"module"`
	Args         map[string]any `json:"args"`
	Vars         map[string]any `json:"vars,omitempty"`
	When         []string       `json:"when,omitempty"`
	Register     string         `json:"register,omitempty"`
	Loop         any            `json:"loop,omitempty"`
	Notify       []string       `json:"notify,omitempty"`
	Handler      bool           `json:"handler,omitempty"`
	Become       bool           `json:"become,omitempty"`
	BecomeUser   string         `json:"become_user,omitempty"`
	IgnoreErrors bool           `json:"ignore_errors,omitempty"`
	Timeout      int            `json:"timeout,omitempty"`
	Until        []string       `json:"until,omitempty"`
	Retries      int            `json:"retries,omitempty"`
	Delay        int            `json:"delay,omitempty"`
	ChangedWhen  []string       `json:"changed_when,omitempty"`
	FailedWhen   []string       `json:"failed_when,omitempty"`
}
type Result struct {
	RC      int    `json:"rc"`
	Stdout  string `json:"stdout"`
	Stderr  string `json:"stderr"`
	Changed bool   `json:"changed"`
	Failed  bool   `json:"failed"`
	Skipped bool   `json:"skipped"`
}

func (r Result) Variables() map[string]any {
	out := r.Stdout
	err := r.Stderr
	if len(out) > 4096 {
		out = out[:4096]
	}
	if len(err) > 4096 {
		err = err[:4096]
	}
	return map[string]any{"rc": r.RC, "stdout": out, "stdout_lines": slices.Clone(splitLines(out)), "stdout_truncated": len(r.Stdout) > 4096, "stderr": err, "stderr_truncated": len(r.Stderr) > 4096, "changed": r.Changed, "failed": r.Failed, "skipped": r.Skipped}
}
func CloneProgram(p Program) Program {
	// All decoded values are bounded JSON data. Copies never share caller maps.
	raw, _ := json.Marshal(p)
	var out Program
	_ = json.Unmarshal(raw, &out)
	return out
}
func CloneValues(in map[string]any) map[string]any {
	if in == nil {
		return nil
	}
	raw, _ := json.Marshal(in)
	var out map[string]any
	_ = json.Unmarshal(raw, &out)
	return out
}
func Overlay(base, extra map[string]any) map[string]any {
	out := maps.Clone(base)
	if out == nil {
		out = map[string]any{}
	}
	maps.Copy(out, extra)
	return out
}
