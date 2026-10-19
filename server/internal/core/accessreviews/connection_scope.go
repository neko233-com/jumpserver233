package accessreviews

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"strings"

	"github.com/neko233-com/jumpserver233/server/internal/hostagent"
)

type ConnectionContext struct {
	Binding          string `json:"binding"`
	Workspace        string `json:"workspace,omitempty"`
	Identity         string `json:"identity,omitempty"`
	WorkingDirectory string `json:"working_directory,omitempty"`
	WorkingIdentity  string `json:"working_identity,omitempty"`
	PolicyKey        string `json:"policy_key,omitempty"`
}

func ConnectionScope(binding, workspace, identity string) (string, error) {
	value := ConnectionContext{Binding: binding, Workspace: workspace, Identity: identity}
	if !validConnectionContext(value) {
		return "", ErrInvalid
	}
	raw, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	scope := "cx1-" + base64.RawURLEncoding.EncodeToString(raw)
	if len(scope) > 2048 {
		return "", ErrInvalid
	}
	return scope, nil
}

// ExecutionScope includes server-verified cwd and current command policy. The
// original cx1 encoding remains canonical for existing SSH/SFTP approvals.
func ExecutionScope(value ConnectionContext) (string, error) {
	if !validConnectionContext(value) {
		return "", ErrInvalid
	}
	raw, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	scope := "cx2-" + base64.RawURLEncoding.EncodeToString(raw)
	if len(scope) > 4096 {
		return "", ErrInvalid
	}
	return scope, nil
}

func ParseConnectionScope(scope string) (ConnectionContext, error) {
	var value ConnectionContext
	version2 := strings.HasPrefix(scope, "cx2-")
	if !version2 && !strings.HasPrefix(scope, "cx1-") || len(scope) > 4096 || !version2 && len(scope) > 2048 {
		return value, ErrInvalid
	}
	raw, err := base64.RawURLEncoding.DecodeString(scope[4:])
	if err != nil || json.Unmarshal(raw, &value) != nil || !validConnectionContext(value) {
		return ConnectionContext{}, ErrInvalid
	}
	canonical, _ := ConnectionScope(value.Binding, value.Workspace, value.Identity)
	if version2 {
		canonical, _ = ExecutionScope(value)
	}
	if canonical != scope {
		return ConnectionContext{}, ErrInvalid
	}
	return value, nil
}

func validConnectionContext(value ConnectionContext) bool {
	validHash := func(s string) bool {
		_, err := hex.DecodeString(s)
		return len(s) == 64 && strings.ToLower(s) == s && err == nil
	}
	if !validHash(value.Binding) {
		return false
	}
	if value.PolicyKey != "" && !validHash(value.PolicyKey) {
		return false
	}
	if value.WorkingDirectory != "" || value.WorkingIdentity != "" {
		if hostagent.ValidateWorkingDirectory(value.Workspace, value.WorkingDirectory) != nil || !validHash(value.WorkingIdentity) {
			return false
		}
	}
	if value.Workspace == "" {
		return value.Identity == ""
	}
	return hostagent.ValidateWorkspace(value.Workspace) == nil && validHash(value.Identity)
}
