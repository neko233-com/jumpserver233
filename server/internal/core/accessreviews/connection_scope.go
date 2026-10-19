package accessreviews

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"strings"

	"github.com/neko233-com/jumpserver233/server/internal/hostagent"
)

type ConnectionContext struct {
	Binding   string `json:"binding"`
	Workspace string `json:"workspace,omitempty"`
	Identity  string `json:"identity,omitempty"`
}

func ConnectionScope(binding, workspace, identity string) (string, error) {
	value := ConnectionContext{binding, workspace, identity}
	if !validConnectionContext(value) {
		return "", ErrInvalid
	}
	raw, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	return "cx1-" + base64.RawURLEncoding.EncodeToString(raw), nil
}

func ParseConnectionScope(scope string) (ConnectionContext, error) {
	var value ConnectionContext
	if !strings.HasPrefix(scope, "cx1-") || len(scope) > 2048 {
		return value, ErrInvalid
	}
	raw, err := base64.RawURLEncoding.DecodeString(scope[4:])
	if err != nil || json.Unmarshal(raw, &value) != nil || !validConnectionContext(value) {
		return ConnectionContext{}, ErrInvalid
	}
	canonical, _ := ConnectionScope(value.Binding, value.Workspace, value.Identity)
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
	if value.Workspace == "" {
		return value.Identity == ""
	}
	return hostagent.ValidateWorkspace(value.Workspace) == nil && validHash(value.Identity)
}
