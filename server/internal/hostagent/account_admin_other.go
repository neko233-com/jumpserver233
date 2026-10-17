//go:build !linux

package hostagent

import (
	"context"
	"encoding/json"
)

func InstallAccountAdmin() (string, string, error)      { return "", "", ErrAccountAdmin }
func AccountAdminInstallJSON() (json.RawMessage, error) { return nil, ErrAccountAdmin }
func RunAccountAdmin(context.Context, AccountAdminRequest) (AccountAdminResult, error) {
	return AccountAdminResult{}, ErrAccountAdmin
}
