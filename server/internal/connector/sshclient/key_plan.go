package sshclient

import (
	"bytes"
	"errors"
	"regexp"
	"sort"
	"strings"

	xssh "golang.org/x/crypto/ssh"
)

var (
	ErrAuthorizedKeysChanged     = errors.New("SSH authorized keys changed during update")
	ErrAuthorizedKeysUnsafe      = errors.New("SSH authorized keys ownership, permissions, or file type is unsafe")
	ErrAuthorizedKeysUnsupported = errors.New("SSH key updates require the standard home authorized_keys file and OpenSSH SFTP extensions")
	ErrAuthorizedKeysLocked      = errors.New("another SSH key update owns the remote lock")
	ErrAuthorizedKeyMissing      = errors.New("the active SSH key is not present in the standard authorized_keys file")
	ErrKeyPlan                   = errors.New("invalid SSH key update plan")
	keyOperationPattern          = regexp.MustCompile(`^kr-[a-f0-9]{32}$`)
)

const maxAuthorizedKeysBytes = 1024 * 1024
const maxKeyLineBytes = 8192
const maxKeyVariants = 64

// KeyPlan contains public keys and potentially sensitive authorized-key options.
// The core must encrypt it at rest and never return it in API representations.
type KeyPlan struct {
	OperationID string   `json:"operation_id"`
	OldPublic   []byte   `json:"old_public,omitempty"`
	NewPublic   []byte   `json:"new_public"`
	OldLines    []string `json:"old_lines,omitempty"`
	NewLines    []string `json:"new_lines"`
}

func ValidKeyOperationID(id string) bool { return keyOperationPattern.MatchString(id) }
func keyMarker(id string) string         { return "jumpserver233/" + id }
func parsedAuthorization(line string) (xssh.PublicKey, []string, string, bool) {
	if len(line) > maxKeyLineBytes || strings.ContainsAny(line, "\x00\n") {
		return nil, nil, "", false
	}
	key, comment, options, rest, e := xssh.ParseAuthorizedKey([]byte(line + "\n"))
	if e != nil || len(bytes.TrimSpace(rest)) != 0 {
		return nil, nil, "", false
	}
	return key, options, comment, true
}
func keyAuthority(options []string) bool {
	for _, option := range options {
		if strings.EqualFold(strings.SplitN(option, "=", 2)[0], "cert-authority") {
			return true
		}
	}
	return false
}
func hasAuthorityKey(data, public []byte) bool {
	if len(public) == 0 {
		return false
	}
	for _, line := range strings.Split(string(data), "\n") {
		key, options, _, ok := parsedAuthorization(line)
		if ok && keyAuthority(options) && bytes.Equal(key.Marshal(), public) {
			return true
		}
	}
	return false
}
func matchingKeyLines(data []byte, public []byte) []string {
	var lines []string
	for _, line := range strings.Split(string(data), "\n") {
		key, options, _, ok := parsedAuthorization(line)
		if ok && !keyAuthority(options) && bytes.Equal(key.Marshal(), public) {
			lines = append(lines, line)
		}
	}
	return lines
}
func sameKeyLines(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	a = append([]string(nil), a...)
	b = append([]string(nil), b...)
	sort.Strings(a)
	sort.Strings(b)
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
func generatedKeyLine(public xssh.PublicKey, options []string, id string) string {
	prefix := ""
	if len(options) > 0 {
		prefix = strings.Join(options, ",") + " "
	}
	return prefix + strings.TrimSpace(string(xssh.MarshalAuthorizedKey(public))) + " " + keyMarker(id)
}

func prepareKeyPlan(data, oldPublic, newPublic []byte, id string) (KeyPlan, error) {
	if !ValidKeyOperationID(id) || len(data) > maxAuthorizedKeysBytes || bytes.Equal(oldPublic, newPublic) {
		return KeyPlan{}, ErrKeyPlan
	}
	newKey, e := xssh.ParsePublicKey(newPublic)
	if e != nil || newKey.Type() != xssh.KeyAlgoED25519 {
		return KeyPlan{}, ErrKeyPlan
	}
	if hasAuthorityKey(data, oldPublic) || hasAuthorityKey(data, newPublic) {
		return KeyPlan{}, ErrAuthorizedKeysUnsupported
	}
	plan := KeyPlan{OperationID: id, OldPublic: oldPublic, NewPublic: newPublic}
	if len(matchingKeyLines(data, newPublic)) != 0 {
		return KeyPlan{}, ErrAuthorizedKeysChanged
	}
	if len(oldPublic) == 0 {
		plan.NewLines = []string{generatedKeyLine(newKey, nil, id)}
	} else {
		if _, e = xssh.ParsePublicKey(oldPublic); e != nil {
			return KeyPlan{}, ErrKeyPlan
		}
		plan.OldLines = matchingKeyLines(data, oldPublic)
		if len(plan.OldLines) == 0 {
			return KeyPlan{}, ErrAuthorizedKeyMissing
		}
		if len(plan.OldLines) > maxKeyVariants {
			return KeyPlan{}, ErrKeyPlan
		}
		seen := map[string]bool{}
		for _, line := range plan.OldLines {
			_, options, _, _ := parsedAuthorization(line)
			candidate := generatedKeyLine(newKey, options, id)
			if !seen[candidate] {
				plan.NewLines = append(plan.NewLines, candidate)
				seen[candidate] = true
			}
		}
	}
	if e = ValidateKeyPlan(plan); e != nil {
		return KeyPlan{}, e
	}
	return plan, nil
}

func ValidateKeyPlan(plan KeyPlan) error {
	if !ValidKeyOperationID(plan.OperationID) || len(plan.NewLines) == 0 || len(plan.NewLines) > maxKeyVariants || len(plan.OldLines) > maxKeyVariants || bytes.Equal(plan.NewPublic, plan.OldPublic) {
		return ErrKeyPlan
	}
	newKey, e := xssh.ParsePublicKey(plan.NewPublic)
	if e != nil || newKey.Type() != xssh.KeyAlgoED25519 {
		return ErrKeyPlan
	}
	expected := map[string]bool{}
	if len(plan.OldPublic) == 0 {
		if len(plan.OldLines) != 0 {
			return ErrKeyPlan
		}
		expected[generatedKeyLine(newKey, nil, plan.OperationID)] = true
	} else {
		if _, e = xssh.ParsePublicKey(plan.OldPublic); e != nil || len(plan.OldLines) == 0 {
			return ErrKeyPlan
		}
		for _, line := range plan.OldLines {
			key, options, _, ok := parsedAuthorization(line)
			if !ok || keyAuthority(options) || !bytes.Equal(key.Marshal(), plan.OldPublic) {
				return ErrKeyPlan
			}
			expected[generatedKeyLine(newKey, options, plan.OperationID)] = true
		}
	}
	if len(expected) != len(plan.NewLines) {
		return ErrKeyPlan
	}
	for _, line := range plan.NewLines {
		if !expected[line] || len(line) > maxKeyLineBytes {
			return ErrKeyPlan
		}
		delete(expected, line)
	}
	return nil
}

// transformKeyFile preserves unrelated lines byte for byte. Revocation only
// removes the exact, previously captured non-CA authorization entries.
func transformKeyFile(data []byte, plan KeyPlan, action string) ([]byte, error) {
	if len(data) > maxAuthorizedKeysBytes || ValidateKeyPlan(plan) != nil {
		return nil, ErrKeyPlan
	}
	if hasAuthorityKey(data, plan.OldPublic) || hasAuthorityKey(data, plan.NewPublic) {
		return nil, ErrAuthorizedKeysChanged
	}
	old := matchingKeyLines(data, plan.OldPublic)
	currentNew := matchingKeyLines(data, plan.NewPublic)
	if len(currentNew) > 0 && !sameKeyLines(currentNew, plan.NewLines) {
		return nil, ErrAuthorizedKeysChanged
	}
	switch action {
	case "install":
		if !sameKeyLines(old, plan.OldLines) {
			return nil, ErrAuthorizedKeysChanged
		}
		if len(currentNew) > 0 {
			return append([]byte(nil), data...), nil
		}
		result := append([]byte(nil), data...)
		if len(result) > 0 && result[len(result)-1] != '\n' {
			result = append(result, '\n')
		}
		for _, line := range plan.NewLines {
			result = append(result, []byte(line+"\n")...)
		}
		if len(result) > maxAuthorizedKeysBytes {
			return nil, ErrKeyPlan
		}
		return result, nil
	case "retire":
		if !sameKeyLines(currentNew, plan.NewLines) || (len(old) > 0 && !sameKeyLines(old, plan.OldLines)) {
			return nil, ErrAuthorizedKeysChanged
		}
		return removeKeyLines(data, plan.OldLines), nil
	case "rollback":
		return removeKeyLines(data, plan.NewLines), nil
	default:
		return nil, ErrKeyPlan
	}
}
func removeKeyLines(data []byte, remove []string) []byte {
	wanted := map[string]bool{}
	for _, line := range remove {
		wanted[line] = true
	}
	parts := strings.SplitAfter(string(data), "\n")
	var result strings.Builder
	for _, part := range parts {
		line := strings.TrimSuffix(part, "\n")
		if wanted[line] {
			continue
		}
		result.WriteString(part)
	}
	return []byte(result.String())
}
