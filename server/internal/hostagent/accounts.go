package hostagent

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"sort"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

const AccountFormat = "jms233/linux-local-accounts/v1"
const MaxAccounts = 4096
const AccountPageSize = 32
const MaxAccountPageBytes = 60 << 10
const maxPasswdBytes = 4 << 20

var ErrAccounts = errors.New("account_inventory_unavailable")

// Account contains only public passwd metadata. Password and GECOS fields are
// discarded on the host and never enter the platform transport or digest.
type Account struct {
	Username string `json:"username"`
	UID      uint32 `json:"uid"`
	GID      uint32 `json:"gid"`
	Home     string `json:"home"`
	Shell    string `json:"shell"`
}
type AccountPage struct {
	Format   string    `json:"format"`
	Digest   string    `json:"digest"`
	Offset   int       `json:"offset"`
	Total    int       `json:"total"`
	Accounts []Account `json:"accounts"`
}

func validAccountText(s string, max int) bool {
	return len(s) <= max && utf8.ValidString(s) && strings.IndexFunc(s, unicode.IsControl) < 0
}
func ValidAccount(a Account) bool {
	return a.Username != "" && validAccountText(a.Username, 128) && !strings.ContainsAny(a.Username, ":/\\ \t") && validAccountText(a.Home, 512) && validAccountText(a.Shell, 512) && (a.Home == "" || strings.HasPrefix(a.Home, "/")) && (a.Shell == "" || strings.HasPrefix(a.Shell, "/"))
}
func ParseAccounts(data []byte) ([]Account, error) {
	if len(data) == 0 || len(data) > maxPasswdBytes || !utf8.Valid(data) {
		return nil, ErrAccounts
	}
	scan := bufio.NewScanner(bytes.NewReader(data))
	scan.Buffer(make([]byte, 4096), 16384)
	rows := []Account{}
	names := map[string]bool{}
	for scan.Scan() {
		line := scan.Text()
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.Split(line, ":")
		if len(parts) != 7 {
			return nil, ErrAccounts
		}
		uid, e := strconv.ParseUint(parts[2], 10, 32)
		if e != nil {
			return nil, ErrAccounts
		}
		gid, e := strconv.ParseUint(parts[3], 10, 32)
		if e != nil {
			return nil, ErrAccounts
		}
		a := Account{parts[0], uint32(uid), uint32(gid), parts[5], parts[6]}
		if !ValidAccount(a) || names[a.Username] || len(rows) >= MaxAccounts {
			return nil, ErrAccounts
		}
		names[a.Username] = true
		rows = append(rows, a)
	}
	if scan.Err() != nil || len(rows) == 0 {
		return nil, ErrAccounts
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].Username < rows[j].Username })
	return rows, nil
}
func AccountDigest(rows []Account) string {
	raw, _ := json.Marshal(rows)
	h := sha256.Sum256(raw)
	return hex.EncodeToString(h[:])
}
func LocalAccountPage(offset int) (AccountPage, error) {
	if offset < 0 || offset > MaxAccounts || offset%AccountPageSize != 0 {
		return AccountPage{}, ErrAccounts
	}
	f, e := openSnapshot("/etc/passwd")
	if e != nil {
		return AccountPage{}, ErrAccounts
	}
	defer f.Close()
	before, e := f.Stat()
	if e != nil || !trustedAccountFile(before) {
		return AccountPage{}, ErrAccounts
	}
	data, e := io.ReadAll(io.LimitReader(f, maxPasswdBytes+1))
	if e != nil {
		return AccountPage{}, ErrAccounts
	}
	after, e := f.Stat()
	if e != nil || before.Size() != after.Size() || !before.ModTime().Equal(after.ModTime()) {
		return AccountPage{}, ErrAccounts
	}
	rows, e := ParseAccounts(data)
	if e != nil || offset >= len(rows) {
		return AccountPage{}, ErrAccounts
	}
	return AccountPage{AccountFormat, AccountDigest(rows), offset, len(rows), rows[offset:min(offset+AccountPageSize, len(rows))]}, nil
}
func DecodeAccountPage(raw []byte) (AccountPage, error) {
	var page AccountPage
	if len(raw) > MaxAccountPageBytes || validateJSON(raw) != nil {
		return page, ErrAccounts
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&page) != nil || d.Decode(new(any)) != io.EOF || page.Format != AccountFormat || !validHex(page.Digest, 32) || page.Total < 1 || page.Total > MaxAccounts || page.Offset < 0 || page.Offset >= page.Total || page.Offset%AccountPageSize != 0 || len(page.Accounts) != min(AccountPageSize, page.Total-page.Offset) {
		return AccountPage{}, ErrAccounts
	}
	for i, a := range page.Accounts {
		if !ValidAccount(a) || i > 0 && page.Accounts[i-1].Username >= a.Username {
			return AccountPage{}, ErrAccounts
		}
	}
	return page, nil
}
