package ldapclient

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"

	ldap "github.com/go-ldap/ldap/v3"
)

var ErrIncomplete = errors.New("directory snapshot incomplete or exceeds limits")

type ScanOptions struct {
	UserFilter        string `json:"user_filter"`
	UsernameAttribute string `json:"username_attribute"`
	GroupBaseDN       string `json:"group_base_dn"`
	GroupFilter       string `json:"group_filter"`
}
type DirectoryUser struct {
	Subject  string   `json:"subject"`
	Username string   `json:"username"`
	Disabled bool     `json:"disabled"`
	Groups   []string `json:"groups"`
}
type DirectoryGroup struct {
	DN   string `json:"dn"`
	Name string `json:"name"`
}
type DirectorySnapshot struct {
	Users  []DirectoryUser  `json:"users"`
	Groups []DirectoryGroup `json:"groups"`
}
type Scanner interface {
	Scan(context.Context, Config, string, ScanOptions) (DirectorySnapshot, error)
}

func ValidateScan(o ScanOptions) error {
	if o.UserFilter == "" || len(o.UserFilter) > 2048 || strings.Contains(o.UserFilter, "{username}") || !attributePattern.MatchString(o.UsernameAttribute) {
		return ErrConfig
	}
	if _, e := ldap.CompileFilter(o.UserFilter); e != nil {
		return ErrConfig
	}
	if o.GroupBaseDN == "" {
		if o.GroupFilter != "" {
			return ErrConfig
		}
		return nil
	}
	if len(o.GroupBaseDN) > 2048 || o.GroupFilter == "" || len(o.GroupFilter) > 2048 {
		return ErrConfig
	}
	if _, e := ldap.ParseDN(o.GroupBaseDN); e != nil {
		return ErrConfig
	}
	if _, e := ldap.CompileFilter(o.GroupFilter); e != nil {
		return ErrConfig
	}
	return nil
}

// DNKey handles escaped values, case-insensitive matching and unordered
// attributes of a multi-valued RDN. It never compares raw DN spellings.
func DNKey(raw string) (string, error) {
	if raw == "" || len(raw) > 2048 {
		return "", ErrConfig
	}
	dn, e := ldap.ParseDN(raw)
	if e != nil {
		return "", ErrConfig
	}
	rdns := make([][]string, 0, len(dn.RDNs))
	for _, rdn := range dn.RDNs {
		av := []string{}
		for _, a := range rdn.Attributes {
			b, _ := json.Marshal([]string{foldText(a.Type), foldText(a.Value)})
			av = append(av, string(b))
		}
		sort.Strings(av)
		rdns = append(rdns, av)
	}
	b, _ := json.Marshal(rdns)
	return string(b), nil
}
func foldText(s string) string {
	return strings.Map(func(r rune) rune {
		small := r
		for next := unicode.SimpleFold(r); next != r; next = unicode.SimpleFold(next) {
			if next < small {
				small = next
			}
		}
		return small
	}, s)
}
func inBase(raw, base string) bool {
	dn, e := ldap.ParseDN(raw)
	b, be := ldap.ParseDN(base)
	return e == nil && be == nil && (b.EqualFold(dn) || b.AncestorOfFold(dn))
}
func paged(l *ldap.Conn, base, filter string, attrs []string, limit int) ([]*ldap.Entry, error) {
	out := []*ldap.Entry{}
	control := ldap.NewControlPaging(500)
	seen := map[string]bool{}
	for pages := 0; pages < 100; pages++ {
		result, e := l.Search(ldap.NewSearchRequest(base, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 15, false, filter, attrs, []ldap.Control{control}))
		if e != nil || result == nil || len(result.Referrals) > 0 {
			return nil, ErrIncomplete
		}
		if len(out)+len(result.Entries) > limit {
			return nil, ErrIncomplete
		}
		for _, entry := range result.Entries {
			if !inBase(entry.DN, base) {
				return nil, ErrIncomplete
			}
			for _, a := range entry.Attributes {
				if strings.Contains(strings.ToLower(a.Name), ";range=") {
					return nil, ErrIncomplete
				}
			}
			out = append(out, entry)
		}
		value := ldap.FindControl(result.Controls, ldap.ControlTypePaging)
		paging, ok := value.(*ldap.ControlPaging)
		if !ok {
			return nil, ErrIncomplete
		}
		if len(paging.Cookie) == 0 {
			return out, nil
		}
		if len(paging.Cookie) > 4096 || seen[string(paging.Cookie)] {
			return nil, ErrIncomplete
		}
		seen[string(paging.Cookie)] = true
		control.SetCookie(slices.Clone(paging.Cookie))
	}
	return nil, ErrIncomplete
}
func (Client) Scan(ctx context.Context, c Config, password string, o ScanOptions) (DirectorySnapshot, error) {
	if ValidateScan(o) != nil {
		return DirectorySnapshot{}, ErrConfig
	}
	l, close, e := connectWithBudget(ctx, c, password, time.Minute, 32<<20)
	if e != nil {
		return DirectorySnapshot{}, e
	}
	defer close()
	users, e := paged(l, c.BaseDN, o.UserFilter, []string{c.IdentityAttribute, o.UsernameAttribute, "userAccountControl"}, 10000)
	if e != nil {
		return DirectorySnapshot{}, e
	}
	groups := []*ldap.Entry{}
	if o.GroupBaseDN != "" {
		groups, e = paged(l, o.GroupBaseDN, o.GroupFilter, []string{"cn", "member", "uniqueMember", "memberUid"}, 2000)
		if e != nil {
			return DirectorySnapshot{}, e
		}
	}
	return makeSnapshot(c, o, users, groups)
}
func makeSnapshot(c Config, o ScanOptions, users, groups []*ldap.Entry) (DirectorySnapshot, error) {
	if len(users) > 10000 || len(groups) > 2000 {
		return DirectorySnapshot{}, ErrIncomplete
	}
	out := DirectorySnapshot{Users: []DirectoryUser{}, Groups: []DirectoryGroup{}}
	byDN := map[string]int{}
	byName := map[string]int{}
	subjects := map[string]bool{}
	for _, entry := range users {
		key, e := DNKey(entry.DN)
		raw := entry.GetRawAttributeValues(c.IdentityAttribute)
		names := entry.GetAttributeValues(o.UsernameAttribute)
		if e != nil || !inBase(entry.DN, c.BaseDN) || len(raw) != 1 || len(raw[0]) == 0 || len(raw[0]) > 256 || len(names) != 1 || !validUsername(names[0]) {
			return DirectorySnapshot{}, ErrIncomplete
		}
		sub := base64.RawURLEncoding.EncodeToString(raw[0])
		if _, exists := byDN[key]; exists || subjects[sub] {
			return DirectorySnapshot{}, ErrIncomplete
		}
		if _, exists := byName[names[0]]; exists {
			return DirectorySnapshot{}, ErrIncomplete
		}
		disabled := false
		if flags := entry.GetAttributeValues("userAccountControl"); len(flags) > 0 {
			if len(flags) != 1 {
				return DirectorySnapshot{}, ErrIncomplete
			}
			n, e := strconv.ParseUint(flags[0], 10, 32)
			if e != nil {
				return DirectorySnapshot{}, ErrIncomplete
			}
			disabled = n&2 != 0
		}
		byDN[key] = len(out.Users)
		byName[names[0]] = len(out.Users)
		subjects[sub] = true
		out.Users = append(out.Users, DirectoryUser{sub, names[0], disabled, []string{}})
	}
	groupKeys := map[string]int{}
	edges := 0
	for i, entry := range groups {
		key, e := DNKey(entry.DN)
		if e != nil || !inBase(entry.DN, o.GroupBaseDN) {
			return DirectorySnapshot{}, ErrIncomplete
		}
		if _, ok := groupKeys[key]; ok {
			return DirectorySnapshot{}, ErrIncomplete
		}
		if _, ok := byDN[key]; ok {
			return DirectorySnapshot{}, ErrIncomplete
		}
		groupKeys[key] = i
		out.Groups = append(out.Groups, DirectoryGroup{entry.DN, entry.GetAttributeValue("cn")})
	}
	memo := map[int]map[int]bool{}
	visiting := map[int]bool{}
	expanded := 0
	heights := map[int]int{}
	var expand func(int, int) (map[int]bool, error)
	expand = func(index, depth int) (map[int]bool, error) {
		if depth > 16 || visiting[index] {
			return nil, ErrIncomplete
		}
		if v, ok := memo[index]; ok {
			if depth+heights[index] > 16 {
				return nil, ErrIncomplete
			}
			return v, nil
		}
		visiting[index] = true
		members := map[int]bool{}
		entry := groups[index]
		for _, attr := range []string{"member", "uniqueMember"} {
			for _, raw := range entry.GetAttributeValues(attr) {
				edges++
				if edges > 100000 {
					return nil, ErrIncomplete
				}
				key, e := DNKey(raw)
				if e != nil {
					return nil, ErrIncomplete
				}
				if user, ok := byDN[key]; ok {
					members[user] = true
				} else if child, ok := groupKeys[key]; ok {
					nested, e := expand(child, depth+1)
					if e != nil {
						return nil, e
					}
					heights[index] = max(heights[index], heights[child]+1)
					if depth+heights[index] > 16 {
						return nil, ErrIncomplete
					}
					for u := range nested {
						members[u] = true
					}
				}
				if len(members) > 10000 {
					return nil, ErrIncomplete
				}
			}
		}
		for _, name := range entry.GetAttributeValues("memberUid") {
			edges++
			if edges > 100000 {
				return nil, ErrIncomplete
			}
			if u, ok := byName[name]; ok {
				members[u] = true
			}
		}
		expanded += len(members)
		if expanded > 100000 {
			return nil, ErrIncomplete
		}
		visiting[index] = false
		memo[index] = members
		return members, nil
	}
	memberships := 0
	for i, group := range groups {
		members, e := expand(i, 0)
		if e != nil {
			return DirectorySnapshot{}, e
		}
		for u := range members {
			memberships++
			if memberships > 100000 || len(out.Users[u].Groups) >= 256 {
				return DirectorySnapshot{}, ErrIncomplete
			}
			out.Users[u].Groups = append(out.Users[u].Groups, group.DN)
		}
	}
	for i := range out.Users {
		sort.Strings(out.Users[i].Groups)
	}
	sort.Slice(out.Users, func(i, j int) bool { return out.Users[i].Subject < out.Users[j].Subject })
	sort.Slice(out.Groups, func(i, j int) bool { return out.Groups[i].DN < out.Groups[j].DN })
	return out, nil
}
