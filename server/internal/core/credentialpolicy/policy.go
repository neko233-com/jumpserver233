// Package credentialpolicy generates remote SSH passwords; it never validates
// platform login passwords or returns generated credentials through an API.
package credentialpolicy

import (
	"crypto/rand"
	"errors"
	"io"
	"math/big"
	"strings"
)

var ErrInvalid = errors.New("invalid SSH password generation policy")
var ErrConflict = errors.New("SSH password generation policy conflict")

const upper = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
const lower = "abcdefghijklmnopqrstuvwxyz"
const digits = "0123456789"
const symbols = "!#%+,-.=?@[]^_{}~"
const alphabet = upper + lower + digits + symbols

type Rules struct {
	MinLength  int    `json:"min_length"`
	MaxLength  int    `json:"max_length"`
	MinUpper   int    `json:"min_upper"`
	MinLower   int    `json:"min_lower"`
	MinDigits  int    `json:"min_digits"`
	MinSymbols int    `json:"min_symbols"`
	Exclude    string `json:"exclude"`
}

// A zero optional rule set inherits the organization policy. Explicit rules
// are additional constraints, merged at the time a new password is selected.
func (r Rules) IsZero() bool        { return r == (Rules{}) }
func (r Rules) OptionalValid() bool { return r.IsZero() || r.Valid() }

func Defaults() Rules {
	return Rules{MinLength: 43, MaxLength: 128, MinUpper: 1, MinLower: 1, MinDigits: 1, MinSymbols: 1}
}

// Fixed candidates still have to satisfy the current merged rules at dispatch.
func ValidFixedPassword(password string) bool {
	return (Rules{MinLength: 16, MaxLength: 128}).Matches(password)
}
func pool(chars, exclude string) string {
	return strings.Map(func(r rune) rune {
		if strings.ContainsRune(exclude, r) {
			return -1
		}
		return r
	}, chars)
}
func (r Rules) Valid() bool {
	if r.MinLength < 16 || r.MaxLength > 128 || r.MaxLength < r.MinLength || len(r.Exclude) > len(alphabet)-16 {
		return false
	}
	seen := map[rune]bool{}
	for _, c := range r.Exclude {
		if !strings.ContainsRune(alphabet, c) || seen[c] {
			return false
		}
		seen[c] = true
	}
	total := 0
	for i, n := range []int{r.MinUpper, r.MinLower, r.MinDigits, r.MinSymbols} {
		if n < 0 || n > 128 || n > 0 && len(pool([]string{upper, lower, digits, symbols}[i], r.Exclude)) == 0 {
			return false
		}
		total += n
	}
	return total <= r.MaxLength && len(pool(alphabet, r.Exclude)) >= 16
}

// Merge takes the intersection of allowed characters/lengths and the strongest
// category minima. Shared identities must satisfy every participating store.
func Merge(all ...Rules) (Rules, error) {
	if len(all) == 0 {
		return Rules{}, ErrInvalid
	}
	r := all[0]
	for _, p := range all {
		if !p.Valid() {
			return Rules{}, ErrInvalid
		}
		r.MinLength = max(r.MinLength, p.MinLength)
		r.MaxLength = min(r.MaxLength, p.MaxLength)
		r.MinUpper = max(r.MinUpper, p.MinUpper)
		r.MinLower = max(r.MinLower, p.MinLower)
		r.MinDigits = max(r.MinDigits, p.MinDigits)
		r.MinSymbols = max(r.MinSymbols, p.MinSymbols)
		for _, c := range p.Exclude {
			if !strings.ContainsRune(r.Exclude, c) {
				r.Exclude += string(c)
			}
		}
	}
	if !r.Valid() {
		return Rules{}, ErrConflict
	}
	return r, nil
}
func Generate(r Rules) (string, error) { return generate(r, rand.Reader) }
func generate(r Rules, random io.Reader) (string, error) {
	if !r.Valid() {
		return "", ErrInvalid
	}
	take := func(chars string) (byte, error) {
		n, e := rand.Int(random, big.NewInt(int64(len(chars))))
		if e != nil {
			return 0, e
		}
		return chars[n.Int64()], nil
	}
	size := max(r.MinLength, r.MinUpper+r.MinLower+r.MinDigits+r.MinSymbols)
	out := make([]byte, 0, size)
	for i, n := range []int{r.MinUpper, r.MinLower, r.MinDigits, r.MinSymbols} {
		chars := pool([]string{upper, lower, digits, symbols}[i], r.Exclude)
		for range n {
			c, e := take(chars)
			if e != nil {
				return "", e
			}
			out = append(out, c)
		}
	}
	chars := pool(alphabet, r.Exclude)
	for len(out) < size {
		c, e := take(chars)
		if e != nil {
			return "", e
		}
		out = append(out, c)
	}
	for i := len(out) - 1; i > 0; i-- {
		n, e := rand.Int(random, big.NewInt(int64(i+1)))
		if e != nil {
			return "", e
		}
		j := int(n.Int64())
		out[i], out[j] = out[j], out[i]
	}
	return string(out), nil
}
func (r Rules) Matches(password string) bool {
	if !r.Valid() || len(password) < r.MinLength || len(password) > r.MaxLength {
		return false
	}
	counts := [4]int{}
	for _, c := range password {
		if !strings.ContainsRune(alphabet, c) || strings.ContainsRune(r.Exclude, c) {
			return false
		}
		for i, chars := range []string{upper, lower, digits, symbols} {
			if strings.ContainsRune(chars, c) {
				counts[i]++
			}
		}
	}
	return counts[0] >= r.MinUpper && counts[1] >= r.MinLower && counts[2] >= r.MinDigits && counts[3] >= r.MinSymbols
}
