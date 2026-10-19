package credentialpolicy

import (
	"errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

type badRandom struct{}

func (badRandom) Read([]byte) (int, error) { return 0, io.ErrUnexpectedEOF }
func TestGenerationMeetsEveryClassAndExclusion(t *testing.T) {
	r := Defaults()
	r.MinLength = 24
	r.MaxLength = 24
	r.MinUpper = 3
	r.MinLower = 3
	r.MinDigits = 4
	r.MinSymbols = 4
	r.Exclude = "01OIl!"
	seen := map[string]bool{}
	for range 100 {
		p, e := Generate(r)
		require.NoError(t, e)
		assert.True(t, r.Matches(p))
		assert.Len(t, p, 24)
		seen[p] = true
	}
	assert.Len(t, seen, 100)
	_, e := generate(r, badRandom{})
	require.ErrorIs(t, e, io.ErrUnexpectedEOF)
}
func TestPolicyValidationAndSharedIntersection(t *testing.T) {
	for _, mutate := range []func(*Rules){func(r *Rules) { r.MinLength = 15 }, func(r *Rules) { r.MaxLength = 129 }, func(r *Rules) { r.MinUpper = -1 }, func(r *Rules) { r.MinSymbols = 129 }, func(r *Rules) { r.Exclude = "aa" }, func(r *Rules) { r.Exclude = "\n" }, func(r *Rules) { r.Exclude = symbols }, func(r *Rules) { r.Exclude = alphabet }, func(r *Rules) { r.MaxLength = 16 }} {
		r := Defaults()
		mutate(&r)
		assert.False(t, r.Valid())
		_, e := Generate(r)
		assert.ErrorIs(t, e, ErrInvalid)
	}
	a, b := Defaults(), Defaults()
	a.MinLength = 48
	a.Exclude = "OI"
	b.MinUpper = 4
	b.MinDigits = 5
	b.MinSymbols = 6
	b.Exclude = "l1"
	merged, e := Merge(a, b)
	require.NoError(t, e)
	for range 20 {
		p, e := Generate(merged)
		require.NoError(t, e)
		assert.True(t, a.Matches(p) && b.Matches(p))
	}
	b.MaxLength = 32
	b.MinLength = 16
	_, e = Merge(a, b)
	assert.ErrorIs(t, e, ErrConflict)
	_, e = Merge()
	assert.ErrorIs(t, e, ErrInvalid)
	assert.False(t, Defaults().Matches(strings.Repeat("a", 43)))
}
func TestEncryptedPolicyCASReplayActorAndRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "policy.json")
	key := make([]byte, 32)
	s, e := Open(path, key, nil)
	require.NoError(t, e)
	p := s.Snapshot()
	p.MinUpper = 3
	in := Input{RequestID: "policy-retry-01", Policy: p}
	saved, e := s.Save(in, "admin", "Admin")
	require.NoError(t, e)
	assert.Equal(t, 2, saved.Revision)
	replay, e := s.Save(in, "admin", "Admin")
	require.NoError(t, e)
	assert.Equal(t, saved, replay)
	assert.Len(t, s.Audit(), 1)
	_, e = s.Save(in, "other", "Other")
	assert.ErrorIs(t, e, ErrConflict)
	changed := in
	changed.Policy.MinUpper = 4
	_, e = s.Save(changed, "admin", "Admin")
	assert.ErrorIs(t, e, ErrConflict)
	stale := in
	stale.RequestID = "new-stale"
	_, e = s.Save(stale, "admin", "Admin")
	assert.ErrorIs(t, e, ErrConflict)
	noChange := Input{RequestID: "no-change", Policy: saved}
	_, e = s.Save(noChange, "admin", "Admin")
	require.NoError(t, e)
	assert.Len(t, s.Audit(), 1)
	assert.Equal(t, 2, s.Snapshot().Revision)
	raw, e := os.ReadFile(path)
	require.NoError(t, e)
	assert.NotContains(t, string(raw), "min_upper")
	assert.NotContains(t, string(raw), "Admin")
	reopened, e := Open(path, key, nil)
	require.NoError(t, e)
	assert.Equal(t, saved, reopened.Snapshot())
	_, e = reopened.Save(in, "admin", "Admin")
	require.NoError(t, e)
	badKey := make([]byte, 32)
	badKey[0] = 1
	_, e = Open(path, badKey, nil)
	assert.ErrorIs(t, e, ErrInvalid)
	require.NoError(t, os.WriteFile(path, []byte(`{"version":999}`), 0600))
	_, e = Open(path, key, nil)
	assert.ErrorIs(t, e, ErrInvalid)
}
func TestConcurrentPolicySavesHaveOneWinner(t *testing.T) {
	s, e := Open(filepath.Join(t.TempDir(), "p.json"), make([]byte, 32), nil)
	require.NoError(t, e)
	var wg sync.WaitGroup
	var mu sync.Mutex
	wins := 0
	for i, id := range []string{"first", "second"} {
		wg.Add(1)
		go func(i int, id string) {
			defer wg.Done()
			p := s.Snapshot()
			p.Revision = 1
			p.MinUpper = 2 + i
			_, e := s.Save(Input{RequestID: id, Policy: p}, "admin", "Admin")
			mu.Lock()
			defer mu.Unlock()
			if e == nil {
				wins++
			} else {
				assert.True(t, errors.Is(e, ErrConflict))
			}
		}(i, id)
	}
	wg.Wait()
	assert.Equal(t, 1, wins)
}
