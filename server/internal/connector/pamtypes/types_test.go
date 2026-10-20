package pamtypes

import (
	"context"
	"errors"
	"github.com/stretchr/testify/assert"
	"strings"
	"testing"
)

func TestPAMInputBoundsGuardAndLogicalIdentity(t *testing.T) {
	for _, v := range []string{"", "line\nfeed", "zero\x00byte", string([]byte{0xff}), strings.Repeat("x", 4097)} {
		assert.False(t, ValidPassword(v))
	}
	assert.True(t, ValidPassword("Unicode-密码 ' \\ 233"))
	assert.NotEqual(t, MySQLID("operator", "%"), MySQLID("operator", "localhost"))
	assert.NotEqual(t, MySQLID("a@b", "c"), MySQLID("a", "b@c"))
	assert.ErrorIs(t, Check(t.Context(), nil), ErrInvalid)
	denied := errors.New("denied")
	assert.ErrorIs(t, Check(t.Context(), func() error { return denied }), denied)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	assert.ErrorIs(t, Check(ctx, func() error { t.Fatal("guard after cancellation"); return nil }), context.Canceled)
}
