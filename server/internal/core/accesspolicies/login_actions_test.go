package accesspolicies

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoginApprovalAndNotificationAreLoginOnly(t *testing.T) {
	for _, action := range []string{"review", "notify"} {
		t.Run(action, func(t *testing.T) {
			s := openTest(t)
			in := testInput()
			in.Kind = Login
			in.Action = action
			in.UserID = "operator"
			if action == "review" {
				in.ApproverIDs = []string{"z", "a"}
				in.ApproverGroupIDs = []string{"group"}
			}
			r := saveTest(t, s, in)
			d := s.Decide(Scope{Kind: Login, UserID: "operator", Origin: Origin{SourceIP: "192.0.2.5"}}, time.Now())
			assert.True(t, d.Allowed)
			assert.Equal(t, action, d.Action)
			assert.Equal(t, r.ID, d.RuleID)
			assert.Equal(t, r.Revision, d.RuleRevision)
			if action == "review" {
				in.ApproverIDs[0] = "changed"
				copy, e := s.Get(r.ID)
				require.NoError(t, e)
				assert.Equal(t, []string{"a", "z"}, copy.ApproverIDs)
				copy.ApproverIDs[0] = "other"
				again, e := s.Get(r.ID)
				require.NoError(t, e)
				assert.Equal(t, "a", again.ApproverIDs[0])
			}
			for _, kind := range []string{Asset, Method} {
				in.Kind = kind
				if kind == Method {
					in.Methods = []string{"ssh"}
				}
				_, e := s.Save("", in, "admin", nil)
				assert.ErrorIs(t, e, ErrInvalid)
			}
		})
	}
	in := testInput()
	in.Kind = Login
	in.Action = "notify"
	in.ApproverIDs = []string{"reviewer"}
	_, e := normalize(in)
	assert.ErrorIs(t, e, ErrInvalid)
	in.Action = "review"
	in.ApproverIDs = []string{"reviewer", "reviewer"}
	_, e = normalize(in)
	assert.ErrorIs(t, e, ErrInvalid)
	in.ApproverIDs = []string{" reviewer"}
	_, e = normalize(in)
	assert.ErrorIs(t, e, ErrInvalid)
}
