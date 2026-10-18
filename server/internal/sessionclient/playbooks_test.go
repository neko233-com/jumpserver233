package sessionclient

import (
	"context"
	"fmt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestPlaybookSDKRoutesAndSafeValidationErrors(t *testing.T) {
	book := "playbook-" + strings.Repeat("a", 32)
	run := "run-" + strings.Repeat("b", 32)
	step := "step-" + strings.Repeat("c", 32)
	plan := "plan-" + strings.Repeat("d", 32)
	calls := 0
	bad := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		assert.Equal(t, "Bearer synthetic-token", r.Header.Get("Authorization"))
		if bad {
			w.WriteHeader(400)
			fmt.Fprint(w, `{"error_code":"playbook_invalid","issue":{"code":"module_invalid","file":"main.yml","line":3},"secret":"private"}`)
			return
		}
		if r.Method == "DELETE" {
			w.WriteHeader(204)
			return
		}
		fmt.Fprintf(w, `{"id":%q,"results":[],"total":0,"files":{},"tasks":[],"result":{"rc":0}}`, book)
	}))
	defer srv.Close()
	c, e := New(srv.URL, "synthetic-token")
	require.NoError(t, e)
	ctx := context.Background()
	_, e = c.ValidatePlaybook(ctx, PlaybookWorkspace{})
	require.NoError(t, e)
	_, e = c.Playbooks(ctx, 0, 25)
	require.NoError(t, e)
	_, e = c.Playbook(ctx, book)
	require.NoError(t, e)
	_, e = c.SavePlaybook(ctx, "", PlaybookInput{})
	require.NoError(t, e)
	_, e = c.SavePlaybook(ctx, book, PlaybookInput{Revision: 1})
	require.NoError(t, e)
	_, e = c.PlaybookEvents(ctx, book, 0, 25)
	require.NoError(t, e)
	_, e = c.OperationProgram(ctx, run)
	require.NoError(t, e)
	_, e = c.OperationStepOutput(ctx, run, "asset", step)
	require.NoError(t, e)
	_, e = c.TriggerOperationPlan(ctx, plan, "unique")
	require.NoError(t, e)
	require.NoError(t, c.DeletePlaybook(ctx, book, 1))
	assert.Equal(t, 10, calls)
	_, e = c.Playbook(ctx, "../escape")
	require.Error(t, e)
	_, e = c.OperationStepOutput(ctx, run, "../asset", step)
	require.Error(t, e)
	_, e = c.TriggerOperationPlan(ctx, plan, "")
	require.Error(t, e)
	assert.Equal(t, 10, calls)
	bad = true
	_, e = c.ValidatePlaybook(ctx, PlaybookWorkspace{})
	var issue *PlaybookValidationError
	require.ErrorAs(t, e, &issue)
	assert.Equal(t, 3, issue.Issue.Line)
	assert.NotContains(t, e.Error(), "private")
}
