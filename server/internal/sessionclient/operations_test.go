package sessionclient

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestOperationsSDKRoutesPagingRevisionAndResponseBounds(t *testing.T) {
	id := "plan-" + strings.Repeat("a", 32)
	run := "run-" + strings.Repeat("b", 32)
	template := "template-" + strings.Repeat("c", 32)
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		assert.Equal(t, "Bearer synthetic-calendar-token", r.Header.Get("Authorization"))
		switch {
		case r.Method == "DELETE" || strings.HasSuffix(r.URL.Path, "/cancel"):
			w.WriteHeader(204)
		case strings.HasSuffix(r.URL.Path, "/preview"):
			fmt.Fprint(w, `{"kind":"cron","occurrences":[]}`)
		case r.Method == "PUT":
			var v map[string]any
			require.NoError(t, json.NewDecoder(r.Body).Decode(&v))
			assert.Equal(t, float64(2), v["revision"])
			fmt.Fprintf(w, `{"id":%q,"config_revision":3}`, id)
		case r.URL.Path == "/api/v1/ops/templates":
			fmt.Fprint(w, `[]`)
		case strings.HasSuffix(r.URL.Path, "/events") || strings.HasSuffix(r.URL.Path, "/runs") || r.URL.Query().Has("offset"):
			assert.Equal(t, "25", r.URL.Query().Get("limit"))
			fmt.Fprint(w, `{"results":[],"total":0}`)
		case r.URL.Path == "/api/v1/ops/plans" && r.Method == "GET":
			fmt.Fprint(w, `[]`)
		default:
			fmt.Fprintf(w, `{"id":%q}`, id)
		}
	}))
	defer srv.Close()
	c, e := New(srv.URL, "synthetic-calendar-token")
	require.NoError(t, e)
	ctx := context.Background()
	_, e = c.PreviewOperationSchedule(ctx, OperationPreviewInput{Schedule: OperationSchedule{Kind: "cron", CronExpression: "* * * * *", Timezone: "UTC"}})
	require.NoError(t, e)
	_, e = c.OperationPlans(ctx)
	require.NoError(t, e)
	_, e = c.OperationPlansPage(ctx, 0, 25)
	require.NoError(t, e)
	_, e = c.OperationPlan(ctx, id)
	require.NoError(t, e)
	_, e = c.CreateOperationPlan(ctx, OperationPlanInput{})
	require.NoError(t, e)
	_, e = c.UpdateOperationSchedule(ctx, id, OperationScheduleUpdate{Revision: 2})
	require.NoError(t, e)
	_, e = c.SetOperationPlanEnabled(ctx, id, false, 2)
	require.NoError(t, e)
	_, e = c.OperationScheduleEvents(ctx, id, 0, 25)
	require.NoError(t, e)
	_, e = c.OperationRuns(ctx, 0, 25)
	require.NoError(t, e)
	_, e = c.OperationRun(ctx, run)
	require.NoError(t, e)
	require.NoError(t, c.CancelOperationRun(ctx, run))
	_, e = c.OperationTemplates(ctx)
	require.NoError(t, e)
	_, e = c.SaveOperationTemplate(ctx, template, OperationTemplateInput{Revision: 2})
	require.NoError(t, e)
	require.NoError(t, c.DeleteOperationTemplate(ctx, template, 2))
	before := calls
	_, e = c.OperationPlan(ctx, "../plans")
	require.Error(t, e)
	_, e = c.OperationRuns(ctx, -1, 25)
	require.Error(t, e)
	_, e = c.OperationPlansPage(ctx, 0, 101)
	require.Error(t, e)
	_, e = c.SetOperationPlanEnabled(ctx, id, true, 0)
	require.Error(t, e)
	_, e = c.OperationScheduleEvents(ctx, id, 0, 0)
	require.Error(t, e)
	require.Error(t, c.CancelOperationRun(ctx, id))
	require.Error(t, c.DeleteOperationTemplate(ctx, template, 0))
	assert.Equal(t, before, calls)
}

func TestOperationsSDKAllowsBoundedLargePagesAndRedactsServerErrors(t *testing.T) {
	mode := "large"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if mode == "denied" {
			w.WriteHeader(403)
			fmt.Fprint(w, `{"password":"synthetic-private"}`)
			return
		}
		if mode == "overflow" {
			fmt.Fprint(w, strings.Repeat("x", (16<<20)+1))
			return
		}
		fmt.Fprintf(w, `{"results":[],"total":0,"ignored":%q}`, strings.Repeat("x", 2<<20))
	}))
	defer srv.Close()
	c, e := New(srv.URL, "synthetic-token")
	require.NoError(t, e)
	_, e = c.OperationPlansPage(context.Background(), 0, 25)
	require.NoError(t, e)
	mode = "denied"
	_, e = c.OperationPlansPage(context.Background(), 0, 25)
	require.Error(t, e)
	assert.NotContains(t, e.Error(), "synthetic-private")
	mode = "overflow"
	_, e = c.OperationPlansPage(context.Background(), 0, 25)
	require.Error(t, e)
}
