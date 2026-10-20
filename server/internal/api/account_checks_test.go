package api

import (
	"context"
	"encoding/json"
	"sync/atomic"
	"testing"
	"time"

	"github.com/neko233-com/jumpserver233/server/internal/core/rbac"
	"github.com/neko233-com/jumpserver233/server/internal/core/rotationplans"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAccountCheckAPIDedicatedRoleNeedsNoRotationRightsAndRechecksReplay(t *testing.T) {
	e := rotationAPIEnv(t)
	permissions := []string{"assets.view_all", "assets.probe", "accounts.rotation.view", "accounts.rotation.manage", "accounts.rotation.check"}
	role, err := e.d.RBAC.SaveRole("", rbac.RoleInput{Name: "Check-only operator", Permissions: permissions}, e.admin.ID, e.admin.Username)
	require.NoError(t, err)
	_, err = e.d.RBAC.SaveBinding(rbac.BindingInput{SubjectType: "user", SubjectID: e.operator.ID, RoleIDs: []string{role.ID}}, e.admin.ID, e.admin.Username)
	require.NoError(t, err)
	calls := atomic.Int32{}
	e.d.RotationPlans.SetRunner(rotationplans.Runner{Prepare: func(ctx context.Context, _ rotationplans.Actor, selected []rotationplans.Selection) ([]rotationplans.Prepared, error) {
		return e.d.Assets.PrepareManagedRotations(ctx, selected)
	}, Authorize: func(rotationplans.Actor) error { return rotationplans.ErrDenied }, AuthorizeCheck: func(rotationplans.Actor) error {
		p := e.d.RBAC.Effective(e.operator.ID, e.operator.Role, nil)
		if !p.Allows("accounts.rotation.check") || !p.Allows("assets.probe") {
			return rotationplans.ErrDenied
		}
		return nil
	}, Check: func(_ context.Context, _ rotationplans.Intent, guard func() error) (rotationplans.Outcome, error) {
		if err := guard(); err != nil {
			return rotationplans.Outcome{}, err
		}
		calls.Add(1)
		return rotationplans.Outcome{State: "succeeded", CheckDurationMS: 1}, nil
	}})
	in := rotationplans.SaveInput{PlanInput: rotationplans.PlanInput{Name: "Dedicated auth checks", Kind: "manual", Targets: []rotationplans.Selection{{AccountID: e.asset.ID}}}, RequestID: "check-api-plan"}
	created := e.send(t, "POST", "/api/v1/accounts/rotation-plans", in, e.token, "192.0.2.3:4000")
	require.Equal(t, 201, created.Code, created.Body.String())
	var p rotationplans.Plan
	require.NoError(t, json.Unmarshal(created.Body.Bytes(), &p))
	path := "/api/v1/accounts/rotation-plans/" + p.ID
	assert.Equal(t, 403, e.send(t, "POST", path+"/runs", map[string]string{"request_id": "check-role-cannot-rotate"}, e.token, "192.0.2.3:4000").Code)
	assert.Equal(t, 400, e.send(t, "POST", path+"/checks", map[string]string{"request_id": "check-invalid", "fixed_password": "never-accepted"}, e.token, "192.0.2.3:4000").Code)
	input := map[string]string{"request_id": "check-api-once"}
	submitted := e.send(t, "POST", path+"/checks", input, e.token, "192.0.2.3:4000")
	require.Equal(t, 202, submitted.Code, submitted.Body.String())
	var run rotationplans.Run
	require.NoError(t, json.Unmarshal(submitted.Body.Bytes(), &run))
	assert.Equal(t, "check", run.Operation)
	e.d.RotationPlans.Tick()
	require.Eventually(t, func() bool { r, _ := e.d.RotationPlans.Run(run.ID); return r.State == "succeeded" }, time.Second, 5*time.Millisecond)
	replay := e.send(t, "POST", path+"/checks", input, e.token, "192.0.2.3:4000")
	require.Equal(t, 202, replay.Code)
	assert.Contains(t, replay.Body.String(), run.ID)
	assert.EqualValues(t, 1, calls.Load())
	csv := e.send(t, "GET", "/api/v1/accounts/rotation-runs/"+run.ID+"/export", nil, e.token, "192.0.2.3:4000")
	require.Equal(t, 200, csv.Code)
	assert.Contains(t, csv.Body.String(), "check_duration_ms")
	assert.Contains(t, csv.Body.String(), ",check,")
	_, err = e.d.RBAC.SaveRole(role.ID, rbac.RoleInput{Name: role.Name, Revision: role.Revision, Permissions: []string{"assets.view_all", "assets.probe", "accounts.rotation.view", "accounts.rotation.manage"}}, e.admin.ID, e.admin.Username)
	require.NoError(t, err)
	assert.Equal(t, 403, e.send(t, "POST", path+"/checks", input, e.token, "192.0.2.3:4000").Code)
}
