package api

import (
	"github.com/neko233-com/jumpserver233/server/internal/runtimelog"
	"github.com/stretchr/testify/require"
	"net/http"
	"testing"
)

func TestRuntimeLogsAdminGlobalIsolationAndReplay(t *testing.T) {
	e := monitoringEnv(t)
	w, err := runtimelog.Open(runtimelog.Options{Dir: t.TempDir(), MaxBytes: 1024, Backups: 2, Days: 1})
	require.NoError(t, err)
	defer w.Close()
	e.d.RuntimeLogs = w
	e.router = NewOrganizationRouter("test", e.d, func(string) (http.Handler, error) { t.Fatal("runtime logs selected tenant"); return nil, nil })
	for _, method := range []string{"GET", "POST"} {
		path := runtimeLogsPath
		if method == "POST" {
			path += "/rotate"
		}
		for _, token := range []string{"", e.token} {
			status := 401
			if token != "" {
				status = 403
			}
			require.Equal(t, status, e.send(t, method, path, nil, token, "192.0.2.1:1234").Code)
		}
	}
	r := e.send(t, "GET", runtimeLogsPath, nil, e.adminToken, "192.0.2.1:1234")
	require.Equal(t, 200, r.Code)
	require.Contains(t, r.Header().Get("Cache-Control"), "no-store")
	require.NotContains(t, r.Body.String(), "server.log")
	_, err = w.Write([]byte("keep this record\n"))
	require.NoError(t, err)
	s := w.Snapshot()
	in := runtimelog.Input{Instance: s.Instance, Revision: s.Revision, RequestID: "rotate-api-request"}
	for i := 0; i < 2; i++ {
		require.Equal(t, 200, e.send(t, "POST", runtimeLogsPath+"/rotate", in, e.adminToken, "192.0.2.1:1234").Code)
	}
	require.Equal(t, 1, w.Snapshot().Backups)
	in.RequestID = "other-api-request"
	require.Equal(t, 409, e.send(t, "POST", runtimeLogsPath+"/rotate", in, e.adminToken, "192.0.2.1:1234").Code)
}
