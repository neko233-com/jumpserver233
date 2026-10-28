package sessionclient

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestSSHConfigInventoryUsesAuthenticatedVisibleAccounts(t *testing.T) {
	server:=httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){
		if r.Header.Get("Authorization")!="Bearer fixture-token" {t.Error("missing platform authentication");http.Error(w,"denied",401);return}
		switch r.URL.Path {
		case "/api/v1/users/me": fmt.Fprint(w,`{"username":"operator"}`)
		case "/api/v1/assets": fmt.Fprint(w,`[{"id":"asset-a","name":"A","protocol":"ssh","accounts":[{"id":"account-a","name":"ops","active":true,"permissions":["connect"]}]}]`)
		default: http.NotFound(w,r)
		}
	}))
	defer server.Close()
	client,err:=New(server.URL,"fixture-token");if err!=nil {t.Fatal(err)}
	user,assets,err:=client.SSHConfigInventory(context.Background())
	if err!=nil || user!="operator" || len(assets)!=1 || len(assets[0].Accounts)!=1 || assets[0].Accounts[0].ID!="account-a" {t.Fatalf("inventory user=%q assets=%+v err=%v",user,assets,err)}
}
