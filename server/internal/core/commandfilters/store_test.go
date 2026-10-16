package commandfilters

import (
	"path/filepath"
	"testing"
	"time"
)

func TestDecideUsesPriorityAndSessionScope(t *testing.T) {
	store, err := OpenStore(filepath.Join(t.TempDir(), "command-filters.json"))
	if err != nil {
		t.Fatal(err)
	}
	createFilter(t, store, Input{Name: "deny destructive", Account: "*", Match: MatchHas, Pattern: "rm -rf", Action: ActionDeny, Priority: 100})
	createFilter(t, store, Input{Name: "allow health check", UserID: "user-1", AssetID: "asset-1", Account: "ops", Match: MatchExact, Pattern: "systemctl status app", Action: ActionAllow, Priority: 10})
	createFilter(t, store, Input{Name: "deny reboot", GroupID: "group-1", NodeID: "node-1", Account: "ops", Match: MatchHas, Pattern: "reboot", Action: ActionDeny, Priority: 50})

	base := Scope{UserID: "user-1", AssetID: "asset-1", NodeIDs: []string{"node-1", "root"}, Account: "ops", GroupIDs: []string{"group-1"}}
	if decision := store.Decide(base, "systemctl status app", true, time.Now()); !decision.Allowed || decision.RuleName != "allow health check" {
		t.Fatalf("higher-priority allow decision = %#v", decision)
	}
	if decision := store.Decide(base, "rm -rf /tmp/cache", true, time.Now()); decision.Allowed || decision.RuleName != "deny destructive" {
		t.Fatalf("destructive command decision = %#v", decision)
	}
	if decision := store.Decide(base, "sudo reboot", true, time.Now()); decision.Allowed || decision.RuleName != "deny reboot" {
		t.Fatalf("node and group scoped command decision = %#v", decision)
	}
	if decision := store.Decide(base, "history", false, time.Now()); decision.Allowed || decision.RuleName != "allow health check" {
		t.Fatalf("unknown command should fail closed at first applicable rule: %#v", decision)
	}
	otherUser := Scope{UserID: "user-2", AssetID: "asset-2", Account: "ops"}
	if decision := store.Decide(otherUser, "rm -rf /tmp/cache", true, time.Now()); decision.Allowed || decision.RuleName != "deny destructive" {
		t.Fatalf("global deny decision = %#v", decision)
	}
	if decision := store.Decide(otherUser, "systemctl status app", true, time.Now()); !decision.Allowed {
		t.Fatalf("unmatched command should default to allow: %#v", decision)
	}
}

func TestStorePersistsAndValidatesFilters(t *testing.T) {
	path := filepath.Join(t.TempDir(), "command-filters.json")
	store, err := OpenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Create(Input{Name: "bad regex", Account: "*", Match: MatchRegex, Pattern: "[", Action: ActionDeny}, "admin"); err == nil {
		t.Fatal("invalid regular expression was accepted")
	}
	filter := createFilter(t, store, Input{Name: "block reboot", Account: "deploy", Match: MatchRegex, Pattern: `^reboot(?:\s|$)`, Action: ActionDeny, Priority: 25})
	reloaded, err := OpenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(reloaded.List()) != 1 || reloaded.List()[0].ID != filter.ID {
		t.Fatalf("reloaded filters = %#v", reloaded.List())
	}
	decision := reloaded.Decide(Scope{UserID: "any", AssetID: "host", Account: "deploy"}, "reboot now", true, time.Now())
	if decision.Allowed || decision.RuleName != "block reboot" {
		t.Fatalf("reloaded regular expression decision = %#v", decision)
	}
}

func TestFilterTimeWindow(t *testing.T) {
	store, err := OpenStore(filepath.Join(t.TempDir(), "command-filters.json"))
	if err != nil {
		t.Fatal(err)
	}
	starts := time.Now().UTC().Add(time.Hour)
	ends := starts.Add(time.Hour)
	createFilter(t, store, Input{Name: "scheduled deny", Account: "*", Match: MatchHas, Pattern: "shutdown", Action: ActionDeny, StartsAt: &starts, EndsAt: &ends})
	scope := Scope{UserID: "user", AssetID: "asset", Account: "ops"}
	if decision := store.Decide(scope, "shutdown now", true, starts.Add(-time.Second)); !decision.Allowed {
		t.Fatalf("rule applied before start time: %#v", decision)
	}
	if decision := store.Decide(scope, "shutdown now", true, starts.Add(time.Second)); decision.Allowed {
		t.Fatalf("rule did not apply in active window: %#v", decision)
	}
	if decision := store.Decide(scope, "shutdown now", true, ends); !decision.Allowed {
		t.Fatalf("rule applied at or after end time: %#v", decision)
	}
}

func TestReviewActionRequestsApprovalAndUnknownInputStillDenies(t *testing.T) {
	store, err := OpenStore(filepath.Join(t.TempDir(), "command-filters.json"))
	if err != nil {
		t.Fatal(err)
	}
	createFilter(t, store, Input{Name: "review deploy", Account: "ops", Match: MatchHas, Pattern: "deploy", Action: ActionReview})
	scope := Scope{UserID: "operator", AssetID: "asset-1", Account: "ops"}
	decision := store.Decide(scope, "./deploy.sh", true, time.Now())
	if decision.Allowed || decision.Action != ActionReview || decision.RuleName != "review deploy" {
		t.Fatalf("review decision = %#v", decision)
	}
	unknown := store.Decide(scope, "", false, time.Now())
	if unknown.Allowed || unknown.Action != ActionDeny || unknown.RuleName != "review deploy" {
		t.Fatalf("unknown terminal input should be denied under a review rule: %#v", unknown)
	}
}

func createFilter(t *testing.T, store *Store, input Input) Filter {
	t.Helper()
	if input.Priority == 0 && input.Name != "" {
		input.Priority = 500
	}
	filter, err := store.Create(input, "admin")
	if err != nil {
		t.Fatalf("create filter %q: %v", input.Name, err)
	}
	return filter
}
