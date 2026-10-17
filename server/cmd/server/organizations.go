package main

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"net/http"
	"path/filepath"
	"slices"
	"sync"

	"github.com/neko233-com/jumpserver233/server/internal/api"
	"github.com/neko233-com/jumpserver233/server/internal/config"
	"github.com/neko233-com/jumpserver233/server/internal/core/accesspolicies"
	"github.com/neko233-com/jumpserver233/server/internal/core/accessreviews"
	"github.com/neko233-com/jumpserver233/server/internal/core/agentevents"
	coreassets "github.com/neko233-com/jumpserver233/server/internal/core/assets"
	coreauth "github.com/neko233-com/jumpserver233/server/internal/core/auth"
	"github.com/neko233-com/jumpserver233/server/internal/core/commandfilters"
	"github.com/neko233-com/jumpserver233/server/internal/core/databasequery"
	corefiles "github.com/neko233-com/jumpserver233/server/internal/core/files"
	"github.com/neko233-com/jumpserver233/server/internal/core/grants"
	"github.com/neko233-com/jumpserver233/server/internal/core/groups"
	"github.com/neko233-com/jumpserver233/server/internal/core/hostplugins"
	"github.com/neko233-com/jumpserver233/server/internal/core/jobs"
	"github.com/neko233-com/jumpserver233/server/internal/core/nodes"
	"github.com/neko233-com/jumpserver233/server/internal/core/operations"
	"github.com/neko233-com/jumpserver233/server/internal/core/organizations"
	"github.com/neko233-com/jumpserver233/server/internal/core/rbac"
	"github.com/neko233-com/jumpserver233/server/internal/desktop"
	"github.com/neko233-com/jumpserver233/server/internal/gateway"
	"github.com/neko233-com/jumpserver233/server/internal/storage"
)

type organizationRuntime struct {
	d       api.Dependencies
	handler http.Handler
	cancel  context.CancelFunc
	done    chan struct{}
}
type organizationRuntimes struct {
	mu         sync.Mutex
	cfg        *config.Config
	ctx        context.Context
	key        []byte
	documents  *storage.Documents
	root       api.Dependencies
	store      *organizations.Store
	items      map[string]*organizationRuntime
	closed     bool
	privileged sync.Map
	passwords  *coreassets.PasswordCoordinator
}

func (r *organizationRuntimes) assetStore(id string) (*coreassets.Store, error) {
	if st := r.passwords.Store(id); st != nil {
		return st, nil
	}
	key := r.key
	if id != organizations.DefaultID {
		mac := hmac.New(sha256.New, r.key)
		mac.Write([]byte("jms233/organization-vault/v1\x00" + id))
		key = mac.Sum(nil)
	}
	var docs *storage.Documents
	var e error
	if r.documents != nil {
		docs, e = r.documents.Scoped(id)
		if e != nil {
			return nil, e
		}
	}
	path := filepath.Join(r.cfg.DataDir, "organizations", id, "assets.json")
	var st *coreassets.Store
	if docs == nil {
		st, e = coreassets.OpenStore(path, key)
	} else {
		st, e = coreassets.OpenStoreWithDocuments(path, key, docs)
	}
	if e != nil {
		return nil, e
	}
	if e = r.passwords.Register(id, st); e != nil {
		return nil, e
	}
	return st, nil
}

func (r *organizationRuntimes) allowed(id string, u coreauth.User) bool {
	if !r.store.Enabled(id) {
		return false
	}
	if u.Role == coreauth.RoleAdmin {
		return true
	}
	var globalGroups []string
	if r.root.Groups != nil {
		globalGroups = r.root.Groups.GroupIDsForUser(u.ID)
	}
	if slices.Contains(r.root.RBAC.Effective(u.ID, u.Role, globalGroups).RoleIDs, "system-administrator") {
		return true
	}
	return r.store.Role(id, u.ID) != "none"
}
func (r *organizationRuntimes) inherited(id, user, role string) rbac.Snapshot {
	u := coreauth.User{ID: user, Role: role}
	if !r.allowed(id, u) {
		return rbac.Snapshot{}
	}
	ids := r.root.Groups.GroupIDsForUser(user)
	out := r.root.RBAC.Effective(user, role, ids)
	switch r.store.Role(id, user) {
	case "admin":
		out = rbac.Union(out, rbac.Snapshot{RoleIDs: []string{"organization-administrator"}, Permissions: rbac.OrganizationCatalog()})
	case "auditor":
		out = rbac.Union(out, rbac.Snapshot{RoleIDs: []string{"organization-auditor"}, Permissions: []string{"assets.view_all", "audit.sessions.view_all", "audit.replays.view_all", "audit.commands.view_all", "audit.files.view_all", "database.audit.view_all", "jobs.view_all", "plans.view_all"}})
	}
	return out
}
func (r *organizationRuntimes) get(id string) (*organizationRuntime, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return nil, context.Canceled
	}
	if current := r.items[id]; current != nil {
		return current, nil
	}
	if !organizations.ValidID(id) || !r.store.Enabled(id) {
		return nil, organizations.ErrNotFound
	}
	d := api.Dependencies{SessionPolicy: r.root.SessionPolicy, Tenant: true, OrganizationID: id, Organizations: r.store, Auth: r.root.Auth, AdminToken: r.root.AdminToken, PublicURL: r.root.PublicURL, TrustedProxies: r.root.TrustedProxies, GlobalRBAC: r.root.RBAC, GlobalGroups: r.root.Groups, GlobalPolicies: r.root.AccessPolicies}
	d.OrganizationAllowed = func(u coreauth.User) bool { return r.allowed(id, u) }
	orgKey := r.key
	if id != organizations.DefaultID {
		mac := hmac.New(sha256.New, r.key)
		mac.Write([]byte("jms233/organization-vault/v1\x00" + id))
		orgKey = mac.Sum(nil)
	}
	orgPath := filepath.Join(r.cfg.DataDir, "organizations", id)
	var docs *storage.Documents
	var e error
	if r.documents != nil {
		docs, e = r.documents.Scoped(id)
		if e != nil {
			return nil, e
		}
	}
	if id == organizations.DefaultID {
		d = r.root
		d.Tenant = true
		d.OrganizationID = id
		d.Organizations = r.store
		d.GlobalRBAC = r.root.RBAC
		d.GlobalGroups = r.root.Groups
		d.GlobalPolicies = r.root.AccessPolicies
		d.OrganizationAllowed = func(u coreauth.User) bool { return r.allowed(id, u) }
		d.Organizations = r.store
		orgPath = r.cfg.DataDir
	} else {
		assetStore, openError := r.assetStore(id)
		e = openError
		if e != nil {
			return nil, e
		}
		d.Assets = coreassets.NewService(assetStore, nil)
		if e = d.Assets.CoordinatePasswords(r.passwords, id); e != nil {
			return nil, e
		}
		audit, e := corefiles.OpenAuditStore(filepath.Join(orgPath, "file-transfers", "index.jsonl"))
		if e != nil {
			return nil, e
		}
		d.Files = corefiles.NewService(func(ctx context.Context, id string) (corefiles.Remote, error) {
			_, remote, e := d.Assets.OpenSFTP(ctx, id)
			return remote, e
		}, audit)
		d.SFTPSessions = corefiles.NewAccessSessionStore()
		if docs == nil {
			d.Groups, e = groups.OpenStore(filepath.Join(orgPath, "user-groups.json"))
		} else {
			d.Groups, e = groups.OpenStoreWithDocuments(filepath.Join(orgPath, "user-groups.json"), docs)
		}
		if e != nil {
			return nil, e
		}
		if docs == nil {
			d.Nodes, e = nodes.OpenStore(filepath.Join(orgPath, "asset-nodes.json"))
		} else {
			d.Nodes, e = nodes.OpenStoreWithDocuments(filepath.Join(orgPath, "asset-nodes.json"), docs)
		}
		if e != nil {
			return nil, e
		}
		if docs == nil {
			d.Grants, e = grants.OpenStore(filepath.Join(orgPath, "grants.json"))
		} else {
			d.Grants, e = grants.OpenStoreWithDocuments(filepath.Join(orgPath, "grants.json"), docs)
		}
		if e != nil {
			return nil, e
		}
		if docs == nil {
			d.AccessReviews, e = accessreviews.OpenStore(filepath.Join(orgPath, "access-reviews.json"))
		} else {
			d.AccessReviews, e = accessreviews.OpenStoreWithDocuments(filepath.Join(orgPath, "access-reviews.json"), docs)
		}
		if e != nil {
			return nil, e
		}
		if docs == nil {
			d.CommandFilters, e = commandfilters.OpenStore(filepath.Join(orgPath, "command-filters.json"))
		} else {
			d.CommandFilters, e = commandfilters.OpenStoreWithDocuments(filepath.Join(orgPath, "command-filters.json"), docs)
		}
		if e != nil {
			return nil, e
		}
		d.AccessPolicies, e = accesspolicies.Open(filepath.Join(orgPath, "access-policies.json"), docs)
		if e != nil {
			return nil, e
		}
		d.Desktops, e = desktop.New(orgPath, orgKey)
		if e != nil {
			return nil, e
		}
		d.Sessions = gateway.NewBroker(orgPath, orgKey, func(ctx context.Context, id string, cols, rows int) (gateway.AssetInfo, gateway.Terminal, error) {
			asset, shell, e := d.Assets.OpenShell(ctx, id, cols, rows)
			if e != nil {
				return gateway.AssetInfo{}, nil, e
			}
			return gateway.AssetInfo{ID: asset.ID, GatewayIDs: asset.GatewayIDs, Name: asset.Name, Host: asset.Host, Port: asset.Port, Username: asset.Username}, shell, nil
		})
		d.Jobs, e = jobs.Open(filepath.Join(orgPath, "ssh-jobs.json"), orgKey, docs, d.Assets.Exec)
		if d.SessionPolicy != nil {
			d.Sessions.SetSessionPolicy(d.SessionPolicy.Snapshot)
			d.Desktops.SetSessionPolicy(d.SessionPolicy.Snapshot)
		}
		if e != nil {
			d.Sessions.CloseAll()
			if d.Desktops != nil {
				d.Desktops.CloseAll()
			}
			return nil, e
		}
		pluginCache, e := hostplugins.NewCache(orgPath)
		if e != nil {
			d.Jobs.Close()
			d.Sessions.CloseAll()
			if d.Desktops != nil {
				d.Desktops.CloseAll()
			}
			return nil, e
		}
		d.HostPlugins = hostplugins.New(func(ctx context.Context, id string) (hostplugins.Transport, error) {
			return d.Assets.OpenManagedHost(ctx, id)
		}, pluginCache)
		d.Operations, e = operations.Open(filepath.Join(orgPath, "operations.json"), orgKey, docs, d.Jobs)
		if e != nil {
			d.Jobs.Close()
			d.Sessions.CloseAll()
			if d.Desktops != nil {
				d.Desktops.CloseAll()
			}
			return nil, e
		}
		d.DatabaseQueries, e = databasequery.Open(filepath.Join(orgPath, "database-queries.json"), orgKey, docs, d.Assets.QueryDatabase)
		if e != nil {
			d.Operations.Close()
			d.Jobs.Close()
			d.Sessions.CloseAll()
			if d.Desktops != nil {
				d.Desktops.CloseAll()
			}
			return nil, e
		}
	}
	if id != organizations.DefaultID {
		d.AgentEvents, e = agentevents.Open(filepath.Join(orgPath, "agent-events"), orgKey, docs)
		if e != nil {
			d.Operations.Close()
			d.Jobs.Close()
			d.DatabaseQueries.Close()
			d.Sessions.CloseAll()
			if d.Desktops != nil {
				d.Desktops.CloseAll()
			}
			return nil, e
		}
	}
	d.RBAC, e = rbac.OpenOrganization(filepath.Join(orgPath, "organization-rbac.json"), docs, func(user, role string) rbac.Snapshot { return r.inherited(id, user, role) })
	if e != nil {
		if id != organizations.DefaultID {
			d.Operations.Close()
			d.Jobs.Close()
			d.Sessions.CloseAll()
			if d.Desktops != nil {
				d.Desktops.CloseAll()
			}
			d.DatabaseQueries.Close()
		}
		return nil, e
	}
	runtime := &organizationRuntime{d: d, handler: api.NewRouter(r.cfg.Version, d)}
	if id != organizations.DefaultID {
		ctx, cancel := context.WithCancel(r.ctx)
		runtime.cancel = cancel
		runtime.done = make(chan struct{})
		d.DatabaseQueries.BindOwner(ctx)
		d.AgentEvents.BindOwner(ctx)
		go func() { defer close(runtime.done); d.Assets.Run(ctx, r.cfg.MonitorInterval) }()
	}
	r.items[id] = runtime
	r.privileged.Store(id, runtime)
	return runtime, nil
}
func (r *organizationRuntimes) handler(id string) (http.Handler, error) {
	current, e := r.get(id)
	if e != nil {
		return nil, e
	}
	return current.handler, nil
}
func (r *organizationRuntimes) snapshot(id string, u coreauth.User) (rbac.Snapshot, error) {
	if !r.allowed(id, u) {
		return rbac.Snapshot{}, organizations.ErrNotFound
	}
	current, e := r.get(id)
	if e != nil {
		return rbac.Snapshot{}, e
	}
	return current.d.RBAC.Effective(u.ID, u.Role, current.d.Groups.GroupIDsForUser(u.ID)), nil
}

// Disable/archive keeps storage intact but stops all work belonging to that org.
// Membership changes are checked dynamically without replacing a live runtime.
func (r *organizationRuntimes) changed(id string) {
	if id == organizations.DefaultID || r.store.Enabled(id) {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if current := r.items[id]; current != nil {
		r.stop(current, false)
		delete(r.items, id)
		r.privileged.Delete(id)
	}
}
func (r *organizationRuntimes) stop(current *organizationRuntime, abandon bool) {
	if current.d.AgentEvents != nil {
		current.d.AgentEvents.Close()
	}
	if current.cancel != nil {
		current.cancel()
	}
	if abandon {
		current.d.Operations.Abandon()
		current.d.Jobs.Abandon()
		if current.d.DatabaseQueries != nil {
			current.d.DatabaseQueries.Abandon()
		}
	} else {
		current.d.Operations.Close()
		current.d.Jobs.Close()
		if current.d.DatabaseQueries != nil {
			current.d.DatabaseQueries.Close()
		}
	}
	current.d.Sessions.CloseAll()
	if current.d.Desktops != nil {
		current.d.Desktops.CloseAll()
	}
	if current.done != nil {
		<-current.done
	}
}
func (r *organizationRuntimes) close(abandon bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return
	}
	r.closed = true
	for id, current := range r.items {
		if id != organizations.DefaultID {
			r.stop(current, abandon)
		}
	}
}
func (r *organizationRuntimes) initialize() error {
	var e error
	r.passwords, e = coreassets.OpenPasswordCoordinator(filepath.Join(r.cfg.DataDir, "shared-passwords.json"), r.key, r.documents)
	if e != nil {
		return e
	}
	r.passwords.BindOwner(r.ctx)
	if e = r.root.Assets.CoordinatePasswords(r.passwords, organizations.DefaultID); e != nil {
		return e
	}
	// All stores participate in a shared password change, even when their org is
	// disabled or archived. Load them before starting any scheduler.
	for _, o := range r.store.List(true) {
		if o.ID != organizations.DefaultID {
			if _, e = r.assetStore(o.ID); e != nil {
				return e
			}
		}
	}
	r.passwords.Recover(r.ctx)
	for _, o := range r.store.List(false) {
		if !o.Enabled {
			continue
		}
		if _, e := r.get(o.ID); e != nil {
			r.close(false)
			return errors.Join(errors.New("initialize organization runtime"), e)
		}
	}
	return nil
}

func (r *organizationRuntimes) isPrivileged(user string) bool {
	if len(r.root.RBAC.Effective(user, coreauth.RoleOperator, r.root.Groups.GroupIDsForUser(user)).Permissions) > 0 {
		return true
	}
	privileged := false
	r.privileged.Range(func(key, value any) bool {
		current := value.(*organizationRuntime)
		if r.allowed(key.(string), coreauth.User{ID: user, Role: coreauth.RoleOperator}) && len(current.d.RBAC.Effective(user, coreauth.RoleOperator, current.d.Groups.GroupIDsForUser(user)).Permissions) > 0 {
			privileged = true
			return false
		}
		return true
	})
	return privileged
}
