package api

import (
	"net/http"
	"sync"

	"github.com/neko233-com/jumpserver233/server/internal/core/accesspolicies"
	coreaccessreviews "github.com/neko233-com/jumpserver233/server/internal/core/accessreviews"
	"github.com/neko233-com/jumpserver233/server/internal/core/accountdiscovery"
	"github.com/neko233-com/jumpserver233/server/internal/core/accountrisks"
	"github.com/neko233-com/jumpserver233/server/internal/core/agentevents"
	coreassets "github.com/neko233-com/jumpserver233/server/internal/core/assets"
	coreauth "github.com/neko233-com/jumpserver233/server/internal/core/auth"
	"github.com/neko233-com/jumpserver233/server/internal/core/caslogin"
	"github.com/neko233-com/jumpserver233/server/internal/core/commandalerts"
	corecommandfilters "github.com/neko233-com/jumpserver233/server/internal/core/commandfilters"
	"github.com/neko233-com/jumpserver233/server/internal/core/databasequery"
	corefiles "github.com/neko233-com/jumpserver233/server/internal/core/files"
	coregrants "github.com/neko233-com/jumpserver233/server/internal/core/grants"
	coregroups "github.com/neko233-com/jumpserver233/server/internal/core/groups"
	"github.com/neko233-com/jumpserver233/server/internal/core/hostplugins"
	corejobs "github.com/neko233-com/jumpserver233/server/internal/core/jobs"
	"github.com/neko233-com/jumpserver233/server/internal/core/ldaplogin"
	"github.com/neko233-com/jumpserver233/server/internal/core/loginaudit"
	"github.com/neko233-com/jumpserver233/server/internal/core/loginreviews"
	"github.com/neko233-com/jumpserver233/server/internal/core/monitoralerts"
	corenodes "github.com/neko233-com/jumpserver233/server/internal/core/nodes"
	"github.com/neko233-com/jumpserver233/server/internal/core/notifications"
	"github.com/neko233-com/jumpserver233/server/internal/core/oidclogin"
	coreoperations "github.com/neko233-com/jumpserver233/server/internal/core/operations"
	"github.com/neko233-com/jumpserver233/server/internal/core/organizations"
	"github.com/neko233-com/jumpserver233/server/internal/core/passkeys"
	"github.com/neko233-com/jumpserver233/server/internal/core/radiuslogin"
	"github.com/neko233-com/jumpserver233/server/internal/core/rbac"
	"github.com/neko233-com/jumpserver233/server/internal/core/reporting"
	"github.com/neko233-com/jumpserver233/server/internal/core/rotationplans"
	"github.com/neko233-com/jumpserver233/server/internal/core/samllogin"
	"github.com/neko233-com/jumpserver233/server/internal/core/sessionpolicy"
	"github.com/neko233-com/jumpserver233/server/internal/core/tickets"
	"github.com/neko233-com/jumpserver233/server/internal/desktop"
	"github.com/neko233-com/jumpserver233/server/internal/gateway"
)

type Dependencies struct {
	Reports               *reporting.Store
	PlatformNotifications bool
	LoginAudit            *loginaudit.Store
	MonitorAlerts         *monitoralerts.Service
	CommandAlerts         *commandalerts.Store
	Notifications         *notifications.Service
	Tickets               *tickets.Service
	RotationPlans         *rotationplans.Service
	AccountRisks          *accountrisks.Service
	AccountDiscovery      *accountdiscovery.Store
	SessionPolicy         *sessionpolicy.Store
	AgentEvents           *agentevents.Store
	HostPlugins           *hostplugins.Service
	Desktops              *desktop.Broker
	DatabaseQueries       *databasequery.Service
	AccessMu              *sync.RWMutex
	GlobalAccessMu        *sync.RWMutex
	PlatformOnlyPolicies  bool
	Tenant                bool
	OrganizationID        string
	Organizations         *organizations.Store
	GlobalRBAC            *rbac.Store
	GlobalGroups          *coregroups.Store
	GlobalPolicies        *accesspolicies.Store
	OrganizationAllowed   func(coreauth.User) bool
	OrganizationSnapshot  func(string, coreauth.User) (rbac.Snapshot, error)
	OrganizationChanged   func(string)

	LoginReviews   *loginreviews.Store
	AccessPolicies *accesspolicies.Store
	TrustedProxies []string
	Assets         *coreassets.Service
	AccessReviews  *coreaccessreviews.Store
	Auth           *coreauth.Service
	Grants         *coregrants.Store
	CommandFilters *corecommandfilters.Store
	Groups         *coregroups.Store
	Nodes          *corenodes.Store
	Sessions       *gateway.Broker
	Files          *corefiles.Service
	SFTPSessions   *corefiles.AccessSessionStore
	AdminToken     string
	Jobs           *corejobs.Service
	Operations     *coreoperations.Service
	RBAC           *rbac.Store
	OIDC           *oidclogin.Service
	LDAP           *ldaplogin.Service
	CAS            *caslogin.Service
	SAML           *samllogin.Service
	Passkeys       *passkeys.Service
	RADIUS         *radiuslogin.Service
	PublicURL      string
}

// NewRouter builds the HTTP routing tree.
//
// Route layout follows JumpServer conventions: health under /api/,
// versioned resources under /api/v1/ (registered as phases land).
func NewRouter(version string, dependencies ...Dependencies) http.Handler {
	mux := http.NewServeMux()
	accessMu := &sync.RWMutex{}
	if len(dependencies) > 0 && dependencies[0].AccessMu != nil {
		accessMu = dependencies[0].AccessMu
	}
	if len(dependencies) > 0 {
		dependencies[0].AccessMu = accessMu
	}
	if len(dependencies) > 0 && !dependencies[0].Tenant && dependencies[0].Auth != nil && dependencies[0].RBAC != nil {
		d := dependencies[0]
		d.Auth.SetPrivilegedCheck(func(id string) bool {
			return len(effectivePermissions(coreauth.User{ID: id, Role: coreauth.RoleOperator}, d.RBAC, d.Groups).Permissions) > 0
		})
	}

	mux.HandleFunc("GET /api/health", HealthHandler(version))
	if len(dependencies) > 0 && dependencies[0].CommandAlerts != nil && dependencies[0].Sessions != nil {
		dependencies[0].Sessions.SetCommandAlerts(dependencies[0].CommandAlerts.Publish)
	}
	if len(dependencies) > 0 {
		if !dependencies[0].Tenant && dependencies[0].Auth != nil {
			registerUserLifecycle(mux, dependencies[0])
			registerPasswordSecurity(mux, dependencies[0])
		}
		registerReportRoutes(mux, dependencies[0], accessMu)
		registerMonitorAlertRoutes(mux, dependencies[0], accessMu)
		registerTicketRoutes(mux, dependencies[0], accessMu)
		registerNotificationRoutes(mux, dependencies[0])
	}
	if len(dependencies) > 0 && dependencies[0].RotationPlans != nil {
		registerRotationPlanRoutes(mux, dependencies[0], accessMu)
	}
	if len(dependencies) > 0 && dependencies[0].AccountRisks != nil {
		registerAccountRiskRoutes(mux, dependencies[0], accessMu)
	}
	if len(dependencies) > 0 && dependencies[0].SessionPolicy != nil {
		registerSessionPolicyRoutes(mux, dependencies[0])
	}
	if len(dependencies) > 0 && dependencies[0].Desktops != nil && dependencies[0].Assets != nil && dependencies[0].Auth != nil {
		registerRDPRoutes(mux, dependencies[0], accessMu)
	}
	if len(dependencies) > 0 && dependencies[0].Assets != nil && dependencies[0].Sessions != nil && dependencies[0].Auth != nil {
		registerKubernetesRoutes(mux, dependencies[0], accessMu)
		registerTelnetRoutes(mux, dependencies[0], accessMu)
	}
	if len(dependencies) > 0 && dependencies[0].Assets != nil && dependencies[0].DatabaseQueries != nil && dependencies[0].Auth != nil {
		registerDatabaseQueryRoutes(mux, dependencies[0], accessMu)
	}
	if len(dependencies) > 0 && dependencies[0].Organizations != nil && !dependencies[0].Tenant {
		registerOrganizationRoutes(mux, dependencies[0])
	}
	if len(dependencies) > 0 && !dependencies[0].Tenant && dependencies[0].Auth != nil && dependencies[0].LoginReviews != nil {
		registerPlatformLoginReviewRoutes(mux, dependencies[0])
	}
	if len(dependencies) > 0 && dependencies[0].AccessPolicies != nil && dependencies[0].Auth != nil {
		registerAccessPolicyRoutes(mux, dependencies[0])
	}
	if len(dependencies) > 0 && !dependencies[0].Tenant && dependencies[0].Passkeys != nil && dependencies[0].Auth != nil {
		d := dependencies[0]
		d.Auth.SetPasskeyAllowed(d.Passkeys.Allowed)
		registerPasskeyRoutes(mux, d)
	}
	if len(dependencies) > 0 && !dependencies[0].Tenant && dependencies[0].SAML != nil && dependencies[0].Auth != nil {
		d := dependencies[0]
		d.Auth.SetExternalSourceAllowed("saml", d.SAML.IssuerAllowed)
		registerSAMLRoutes(mux, d)
	}
	if len(dependencies) > 0 && !dependencies[0].Tenant && dependencies[0].CAS != nil && dependencies[0].Auth != nil {
		d := dependencies[0]
		d.Auth.SetExternalSourceAllowed("cas", d.CAS.IssuerAllowed)
		registerCASRoutes(mux, d)
	}
	if len(dependencies) > 0 && !dependencies[0].Tenant && dependencies[0].LDAP != nil && dependencies[0].Auth != nil {
		d := dependencies[0]
		d.Auth.SetExternalSourceAllowed("ldap", d.LDAP.IssuerAllowed)
		registerLDAPRoutes(mux, d)
	}
	if len(dependencies) > 0 && !dependencies[0].Tenant && dependencies[0].RADIUS != nil && dependencies[0].Auth != nil {
		d := dependencies[0]
		d.Auth.SetExternalSourceAllowed("radius", d.RADIUS.IssuerAllowed)
		registerRadiusRoutes(mux, d)
	}
	if len(dependencies) > 0 && !dependencies[0].Tenant && dependencies[0].OIDC != nil && dependencies[0].Auth != nil {
		d := dependencies[0]
		d.Auth.SetExternalIssuerAllowed(d.OIDC.IssuerAllowed)
		registerOIDCRoutes(mux, d)
	}
	if len(dependencies) > 0 && dependencies[0].RBAC != nil && dependencies[0].Auth != nil {
		registerRBACRoutes(mux, dependencies[0])
	}
	if len(dependencies) > 0 && dependencies[0].Jobs != nil && dependencies[0].Assets != nil && dependencies[0].Auth != nil {
		registerJobRoutes(mux, dependencies[0], accessMu)
	}
	if len(dependencies) > 0 && dependencies[0].Assets != nil {
		registerAssetRoutes(mux, dependencies[0].Assets, dependencies[0].AdminToken, dependencies[0].Auth, dependencies[0].Grants, dependencies[0].Groups, dependencies[0].Nodes, accessMu)
		registerManagedAccountRoutes(mux, dependencies[0], accessMu)
		registerAccountImportRoutes(mux, dependencies[0], accessMu)
	}
	if len(dependencies) > 0 && dependencies[0].Sessions != nil {
		registerSessionRoutes(mux, dependencies[0].Sessions, dependencies[0].AdminToken, dependencies[0].Auth, dependencies[0].Assets, dependencies[0].Grants, dependencies[0].CommandFilters, dependencies[0].Groups, dependencies[0].Nodes, dependencies[0].AccessReviews, accessMu)
		if dependencies[0].Auth != nil {
			registerCommandReviewRoutes(mux, dependencies[0].Sessions, dependencies[0].Auth, dependencies[0].AdminToken)
		}
	}
	if len(dependencies) > 0 && dependencies[0].AccessReviews != nil && dependencies[0].Auth != nil {
		registerAccessReviewRoutes(mux, dependencies[0].AccessReviews, dependencies[0].Auth, dependencies[0].AdminToken)
	}
	if len(dependencies) > 0 && dependencies[0].Auth != nil && !dependencies[0].Tenant {
		registerAuthRoutes(mux, dependencies[0].Auth, dependencies[0].AdminToken)
	}
	if len(dependencies) > 0 && dependencies[0].Grants != nil && dependencies[0].Assets != nil && dependencies[0].Auth != nil {
		registerGrantRoutes(mux, dependencies[0].Grants, dependencies[0].Groups, dependencies[0].Nodes, dependencies[0].Assets, dependencies[0].Auth, dependencies[0].AdminToken, accessMu)
	}
	if len(dependencies) > 0 && dependencies[0].CommandFilters != nil && dependencies[0].Assets != nil && dependencies[0].Auth != nil {
		registerCommandFilterRoutes(mux, dependencies[0].CommandFilters, dependencies[0].Groups, dependencies[0].Nodes, dependencies[0].Assets, dependencies[0].Auth, dependencies[0].AdminToken, accessMu)
	}
	if len(dependencies) > 0 && dependencies[0].Groups != nil && dependencies[0].Auth != nil {
		registerGroupRoutes(mux, dependencies[0].Groups, dependencies[0].Auth, dependencies[0].Grants, dependencies[0].CommandFilters, dependencies[0].AdminToken, accessMu)
	}
	if len(dependencies) > 0 && dependencies[0].Files != nil && dependencies[0].Assets != nil {
		registerFileRoutes(mux, dependencies[0].Files, dependencies[0].Assets, dependencies[0].Auth, dependencies[0].Grants, dependencies[0].AdminToken, dependencies[0].Groups, dependencies[0].Nodes, dependencies[0].AccessReviews, dependencies[0].SFTPSessions, accessMu)
	}
	if len(dependencies) > 0 && dependencies[0].Nodes != nil && dependencies[0].Assets != nil && dependencies[0].Auth != nil {
		registerAssetNodeRoutes(mux, dependencies[0].Nodes, dependencies[0].Assets, dependencies[0].Groups, dependencies[0].Grants, dependencies[0].CommandFilters, dependencies[0].Auth, dependencies[0].AdminToken, accessMu)
	}

	if len(dependencies) > 0 && dependencies[0].Tenant {
		registerOrganizationUserRoutes(mux, dependencies[0])
	}
	var h http.Handler = mux
	if len(dependencies) > 0 {
		registerLoginAuditRoutes(mux, dependencies[0])
	}
	if len(dependencies) > 0 {
		h = withRBAC(h, dependencies[0].RBAC, dependencies[0].Groups)
		h = withAccessPolicies(h, dependencies[0])
	}
	h = WithCORS(h)
	h = WithAccessLog(h)
	h = WithRecover(h)
	if len(dependencies) > 0 {
		h = withPublicOrigin(h, dependencies[0].PublicURL)
		h = withLoginAudit(h, dependencies[0])
	}
	return h
}
