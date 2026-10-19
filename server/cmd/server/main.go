package main

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/neko233-com/jumpserver233/server/internal/api"
	"github.com/neko233-com/jumpserver233/server/internal/cluster"
	"github.com/neko233-com/jumpserver233/server/internal/config"
	"github.com/neko233-com/jumpserver233/server/internal/core/accesspolicies"
	coreaccessreviews "github.com/neko233-com/jumpserver233/server/internal/core/accessreviews"
	"github.com/neko233-com/jumpserver233/server/internal/core/accountdiscovery"
	"github.com/neko233-com/jumpserver233/server/internal/core/accountrisks"
	"github.com/neko233-com/jumpserver233/server/internal/core/agentevents"
	coreassets "github.com/neko233-com/jumpserver233/server/internal/core/assets"
	coreauth "github.com/neko233-com/jumpserver233/server/internal/core/auth"
	"github.com/neko233-com/jumpserver233/server/internal/core/branding"
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
	"github.com/neko233-com/jumpserver233/server/internal/core/monitorhistory"
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
	"github.com/neko233-com/jumpserver233/server/internal/storage"
	"github.com/neko233-com/jumpserver233/server/internal/webui"
)

const (
	clusterRetryInterval = 2 * time.Second
	clusterCheckInterval = 2 * time.Second
	clusterCheckTimeout  = time.Second
)

func main() {
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo})))

	cfg, err := config.FromEnv()
	if err != nil {
		slog.Error("invalid config", "err", err)
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if cfg.ClusterMode {
		err = runActiveStandby(ctx, cfg)
	} else {
		err = runNode(ctx, cfg, nil)
	}
	if err != nil && !errors.Is(err, context.Canceled) {
		slog.Error("server stopped", "err", err)
		os.Exit(1)
	}
}

func runNode(ctx context.Context, cfg *config.Config, setReady func(bool)) error {
	vaultKey, err := coreassets.LoadOrCreateVaultKey(cfg.DataDir, cfg.VaultKey)
	if err != nil {
		return err
	}
	var documents *storage.Documents
	if cfg.ClusterMode {
		documents, err = storage.OpenPostgres(ctx, cfg.DatabaseURL, cfg.ClusterID)
		if err != nil {
			return err
		}
		defer documents.Close()
	}
	var assetStore *coreassets.Store
	if documents != nil {
		assetStore, err = coreassets.OpenStoreWithDocuments(filepath.Join(cfg.DataDir, "assets.json"), vaultKey, documents)
	} else {
		assetStore, err = coreassets.OpenStore(filepath.Join(cfg.DataDir, "assets.json"), vaultKey)
	}
	if err != nil {
		return err
	}
	assetService := coreassets.NewService(assetStore, nil)
	historyStore, err := monitorhistory.Open(filepath.Join(cfg.DataDir, "monitor-history"), vaultKey, documents)
	if err != nil {
		return err
	}
	defer historyStore.Close()
	assetService.SetMonitorHistory(historyStore)
	fileAudit, err := corefiles.OpenAuditStore(filepath.Join(cfg.DataDir, "file-transfers", "index.jsonl"))
	if err != nil {
		return err
	}
	fileService := corefiles.NewService(func(ctx context.Context, assetID string) (corefiles.Remote, error) {
		_, remote, err := assetService.OpenSFTP(ctx, assetID)
		return remote, err
	}, fileAudit)
	sftpSessions := corefiles.NewAccessSessionStore()
	var identityService *coreauth.Service
	if documents != nil {
		identityService, err = coreauth.OpenServiceWithDocumentsAndVaultKey(filepath.Join(cfg.DataDir, "users.json"), documents, vaultKey)
	} else {
		identityService, err = coreauth.OpenServiceWithVaultKey(filepath.Join(cfg.DataDir, "users.json"), vaultKey)
	}
	if err != nil {
		return err
	}
	var groupStore *coregroups.Store
	if cfg.DefaultAdminEnabled {
		if err := identityService.InitializeDefaultAdministrator(); err != nil {
			return err
		}
	}
	if documents != nil {
		groupStore, err = coregroups.OpenStoreWithDocuments(filepath.Join(cfg.DataDir, "user-groups.json"), documents)
	} else {
		groupStore, err = coregroups.OpenStore(filepath.Join(cfg.DataDir, "user-groups.json"))
	}
	if err != nil {
		return err
	}
	var nodeStore *corenodes.Store
	if documents != nil {
		nodeStore, err = corenodes.OpenStoreWithDocuments(filepath.Join(cfg.DataDir, "asset-nodes.json"), documents)
	} else {
		nodeStore, err = corenodes.OpenStore(filepath.Join(cfg.DataDir, "asset-nodes.json"))
	}
	if err != nil {
		return err
	}
	var grantStore *coregrants.Store
	if documents != nil {
		grantStore, err = coregrants.OpenStoreWithDocuments(filepath.Join(cfg.DataDir, "grants.json"), documents)
	} else {
		grantStore, err = coregrants.OpenStore(filepath.Join(cfg.DataDir, "grants.json"))
	}
	if err != nil {
		return err
	}
	var accessReviewStore *coreaccessreviews.Store
	if documents != nil {
		accessReviewStore, err = coreaccessreviews.OpenStoreWithDocuments(filepath.Join(cfg.DataDir, "access-reviews.json"), documents)
	} else {
		accessReviewStore, err = coreaccessreviews.OpenStore(filepath.Join(cfg.DataDir, "access-reviews.json"))
	}
	if err != nil {
		return err
	}
	var commandFilterStore *corecommandfilters.Store
	if documents != nil {
		commandFilterStore, err = corecommandfilters.OpenStoreWithDocuments(filepath.Join(cfg.DataDir, "command-filters.json"), documents)
	} else {
		commandFilterStore, err = corecommandfilters.OpenStore(filepath.Join(cfg.DataDir, "command-filters.json"))
	}
	if err != nil {
		return err
	}
	sessionBroker := gateway.NewBroker(cfg.DataDir, vaultKey, func(ctx context.Context, assetID string, cols, rows int) (gateway.AssetInfo, gateway.Terminal, error) {
		asset, shell, err := assetService.OpenShell(ctx, assetID, cols, rows)
		if err != nil {
			return gateway.AssetInfo{}, nil, err
		}
		return gateway.AssetInfo{
			ID:         asset.ID,
			GatewayIDs: asset.GatewayIDs,
			Name:       asset.Name,
			Host:       asset.Host,
			Port:       asset.Port,
			Username:   asset.Username,
		}, shell, nil
	})
	defer sessionBroker.CloseAll()
	sessionSettings, err := sessionpolicy.Open(filepath.Join(cfg.DataDir, "session-security.json"), documents)
	if err != nil {
		return err
	}
	sessionBroker.SetSessionPolicy(sessionSettings.Snapshot)
	desktopBroker, err := desktop.New(cfg.DataDir, vaultKey)
	if err != nil {
		return err
	}
	defer desktopBroker.CloseAll()
	desktopBroker.SetSessionPolicy(sessionSettings.Snapshot)
	jobService, err := corejobs.Open(filepath.Join(cfg.DataDir, "ssh-jobs.json"), vaultKey, documents, assetService.Exec)
	if err != nil {
		return err
	}
	defer jobService.Close()
	agentEvents, err := agentevents.Open(filepath.Join(cfg.DataDir, "agent-events"), vaultKey, documents)
	if err != nil {
		return err
	}
	agentEvents.BindOwner(ctx)
	defer agentEvents.Close()
	discoveredAccounts, err := accountdiscovery.Open(filepath.Join(cfg.DataDir, "account-discovery"), vaultKey, documents)
	if err != nil {
		return err
	}
	discoveredAccounts.BindOwner(ctx)
	defer discoveredAccounts.Close()
	accountRisks, err := accountrisks.Open(filepath.Join(cfg.DataDir, "account-risks.json"), vaultKey, documents)
	if err != nil {
		return err
	}
	defer accountRisks.Close()
	credentialPlans, err := rotationplans.Open(filepath.Join(cfg.DataDir, "rotation-plans.json"), vaultKey, documents)
	if err != nil {
		return err
	}
	defer credentialPlans.Close()
	accessTickets, err := tickets.Open(filepath.Join(cfg.DataDir, "access-tickets.json"), vaultKey, documents)
	if err != nil {
		return err
	}
	defer accessTickets.Close()
	notificationService, err := notifications.Open(filepath.Join(cfg.DataDir, "notifications.json"), vaultKey, documents)
	if err != nil {
		return err
	}
	defer notificationService.Close()
	commandAlertStore, err := commandalerts.Open(filepath.Join(cfg.DataDir, "command-alerts.json"), vaultKey, documents)
	if err != nil {
		return err
	}
	defer commandAlertStore.Close()
	monitorAlertService, err := monitoralerts.Open(filepath.Join(cfg.DataDir, "monitor-alerts.json"), vaultKey, documents)
	if err != nil {
		return err
	}
	defer monitorAlertService.Close()
	reportStore, err := reporting.Open(filepath.Join(cfg.DataDir, "report-exports.json"), vaultKey, documents)
	if err != nil {
		return err
	}
	defer reportStore.Close()
	platformKeyMAC := hmac.New(sha256.New, vaultKey)
	platformKeyMAC.Write([]byte("jms233/platform-identity/v1"))
	platformKey := platformKeyMAC.Sum(nil)
	defer clear(platformKey)
	var platformDocuments *storage.Documents
	if documents != nil {
		platformDocuments, err = documents.Scoped("platform-identity")
		if err != nil {
			return err
		}
	}
	loginAuditStore, err := loginaudit.Open(filepath.Join(cfg.DataDir, "platform-login-audit"), platformKey, platformDocuments)
	if err != nil {
		return err
	}
	defer loginAuditStore.Close()
	platformNotifications, err := notifications.Open(filepath.Join(cfg.DataDir, "platform-notifications.json"), platformKey, platformDocuments)
	if err != nil {
		return err
	}
	defer platformNotifications.Close()
	databaseService, err := databasequery.Open(filepath.Join(cfg.DataDir, "database-queries.json"), vaultKey, documents, assetService.QueryDatabase)
	if err != nil {
		return err
	}
	databaseService.BindOwner(ctx)
	defer databaseService.Close()
	operationService, err := coreoperations.Open(filepath.Join(cfg.DataDir, "operations.json"), vaultKey, documents, jobService)
	if err != nil {
		return err
	}
	defer operationService.Close()
	roleStore, err := rbac.Open(filepath.Join(cfg.DataDir, "rbac.json"), documents)
	if err != nil {
		return err
	}
	policyStore, err := accesspolicies.Open(filepath.Join(cfg.DataDir, "access-policies.json"), documents)
	if err != nil {
		return err
	}
	loginReviewStore, err := loginreviews.Open(filepath.Join(cfg.DataDir, "platform-login-reviews.json"), vaultKey, documents)
	if err != nil {
		return err
	}
	oidcService, err := oidclogin.Open(filepath.Join(cfg.DataDir, "oidc.json"), vaultKey, documents, cfg.PublicURL)
	if err != nil {
		return err
	}

	ldapService, err := ldaplogin.Open(filepath.Join(cfg.DataDir, "ldap.json"), vaultKey, documents, nil)
	if err != nil {
		return err
	}
	radiusService, err := radiuslogin.Open(filepath.Join(cfg.DataDir, "radius.json"), vaultKey, documents, nil)
	if err != nil {
		return err
	}
	defer radiusService.Close()
	casService, err := caslogin.Open(filepath.Join(cfg.DataDir, "cas.json"), vaultKey, documents, cfg.PublicURL, nil)
	if err != nil {
		return err
	}

	samlService, err := samllogin.Open(filepath.Join(cfg.DataDir, "saml.json"), vaultKey, documents, cfg.PublicURL)
	if err != nil {
		return err
	}
	passkeyService, err := passkeys.Open(filepath.Join(cfg.DataDir, "passkeys.json"), vaultKey, documents, cfg.PublicURL)
	if err != nil {
		return err
	}
	orgStore, err := organizations.Open(filepath.Join(cfg.DataDir, "organizations.json"), documents)
	if err != nil {
		return err
	}
	pluginCache, err := hostplugins.NewCache(cfg.DataDir)
	if err != nil {
		return err
	}
	pluginService := hostplugins.New(func(ctx context.Context, id string) (hostplugins.Transport, error) {
		return assetService.OpenManagedHost(ctx, id)
	}, pluginCache)
	brandStore, err := branding.Open(filepath.Join(cfg.DataDir, "branding.json"), documents)
	if err != nil {
		return err
	}
	root := api.Dependencies{AgentEvents: agentEvents, HostPlugins: pluginService, Desktops: desktopBroker, LoginReviews: loginReviewStore, AccessPolicies: policyStore, TrustedProxies: cfg.TrustedProxies, Assets: assetService, AccessReviews: accessReviewStore, Auth: identityService, Grants: grantStore, CommandFilters: commandFilterStore, Groups: groupStore, Nodes: nodeStore, Sessions: sessionBroker, Files: fileService, SFTPSessions: sftpSessions, Jobs: jobService, Operations: operationService, RBAC: roleStore, OIDC: oidcService, LDAP: ldapService, CAS: casService, SAML: samlService, Passkeys: passkeyService, RADIUS: radiusService, PublicURL: cfg.PublicURL, AdminToken: cfg.AdminToken}
	root.AccessMu = &sync.RWMutex{}
	root.Branding = brandStore
	root.AccountDiscovery = discoveredAccounts
	root.AccountRisks = accountRisks
	root.RotationPlans = credentialPlans
	root.Tickets = accessTickets
	root.Notifications = notificationService
	root.CommandAlerts = commandAlertStore
	root.MonitorAlerts = monitorAlertService
	root.LoginAudit = loginAuditStore
	root.Reports = reportStore
	root.GlobalAccessMu = root.AccessMu
	root.SessionPolicy = sessionSettings
	root.DatabaseQueries = databaseService
	root.GlobalRBAC = roleStore
	root.GlobalGroups = groupStore
	root.GlobalPolicies = policyStore
	root.Organizations = orgStore
	runtimes := &organizationRuntimes{cfg: cfg, ctx: ctx, key: vaultKey, documents: documents, root: root, store: orgStore, items: map[string]*organizationRuntime{}}
	defer runtimes.close(false)
	if err = runtimes.initialize(); err != nil {
		return err
	}
	// System authentication and identity administration have one shared identity
	// store. All operational paths are dispatched to a selected resource runtime.
	global := root
	global.PlatformOnlyPolicies = true
	global.OrganizationSnapshot = runtimes.snapshot
	global.OrganizationChanged = runtimes.changed
	global.Assets = nil
	global.AccessReviews = nil
	global.Nodes = nil
	global.Sessions = nil
	global.Files = nil
	global.SFTPSessions = nil
	global.Jobs = nil
	global.DatabaseQueries = nil
	global.Operations = nil
	global.AgentEvents = nil
	global.AccountDiscovery = nil
	global.AccountRisks = nil
	global.RotationPlans = nil
	global.Tickets = nil
	global.Notifications = platformNotifications
	global.PlatformNotifications = true
	global.CommandAlerts = nil
	global.MonitorAlerts = nil
	global.Reports = nil
	handler := api.NewOrganizationRouter(cfg.Version, global, runtimes.handler)
	if cfg.WebDir != "" {
		ui, err := webui.Open(handler, cfg.WebDir)
		if err != nil {
			return err
		}
		defer ui.Close()
		handler = ui
	}
	identityService.SetPrivilegedCheck(runtimes.isPrivileged)
	srv := &http.Server{Addr: cfg.Addr, Handler: handler, ReadHeaderTimeout: 10 * time.Second}
	listener, err := net.Listen("tcp", cfg.Addr)
	if err != nil {
		return err
	}

	nodeCtx, cancelNode := context.WithCancel(ctx)
	accountRisks.Start(nodeCtx)
	credentialPlans.Start(nodeCtx)
	accessTickets.Start(nodeCtx)
	notificationService.Start(nodeCtx)
	platformNotifications.Start(nodeCtx)
	loginAuditStore.Start(nodeCtx, loginaudit.ReviewSource(loginReviewStore))
	monitorAlertService.Start(nodeCtx)
	monitorDone := make(chan struct{})
	go func() {
		defer close(monitorDone)
		assetService.Run(nodeCtx, cfg.MonitorInterval)
	}()

	serverDone := make(chan error, 1)
	go func() { serverDone <- srv.Serve(listener) }()
	var stateStoreErr <-chan error
	if documents != nil {
		checkDone := make(chan error, 1)
		stateStoreErr = checkDone
		go func() {
			ticker := time.NewTicker(5 * time.Second)
			defer ticker.Stop()
			for {
				select {
				case <-nodeCtx.Done():
					return
				case <-ticker.C:
					if err := documents.Ping(); err != nil {
						if setReady != nil {
							setReady(false)
						}
						checkDone <- err
						return
					}
				}
			}
		}()
	}
	if setReady != nil {
		setReady(true)
	}
	slog.Info("server listening", "addr", cfg.Addr, "version", cfg.Version, "cluster", cfg.ClusterMode)

	var serverErr error
	select {
	case <-ctx.Done():
	case serverErr = <-serverDone:
		if errors.Is(serverErr, http.ErrServerClosed) {
			serverErr = nil
		}
	case serverErr = <-stateStoreErr:
	}
	if setReady != nil {
		setReady(false)
	}
	cancelNode()
	radiusService.Close()

	if errors.Is(context.Cause(ctx), cluster.ErrLeaseLost) {
		// Drop established requests immediately when leadership can no longer be
		// proven; a standby must not overlap file-store writes during takeover.
		_ = srv.Close()
		runtimes.close(true)
		operationService.Abandon()
		jobService.Abandon()
		databaseService.Abandon()
	} else {
		shutdownCtx, cancelShutdown := context.WithTimeout(context.Background(), 10*time.Second)
		if err := srv.Shutdown(shutdownCtx); err != nil {
			serverErr = errors.Join(serverErr, err)
			_ = srv.Close()
		}
		cancelShutdown()
		runtimes.close(false)
		operationService.Close()
		jobService.Close()
		databaseService.Close()
	}
	desktopBroker.CloseAll()
	sessionBroker.CloseAll()
	<-monitorDone
	select {
	case serveErr := <-serverDone:
		if !errors.Is(serveErr, http.ErrServerClosed) {
			serverErr = errors.Join(serverErr, serveErr)
		}
	default:
	}
	return serverErr
}

func runActiveStandby(ctx context.Context, cfg *config.Config) error {
	var ready atomic.Bool
	probeServer := &http.Server{
		Addr:              cfg.ClusterHealthAddr,
		Handler:           cluster.ProbeHandler(ready.Load),
		ReadHeaderTimeout: 3 * time.Second,
	}
	probeListener, err := net.Listen("tcp", cfg.ClusterHealthAddr)
	if err != nil {
		return err
	}
	probeDone := make(chan error, 1)
	go func() { probeDone <- probeServer.Serve(probeListener) }()
	defer func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = probeServer.Shutdown(shutdownCtx)
	}()

	slog.Info("active/standby node started", "cluster", cfg.ClusterID, "probe_addr", cfg.ClusterHealthAddr)
	for {
		if ctx.Err() != nil {
			return nil
		}
		acquireCtx, cancelAcquire := context.WithTimeout(ctx, 3*time.Second)
		lease, acquired, acquireErr := cluster.TryAcquire(acquireCtx, cfg.DatabaseURL, cfg.ClusterID)
		cancelAcquire()
		if acquireErr != nil {
			if errors.Is(acquireErr, cluster.ErrInvalidClusterID) || errors.Is(acquireErr, cluster.ErrInvalidDatabaseConfig) {
				return acquireErr
			}
			slog.Warn("cluster election unavailable; retrying", "cluster", cfg.ClusterID, "error_code", "database_unavailable")
			if err := waitForClusterRetry(ctx, probeDone); err != nil {
				return err
			}
			continue
		}
		if !acquired {
			if err := waitForClusterRetry(ctx, probeDone); err != nil {
				return err
			}
			continue
		}

		slog.Info("cluster leadership acquired", "cluster", cfg.ClusterID)
		leaderCtx, cancelLeader := context.WithCancelCause(ctx)
		leaseDone := make(chan error, 1)
		go func() {
			leaseDone <- watchLease(leaderCtx, lease, &ready, cancelLeader)
		}()
		nodeErr := runNode(leaderCtx, cfg, ready.Store)
		ready.Store(false)
		cancelLeader(context.Canceled)
		leaseErr := <-leaseDone
		closeCtx, cancelClose := context.WithTimeout(context.Background(), 3*time.Second)
		closeErr := lease.Close(closeCtx)
		cancelClose()

		if ctx.Err() != nil {
			return nil
		}
		if errors.Is(leaseErr, cluster.ErrLeaseLost) {
			slog.Error("cluster leadership lost; node stopped", "cluster", cfg.ClusterID, "error_code", "leader_session_lost")
		} else if nodeErr != nil {
			slog.Error("active node stopped; attempting re-election", "cluster", cfg.ClusterID, "error_code", "server_stopped")
		}
		if closeErr != nil {
			slog.Warn("cluster lock release failed", "cluster", cfg.ClusterID, "error_code", "lock_release_failed")
		}
		if err := waitForClusterRetry(ctx, probeDone); err != nil {
			return err
		}
	}
}

func watchLease(ctx context.Context, lease *cluster.Lease, ready *atomic.Bool, cancel context.CancelCauseFunc) error {
	ticker := time.NewTicker(clusterCheckInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			checkCtx, cancelCheck := context.WithTimeout(ctx, clusterCheckTimeout)
			err := lease.Check(checkCtx)
			cancelCheck()
			if err != nil {
				ready.Store(false)
				cancel(cluster.ErrLeaseLost)
				return cluster.ErrLeaseLost
			}
		}
	}
}

func waitForClusterRetry(ctx context.Context, probeDone <-chan error) error {
	timer := time.NewTimer(clusterRetryInterval)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return nil
	case err := <-probeDone:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case <-timer.C:
		return nil
	}
}
