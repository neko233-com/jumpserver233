package api

import (
	"bufio"
	"context"
	"crypto/subtle"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"

	coreauth "github.com/neko233-com/jumpserver233/server/internal/core/auth"
	"github.com/neko233-com/jumpserver233/server/internal/originpolicy"
)

type principalContextKey struct{}

var principalKey = principalContextKey{}

// statusRecorder captures the response status for access logging.
type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(code int) {
	r.status = code
	r.ResponseWriter.WriteHeader(code)
}

func (r *statusRecorder) Unwrap() http.ResponseWriter { return r.ResponseWriter }

func (r *statusRecorder) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	connection, buffered, err := http.NewResponseController(r.ResponseWriter).Hijack()
	if err == nil {
		r.status = http.StatusSwitchingProtocols
	}
	return connection, buffered, err
}

// WithRecover converts panics into 500 responses.
func WithRecover(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				slog.Error("panic recovered", "err", rec, "path", requestLogPath(r))
				writeJSON(w, http.StatusInternalServerError, map[string]string{"detail": "internal server error"})
			}
		}()
		next.ServeHTTP(w, r)
	})
}

// WithAccessLog logs method, path, status and duration.
func WithAccessLog(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rec, r)
		slog.Info("request",
			"method", r.Method,
			"path", requestLogPath(r),
			"status", rec.status,
			"dur", time.Since(start),
		)
	})
}

// WebSocket URLs may carry one-use session capabilities in path segments.
// Preserve the registered route for diagnostics without logging their values.
func requestLogPath(r *http.Request) string {
	if strings.HasPrefix(r.URL.Path, "/ws/") {
		if r.Pattern != "" {
			return r.Pattern
		}
		return "/ws/[redacted]"
	}
	return r.URL.Path
}

// WithCORS allows the local Vite development origins without exposing the API
// to arbitrary browser origins.
func WithCORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if origin != "" && allowedRequestOrigin(r) {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Add("Vary", "Origin")
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type, Date, X-JMS-ORG, X-JMS-SFTP-Session, X-JMS-Browser-Session")
		}
		if r.Method == http.MethodOptions {
			if !allowedRequestOrigin(r) {
				w.WriteHeader(http.StatusForbidden)
				return
			}
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func protectAPI(next http.Handler, adminToken string) http.Handler {
	return protectWithIdentity(next, adminToken, nil, false)
}

func protectAdminAPI(next http.Handler, adminToken string, identities *coreauth.Service) http.Handler {
	return protectWithIdentity(next, adminToken, identities, true)
}

func protectAuthenticatedAPI(next http.Handler, adminToken string, identities *coreauth.Service) http.Handler {
	return protectWithIdentity(next, adminToken, identities, false)
}

func protectWithIdentity(next http.Handler, adminToken string, identities *coreauth.Service, adminOnly bool) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		setNoStore(w)
		principal, status := resolvePrincipal(r, adminToken, identities)
		if status != http.StatusOK {
			if status == http.StatusForbidden {
				writeJSON(w, status, map[string]string{"detail": "authentication required"})
			} else {
				writeJSON(w, status, map[string]string{"detail": "authentication required"})
			}
			return
		}
		if adminOnly && !adminAPIAllowed(r, principal) {
			writeJSON(w, http.StatusForbidden, map[string]string{"detail": "system permission required"})
			return
		}
		if !allowedRequestOrigin(r) {
			rejectRequestOrigin(w)
			return
		}
		if r.URL.Path != "/api/v1/authentication/expire-session/" && !enforceLoginPolicy(w, r, principal) {
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), principalKey, principal)))
	})
}

func resolvePrincipal(r *http.Request, adminToken string, identities *coreauth.Service) (coreauth.User, int) {
	authorization := r.Header.Get("Authorization")
	if authorization != "" {
		scheme, token, ok := strings.Cut(authorization, " ")
		if !ok || token == "" {
			return coreauth.User{}, http.StatusUnauthorized
		}
		if ok && strings.EqualFold(scheme, "Signature") {
			if user, valid := authenticateHTTPSignature(r, identities); valid {
				return user, http.StatusOK
			}
			return coreauth.User{}, http.StatusUnauthorized
		}
		switch {
		case strings.EqualFold(scheme, "Bearer"):
			if adminToken != "" && subtle.ConstantTimeCompare([]byte(token), []byte(adminToken)) == 1 {
				return coreauth.User{ID: "admin-token", Username: "admin", Role: coreauth.RoleAdmin}, http.StatusOK
			}
			if identities != nil {
				if user, valid := identities.ValidateToken(token); valid {
					return user, http.StatusOK
				}
			}
		case strings.EqualFold(scheme, "Token"):
			if identities != nil {
				if user, valid := identities.ValidatePermanentToken(token); valid {
					return user, http.StatusOK
				}
			}
		}
		return coreauth.User{}, http.StatusUnauthorized
	}
	if identities != nil {
		if cookie, err := r.Cookie("jms_sessionid"); err == nil {
			if user, valid := identities.ValidateToken(cookie.Value); valid {
				return user, http.StatusOK
			}
			return coreauth.User{}, http.StatusUnauthorized
		}
	}
	if adminToken != "" {
		return coreauth.User{}, http.StatusUnauthorized
	}
	if identities != nil && !identities.BootstrapRequired() {
		return coreauth.User{}, http.StatusUnauthorized
	}
	if !isLoopbackRemote(r.RemoteAddr) {
		return coreauth.User{}, http.StatusForbidden
	}
	// Only an uninitialized instance (or the legacy no-identity router) permits
	// local bootstrap access. A configured instance always requires an identity.
	return coreauth.User{ID: "loopback-admin", Username: "admin", Role: coreauth.RoleAdmin}, http.StatusOK
}

func PrincipalFromContext(ctx context.Context) (coreauth.User, bool) {
	principal, ok := ctx.Value(principalKey).(coreauth.User)
	return principal, ok
}

func isAllowedOrigin(origin string) bool {
	switch origin {
	case "http://127.0.0.1:5173", "http://localhost:5173", "http://[::1]:5173", "http://127.0.0.1:5174", "http://localhost:5174", "http://127.0.0.1:5177", "http://localhost:5177":
		return true
	default:
		return false
	}
}

type publicOriginKey struct{}
type additionalHTTPSOriginKey struct{}
type additionalHTTPSOrigin struct {
	origin  string
	proxies []string
}

func withAdditionalHTTPSOrigin(next http.Handler, origin string, proxies []string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), additionalHTTPSOriginKey{}, additionalHTTPSOrigin{origin: origin, proxies: proxies})))
	})
}

// Only direct TLS or a configured immediate proxy that overwrites the scheme
// can assert the optional second HTTPS origin. Host and Origin remain exact.
func additionalHTTPSRequest(r *http.Request) bool {
	config, _ := r.Context().Value(additionalHTTPSOriginKey{}).(additionalHTTPSOrigin)
	u, err := url.Parse(config.origin)
	if err != nil || u.Scheme != "https" || u.Host == "" || !strings.EqualFold(u.Host, r.Host) {
		return false
	}
	if r.TLS != nil {
		return true
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return false
	}
	peer, err := netip.ParseAddr(host)
	if err != nil || peer.Zone() != "" {
		return false
	}
	if len(r.Header.Values("X-Forwarded-Proto")) != 1 || !strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https") {
		return false
	}
	for _, raw := range config.proxies {
		if prefix, e := netip.ParsePrefix(raw); e == nil && prefix.Contains(peer.Unmap()) {
			return true
		}
	}
	return false
}

func withPublicOrigin(next http.Handler, origin string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), publicOriginKey{}, origin)))
	})
}
func allowedRequestOrigin(r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		return r.Header.Get("Sec-Fetch-Site") != "cross-site"
	}
	if isAllowedOrigin(origin) {
		return true
	}
	additional, _ := r.Context().Value(additionalHTTPSOriginKey{}).(additionalHTTPSOrigin)
	if origin == additional.origin && origin != "" && additionalHTTPSRequest(r) {
		return true
	}
	public, _ := r.Context().Value(publicOriginKey{}).(string)
	if public != "" {
		return origin == public
	}
	return originpolicy.SameLocal(origin, r.Host, r.TLS != nil)
}

func rejectRequestOrigin(w http.ResponseWriter) {
	writeJSON(w, http.StatusForbidden, map[string]string{"detail": "origin is not allowed", "code": "origin_not_allowed"})
}
func secureSessionCookie(r *http.Request) bool {
	public, _ := r.Context().Value(publicOriginKey{}).(string)
	return r.TLS != nil || additionalHTTPSRequest(r) || strings.HasPrefix(public, "https://")
}

func isLoopbackRemote(remote string) bool {
	host, _, err := net.SplitHostPort(remote)
	if err != nil {
		return false
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
