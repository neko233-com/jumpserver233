package api

import (
	"context"
	coreauth "github.com/neko233-com/jumpserver233/server/internal/core/auth"
	"github.com/neko233-com/jumpserver233/server/internal/core/identityscope"
	"github.com/neko233-com/jumpserver233/server/internal/core/identitysources"
	"net/http"
	"strings"
)

// Only the source router may install this value; request headers and JSON cannot.
type identitySourceContextKey struct{}
type externalScope struct {
	ID         string
	Runtime    *identitysources.Runtime
	Generation uint64
}
type identityOriginalURIKey struct{}

func identityScopedPath(path string) (id, suffix string) {
	rest, ok := strings.CutPrefix(path, "/api/v1/identity-sources/")
	if !ok {
		return "", path
	}
	id, suffix, ok = strings.Cut(rest, "/")
	if !ok || !identityscope.ValidID(id) {
		return "", path
	}
	return id, "/" + suffix
}
func externalSourceID(r *http.Request) string {
	scope, _ := r.Context().Value(identitySourceContextKey{}).(externalScope)
	return scope.ID
}
func withExternalSource(r *http.Request, id string, runtime *identitysources.Runtime) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), identitySourceContextKey{}, externalScope{id, runtime, runtime.Generation()}))
}
func externalFlowGeneration(r *http.Request) bool {
	scope, ok := r.Context().Value(identitySourceContextKey{}).(externalScope)
	return !ok || scope.Runtime.Generation() == scope.Generation
}
func externalSetFlowCookie(r *http.Request, name, proof string) string {
	scope, ok := r.Context().Value(identitySourceContextKey{}).(externalScope)
	if !ok {
		return proof
	}
	return scope.Runtime.SealCookie(name, proof, scope.Generation)
}
func externalReadFlowCookie(r *http.Request, name, value string) string {
	scope, ok := r.Context().Value(identitySourceContextKey{}).(externalScope)
	if !ok {
		if len(value) > 128 {
			return ""
		}
		return value
	}
	return scope.Runtime.OpenCookie(name, value)
}
func externalCookiePath(r *http.Request, path string) string {
	return identityscope.Prefix(externalSourceID(r)) + path
}
func ensureExternalForRequest(r *http.Request, s *coreauth.Service, kind, issuer, subject, alias string, provision bool) (coreauth.User, error) {
	if id := externalSourceID(r); id != "" {
		if strings.HasPrefix(r.URL.Path, "/api/v1/authentication/") {
			return s.EnsureNamedExternalLoginUser(kind, id, issuer, subject, alias, provision, func() bool { return externalFlowGeneration(r) })
		}
		return s.EnsureNamedExternalUser(kind, id, issuer, subject, alias, provision)
	}
	return s.EnsureExternalUser(kind, issuer, subject, alias, provision)
}
func authenticateExternalForRequest(r *http.Request, s *coreauth.Service, id, kind, otp string, generation int) (coreauth.LoginSession, *coreauth.MFASetupChallenge, error) {
	if source := externalSourceID(r); source != "" {
		return s.AuthenticateNamedExternalUser(id, kind, source, otp, generation)
	}
	return s.AuthenticateExternalUser(id, kind, otp, generation)
}
