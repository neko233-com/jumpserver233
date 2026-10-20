package api

import (
	"net/http"
	"strconv"
	"strings"
	"time"

	coreauth "github.com/neko233-com/jumpserver233/server/internal/core/auth"
)

const accessKeyClockSkew = 5 * time.Minute

type signatureAuthorization struct {
	keyID     string
	algorithm string
	headers   string
	signature string
}

func authenticateHTTPSignature(r *http.Request, identities *coreauth.Service) (coreauth.User, bool) {
	if identities == nil || len(r.Header.Get("Authorization")) > 2048 {
		return coreauth.User{}, false
	}
	authorization, ok := parseSignatureAuthorization(r.Header.Get("Authorization"))
	if !ok || !strings.EqualFold(authorization.algorithm, "hmac-sha256") || authorization.keyID == "" || len(authorization.keyID) > 64 {
		return coreauth.User{}, false
	}

	dateValues := r.Header.Values("Date")
	if len(dateValues) != 1 {
		return coreauth.User{}, false
	}
	date := strings.TrimSpace(dateValues[0])
	parsedDate, err := http.ParseTime(date)
	if err != nil {
		return coreauth.User{}, false
	}
	if delta := time.Since(parsedDate); delta > accessKeyClockSkew || delta < -accessKeyClockSkew {
		return coreauth.User{}, false
	}

	headerNames := strings.Fields(strings.ToLower(authorization.headers))
	if len(headerNames) != 2 && len(headerNames) != 3 {
		return coreauth.User{}, false
	}
	if headerNames[0] != "(request-target)" || headerNames[len(headerNames)-1] != "date" {
		return coreauth.User{}, false
	}
	if len(headerNames) == 3 && headerNames[1] != "accept" {
		return coreauth.User{}, false
	}

	uri := r.URL.RequestURI()
	if original, ok := r.Context().Value(identityOriginalURIKey{}).(string); ok {
		uri = original
	}
	requestTarget := strings.ToLower(r.Method) + " " + uri
	lines := []string{"(request-target): " + requestTarget}
	if len(headerNames) == 3 {
		acceptValues := r.Header.Values("Accept")
		if len(acceptValues) != 1 {
			return coreauth.User{}, false
		}
		lines = append(lines, "accept: "+strings.TrimSpace(acceptValues[0]))
	}
	lines = append(lines, "date: "+date)
	return identities.VerifyAccessKeySignature(authorization.keyID, strings.Join(lines, "\n"), authorization.signature)
}

func parseSignatureAuthorization(value string) (signatureAuthorization, bool) {
	scheme, parameters, ok := strings.Cut(strings.TrimSpace(value), " ")
	if !ok || !strings.EqualFold(scheme, "Signature") {
		return signatureAuthorization{}, false
	}
	fields := make(map[string]string, 4)
	for _, raw := range strings.Split(parameters, ",") {
		name, encoded, found := strings.Cut(strings.TrimSpace(raw), "=")
		if !found {
			return signatureAuthorization{}, false
		}
		name = strings.ToLower(strings.TrimSpace(name))
		if name != "keyid" && name != "algorithm" && name != "headers" && name != "signature" && name != "realm" {
			return signatureAuthorization{}, false
		}
		if _, duplicate := fields[name]; duplicate {
			return signatureAuthorization{}, false
		}
		decoded, err := strconv.Unquote(strings.TrimSpace(encoded))
		if err != nil || strings.ContainsAny(decoded, "\r\n") {
			return signatureAuthorization{}, false
		}
		fields[name] = decoded
	}
	for _, required := range []string{"keyid", "algorithm", "headers", "signature"} {
		if fields[required] == "" {
			return signatureAuthorization{}, false
		}
	}
	return signatureAuthorization{
		keyID:     fields["keyid"],
		algorithm: fields["algorithm"],
		headers:   fields["headers"],
		signature: fields["signature"],
	}, true
}
