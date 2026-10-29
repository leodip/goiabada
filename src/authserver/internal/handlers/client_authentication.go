package handlers

import (
	"encoding/base64"
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"strings"

	"github.com/leodip/goiabada/core/logging"
	"github.com/leodip/goiabada/core/oauth"
)

// The handler side of client authentication, which every endpoint that authenticates its caller
// shares: reading the client's credentials off the request, and the Warn record of a refusal.
// Deciding whether they authenticate the client is clientauth's (#676 decision 9).

// clientAuthenticationEndpoint is an endpoint that authenticates the calling client, so the record
// of a refusal says which endpoint refused.
type clientAuthenticationEndpoint int

const (
	atTokenEndpoint clientAuthenticationEndpoint = iota + 1
	atRevocationEndpoint
	atIntrospectionEndpoint
)

// logClientAuthenticationRefusal writes the Warn record of a client that could not be authenticated
// at the endpoint, when err is that refusal: an invalid_client, an unknown or disabled client or a
// missing or wrong secret. Any other error writes nothing. clientIdentifier is the identifier the
// request sent.
//
// The answer's 401 was all the server's log showed, so a client refused for a reason its operator
// couldn't see stayed refused, which is how a library that form-encodes its Basic credentials went
// unnoticed. The record says which reason, how the client sent its credentials and what identifier
// it sent. It is a log record and not an audit event, because the identifier is the caller's own,
// unproven, and an audit row would let anyone write ones naming a legitimate client. The record
// escapes and bounds it.
func (endpoint clientAuthenticationEndpoint) logClientAuthenticationRefusal(r *http.Request,
	clientIdentifier string, err error) {

	var errDetail *oauth.ErrorDetail
	if !errors.As(err, &errDetail) || errDetail.Code() != "invalid_client" {
		return
	}
	// One literal message per endpoint, so a record is found by its message.
	switch endpoint {
	case atTokenEndpoint:
		slog.WarnContext(r.Context(), "client authentication refused at the token endpoint",
			"reason", errDetail.Description(),
			"client_identifier", logging.FieldForLog(clientIdentifier),
			"client_auth_method", clientAuthMethod(r),
			"grant_type", requestedGrantType(r).String())
	case atRevocationEndpoint:
		slog.WarnContext(r.Context(), "client authentication refused at the revocation endpoint",
			"reason", errDetail.Description(),
			"client_identifier", logging.FieldForLog(clientIdentifier),
			"client_auth_method", clientAuthMethod(r))
	case atIntrospectionEndpoint:
		slog.WarnContext(r.Context(), "client authentication refused at the introspection endpoint",
			"reason", errDetail.Description(),
			"client_identifier", logging.FieldForLog(clientIdentifier),
			"client_auth_method", clientAuthMethod(r))
	}
}

// clientAuthMethod names how a request presented its client credentials, as discovery's
// token_endpoint_auth_methods_supported names them, for a log record: client_secret_basic for the
// Authorization header, client_secret_post for a secret in the body, and none for neither.
func clientAuthMethod(r *http.Request) string {
	if strings.HasPrefix(r.Header.Get("Authorization"), "Basic ") {
		return "client_secret_basic"
	}
	if r.PostForm.Get("client_secret") != "" {
		return "client_secret_post"
	}
	return "none"
}

// extractClientCredentials extracts client_id and client_secret from the request.
// It supports both client_secret_basic (Authorization header) and client_secret_post (form body).
// Per RFC 6749 clients MUST NOT use more than one authentication method per request.
// Which of the two was used is not returned: every invalid_client carries the same challenge
// whichever it was (#437).
func extractClientCredentials(r *http.Request) (clientId, clientSecret string, err error) {
	// Check for Basic auth in Authorization header
	basicClientId, basicClientSecret, hasBasicAuth := parseBasicAuth(r.Header.Get("Authorization"))

	// Get credentials from POST body
	postClientId := r.PostForm.Get("client_id")
	postClientSecret := r.PostForm.Get("client_secret")
	hasPostAuth := postClientSecret != ""

	// RFC 6749 clients MUST NOT use more than one authentication method
	if hasBasicAuth && hasPostAuth {
		return "", "", oauth.NewErrorDetailWithHTTPStatus("invalid_request",
			"Client authentication failed: multiple authentication methods provided. "+
				"Use either HTTP Basic authentication OR client_secret in the request body, but not both.",
			http.StatusBadRequest)
	}

	// Use Basic auth if present
	if hasBasicAuth {
		return basicClientId, basicClientSecret, nil
	}

	// Fall back to POST body credentials
	return postClientId, postClientSecret, nil
}

// parseBasicAuth parses an HTTP Basic Authentication header value.
// It returns the client_id, client_secret, and whether Basic auth was present.
func parseBasicAuth(authHeader string) (clientId, clientSecret string, ok bool) {
	if authHeader == "" {
		return "", "", false
	}

	// Must start with "Basic "
	const prefix = "Basic "
	if !strings.HasPrefix(authHeader, prefix) {
		return "", "", false
	}

	// Decode base64
	encoded := authHeader[len(prefix):]
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return "", "", false
	}

	// Split on first colon (password may contain colons)
	credentials := string(decoded)
	colonIdx := strings.Index(credentials, ":")
	if colonIdx < 0 {
		return "", "", false
	}

	return percentDecoded(credentials[:colonIdx]), percentDecoded(credentials[colonIdx+1:]), true
}

// percentDecoded undoes RFC 6749 section 2.3.1's form encoding before Basic authentication:
// '+' is a space and '%2B' a literal plus. A malformed percent escape keeps the whole value
// unchanged, preserving the existing fallback for clients that send an unencoded '%' (#474).
func percentDecoded(value string) string {
	decoded, err := url.QueryUnescape(value)
	if err != nil {
		return value
	}
	return decoded
}
