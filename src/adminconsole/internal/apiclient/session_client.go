package apiclient

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/customerrors"
	"github.com/leodip/goiabada/core/oauth"
	"github.com/pkg/errors"
)

const (
	// sessionTokenExpiryMargin is how long before a token's stated expiry it stops being
	// served from the cache. Without it a token can expire between the check and the
	// endpoint's own validation, which costs a 401 and a retry for no reason; with it the
	// only 401s left are revocations and clock disagreements, which is what that path is
	// for (#266).
	sessionTokenExpiryMargin = 30 * time.Second

	// sessionTokenTimeout bounds one token request. The session lookup it precedes sits on
	// the request path of every admin console page, so this cannot be generous.
	sessionTokenTimeout = 10 * time.Second
)

// SessionTokenSource obtains and caches the bearer token the admin console presents to the
// auth server's browser session endpoint.
//
// The grant is client_credentials on the admin console's own client, and the scope is a
// single narrow permission rather than one of the manage-* admin API scopes: holding this
// module's client secret must not be a way to drive the whole admin API with no user
// present (#266).
//
// The token is cached until shortly before it expires, so an ordinary page load costs no
// token request at all. It is dropped on Invalidate, which the session backend calls when
// the endpoint answers 401, so a revoked or expired token costs exactly one refresh.
type SessionTokenSource struct {
	tokenURL     string
	clientId     string
	clientSecret string
	scope        string
	httpClient   *http.Client

	// mu guards the cached token and also serialises fetches. A fetch holding the lock
	// blocks concurrent requests for the length of one token request, which is the point:
	// the alternative is every in-flight request discovering the expiry at the same
	// instant and asking the auth server for a token each.
	mu        sync.Mutex
	token     string
	expiresAt time.Time
}

// NewSessionTokenSource builds a token source against the auth server at baseURL, which
// should be the internal base URL where one is configured.
func NewSessionTokenSource(baseURL, clientId, clientSecret string) *SessionTokenSource {
	return &SessionTokenSource{
		tokenURL:     strings.TrimSuffix(baseURL, "/") + "/auth/token",
		clientId:     clientId,
		clientSecret: clientSecret,
		scope: constants.AuthServerResourceIdentifier + ":" +
			constants.BrowserSessionsPermissionIdentifier,
		httpClient: &http.Client{Timeout: sessionTokenTimeout},
	}
}

// Token returns a live bearer token, fetching one only when there is nothing usable cached.
func (s *SessionTokenSource) Token(ctx context.Context) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.token != "" && time.Now().UTC().Add(sessionTokenExpiryMargin).Before(s.expiresAt) {
		return s.token, nil
	}

	token, expiresAt, err := s.fetch(ctx)
	if err != nil {
		// The cache is left cleared rather than holding whatever failed to be replaced.
		// A token that is past the margin is one this source has already decided not to
		// serve, so keeping it would mean serving it only on the failure path.
		s.token = ""
		s.expiresAt = time.Time{}
		return "", err
	}

	s.token = token
	s.expiresAt = expiresAt
	return token, nil
}

// Invalidate drops the cached token, so the next Token fetches a fresh one.
func (s *SessionTokenSource) Invalidate() {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.token = ""
	s.expiresAt = time.Time{}
}

// fetch performs the client_credentials exchange. Called with the lock held.
func (s *SessionTokenSource) fetch(ctx context.Context) (string, time.Time, error) {
	form := url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {s.clientId},
		"client_secret": {s.clientSecret},
		"scope":         {s.scope},
	}

	request, err := http.NewRequestWithContext(ctx, http.MethodPost, s.tokenURL,
		strings.NewReader(form.Encode()))
	if err != nil {
		return "", time.Time{}, errors.Wrap(err, "unable to build the session token request")
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("Accept", "application/json")

	response, err := s.httpClient.Do(request)
	if err != nil {
		return "", time.Time{}, errors.Wrap(err, "unable to reach the auth server's token endpoint")
	}
	defer func() { _ = response.Body.Close() }()

	body, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if err != nil {
		return "", time.Time{}, errors.Wrap(err, "unable to read the session token response")
	}

	if response.StatusCode != http.StatusOK {
		return "", time.Time{}, errors.WithStack(errors.New(
			s.refusalMessage(response.StatusCode, body)))
	}

	var tokenResponse oauth.TokenResponse
	if err := json.Unmarshal(body, &tokenResponse); err != nil {
		return "", time.Time{}, errors.Wrap(err, "unable to decode the session token response")
	}
	if strings.TrimSpace(tokenResponse.AccessToken) == "" {
		// Reported rather than cached. An empty bearer would be sent on every session
		// call and answered 401 on every one of them, which reads in a log as the
		// endpoint refusing the admin console rather than as the token never arriving.
		return "", time.Time{}, errors.WithStack(errors.New(
			"the auth server's token endpoint returned no access token"))
	}

	return tokenResponse.AccessToken,
		time.Now().UTC().Add(time.Duration(tokenResponse.ExpiresIn) * time.Second), nil
}

// refusalMessage explains a refused token request, naming the client that was refused and,
// where the refusal says the client is not provisioned for this, the two things it needs.
//
// The reason it is worth more than a status code: a deployment this fails on cannot be
// repaired through the admin console, because obtaining this token is what every admin
// console page needs, so an administrator locked out by it has no page to fix it from. The
// route back in is direct SQL or a temporary swap of the configured client id, and neither
// is discoverable from "answered 400" (#266).
//
// How a deployment reaches it: migration 000035 provisions the client-credentials switch and
// the browser-sessions permission against the literal identifier `admin-console-client`,
// while this source authenticates as whatever GOIABADA_ADMINCONSOLE_OAUTH_CLIENT_ID names,
// for which that literal is only the default. A deployment that pointed the variable at a
// client of its own therefore upgrades into a token endpoint that refuses it, and the two
// codes below are the two ways it says so: unauthorized_client when client credentials is off
// on that client, invalid_scope when that client does not hold the permission.
//
// The remedy sentence is attached to exactly those two codes rather than to every refusal,
// because a server_error or a gateway's 502 is not a provisioning fault and telling an
// operator to grant a permission would send them to the wrong place.
//
// The `error` field is a fixed OAuth code, but it arrives over the wire, so it goes through
// the same RFC 6749 Appendix A.8 filter the auth server applies on the way out (RFC 6749
// section 5.2) rather than reaching a log line unbounded and carrying its own newlines.
func (s *SessionTokenSource) refusalMessage(statusCode int, body []byte) string {
	var refusal struct {
		Error string `json:"error"`
	}
	// Best effort: a refusal with no JSON body at all, or one written by a proxy rather than
	// by the token endpoint, still has to produce a message.
	_ = json.Unmarshal(body, &refusal)
	code := customerrors.ConformErrorDescription(refusal.Error)

	message := fmt.Sprintf("the auth server's token endpoint answered %d", statusCode)
	if code != "" {
		message += fmt.Sprintf(" (%s)", code)
	}
	// %q rather than %s: the client id comes from the deployment's own environment, and a
	// stray control character in it must not forge a line in the log this lands in.
	message += fmt.Sprintf(" for client_id %q", s.clientId)

	if code == "unauthorized_client" || code == "invalid_scope" {
		message += fmt.Sprintf(", which needs the client credentials flow enabled and the"+
			" %s permission granted", s.scope)
	}

	return message
}
