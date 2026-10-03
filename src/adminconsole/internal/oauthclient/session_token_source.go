package oauthclient

import (
	"context"
	"strings"
	"sync"
	"time"

	"github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/errs"
)

// sessionTokenExpiryMargin is how long before a token's stated expiry it stops being served
// from the cache. Without it a token can expire between the check and the endpoint's own
// validation, which costs a 401 and a retry for no reason; with it the only 401s left are
// revocations and clock disagreements, which is what that path is for (#266). It is the same
// 30 seconds as refreshMargin, which gives the console's other token, the administrator's, its
// margin.
const sessionTokenExpiryMargin = 30 * time.Second

// SessionTokenSource obtains and caches the bearer token the admin console presents to the
// auth server's browser session endpoint: a cache over TokenClient.ClientCredentials (#441).
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
	tokens *TokenClient
	scope  string

	// mu guards the cached token and also serialises fetches. A fetch holding the lock
	// blocks concurrent requests for the length of one token request, which is the point:
	// the alternative is every in-flight request discovering the expiry at the same
	// instant and asking the auth server for a token each.
	mu        sync.Mutex
	token     string
	expiresAt time.Time
}

// NewSessionTokenSource builds a token source over tokens, which should be a client of the
// token endpoint at the internal base URL where one is configured.
func NewSessionTokenSource(tokens *TokenClient) *SessionTokenSource {
	return &SessionTokenSource{
		tokens: tokens,
		scope: constants.AuthServerResourceIdentifier + ":" +
			constants.BrowserSessionsPermissionIdentifier,
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

// fetch asks the token client for a token. Called with the lock held.
func (s *SessionTokenSource) fetch(ctx context.Context) (string, time.Time, error) {
	tokenResponse, err := s.tokens.ClientCredentials(ctx, s.scope)
	if err != nil {
		return "", time.Time{}, err
	}
	if strings.TrimSpace(tokenResponse.AccessToken) == "" {
		// Reported rather than cached. An empty bearer would be sent on every session
		// call and answered 401 on every one of them, which reads in a log as the
		// endpoint refusing the admin console rather than as the token never arriving.
		return "", time.Time{}, errs.New("the auth server's token endpoint returned no access token")
	}

	return tokenResponse.AccessToken,
		time.Now().UTC().Add(time.Duration(tokenResponse.ExpiresIn) * time.Second), nil
}
