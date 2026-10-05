package server

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/config"
	"github.com/leodip/goiabada/authserver/internal/data/mocks"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/authserver/web"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// The token requests refused, counted whichever part of the chain answered them (#400 decision 5).
// The handler counts what it refuses; these drive POST /auth/token through the real initMiddleware
// and initRoutes, where a refusal can also be written before the handler runs: by the token branch's
// faults, a settings read that failed, and by LimitROPC, a body that does not parse or a credential
// count that could not be read. Each is the 400 or 500 a client received, counted once, under the
// grant it asked for and the code it was answered with; a 429 is the rate limiter's and is counted
// under its limiter instead.

// newTokenRefusalTestServer runs the real initMiddleware and initRoutes over database, with
// configure applied to the configuration first.
func newTokenRefusalTestServer(database *datamocks.Database, configure func(cfg *config.Config)) *Server {
	s := newStaticBranchTestServer(database)
	s.templateFS = web.TemplateFS()
	if configure != nil {
		configure(s.cfg)
	}
	s.initRoutes(s.initMiddleware())
	return s
}

// postToken posts body to the token endpoint through the whole chain.
func postToken(s *Server, body string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodPost, "/auth/token", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	s.router.ServeHTTP(rr, r)
	return rr
}

// scrapeSamples answers the sample lines of family in s's exposition, as "labels value".
func scrapeSamples(t *testing.T, s *Server, family string) []string {
	t.Helper()

	rec := httptest.NewRecorder()
	s.metrics.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	require.Equal(t, http.StatusOK, rec.Code)

	var samples []string
	for _, line := range strings.Split(rec.Body.String(), "\n") {
		if rest, ok := strings.CutPrefix(line, family); ok && (strings.HasPrefix(rest, "{") || strings.HasPrefix(rest, " ")) {
			samples = append(samples, rest)
		}
	}
	return samples
}

func TestInitRoutes_ATokenFormThatDoesNotParseIsCountedOnceWhicheverAnswersIt(t *testing.T) {
	// With the limiter on, LimitROPC parses the form first and answers it; off, the handler does.
	// Either way the client gets the one 400 and the scrape counts it once, where the limiter's
	// answer used to go uncounted.
	for limiter, enabled := range map[string]bool{"on": true, "off": false} {
		t.Run("limiter "+limiter, func(t *testing.T) {
			database := datamocks.NewDatabase(t)
			database.On("GetSettingsById", mock.Anything, mock.Anything, int64(1)).Return(&record.Settings{Id: 1}, nil)
			s := newTokenRefusalTestServer(database, func(cfg *config.Config) {
				cfg.AuthServer.RateLimiterEnabled = enabled
			})

			rr := postToken(s, "grant_type=refresh_token&refresh_token=%zz")

			require.Equal(t, http.StatusBadRequest, rr.Code, rr.Body.String())
			assert.Contains(t, rr.Body.String(), `"error":"invalid_request"`)
			assert.Equal(t, []string{`{grant_type="refresh_token",error="invalid_request"} 1`},
				scrapeSamples(t, s, "goiabada_token_requests_refused_total"))
		})
	}
}

func TestInitRoutes_ATokenRequestStoppedByASettingsFaultIsCounted(t *testing.T) {
	database := datamocks.NewDatabase(t)
	database.On("GetSettingsById", mock.Anything, mock.Anything, int64(1)).Return(nil, errors.New("the database is down"))
	s := newTokenRefusalTestServer(database, nil)

	rr := postToken(s, "grant_type=client_credentials&client_id=c&client_secret=s")

	require.Equal(t, http.StatusInternalServerError, rr.Code, rr.Body.String())
	assert.Contains(t, rr.Body.String(), `"error":"server_error"`)
	assert.Equal(t, []string{`{grant_type="client_credentials",error="server_error"} 1`},
		scrapeSamples(t, s, "goiabada_token_requests_refused_total"),
		"counted under the grant the body named, though nothing had parsed it before the fault")

	// The same fault on another protocol endpoint is no token request, and is not counted as one.
	certs := httptest.NewRecorder()
	s.router.ServeHTTP(certs, httptest.NewRequest(http.MethodGet, "/certs", nil))
	require.Equal(t, http.StatusInternalServerError, certs.Code)
	assert.Equal(t, []string{`{grant_type="client_credentials",error="server_error"} 1`},
		scrapeSamples(t, s, "goiabada_token_requests_refused_total"))
}

func TestInitRoutes_APasswordGrantStoppedByTheSharedCountIsCountedAsItsAnswer(t *testing.T) {
	const passwordGrant = "grant_type=password&username=victim%40example.com&password=p&client_id=c"

	// The credential count could not be read: LimitROPC answers the 500 itself, which is a token
	// request refused with server_error and no rate-limit refusal.
	t.Run("a count that could not be read", func(t *testing.T) {
		database := datamocks.NewDatabase(t)
		database.On("GetSettingsById", mock.Anything, mock.Anything, int64(1)).Return(&record.Settings{Id: 1}, nil)
		database.On("ReserveRateLimitHit", mock.Anything, mock.Anything, mock.Anything, mock.Anything,
			mock.Anything, mock.Anything).Return(false, errors.New("the database is down"))
		s := newTokenRefusalTestServer(database, func(cfg *config.Config) {
			cfg.AuthServer.RateLimiterEnabled = true
			cfg.Database.Type = "postgres"
		})

		rr := postToken(s, passwordGrant)

		require.Equal(t, http.StatusInternalServerError, rr.Code, rr.Body.String())
		assert.Equal(t, []string{`{grant_type="password",error="server_error"} 1`},
			scrapeSamples(t, s, "goiabada_token_requests_refused_total"))
		assert.NotContains(t, scrapeSamples(t, s, "goiabada_rate_limit_refusals_total"), `{limiter="pwd_account_net"} 1`)
	})

	// The account's budget is spent: the 429 is the limiter's refusal, counted under its limiter and
	// not as a token request refused.
	t.Run("a spent budget", func(t *testing.T) {
		database := datamocks.NewDatabase(t)
		database.On("GetSettingsById", mock.Anything, mock.Anything, int64(1)).Return(&record.Settings{Id: 1}, nil)
		database.On("ReserveRateLimitHit", mock.Anything, mock.Anything, mock.Anything, mock.Anything,
			mock.Anything, mock.Anything).Return(false, nil)
		s := newTokenRefusalTestServer(database, func(cfg *config.Config) {
			cfg.AuthServer.RateLimiterEnabled = true
			cfg.Database.Type = "postgres"
		})

		rr := postToken(s, passwordGrant)

		require.Equal(t, http.StatusTooManyRequests, rr.Code, rr.Body.String())
		assert.Empty(t, scrapeSamples(t, s, "goiabada_token_requests_refused_total"))
		assert.Contains(t, scrapeSamples(t, s, "goiabada_rate_limit_refusals_total"), `{limiter="pwd_account_net"} 1`)
	})
}
