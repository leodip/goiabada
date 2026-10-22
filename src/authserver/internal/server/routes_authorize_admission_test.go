package server

import (
	"context"
	"net/http"
	"net/url"
	"sync/atomic"
	"testing"
	"time"

	datamocks "github.com/leodip/goiabada/authserver/internal/data/mocks"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/core/sessionstore/sessiontest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// TestInitRoutes_AuthorizeAdmissionBoundsWrites is #504's "Done when" for both routes: with the
// limiter on, one client block creates no more browser-session or parked-request rows than the
// authorize tier's budget, and a request the tier refuses writes nothing.
//
// The wiring case in TestInitRoutes_LimitersAreRegisteredOnTheProductionRoutes spends the budget
// with requests the handler refuses at its first validation, which cost no row, so it shows the
// tier is mounted but not what it bounds. These requests are valid, so each one the tier admits
// costs a row: a cookie-less GET saves a new browser session and a POST parks the form. The rows
// are counted where they are written, the session store's backend and CreateAuthorizeRequest.
func TestInitRoutes_AuthorizeAdmissionBoundsWrites(t *testing.T) {
	const secondBlock = "198.51.100.7:1234" // a /64 other than httptest's 192.0.2.1

	t.Run("GET /auth/authorize writes at most the budget of browser sessions", func(t *testing.T) {
		writes := newAuthorizeWriteCounter(t)

		for i := 0; i < authorizeBudget; i++ {
			rr := serve(writes.server, authorizeGet(""))
			require.Equal(t, http.StatusFound, rr.Code, "request %d is admitted and starts a ceremony", i+1)
		}
		require.Equal(t, int64(authorizeBudget), writes.sessions.Load(),
			"every admitted cookie-less GET saved one browser session")

		assertRefused(t, serve(writes.server, authorizeGet("")), authorizeWindow, shapeBrowser)
		assert.Equal(t, int64(authorizeBudget), writes.sessions.Load(), "the refused GET saved no session")
		assert.Equal(t, int64(0), writes.parked.Load())

		assert.Equal(t, http.StatusFound, serve(writes.server, authorizeGet(secondBlock)).Code,
			"a second client block has its own budget")
		assert.Equal(t, int64(authorizeBudget+1), writes.sessions.Load())
	})

	t.Run("POST /auth/authorize parks at most the budget of requests", func(t *testing.T) {
		writes := newAuthorizeWriteCounter(t)

		for i := 0; i < authorizeBudget; i++ {
			rr := serve(writes.server, authorizePost(""))
			require.Equal(t, http.StatusSeeOther, rr.Code, "request %d is admitted and parked", i+1)
		}
		require.Equal(t, int64(authorizeBudget), writes.parked.Load(), "every admitted POST parked one request")

		assertRefused(t, serve(writes.server, authorizePost("")), authorizeWindow, shapeBrowser)
		assert.Equal(t, int64(authorizeBudget), writes.parked.Load(), "the refused POST parked nothing")
		assert.Equal(t, int64(0), writes.sessions.Load(), "a POST never touches the browser's session")

		assert.Equal(t, http.StatusSeeOther, serve(writes.server, authorizePost(secondBlock)).Code,
			"a second client block has its own budget")
		assert.Equal(t, int64(authorizeBudget+1), writes.parked.Load())
	})

	t.Run("GET and POST together write at most one budget", func(t *testing.T) {
		// Alternating the methods buys nothing: the two routes share one bucket, so the rows
		// both write add up to the budget, not to twice it.
		writes := newAuthorizeWriteCounter(t)

		for i := 0; i < authorizeBudget; i++ {
			if i%2 == 0 {
				require.Equal(t, http.StatusFound, serve(writes.server, authorizeGet("")).Code, "request %d", i+1)
			} else {
				require.Equal(t, http.StatusSeeOther, serve(writes.server, authorizePost("")).Code, "request %d", i+1)
			}
		}
		require.Equal(t, int64(authorizeBudget/2), writes.sessions.Load())
		require.Equal(t, int64(authorizeBudget/2), writes.parked.Load())

		assertRefused(t, serve(writes.server, authorizeGet("")), authorizeWindow, shapeBrowser)
		assertRefused(t, serve(writes.server, authorizePost("")), authorizeWindow, shapeBrowser)
		assert.Equal(t, int64(authorizeBudget), writes.sessions.Load()+writes.parked.Load(),
			"neither refused request wrote a row")

		assert.Equal(t, http.StatusFound, serve(writes.server, authorizeGet(secondBlock)).Code,
			"a second client block has its own budget")
		assert.Equal(t, http.StatusSeeOther, serve(writes.server, authorizePost(secondBlock)).Code,
			"a second client block has its own budget")
		assert.Equal(t, int64(authorizeBudget+2), writes.sessions.Load()+writes.parked.Load())
	})
}

const (
	authorizeAdmissionClientId    = "admission-client"
	authorizeAdmissionRedirectURI = "https://app.example.com/callback"
)

// authorizeWriteCounter is a routes test server whose two authorize writes are counted: the
// browser sessions its session store creates and the requests its database parks.
type authorizeWriteCounter struct {
	server   *Server
	sessions *atomic.Int64
	parked   *atomic.Int64
}

func newAuthorizeWriteCounter(t *testing.T) authorizeWriteCounter {
	t.Helper()

	backend := &creationCountingBackend{MemoryBackend: sessiontest.NewMemoryBackend()}
	s := newRoutesTestServerOver(t, nil, newTestSessionStoreOver(backend))

	// An enabled confidential client with the code flow on and its redirect URI registered, so
	// a request naming it passes every validation and the endpoint writes its row.
	database, ok := s.database.(*datamocks.Database)
	require.True(t, ok)
	database.On("GetClientByClientIdentifier", mock.Anything, mock.Anything, authorizeAdmissionClientId).
		Return(&record.Client{Id: 3, ClientIdentifier: authorizeAdmissionClientId, Enabled: true,
			AuthorizationCodeEnabled: true, DefaultAcrLevel: record.AcrLevel1}, nil).Maybe()
	database.On("ClientLoadRedirectURIs", mock.Anything, mock.Anything, mock.Anything).
		Run(func(args mock.Arguments) {
			client := args.Get(2).(*record.Client)
			client.RedirectURIs = []record.RedirectURI{{URI: authorizeAdmissionRedirectURI, ClientId: client.Id}}
		}).Return(nil).Maybe()
	// What the client-error responder reads to decide whether a redirect would be emitted, which
	// the GET asks before it routes a cookie-less browser to sign in.
	database.On("GetRedirectURIsByClientId", mock.Anything, mock.Anything, int64(3)).
		Return([]record.RedirectURI{{URI: authorizeAdmissionRedirectURI, ClientId: 3}}, nil).Maybe()

	// A cookie-less browser names no session, and none is stored under the empty identifier.
	database.On("GetUserSessionBySessionIdentifier", mock.Anything, mock.Anything, "").
		Return((*record.UserSession)(nil), nil).Maybe()
	database.On("UserSessionLoadUser", mock.Anything, mock.Anything, (*record.UserSession)(nil)).Return(nil).Maybe()

	parked := &atomic.Int64{}
	database.On("CreateAuthorizeRequest", mock.Anything, mock.Anything, mock.Anything).
		Run(func(mock.Arguments) { parked.Add(1) }).Return(nil).Maybe()

	return authorizeWriteCounter{server: s, sessions: &backend.creates, parked: parked}
}

// creationCountingBackend counts the browser-session rows the store creates. Only Create counts:
// it is the one write that adds a row, where an update or a touch rewrites one already there.
type creationCountingBackend struct {
	*sessiontest.MemoryBackend
	creates atomic.Int64
}

func (b *creationCountingBackend) Create(ctx context.Context, id string, data []byte, authenticated bool) (time.Time, error) {
	b.creates.Add(1)
	return b.MemoryBackend.Create(ctx, id, data, authenticated)
}

// authorizeParameters is a valid code-flow request naming the counted client.
func authorizeParameters() url.Values {
	return url.Values{
		"client_id":     {authorizeAdmissionClientId},
		"redirect_uri":  {authorizeAdmissionRedirectURI},
		"response_type": {"code"},
		"scope":         {"openid"},
		"state":         {"a-state"},
	}
}

// authorizeGet is a cookie-less browser GET of a valid request, from remoteAddr when it is set.
func authorizeGet(remoteAddr string) *http.Request {
	r := browserRequest(http.MethodGet, "/auth/authorize?"+authorizeParameters().Encode())
	if remoteAddr != "" {
		r.RemoteAddr = remoteAddr
	}
	return r
}

// authorizePost is a form POST of a valid request, as a client's page posts it cross-site, from
// remoteAddr when it is set.
func authorizePost(remoteAddr string) *http.Request {
	r := browserForm(http.MethodPost, "/auth/authorize", authorizeParameters().Encode())
	if remoteAddr != "" {
		r.RemoteAddr = remoteAddr
	}
	return r
}
