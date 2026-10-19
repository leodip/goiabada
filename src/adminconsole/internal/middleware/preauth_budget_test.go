package middleware

import (
	"context"
	"encoding/gob"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	middlewaremocks "github.com/leodip/goiabada/adminconsole/internal/middleware/mocks"
	"github.com/leodip/goiabada/adminconsole/internal/oauthclient"
	"github.com/leodip/goiabada/adminconsole/internal/reqctx"
	"github.com/leodip/goiabada/adminconsole/internal/sessionkeys"
	"github.com/leodip/goiabada/core/builtin"
	"github.com/leodip/goiabada/core/logging/logtest"
	"github.com/leodip/goiabada/core/oauth"
	"github.com/leodip/goiabada/core/sessionstore"
	sessionstoremocks "github.com/leodip/goiabada/core/sessionstore/mocks"
	"github.com/leodip/goiabada/core/sessionstore/sessiontest"
)

// The two halves of #620 at this package's own arms: the budget that turns the sign-in
// arm's "one row per request, at no limit" into one row per request inside a window, and
// the bound that stops the row tracking the request line's length. The counting backend is
// the house shape: a test that needs to observe the store wraps the memory backend in a
// small type of its own, the way contextHonouringBackend counts loads above.

// createCountingBackend counts the rows the store inserts, which is what an anonymous
// request's write is measured in: one Create per sign-in redirect, and none past the
// budget.
type createCountingBackend struct {
	*sessiontest.MemoryBackend

	mu      sync.Mutex
	created int
}

func (c *createCountingBackend) Create(ctx context.Context, id string, data []byte, authenticated bool) (time.Time, error) {
	expiresAt, err := c.MemoryBackend.Create(ctx, id, data, authenticated)
	c.mu.Lock()
	c.created++
	c.mu.Unlock()
	return expiresAt, err
}

func (c *createCountingBackend) creates() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.created
}

// newCountingStore is the production store over the counting backend, built the way the
// handlers' tests build theirs.
func newCountingStore(t *testing.T) (*sessionstore.ServerSideStore, *createCountingBackend) {
	t.Helper()
	gob.Register(oauth.TokenResponse{})
	backend := &createCountingBackend{MemoryBackend: sessiontest.NewMemoryBackend()}
	store, err := sessionstore.NewServerSideStore(backend, sessionkeys.JWT, false, sessionstore.BrowserSessionCookie,
		sessionstore.KeyPair{
			AuthenticationKey: []byte("12345678901234567890123456789012"),
			EncryptionKey:     []byte("abcdefghijklmnopqrstuvwxyz123456"),
		}, nil)
	require.NoError(t, err)
	return store, backend
}

// The budget's own behaviour over a clock the test moves: its budget per address per
// window, the independence of two addresses, the reset when a window ends, and the sweep
// that keeps the map holding live windows only.
func TestPreAuthBudget_AdmitsItsBudgetPerAddressPerWindow(t *testing.T) {
	budget := NewPreAuthBudget(2, time.Minute)
	now := time.Date(2026, 10, 19, 12, 0, 0, 0, time.UTC)
	budget.now = func() time.Time { return now }

	allow := func(addr string) bool {
		req := httptest.NewRequest(http.MethodGet, "/admin/clients", nil)
		req.RemoteAddr = addr
		return budget.Allow(req)
	}

	require.True(t, allow("203.0.113.7"))
	require.True(t, allow("203.0.113.7"))
	assert.False(t, allow("203.0.113.7"), "the address's window is spent")
	assert.True(t, allow("203.0.113.8"), "one address's budget is not another's")

	now = now.Add(time.Minute)
	assert.True(t, allow("203.0.113.7"), "the window that ended is a fresh one")

	now = now.Add(2 * time.Minute)
	require.True(t, allow("203.0.113.9"))
	budget.mu.Lock()
	assert.Len(t, budget.live, 1, "the sweep dropped the windows that ended")
	budget.mu.Unlock()
}

// The refusal both arms share: a 429 that carries the window's remainder, and a warning
// that names the budget and not the address.
func TestPreAuthBudget_RefusesWith429AndTheWindowRemainder(t *testing.T) {
	budget := NewPreAuthBudget(1, time.Minute)
	logs := logtest.CaptureSlog(t)

	req := httptest.NewRequest(http.MethodGet, "/auth/session-ended", nil)
	req.RemoteAddr = "203.0.113.7"
	require.True(t, budget.Allow(req))
	over := httptest.NewRequest(http.MethodGet, "/auth/session-ended", nil)
	over.RemoteAddr = "203.0.113.7"
	require.False(t, budget.Allow(over))

	w := httptest.NewRecorder()
	budget.Refuse(w, over)

	assert.Equal(t, http.StatusTooManyRequests, w.Code)
	assert.Equal(t, "60", w.Header().Get("Retry-After"))
	records := logs.Records()
	require.Len(t, records, 1)
	assert.Equal(t, slog.LevelWarn, records[0].Level, "a refusal met and handled; nobody has to act")
	assert.Equal(t, "the per-address budget on the console's anonymous session rows refused a request", records[0].Message)
}

// The sign-in arm over the real AuthHelper and the real store: an anonymous request
// starts a sign-in, the sign-in parks its handshake in a fresh session and saves it, and
// that save is the row. What the budget holds is the rate — the third request from the
// address writes nothing and never reaches the auth server's authorize endpoint (#620).
func TestRequiresScope_AnonymousRowsStayInsideThePerAddressBudget(t *testing.T) {
	store, backend := newCountingStore(t)
	authHelper := oauthclient.NewAuthHelper(store, builtin.AdminConsoleSessionName,
		"http://localhost:9091", "http://localhost:9090")
	budget := NewPreAuthBudget(2, time.Minute)

	mw := NewJWT(store, builtin.AdminConsoleSessionName, nil, nil, authHelper,
		stubErrorRenderer{}, "http://localhost:9091", builtin.AdminConsoleClientIdentifier)
	mw.preAuthBudget = budget

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("an anonymous request never reaches the page it asked for")
	})
	handler := mw.RequiresScope([]string{"required:scope"})(next)

	anonymous := func(addr string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, "/admin/clients", nil)
		req.RemoteAddr = addr
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		return w
	}

	// Two admitted requests start two sign-ins: two rows, which is the write the whole
	// arm exists around, and two redirects to the auth server.
	require.Equal(t, http.StatusFound, anonymous("203.0.113.7").Code)
	require.Equal(t, http.StatusFound, anonymous("203.0.113.7").Code)
	assert.Equal(t, 2, backend.creates())

	// The third is refused and writes no row.
	refused := anonymous("203.0.113.7")
	assert.Equal(t, http.StatusTooManyRequests, refused.Code)
	assert.Equal(t, 2, backend.creates(), "the refused request writes no row")

	// Another address carries its own budget, which is what keeps the tier per-address
	// rather than per-console.
	require.Equal(t, http.StatusFound, anonymous("203.0.113.8").Code)
	assert.Equal(t, 3, backend.creates())
}

// The return target the sign-in parks for its callback is bounded, so the row the
// handshake lives in no longer tracks the request line's length: a line no page of this
// console produces is answered with the home page's target rather than the one that was
// sent (#620).
func TestRequiresScope_BoundsTheReturnTargetItStoresForTheSignIn(t *testing.T) {
	testCases := []struct {
		name         string
		requestURI   string
		redirectBack string
	}{
		{
			name:         "a page's own path and query pass through whole",
			requestURI:   "/admin/clients?filter=active",
			redirectBack: "http://localhost:9091/admin/clients?filter=active",
		},
		{
			name:         "a request line past the bound falls back to the home page",
			requestURI:   "/admin/clients?pad=" + strings.Repeat("a", redirectBackMaxLen),
			redirectBack: "http://localhost:9091/",
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			mockAuthHelper := new(middlewaremocks.AuthHelper)
			mockSessionStore := new(sessionstoremocks.Store)

			mw := NewJWT(mockSessionStore, "test-session", nil, nil, mockAuthHelper,
				stubErrorRenderer{}, "http://localhost:9091", builtin.AdminConsoleClientIdentifier)

			jwtInfo := oauthclient.JwtInfo{}
			mockAuthHelper.On("IsAuthorizedToAccessResource", jwtInfo, []string{"required:scope"}).Return(false)
			mockAuthHelper.On("IsAuthenticated", jwtInfo).Return(false)
			mockAuthHelper.On("RedirToAuthorize", mock.Anything, mock.Anything,
				builtin.AdminConsoleClientIdentifier, mock.AnythingOfType("string"),
				testCase.redirectBack).Return(nil)

			req := httptest.NewRequest(http.MethodGet, testCase.requestURI, nil)
			req = req.WithContext(reqctx.WithJwtInfo(req.Context(), jwtInfo))

			rr := httptest.NewRecorder()
			next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				t.Error("an anonymous request never reaches the page it asked for")
			})
			mw.RequiresScope([]string{"required:scope"})(next).ServeHTTP(rr, req)

			// The redirect itself is the mock's to answer, so the recorded target is
			// the assertion: what the sign-in was handed to park for the callback.
			mockAuthHelper.AssertExpectations(t)
		})
	}
}
