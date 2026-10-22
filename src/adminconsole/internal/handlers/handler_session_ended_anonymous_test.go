package handlers

import (
	"context"
	"encoding/gob"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	handlersmocks "github.com/leodip/goiabada/adminconsole/internal/handlers/mocks"
	"github.com/leodip/goiabada/adminconsole/internal/handlertest"
	"github.com/leodip/goiabada/adminconsole/internal/sessionkeys"
	"github.com/leodip/goiabada/core/oauth"
	"github.com/leodip/goiabada/core/sessionstore"
	"github.com/leodip/goiabada/core/sessionstore/sessiontest"
)

// The cookieless half of #620's session-ended arm: a request with no cookie has no session
// to end, and the save it used to reach inserted a row no browser could read back — one
// per request, at no limit. What the handler answers now is the redirect home with
// nothing written, which is measured through the counting backend the way the middleware
// package's tests measure the sign-in arm.

// createCountingBackend counts the rows the store inserts, which is what a cookieless
// request's write is measured in.
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

// newCountingStore is newMemoryStore's construction over a backend this test can count.
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

func TestHandleSessionEndedGet_ACookielessRequestWritesNoRow(t *testing.T) {
	store, backend := newCountingStore(t)
	httpHelper := handlersmocks.NewHttpHelper(t)

	w := httptest.NewRecorder()
	HandleSessionEndedGet(httpHelper, store).ServeHTTP(w,
		handlertest.Request(http.MethodGet, "/auth/session-ended"))

	assert.Equal(t, http.StatusFound, w.Code)
	assert.Equal(t, "/", w.Header().Get("Location"),
		"the home page: nothing ended, and it is the one destination that requires no sign-in")
	assert.Empty(t, w.Result().Cookies(), "a request that stored nothing is handed no cookie")
	assert.Zero(t, backend.creates(),
		"a cookieless request writes no row, where the save it used to reach inserted one per request (#620)")
}
