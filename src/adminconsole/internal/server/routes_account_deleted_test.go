package server

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// /account/deleted is where a deletion lands, after the console's session is gone, so it answers a
// visitor with no session at all: the same page for anyone, never a sign-in (#783 decision 8). The
// Delete account page itself stays behind the account pages' sign-in.
func TestInitRoutes_TheDeletedPageAnswersAnyoneAndTheDeletePageNeedsASignIn(t *testing.T) {
	s, authServerURL := newRoutingTestServer(t)

	deleted := serveRouting(s, http.MethodGet, "/account/deleted", nil)
	require.Equal(t, http.StatusOK, deleted.Code, "drawn for a visitor with no session")
	assert.Contains(t, deleted.Body.String(), `<h1 class="auth-title">Your account is deleted</h1>`)
	assert.Empty(t, deleted.Result().Cookies(), "the page starts no session")

	for _, method := range []string{http.MethodGet, http.MethodPost} {
		page := serveRouting(s, method, "/account/delete", http.Header{"Sec-Fetch-Site": {"same-origin"}})
		assert.Equal(t, http.StatusFound, page.Code, "%s /account/delete", method)
		assert.Contains(t, page.Header().Get("Location"), authServerURL+"/auth/authorize?", "%s /account/delete", method)
	}
}
