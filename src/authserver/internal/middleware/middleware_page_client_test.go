package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/leodip/goiabada/authserver/internal/ceremony"
	"github.com/leodip/goiabada/authserver/internal/reqctx"
	"github.com/leodip/goiabada/core/errs"
)

// heldSignIn answers one sign-in, or one refusal, as the ceremony store answers the sign-in a
// request names.
type heldSignIn struct {
	authContext *ceremony.AuthContext
	err         error
}

func (h heldSignIn) GetAuthContext(_ *http.Request) (*ceremony.AuthContext, error) {
	return h.authContext, h.err
}

// A page request starts drawn for no client, and a step's request is drawn for the client of the
// sign-in it names while the browser holds it; a sign-in the browser does not hold, none, or one that
// cannot be read names no client, so the page is drawn in the default brand (#812).
func TestSignInPageClient_NamesTheClientOfTheSignInTheRequestNames(t *testing.T) {
	for _, tc := range []struct {
		name       string
		ceremonies heldSignIn
		want       string
	}{
		{"a sign-in the browser holds", heldSignIn{authContext: &ceremony.AuthContext{ClientId: "app-1"}}, "app-1"},
		{"a sign-in the browser does not hold", heldSignIn{err: errs.WithStack(ceremony.ErrCeremonyNotHeld)}, ""},
		{"a browser holding no sign-in", heldSignIn{err: ceremony.ErrNoAuthContext}, ""},
		{"a sign-in that cannot be read", heldSignIn{err: errs.New("the session went away")}, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var drawnFor string
			reached, carried := false, false
			handler := PageClient()(SignInPageClient(tc.ceremonies)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				reached = true
				_, carried = reqctx.PageClientFrom(r.Context())
				drawnFor = reqctx.PageClientIdentifier(r.Context())
			})))
			rr := httptest.NewRecorder()

			handler.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/auth/pwd?ceremony=x", nil))

			assert.True(t, reached, "the step runs whatever the middleware found")
			assert.True(t, carried, "a page request carries a page client")
			assert.Equal(t, tc.want, drawnFor)
			assert.Equal(t, http.StatusOK, rr.Code)
		})
	}
}
