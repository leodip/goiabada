package middleware

import (
	"net/http"
	"net/http/httptest"
	"strings"
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

// heldSignInNamed answers the one sign-in the browser holds, under its id, as the ceremony store's
// HeldAuthContext does, and records the ids it was asked for.
type heldSignInNamed struct {
	authContext *ceremony.AuthContext
	err         error
	askedFor    *[]string
}

func (h heldSignInNamed) HeldAuthContext(_ *http.Request, ceremonyId string) (*ceremony.AuthContext, error) {
	*h.askedFor = append(*h.askedFor, ceremonyId)
	if h.err != nil {
		return nil, h.err
	}
	if h.authContext == nil || h.authContext.CeremonyId != ceremonyId {
		return nil, errs.WithStack(ceremony.ErrCeremonyNotHeld)
	}
	return h.authContext, nil
}

// A page a sign-in links to is drawn for the client of the sign-in its URL names, on a GET and on the
// POST of its form alike, while the browser holds it; a sign-in the browser does not hold, a malformed
// id, none, an id in the form's body alone, or a sign-in that cannot be read names no client, and the
// page still runs (#812 decision 4).
func TestLinkedSignInPageClient_NamesTheClientOfTheSignInTheURLNames(t *testing.T) {
	const heldId = "abcdefghijklmnopqrstuvwxyz012345"
	held := &ceremony.AuthContext{CeremonyId: heldId, ClientId: "app-1"}
	otherId := "ABCDEFGHIJKLMNOPQRSTUVWXYZ012345"

	for _, tc := range []struct {
		name     string
		method   string
		target   string
		body     string
		err      error
		want     string
		wantRead bool
	}{
		{"a GET naming a sign-in the browser holds", http.MethodGet, "/forgot-password?ceremony=" + heldId, "", nil, "app-1", true},
		{"a POST whose URL names a sign-in the browser holds", http.MethodPost, "/account/register?ceremony=" + heldId, "email=a%40b.c", nil, "app-1", true},
		{"a sign-in the browser does not hold", http.MethodGet, "/forgot-password?ceremony=" + otherId, "", nil, "", true},
		{"a malformed id", http.MethodGet, "/forgot-password?ceremony=" + heldId + "x", "", nil, "", false},
		{"no id", http.MethodGet, "/forgot-password", "", nil, "", false},
		{"an id in the form's body alone", http.MethodPost, "/forgot-password", "ceremony=" + heldId + "&ceremonyId=" + heldId, nil, "", false},
		{"a sign-in that cannot be read", http.MethodGet, "/account/activate?ceremony=" + heldId, "", errs.New("the session went away"), "", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var askedFor []string
			var drawnFor string
			reached := false
			handler := PageClient()(LinkedSignInPageClient(heldSignInNamed{authContext: held, err: tc.err, askedFor: &askedFor})(
				http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					reached = true
					drawnFor = reqctx.PageClientIdentifier(r.Context())
				})))
			req := httptest.NewRequest(tc.method, tc.target, strings.NewReader(tc.body))
			if tc.body != "" {
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			}
			rr := httptest.NewRecorder()

			handler.ServeHTTP(rr, req)

			assert.True(t, reached, "the page runs whatever the middleware found")
			assert.Equal(t, tc.want, drawnFor)
			assert.Equal(t, tc.wantRead, len(askedFor) > 0, "whether the browser's sign-ins are read")
			assert.Equal(t, http.StatusOK, rr.Code)
		})
	}
}
