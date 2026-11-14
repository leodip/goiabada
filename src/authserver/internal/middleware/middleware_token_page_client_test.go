package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/leodip/goiabada/authserver/internal/reqctx"
	"github.com/leodip/goiabada/core/oauth"
)

// An email sent through the account API is drawn in the brand of the client the caller's access
// token names, and follows the operator's safe mode switch alone: the request names that client, and
// no sign-in's safe mode (#817 decisions 1 and 6).
func TestTokenPageClient_NamesTheClientOfTheRequestsAccessToken(t *testing.T) {
	for _, tc := range []struct {
		name  string
		token *oauth.JwtToken
		want  string
	}{
		{"a token issued to a client", &oauth.JwtToken{Claims: map[string]interface{}{"sub": "u1", "client_id": "app-1"}}, "app-1"},
		{"a token naming no client", &oauth.JwtToken{Claims: map[string]interface{}{"sub": "u1"}}, ""},
		{"no token", nil, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var drawnFor string
			reached, carried, safe := false, false, true
			handler := TokenPageClient()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				reached = true
				_, carried = reqctx.PageClientFrom(r.Context())
				drawnFor = reqctx.PageClientIdentifier(r.Context())
				safe = reqctx.PageSafeMode(r.Context())
			}))
			req := httptest.NewRequest(http.MethodPost, "/api/v1/account/email/verification/send", nil)
			if tc.token != nil {
				req = req.WithContext(reqctx.WithBearerToken(req.Context(), *tc.token))
			}
			rr := httptest.NewRecorder()

			handler.ServeHTTP(rr, req)

			assert.True(t, reached, "the request goes on whatever the token names")
			assert.True(t, carried, "the request carries a page client")
			assert.Equal(t, tc.want, drawnFor)
			assert.False(t, safe, "no sign-in's safe mode reaches the account API")
			assert.Equal(t, http.StatusOK, rr.Code)
		})
	}
}
