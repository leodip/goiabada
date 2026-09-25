package adminclienthandlers

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/leodip/goiabada/adminconsole/internal/apiclient"
	"github.com/leodip/goiabada/adminconsole/internal/constants"
	"github.com/leodip/goiabada/adminconsole/internal/oauthclient"
	"github.com/leodip/goiabada/core/errs"
	"github.com/leodip/goiabada/core/oauth"
	"github.com/leodip/goiabada/core/testutil"
)

// The logo is the one read on this page the page can do without, and a 401 is the one failure of
// it the page does not carry on past: the client read just before it succeeded, so the
// administrator's session ended between the two calls, and every later call with the same token
// meets the same refusal. It goes to the session-ended route, which signs the administrator out
// with the notice, as a 401 from the client read would (#427 decision 17, final review round 2).
// Every other failure keeps the page, drawn without a logo, with the one Warn record.
func TestHandleAdminClientLogoGet_OnlyASessionEndedLogoReadStopsThePage(t *testing.T) {
	testCases := []struct {
		name    string
		logoErr error
		ended   bool
	}{
		{
			name:    "the admin API's 401 signs the administrator out",
			logoErr: &apiclient.APIError{Code: "invalid_token", Message: "Session has been terminated", StatusCode: http.StatusUnauthorized},
			ended:   true,
		},
		{
			name:    "the same 401 wrapped on its way up still does",
			logoErr: errs.Wrap(&apiclient.APIError{Code: "invalid_token", Message: "Session has expired", StatusCode: http.StatusUnauthorized}, "reading the logo"),
			ended:   true,
		},
		{
			name:    "a 404 is a missing logo, not a missing page",
			logoErr: &apiclient.APIError{Code: "NOT_FOUND", Message: "Not found", StatusCode: http.StatusNotFound},
		},
		{
			name:    "a 403 is not a sign-in that has ended",
			logoErr: &apiclient.APIError{Code: "FORBIDDEN", Message: "Forbidden", StatusCode: http.StatusForbidden},
		},
		{
			name:    "a 500 leaves the page without a logo",
			logoErr: &apiclient.APIError{Code: "INTERNAL_ERROR", Message: "Internal error", StatusCode: http.StatusInternalServerError},
		},
		{
			name:    "an error that is not the API's leaves it too",
			logoErr: errs.New("the auth server is unreachable"),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			logs := testutil.CaptureSlog(t)

			httpHelper := &stubHttpHelper{}
			router := chi.NewRouter()
			router.Use(func(next http.Handler) http.Handler {
				return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					ctx := context.WithValue(r.Context(), constants.ContextKeyJwtInfo,
						oauthclient.JwtInfo{TokenResponse: oauth.TokenResponse{AccessToken: "an-access-token"}})
					next.ServeHTTP(w, r.WithContext(ctx))
				})
			})
			router.Get("/admin/clients/{clientId}/logo", HandleAdminClientLogoGet(httpHelper, &logoApiClient{logoErr: tc.logoErr}))

			recorder := httptest.NewRecorder()
			router.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/admin/clients/42/logo", nil))

			if tc.ended {
				assert.Equal(t, http.StatusFound, recorder.Code)
				assert.Equal(t, "/auth/session-ended", recorder.Header().Get("Location"))
				assert.Nil(t, httpHelper.bind, "no page is drawn for a session that has ended")
				assert.Empty(t, logs.Records(), "the session-ended route logs the sign-out, not this page")
				return
			}

			assert.Equal(t, http.StatusOK, recorder.Code)
			require.NotNil(t, httpHelper.bind, "the page is drawn without the logo")
			assert.Empty(t, httpHelper.bind["logoUrl"])
			assert.Nil(t, httpHelper.err, "nothing reached the 500 writer")
			records := logs.Records()
			require.Len(t, records, 1)
			assert.Equal(t, slog.LevelWarn, records[0].Level)
			assert.Equal(t, "unable to fetch the client logo info", records[0].Message)
		})
	}
}
