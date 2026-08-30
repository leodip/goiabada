package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/i18n"
	"github.com/leodip/goiabada/core/oauth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// recordingErrorRenderer stands in for *handlerhelpers.HttpHelper and keeps what it
// was handed, so a test can assert the cause went to the renderer, which logs it
// against the request id, rather than into the response.
type recordingErrorRenderer struct {
	calls int
	err   error
}

func (rec *recordingErrorRenderer) InternalServerError(w http.ResponseWriter, r *http.Request, err error) {
	rec.calls++
	rec.err = err
	http.Error(w, i18n.T(r.Context(), "adminconsole.error.body"), http.StatusInternalServerError)
}

func runSessionIdentifierChain(t *testing.T, ctxValue any, present bool) (*httptest.ResponseRecorder, *recordingErrorRenderer, string) {
	t.Helper()

	var seen string
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if v, ok := r.Context().Value(constants.ContextKeySessionIdentifier).(string); ok {
			seen = v
		}
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/admin/clients", nil)
	if present {
		req = req.WithContext(context.WithValue(req.Context(), constants.ContextKeyJwtInfo, ctxValue))
	}

	rec := &recordingErrorRenderer{}
	recorder := httptest.NewRecorder()
	SessionIdentifierToContext(rec)(next).ServeHTTP(recorder, req)

	return recorder, rec, seen
}

// The middleware's happy path had no test at all, which matters here: without it,
// the refusal case below is satisfied by a middleware that refuses everything.
func TestSessionIdentifierToContext_LiftsTheSidClaimOntoTheContext(t *testing.T) {
	jwtInfo := oauth.JwtInfo{
		AccessToken: &oauth.JwtToken{Claims: jwt.MapClaims{"sid": "session-abc"}},
	}

	recorder, rec, seen := runSessionIdentifierChain(t, jwtInfo, true)

	assert.Equal(t, http.StatusOK, recorder.Code)
	assert.Equal(t, 0, rec.calls)
	assert.Equal(t, "session-abc", seen)
}

func TestSessionIdentifierToContext_NoJwtInfoIsNotAFailure(t *testing.T) {
	recorder, rec, seen := runSessionIdentifierChain(t, nil, false)

	assert.Equal(t, http.StatusOK, recorder.Code)
	assert.Equal(t, 0, rec.calls)
	assert.Empty(t, seen)
}

// The defensive branch: nothing but MiddlewareJwt writes this context key, so a
// value of another type means a programming error. It used to answer with the Go
// sentence naming the middleware, in English, in front of the administrator.
func TestSessionIdentifierToContext_AWrongContextTypeRendersTheErrorPage(t *testing.T) {
	recorder, rec, seen := runSessionIdentifierChain(t, "not a JwtInfo", true)

	assert.Equal(t, http.StatusInternalServerError, recorder.Code)
	require.Equal(t, 1, rec.calls, "the site must answer through the error page, not through http.Error")
	require.Error(t, rec.err)
	assert.Contains(t, rec.err.Error(), "unable to cast the context value to JwtInfo")
	assert.NotContains(t, recorder.Body.String(), "unable to cast",
		"the cause must not reach the response")
	assert.Equal(t, wantBody(t, "en", "adminconsole.error.body"), strings.TrimSpace(recorder.Body.String()))
	assert.Empty(t, seen)
}
