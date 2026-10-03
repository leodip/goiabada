package handlers

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/data/mocks"
	"github.com/leodip/goiabada/authserver/internal/handlers/mocks"
	"github.com/leodip/goiabada/authserver/internal/protocolvalidation"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/authserver/internal/render"
	"github.com/leodip/goiabada/authserver/internal/reqctx"
	"github.com/leodip/goiabada/core/errs"
	"github.com/leodip/goiabada/core/oauth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// The four JSON endpoints answer a server fault as JSON, which is the claim #435 exists for and
// the one a mock writer cannot carry: a mock proves a call was made, not the bytes on the wire.
// Each row builds its endpoint with the real writer, render.New(nil), and one
// fault. A regression to the page writer fails each for its stated reason: the nil template FS
// either panics in the render or answers the text/plain fallback, and neither is a JSON body
// decoding to server_error. Every other handler test keeps the generated mocks.

// assertServerErrorJSON requires RFC 6749 section 5.2's shape for an unexpected fault: 500,
// application/json, and a body whose error is server_error.
func assertServerErrorJSON(t *testing.T, rr *httptest.ResponseRecorder) {
	t.Helper()
	assert.Equal(t, http.StatusInternalServerError, rr.Code)
	assert.Equal(t, "application/json", rr.Header().Get("Content-Type"))
	var body map[string]string
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &body), "the body must be JSON: %q", rr.Body.String())
	assert.Equal(t, "server_error", body["error"])
	assert.NotEmpty(t, body["error_description"])
}

// The token endpoint: a reused code whose revocation transaction never opens.
func TestHandleTokenPost_AServerFaultAnswersJSON(t *testing.T) {
	database := datamocks.NewDatabase(t)
	tokenValidator := handlersmocks.NewTokenValidator(t)

	handler := HandleTokenPost(render.New(nil),
		database, handlersmocks.NewTokenIssuer(t), tokenValidator, handlersmocks.NewAuditLogger(t),
		noCredentialFailures{})

	reuse := &protocolvalidation.AuthCodeReusedError{
		Detail: oauth.NewErrorDetailWithHTTPStatus("invalid_grant", "Code is invalid.",
			http.StatusBadRequest),
		Code: &record.Code{Id: 7, ClientId: 3, UserId: 11, SessionIdentifier: "sid-reused"},
	}
	tokenValidator.On("ValidateTokenRequest", mock.Anything, mock.Anything,
		mock.AnythingOfType("*protocolvalidation.ValidateTokenRequestInput")).Return(nil, reuse)
	datamocks.ExpectRunInTransactionRefused(database, errs.New("the engine refused to begin"))

	req := httptest.NewRequest(http.MethodPost, "/auth/token", strings.NewReader(
		"grant_type=authorization_code&code=abc&redirect_uri=http://example.com&client_id=test_client"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req = withSettings(req, &record.Settings{})
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	assertServerErrorJSON(t, rr)
}

// The userinfo endpoint: the user read fails.
func TestHandleUserInfoGetPost_AServerFaultAnswersJSON(t *testing.T) {
	database := datamocks.NewDatabase(t)
	handler := HandleUserInfoGetPost(render.New(nil), database,
		handlersmocks.NewAuditLogger(t), testBaseURL)

	database.On("GetUserBySubject", mock.Anything, (*sql.Tx)(nil), "user123").
		Return(nil, errs.New("the database went away")).Once()

	req := httptest.NewRequest(http.MethodGet, "/userinfo", nil)
	req = req.WithContext(reqctx.WithValidatedToken(req.Context(), oauth.JwtToken{
		Claims: map[string]interface{}{"sub": "user123", "scope": "openid"},
	}))
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	assertServerErrorJSON(t, rr)
}

// The JWKS endpoint: the key read fails.
func TestHandleCertsGet_AServerFaultAnswersJSON(t *testing.T) {
	database := datamocks.NewDatabase(t)
	handler := HandleCertsGet(render.New(nil), database)

	database.On("GetAllSigningKeys", mock.Anything, (*sql.Tx)(nil)).
		Return(nil, errs.New("the database went away")).Once()

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/certs", nil))

	assertServerErrorJSON(t, rr)
}

// The discovery endpoint reads no database, so its one fault is a request reaching it without
// settings.
func TestHandleWellKnownOIDCConfigGet_AServerFaultAnswersJSON(t *testing.T) {
	handler := HandleWellKnownOIDCConfigGet(render.New(nil), testBaseURL)

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/.well-known/openid-configuration", nil))

	assertServerErrorJSON(t, rr)
}
