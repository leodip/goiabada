package handlers

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	datamocks "github.com/leodip/goiabada/authserver/internal/data/mocks"
	handlersmocks "github.com/leodip/goiabada/authserver/internal/handlers/mocks"
	"github.com/leodip/goiabada/authserver/internal/oidc"
	"github.com/leodip/goiabada/authserver/internal/reqctx"
	"github.com/leodip/goiabada/core/logging/logtest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// Every application route runs under middleware.Settings, so a handler reached without settings is
// a wiring defect rather than a request a client can make. Each answers it through the 500 writer
// its other failures already use, passing reqctx.ErrNoSettings, and nothing is read or written
// first. One row per writer in this package, not one per read site: the rest share these writers
// (#433 decision 6).

func isErrNoSettings(err error) bool {
	return errors.Is(err, reqctx.ErrNoSettings)
}

// The authorization endpoint reads its settings before its parameters, so a request reached without
// them answers the 500 page carrying reqctx.ErrNoSettings and reads nothing else: not a parked
// request a handle names, not the validator, and no refusal page for a request that does not parse
// (#580 decision 5).
func TestMissingSettings_TheAuthorizationEndpointAnswersBeforeReadingItsRequest(t *testing.T) {
	for _, tc := range []struct {
		name  string
		query string
	}{
		{"a request naming a parked request", "request_handle=" + strings.Repeat("A", 43)},
		{"a request that does not parse", "client_id=test-client&state=%zz"},
		{"a well-formed request", validAuthorizeQuery},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := newAuthorizeEndpoint(t)
			req := httptest.NewRequest(http.MethodGet, "/auth/authorize?"+tc.query, nil)
			rr := httptest.NewRecorder()
			e.pageRenderer.On("InternalServerError", rr, req, mock.MatchedBy(isErrNoSettings)).Return().Once()

			e.handler.ServeHTTP(rr, req)

			e.pageRenderer.AssertExpectations(t)
			e.pageRenderer.AssertNotCalled(t, "RenderTemplate", mock.Anything, mock.Anything, mock.Anything,
				mock.Anything, mock.Anything)
			e.database.AssertNotCalled(t, "RunInTransaction", mock.Anything, mock.Anything)
			e.validator.AssertNotCalled(t, "ValidateClientAndRedirectURI", mock.Anything, mock.Anything)
			e.ceremonyStore.AssertNotCalled(t, "AddAuthContext", mock.Anything, mock.Anything, mock.Anything)
		})
	}
}

// A POST to the authorization endpoint reads its settings before its parameters too, so a request
// reached without them answers the 500 page carrying reqctx.ErrNoSettings with nothing validated or
// parked, and no refusal page for a body that does not parse (#580 decision 5).
func TestMissingSettings_TheAuthorizationEndpointPostAnswersBeforeReadingItsRequest(t *testing.T) {
	for _, tc := range []struct {
		name string
		body string
	}{
		{"a body that does not parse", "client_id=test-client&state=%zz"},
		{"a well-formed body", validAuthorizeQuery},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := newAuthorizePostEndpoint(t)
			req := httptest.NewRequest(http.MethodPost, "/auth/authorize", strings.NewReader(tc.body))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			rr := httptest.NewRecorder()
			e.pageRenderer.On("InternalServerError", rr, req, mock.MatchedBy(isErrNoSettings)).Return().Once()

			e.handler.ServeHTTP(rr, req)

			e.pageRenderer.AssertExpectations(t)
			e.pageRenderer.AssertNotCalled(t, "RenderTemplate", mock.Anything, mock.Anything, mock.Anything,
				mock.Anything, mock.Anything)
			e.validator.AssertNotCalled(t, "ValidateClientAndRedirectURI", mock.Anything, mock.Anything)
			e.database.AssertNotCalled(t, "CreateAuthorizeRequest", mock.Anything, mock.Anything, mock.Anything)
			assert.Empty(t, rr.Header().Get("Location"))
		})
	}
}

// A browser page answers the 500 page through PageRenderer.
func TestMissingSettings_ABrowserPageAnswersTheErrorPage(t *testing.T) {
	pageRenderer := handlersmocks.NewPageRenderer(t)
	ceremonyStore := handlersmocks.NewCeremonyStore(t)
	database := datamocks.NewDatabase(t)

	req := httptest.NewRequest(http.MethodGet, "/auth/pwd?ceremony="+testCeremonyId, nil)
	rr := httptest.NewRecorder()

	pageRenderer.On("InternalServerError", rr, req, mock.MatchedBy(isErrNoSettings)).Return().Once()

	auditLogger := handlersmocks.NewAuditLogger(t)
	buildAuthPwdGet(authPwdGetDeps{
		pageRenderer:  pageRenderer,
		ceremonyStore: ceremonyStore,
		database:      database,
		auditLogger:   auditLogger,
	}).ServeHTTP(rr, req)

	pageRenderer.AssertExpectations(t)
	ceremonyStore.AssertNotCalled(t, "GetAuthContext", req)
	database.AssertNotCalled(t, "GetClientByClientIdentifier", mock.Anything, mock.Anything, mock.Anything)
}

// The routing hops read their settings through the route boundary before anything else, so a hop
// reached without them answers the 500 page carrying reqctx.ErrNoSettings and never reads its
// ceremony: no load, no save, no database read (#580 decision 5).
func TestMissingSettings_TheRoutingHopsAnswerBeforeReadingTheirCeremony(t *testing.T) {
	for _, hop := range []struct {
		name  string
		path  string
		build func(t *testing.T, pageRenderer *handlersmocks.PageRenderer, ceremonyStore *handlersmocks.CeremonyStore,
			database *datamocks.Database) http.Handler
	}{
		{"level1", "/auth/level1", func(t *testing.T, pr *handlersmocks.PageRenderer, cs *handlersmocks.CeremonyStore,
			_ *datamocks.Database) http.Handler {
			return buildAuthLevel1Get(authLevel1GetDeps{pageRenderer: pr, ceremonyStore: cs,
				auditLogger: handlersmocks.NewAuditLogger(t)})
		}},
		{"level1completed", "/auth/level1completed", func(t *testing.T, pr *handlersmocks.PageRenderer,
			cs *handlersmocks.CeremonyStore, db *datamocks.Database) http.Handler {
			return buildAuthLevel1CompletedGet(authLevel1CompletedGetDeps{pageRenderer: pr, ceremonyStore: cs,
				userSessionManager: handlersmocks.NewUserSessionManager(t), database: db,
				auditLogger: handlersmocks.NewAuditLogger(t)})
		}},
		{"level2", "/auth/level2", func(t *testing.T, pr *handlersmocks.PageRenderer, cs *handlersmocks.CeremonyStore,
			db *datamocks.Database) http.Handler {
			return buildAuthLevel2Get(authLevel2GetDeps{pageRenderer: pr, ceremonyStore: cs, database: db,
				auditLogger: handlersmocks.NewAuditLogger(t)})
		}},
	} {
		t.Run(hop.name, func(t *testing.T) {
			pageRenderer := handlersmocks.NewPageRenderer(t)
			ceremonyStore := handlersmocks.NewCeremonyStore(t)
			database := datamocks.NewDatabase(t)

			req := httptest.NewRequest(http.MethodGet, hop.path+"?ceremony="+testCeremonyId, nil)
			rr := httptest.NewRecorder()
			pageRenderer.On("InternalServerError", rr, req, mock.MatchedBy(isErrNoSettings)).Return().Once()

			hop.build(t, pageRenderer, ceremonyStore, database).ServeHTTP(rr, req)

			pageRenderer.AssertExpectations(t)
			ceremonyStore.AssertNotCalled(t, "GetAuthContext", req)
			ceremonyStore.AssertNotCalled(t, "SaveAuthContext", mock.Anything, mock.Anything, mock.Anything)
			database.AssertNotCalled(t, "GetClientByClientIdentifier", mock.Anything, mock.Anything, mock.Anything)
		})
	}
}

// The token endpoint answers its 500 through the JSON writer, RFC 6749 section 5.2's shape, as
// every other failure there is answered, and it is refused before the validator sees the request
// (#435).
func TestMissingSettings_TheTokenEndpointAnswersItsOwn500(t *testing.T) {
	jsonWriter := handlersmocks.NewJSONWriter(t)
	tokenValidator := handlersmocks.NewTokenValidator(t)

	req := httptest.NewRequest(http.MethodPost, "/auth/token",
		strings.NewReader("grant_type=client_credentials&client_id=test-client&client_secret=secret"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	jsonWriter.On("JSONError", rr, req, mock.MatchedBy(isErrNoSettings)).Return().Once()

	HandleTokenPost(jsonWriter, datamocks.NewDatabase(t),
		handlersmocks.NewTokenIssuer(t), tokenValidator, handlersmocks.NewAuditLogger(t),
		noCredentialFailures{}, testTokenMetrics()).ServeHTTP(rr, req)

	jsonWriter.AssertExpectations(t)
	tokenValidator.AssertNotCalled(t, "ValidateTokenRequest", mock.Anything, mock.Anything, mock.Anything)
}

// Dynamic client registration keeps RFC 7591 section 3.2.2's envelope for this 500 as for its
// others, and logs the sentinel once.
func TestMissingSettings_DynamicClientRegistrationAnswersTheRFC7591Envelope(t *testing.T) {
	database := datamocks.NewDatabase(t)

	body, err := json.Marshal(oidc.DynamicClientRegistrationRequest{
		ClientName:   "A Test Client",
		RedirectURIs: []string{"https://client.example.com/callback"},
	})
	require.NoError(t, err)
	req := httptest.NewRequest(http.MethodPost, "/connect/register", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	capture := logtest.CaptureSlog(t)
	HandleDynamicClientRegistrationPost(database,
		handlersmocks.NewAuditLogger(t), testDataCipher).ServeHTTP(rr, req)

	assert.Equal(t, http.StatusInternalServerError, rr.Code)
	var envelope map[string]any
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &envelope))
	assert.Equal(t, map[string]any{"error": "server_error", "error_description": "Internal server error"}, envelope)

	records := capture.Records()
	require.Len(t, records, 1)
	assert.Equal(t, "internal server error", records[0].Message)
	logged, isError := records[0].Attrs["error"].(error)
	require.True(t, isError, "the error attribute must carry the error value itself")
	assert.True(t, isErrNoSettings(logged))
	database.AssertNotCalled(t, "RunInTransaction", mock.Anything, mock.Anything)
}
