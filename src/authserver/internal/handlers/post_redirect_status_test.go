package handlers

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/leodip/goiabada/authserver/internal/ceremony"
	datamocks "github.com/leodip/goiabada/authserver/internal/data/mocks"
	handlersmocks "github.com/leodip/goiabada/authserver/internal/handlers/mocks"
	"github.com/leodip/goiabada/authserver/internal/record"
)

// Every redirect the sign-in ceremony sends in answer to a POST is a 303, and every one answering a
// GET stays a 302. RFC 9700 section 4.12 says a redirect of a request that may carry the user's
// credentials SHOULD be 303, the one code RFC 9110 section 15.4.4 has the browser follow with a GET
// whatever the method was, so the form body is never sent on (#576, decision 6). The cases pin each
// redirect the ceremony writes, under both methods, at the four places they are written: the step
// redirect, the no-ceremony redirect to the account page, and the client's query and fragment
// redirects.

func TestRedirectStatus_TheStepRedirect(t *testing.T) {
	cases := []struct {
		method string
		status int
	}{
		{http.MethodPost, http.StatusSeeOther},
		{http.MethodGet, http.StatusFound},
	}
	for _, tc := range cases {
		t.Run(tc.method, func(t *testing.T) {
			rr := httptest.NewRecorder()
			req := stepRequestFor(tc.method, "/auth/pwd", testCeremonyId, testCeremonyId)

			testCeremonyBoundary(nil, nil, nil).stepRedirect(rr, req, "/auth/level1completed",
				&ceremony.AuthContext{CeremonyId: testCeremonyId})

			assert.Equal(t, tc.status, rr.Code)
			assert.Equal(t, testBaseURL+"/auth/level1completed?ceremony="+testCeremonyId, rr.Header().Get("Location"))
		})
	}
}

// A POST finding no ceremony is the case section 4.12 is about: the password form's body goes to the
// admin console's account page, on another origin, unless the browser is told to follow with a GET.
func TestRedirectStatus_TheNoCeremonyRedirect(t *testing.T) {
	cases := []struct {
		method string
		status int
	}{
		{http.MethodPost, http.StatusSeeOther},
		{http.MethodGet, http.StatusFound},
	}
	for _, tc := range cases {
		t.Run(tc.method, func(t *testing.T) {
			ceremonyStore := handlersmocks.NewCeremonyStore(t)
			rr := httptest.NewRecorder()
			req := stepRequestFor(tc.method, "/auth/pwd", testCeremonyId, testCeremonyId)
			ceremonyStore.On("GetAuthContext", req).Return(nil, ceremony.ErrNoAuthContext).Once()

			_, ok := testCeremonyBoundary(handlersmocks.NewPageRenderer(t), ceremonyStore,
				handlersmocks.NewAuditLogger(t)).loadAuthContext(rr, req)

			assert.False(t, ok)
			assert.Equal(t, tc.status, rr.Code)
			assert.Equal(t, testAdminConsoleBaseURL+"/account/profile", rr.Header().Get("Location"))
		})
	}
}

func TestRedirectStatus_TheClientRedirects(t *testing.T) {
	cases := []struct {
		method string
		status int
	}{
		{http.MethodPost, http.StatusSeeOther},
		{http.MethodGet, http.StatusFound},
	}
	for _, tc := range cases {
		t.Run("query, "+tc.method, func(t *testing.T) {
			rr := httptest.NewRecorder()
			req := httptest.NewRequest(tc.method, "/auth/consent", nil)

			require.NoError(t, writeQueryRedirect(rr, req, "https://app.example.com/cb",
				[]responseParam{{"error", "access_denied"}, {"state", "st"}}))

			assert.Equal(t, tc.status, rr.Code)
			assert.Equal(t, "https://app.example.com/cb?error=access_denied&state=st", rr.Header().Get("Location"))
		})

		t.Run("fragment, "+tc.method, func(t *testing.T) {
			rr := httptest.NewRecorder()
			req := httptest.NewRequest(tc.method, "/auth/consent", nil)

			writeFragmentRedirect(rr, req, "https://app.example.com/cb",
				[]responseParam{{"error", "access_denied"}, {"state", "st"}})

			assert.Equal(t, tc.status, rr.Code)
			assert.Equal(t, "https://app.example.com/cb#error=access_denied&state=st", rr.Header().Get("Location"))
		})
	}
}

// The declined consent answers the client from a POST, so its access_denied redirect is a 303 in both
// redirect encodings. The issue had kept it at 302 because it carries no credential, but neither does
// the approved consent's step redirect, and one rule is what the docs state (#576, decision 6).
func TestRedirectStatus_TheDeclinedConsent(t *testing.T) {
	cases := []struct {
		responseMode string
		location     string
	}{
		{"query", "https://example.com/callback?error=access_denied"},
		{"fragment", "https://example.com/callback#error=access_denied"},
	}
	for _, tc := range cases {
		t.Run(tc.responseMode, func(t *testing.T) {
			pageRenderer := handlersmocks.NewPageRenderer(t)
			ceremonyStore := handlersmocks.NewCeremonyStore(t)
			database := datamocks.NewDatabase(t)
			stubRegisteredRedirectURI(database, "https://example.com/callback")
			stubClientProvenanceLookup(database)

			handler := buildConsentPost(consentPostDeps{
				pageRenderer:      pageRenderer,
				ceremonyStore:     ceremonyStore,
				database:          database,
				auditLogger:       handlersmocks.NewAuditLogger(t),
				permissionChecker: handlersmocks.NewPermissionChecker(t),
			})

			form := url.Values{}
			form.Add("btnCancel", "cancel")
			form.Add(ceremony.IdField, testCeremonyId)
			req := httptest.NewRequest(http.MethodPost, "/auth/consent", strings.NewReader(form.Encode()))
			req = withSettings(req, &record.Settings{Issuer: "https://auth.example.com"})
			req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
			rr := httptest.NewRecorder()

			ceremonyStore.On("GetAuthContext", mock.Anything).Return(&ceremony.AuthContext{
				AuthState:    ceremony.AuthStateRequiresConsent,
				CeremonyId:   testCeremonyId,
				ClientId:     "test-client",
				ResponseType: "code",
				ResponseMode: tc.responseMode,
				RedirectURI:  "https://example.com/callback",
				State:        "test-state",
			}, nil)
			ceremonyStore.On("ClearAuthContext", rr, req, testCeremonyId).Return(nil).Once()

			handler.ServeHTTP(rr, req)

			assert.Equal(t, http.StatusSeeOther, rr.Code)
			assert.True(t, strings.HasPrefix(rr.Header().Get("Location"), tc.location),
				"the Location %q should start with %q", rr.Header().Get("Location"), tc.location)
		})
	}
}
