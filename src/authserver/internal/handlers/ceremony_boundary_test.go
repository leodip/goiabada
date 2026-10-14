package handlers

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"github.com/leodip/goiabada/authserver/internal/audit"
	"github.com/leodip/goiabada/authserver/internal/ceremony"
	handlersmocks "github.com/leodip/goiabada/authserver/internal/handlers/mocks"
	"github.com/leodip/goiabada/core/errs"
	"github.com/leodip/goiabada/core/logging/logtest"
)

// The route boundary is built once in the route table, from the values it holds, and every step reads
// them from there. The cases that redirect build it with base URLs no other test uses, so a redirect
// built from anything but the boundary's own fields fails; the others pin the branches the step
// handlers' cases do not reach.

const (
	otherBaseURL             = "https://auth.boundary.test"
	otherAdminConsoleBaseURL = "https://console.boundary.test"
)

func TestCeremonyBoundary_StepRedirect(t *testing.T) {
	boundary := NewCeremonyBoundary(nil, nil, nil, otherBaseURL, otherAdminConsoleBaseURL)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/auth/level1?ceremony="+testCeremonyId, nil)

	boundary.stepRedirect(rr, req, "/auth/pwd", &ceremony.AuthContext{CeremonyId: testCeremonyId})

	assert.Equal(t, http.StatusFound, rr.Code)
	assert.Equal(t, "https://auth.boundary.test/auth/pwd?ceremony="+testCeremonyId, rr.Header().Get("Location"))
}

func TestCeremonyBoundary_LoadAuthContextRedirectsToItsOwnConsole(t *testing.T) {
	ceremonyStore := handlersmocks.NewCeremonyStore(t)
	boundary := NewCeremonyBoundary(handlersmocks.NewPageRenderer(t), ceremonyStore,
		handlersmocks.NewAuditLogger(t), otherBaseURL, otherAdminConsoleBaseURL)
	rr := httptest.NewRecorder()
	req := renderableRequest("/auth/level1")
	ceremonyStore.On("GetAuthContext", req).Return(nil, ceremony.ErrNoAuthContext).Once()

	_, ok := boundary.loadAuthContext(rr, req)

	assert.False(t, ok)
	assert.Equal(t, http.StatusFound, rr.Code)
	assert.Equal(t, "https://console.boundary.test/account/profile", rr.Header().Get("Location"))
}

func TestCeremonyBoundary_AnswerStepSaveFailure(t *testing.T) {
	t.Run("a replaced ceremony, however wrapped, is the no longer active page at warn", func(t *testing.T) {
		logged := logtest.CaptureSlog(t)
		pageRenderer := handlersmocks.NewPageRenderer(t)
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/auth/level2?ceremony="+testCeremonyId, nil)
		expectCeremonyNoLongerActive(t, pageRenderer, rr, req)

		testCeremonyBoundary(pageRenderer, nil, nil).answerStepSaveFailure(rr, req,
			errs.Wrap(ceremony.ErrCeremonyReplaced, "saving the auth context"))

		assertAnsweredNoLongerActive(t, rr)
		assertReplacedAnsweredAtWarn(t, logged)
		pageRenderer.AssertNotCalled(t, "InternalServerError", rr, req, mock.Anything)
	})

	t.Run("any other failure is the 500 carrying that error", func(t *testing.T) {
		pageRenderer := handlersmocks.NewPageRenderer(t)
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/auth/level2?ceremony="+testCeremonyId, nil)
		pageRenderer.On("InternalServerError", rr, req, assert.AnError).Return().Once()

		testCeremonyBoundary(pageRenderer, nil, nil).answerStepSaveFailure(rr, req, assert.AnError)

		pageRenderer.AssertNotCalled(t, "RenderTemplate", rr, req, mock.Anything, mock.Anything, mock.Anything)
	})
}

// The forwarded address the mismatch audit records originates outside the process, so it is bounded:
// the first 100 bytes, whatever arrives.
func TestCeremonyBoundary_RejectCeremonyMismatchBoundsTheAuditedAddress(t *testing.T) {
	pageRenderer := handlersmocks.NewPageRenderer(t)
	auditLogger := handlersmocks.NewAuditLogger(t)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/auth/pwd", nil)
	req.RemoteAddr = strings.Repeat("a", 150)

	auditLogger.On("Log", req.Context(), audit.EventAuthCeremonyMismatch, mock.MatchedBy(func(details map[string]interface{}) bool {
		return details["ip"] == strings.Repeat("a", 100)
	})).Return().Once()
	pageRenderer.On("RenderTemplate", rr, req, "/layouts/no_menu_layout.html", "/auth_error.html",
		mock.Anything).Return(nil).Once()

	testCeremonyBoundary(pageRenderer, nil, auditLogger).rejectCeremonyMismatch(rr, req,
		&ceremony.AuthContext{ClientId: "test-client", AuthState: ceremony.AuthStateLevel1Password})
}

// A "no longer active" page that cannot be rendered is the 500 page, carrying the render's error.
func TestCeremonyBoundary_RenderCeremonyNoLongerActiveFallsBackToThe500(t *testing.T) {
	pageRenderer := handlersmocks.NewPageRenderer(t)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/auth/level2", nil)
	pageRenderer.On("RenderTemplate", rr, req, "/layouts/no_menu_layout.html", "/auth_error.html",
		mock.Anything).Return(assert.AnError).Once()
	pageRenderer.On("InternalServerError", rr, req, assert.AnError).Return().Once()

	testCeremonyBoundary(pageRenderer, nil, nil).renderCeremonyNoLongerActive(rr, req)
}
