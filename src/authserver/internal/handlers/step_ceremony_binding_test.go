package handlers

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"testing/fstest"

	"github.com/leodip/goiabada/authserver/internal/ceremony"
	mocks_data "github.com/leodip/goiabada/authserver/internal/data/mocks"
	mocks_handlers "github.com/leodip/goiabada/authserver/internal/handlers/mocks"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// stepUnderTest is one gated route, built over strict mocks that expect nothing, so any read or write
// past the ceremony comparison and the state gate is reported as an unexpected call rather than
// passing (#246 decision 22, #437 seam 4).
type stepUnderTest struct {
	name   string
	method string
	path   string
	// accepted is a state the route accepts, so a request that got past the comparison would go on
	// and read from the strict mocks.
	accepted ceremony.AuthState
	build    func(t *testing.T, pageRenderer *mocks_handlers.PageRenderer, ceremonyStore *mocks_handlers.CeremonyStore,
		auditLogger *mocks_handlers.AuditLogger) http.Handler
}

func everyGatedStep() []stepUnderTest {
	return []stepUnderTest{
		{name: "level1", method: http.MethodGet, path: "/auth/level1", accepted: ceremony.AuthStateRequiresLevel1,
			build: func(t *testing.T, pr *mocks_handlers.PageRenderer, cs *mocks_handlers.CeremonyStore,
				al *mocks_handlers.AuditLogger) http.Handler {
				return HandleAuthLevel1Get(pr, cs, al, testBaseURL, testAdminConsoleBaseURL)
			}},
		{name: "level1completed", method: http.MethodGet, path: "/auth/level1completed",
			accepted: ceremony.AuthStateLevel1PasswordCompleted,
			build: func(t *testing.T, pr *mocks_handlers.PageRenderer, cs *mocks_handlers.CeremonyStore,
				al *mocks_handlers.AuditLogger) http.Handler {
				return HandleAuthLevel1CompletedGet(pr, cs, mocks_handlers.NewUserSessionManager(t),
					mocks_data.NewDatabase(t), fstest.MapFS{}, al, testBaseURL, testAdminConsoleBaseURL)
			}},
		{name: "level2", method: http.MethodGet, path: "/auth/level2", accepted: ceremony.AuthStateRequiresLevel2,
			build: func(t *testing.T, pr *mocks_handlers.PageRenderer, cs *mocks_handlers.CeremonyStore,
				al *mocks_handlers.AuditLogger) http.Handler {
				return HandleAuthLevel2Get(pr, cs, mocks_data.NewDatabase(t), al, testBaseURL, testAdminConsoleBaseURL)
			}},
		{name: "pwd GET", method: http.MethodGet, path: "/auth/pwd", accepted: ceremony.AuthStateLevel1Password,
			build: func(t *testing.T, pr *mocks_handlers.PageRenderer, cs *mocks_handlers.CeremonyStore,
				al *mocks_handlers.AuditLogger) http.Handler {
				return HandleAuthPwdGet(pr, cs, mocks_data.NewDatabase(t), al, testAdminConsoleBaseURL)
			}},
		{name: "pwd POST", method: http.MethodPost, path: "/auth/pwd", accepted: ceremony.AuthStateLevel1Password,
			build: func(t *testing.T, pr *mocks_handlers.PageRenderer, cs *mocks_handlers.CeremonyStore,
				al *mocks_handlers.AuditLogger) http.Handler {
				return HandleAuthPwdPost(pr, cs, mocks_data.NewDatabase(t), al, noCredentialFailures{},
					testBaseURL, testAdminConsoleBaseURL)
			}},
		{name: "otp GET", method: http.MethodGet, path: "/auth/otp", accepted: ceremony.AuthStateLevel2OTP,
			build: func(t *testing.T, pr *mocks_handlers.PageRenderer, cs *mocks_handlers.CeremonyStore,
				al *mocks_handlers.AuditLogger) http.Handler {
				return HandleAuthOtpGet(pr, cs, mocks_data.NewDatabase(t), mocks_handlers.NewOtpSecretGenerator(t), al,
					testAdminConsoleBaseURL)
			}},
		{name: "otp POST", method: http.MethodPost, path: "/auth/otp", accepted: ceremony.AuthStateLevel2OTP,
			build: func(t *testing.T, pr *mocks_handlers.PageRenderer, cs *mocks_handlers.CeremonyStore,
				al *mocks_handlers.AuditLogger) http.Handler {
				return HandleAuthOtpPost(pr, cs, mocks_data.NewDatabase(t), al, noCredentialFailures{}, testDataCipher,
					testBaseURL, testAdminConsoleBaseURL)
			}},
		{name: "completed", method: http.MethodGet, path: "/auth/completed",
			accepted: ceremony.AuthStateAuthenticationCompleted,
			build: func(t *testing.T, pr *mocks_handlers.PageRenderer, cs *mocks_handlers.CeremonyStore,
				al *mocks_handlers.AuditLogger) http.Handler {
				return HandleAuthCompletedGet(pr, cs, mocks_handlers.NewUserSessionManager(t), mocks_data.NewDatabase(t),
					fstest.MapFS{}, al, mocks_handlers.NewPermissionChecker(t), testBaseURL, testAdminConsoleBaseURL)
			}},
		{name: "consent GET", method: http.MethodGet, path: "/auth/consent", accepted: ceremony.AuthStateRequiresConsent,
			build: func(t *testing.T, pr *mocks_handlers.PageRenderer, cs *mocks_handlers.CeremonyStore,
				al *mocks_handlers.AuditLogger) http.Handler {
				return HandleConsentGet(pr, cs, mocks_data.NewDatabase(t), al, testBaseURL, testAdminConsoleBaseURL)
			}},
		{name: "consent POST", method: http.MethodPost, path: "/auth/consent", accepted: ceremony.AuthStateRequiresConsent,
			build: func(t *testing.T, pr *mocks_handlers.PageRenderer, cs *mocks_handlers.CeremonyStore,
				al *mocks_handlers.AuditLogger) http.Handler {
				return HandleConsentPost(pr, cs, mocks_data.NewDatabase(t), fstest.MapFS{}, al,
					mocks_handlers.NewPermissionChecker(t), testBaseURL, testAdminConsoleBaseURL)
			}},
		{name: "issue", method: http.MethodGet, path: "/auth/issue", accepted: ceremony.AuthStateReadyToIssueCode,
			build: func(t *testing.T, pr *mocks_handlers.PageRenderer, cs *mocks_handlers.CeremonyStore,
				al *mocks_handlers.AuditLogger) http.Handler {
				return HandleIssueGet(pr, cs, fstest.MapFS{}, mocks_handlers.NewCodeIssuer(t),
					mocks_handlers.NewImplicitTokenIssuer(t), mocks_data.NewDatabase(t), al,
					mocks_handlers.NewUserSessionManager(t), mocks_handlers.NewPermissionChecker(t),
					testBaseURL, testAdminConsoleBaseURL)
			}},
	}
}

// Every gated route is judged by the ceremony it names, through loadAuthContext, before its state is
// looked at and before anything else is read: eleven handlers, each in the state it accepts, so the
// only thing that can refuse them is the id (#246 decision 22). Each case varies one thing from a
// request that passes; the passing one is the last subtest, which reaches the state gate instead.
func TestEveryGatedStep_IsJudgedByTheCeremonyItNames(t *testing.T) {
	const otherId = "543210ZyXwVuTsRqPoNmLkJiHgFeDcBa"

	for _, step := range everyGatedStep() {
		// A page load names the ceremony in the URL; a submission, in its body. Each is built the way
		// its route is reached, so a route that read the other place would see nothing.
		idIn := func(id string) *http.Request {
			if step.method == http.MethodPost {
				return stepRequestFor(step.method, step.path, "", id)
			}
			return stepRequestFor(step.method, step.path, id, "")
		}

		refused := map[string]*http.Request{
			"naming no ceremony":      idIn(""),
			"naming another ceremony": idIn(otherId),
		}
		for name, req := range refused {
			t.Run(step.name+" "+name, func(t *testing.T) {
				pageRenderer := mocks_handlers.NewPageRenderer(t)
				ceremonyStore := mocks_handlers.NewCeremonyStore(t)
				auditLogger := mocks_handlers.NewAuditLogger(t)
				rr := httptest.NewRecorder()

				stored := &ceremony.AuthContext{CeremonyId: testCeremonyId, ClientId: "test-client", AuthState: step.accepted}
				ceremonyStore.On("GetAuthContext", req).Return(stored, nil).Once()
				expectCeremonyMismatch(t, pageRenderer, auditLogger, rr, req)

				step.build(t, pageRenderer, ceremonyStore, auditLogger).ServeHTTP(rr, req)

				assert.Equal(t, step.accepted, stored.AuthState, "a refused request leaves the ceremony as it was")
				ceremonyStore.AssertNotCalled(t, "SaveAuthContext", mock.Anything, mock.Anything, mock.Anything)
				ceremonyStore.AssertNotCalled(t, "ClearAuthContext", mock.Anything, mock.Anything)
			})
		}

		t.Run(step.name+" naming the stored ceremony reaches the state gate", func(t *testing.T) {
			pageRenderer := mocks_handlers.NewPageRenderer(t)
			ceremonyStore := mocks_handlers.NewCeremonyStore(t)
			auditLogger := mocks_handlers.NewAuditLogger(t)
			rr := httptest.NewRecorder()
			req := idIn(testCeremonyId)

			// A state no route accepts: what refuses the request is the state gate, past the
			// comparison, and the audit event of a ceremony mismatch is never written.
			stored := &ceremony.AuthContext{CeremonyId: testCeremonyId, ClientId: "test-client",
				AuthState: ceremony.AuthState("not_a_state")}
			ceremonyStore.On("GetAuthContext", req).Return(stored, nil).Once()
			expectAuthStateMismatch(t, pageRenderer, rr, req)

			step.build(t, pageRenderer, ceremonyStore, auditLogger).ServeHTTP(rr, req)
		})
	}
}
