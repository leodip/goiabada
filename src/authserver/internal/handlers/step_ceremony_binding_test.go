package handlers

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"testing/fstest"

	"github.com/leodip/goiabada/authserver/internal/ceremony"
	"github.com/leodip/goiabada/authserver/internal/data/mocks"
	"github.com/leodip/goiabada/authserver/internal/handlers/mocks"
	"github.com/stretchr/testify/assert"
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
	build    func(t *testing.T, pageRenderer *handlersmocks.PageRenderer, ceremonyStore CeremonyStore,
		auditLogger *handlersmocks.AuditLogger) http.Handler
}

func everyGatedStep() []stepUnderTest {
	return []stepUnderTest{
		{name: "level1", method: http.MethodGet, path: "/auth/level1", accepted: ceremony.AuthStateRequiresLevel1,
			build: func(t *testing.T, pr *handlersmocks.PageRenderer, cs CeremonyStore,
				al *handlersmocks.AuditLogger) http.Handler {
				return buildAuthLevel1Get(authLevel1GetDeps{
					pageRenderer:  pr,
					ceremonyStore: cs,
					auditLogger:   al,
				})
			}},
		{name: "level1completed", method: http.MethodGet, path: "/auth/level1completed",
			accepted: ceremony.AuthStateLevel1PasswordCompleted,
			build: func(t *testing.T, pr *handlersmocks.PageRenderer, cs CeremonyStore,
				al *handlersmocks.AuditLogger) http.Handler {
				return buildAuthLevel1CompletedGet(authLevel1CompletedGetDeps{
					pageRenderer:       pr,
					ceremonyStore:      cs,
					userSessionManager: handlersmocks.NewUserSessionManager(t),
					database:           datamocks.NewDatabase(t),
					templateFS:         fstest.MapFS{},
					auditLogger:        al,
				})
			}},
		{name: "level2", method: http.MethodGet, path: "/auth/level2", accepted: ceremony.AuthStateRequiresLevel2,
			build: func(t *testing.T, pr *handlersmocks.PageRenderer, cs CeremonyStore,
				al *handlersmocks.AuditLogger) http.Handler {
				return buildAuthLevel2Get(authLevel2GetDeps{
					pageRenderer:  pr,
					ceremonyStore: cs,
					database:      datamocks.NewDatabase(t),
					auditLogger:   al,
				})
			}},
		{name: "pwd GET", method: http.MethodGet, path: "/auth/pwd", accepted: ceremony.AuthStateLevel1Password,
			build: func(t *testing.T, pr *handlersmocks.PageRenderer, cs CeremonyStore,
				al *handlersmocks.AuditLogger) http.Handler {
				return buildAuthPwdGet(authPwdGetDeps{
					pageRenderer:  pr,
					ceremonyStore: cs,
					database:      datamocks.NewDatabase(t),
					auditLogger:   al,
				})
			}},
		{name: "pwd POST", method: http.MethodPost, path: "/auth/pwd", accepted: ceremony.AuthStateLevel1Password,
			build: func(t *testing.T, pr *handlersmocks.PageRenderer, cs CeremonyStore,
				al *handlersmocks.AuditLogger) http.Handler {
				return buildAuthPwdPost(authPwdPostDeps{
					pageRenderer:  pr,
					ceremonyStore: cs,
					database:      datamocks.NewDatabase(t),
					auditLogger:   al,
				})
			}},
		{name: "otp GET", method: http.MethodGet, path: "/auth/otp", accepted: ceremony.AuthStateLevel2OTP,
			build: func(t *testing.T, pr *handlersmocks.PageRenderer, cs CeremonyStore,
				al *handlersmocks.AuditLogger) http.Handler {
				return buildAuthOtpGet(authOtpGetDeps{
					pageRenderer:       pr,
					ceremonyStore:      cs,
					database:           datamocks.NewDatabase(t),
					otpSecretGenerator: handlersmocks.NewOtpSecretGenerator(t),
					auditLogger:        al,
				})
			}},
		{name: "otp POST", method: http.MethodPost, path: "/auth/otp", accepted: ceremony.AuthStateLevel2OTP,
			build: func(t *testing.T, pr *handlersmocks.PageRenderer, cs CeremonyStore,
				al *handlersmocks.AuditLogger) http.Handler {
				return buildAuthOtpPost(authOtpPostDeps{
					pageRenderer:  pr,
					ceremonyStore: cs,
					database:      datamocks.NewDatabase(t),
					auditLogger:   al,
				})
			}},
		{name: "recovery-codes GET", method: http.MethodGet, path: "/auth/recovery-codes",
			accepted: ceremony.AuthStateLevel2RecoveryCodes,
			build: func(t *testing.T, pr *handlersmocks.PageRenderer, cs CeremonyStore,
				al *handlersmocks.AuditLogger) http.Handler {
				return buildAuthRecoveryCodesGet(authRecoveryCodesGetDeps{
					pageRenderer:  pr,
					ceremonyStore: cs,
					database:      datamocks.NewDatabase(t),
					auditLogger:   al,
				})
			}},
		{name: "recovery-codes POST", method: http.MethodPost, path: "/auth/recovery-codes",
			accepted: ceremony.AuthStateLevel2RecoveryCodes,
			build: func(t *testing.T, pr *handlersmocks.PageRenderer, cs CeremonyStore,
				al *handlersmocks.AuditLogger) http.Handler {
				return buildAuthRecoveryCodesPost(authRecoveryCodesPostDeps{
					pageRenderer:  pr,
					ceremonyStore: cs,
					auditLogger:   al,
				})
			}},
		{name: "completed", method: http.MethodGet, path: "/auth/completed",
			accepted: ceremony.AuthStateAuthenticationCompleted,
			build: func(t *testing.T, pr *handlersmocks.PageRenderer, cs CeremonyStore,
				al *handlersmocks.AuditLogger) http.Handler {
				return buildAuthCompletedGet(authCompletedGetDeps{
					pageRenderer:       pr,
					ceremonyStore:      cs,
					userSessionManager: handlersmocks.NewUserSessionManager(t),
					database:           datamocks.NewDatabase(t),
					templateFS:         fstest.MapFS{},
					auditLogger:        al,
					permissionChecker:  handlersmocks.NewPermissionChecker(t),
				})
			}},
		{name: "legal acceptance GET", method: http.MethodGet, path: "/auth/legal-acceptance",
			accepted: ceremony.AuthStateRequiresLegalAcceptance,
			build: func(t *testing.T, pr *handlersmocks.PageRenderer, cs CeremonyStore,
				al *handlersmocks.AuditLogger) http.Handler {
				return buildLegalAcceptanceGet(legalAcceptanceDeps{
					pageRenderer:      pr,
					ceremonyStore:     cs,
					database:          datamocks.NewDatabase(t),
					templateFS:        fstest.MapFS{},
					auditLogger:       al,
					permissionChecker: handlersmocks.NewPermissionChecker(t),
				})
			}},
		{name: "legal acceptance POST", method: http.MethodPost, path: "/auth/legal-acceptance",
			accepted: ceremony.AuthStateRequiresLegalAcceptance,
			build: func(t *testing.T, pr *handlersmocks.PageRenderer, cs CeremonyStore,
				al *handlersmocks.AuditLogger) http.Handler {
				return buildLegalAcceptancePost(legalAcceptanceDeps{
					pageRenderer:      pr,
					ceremonyStore:     cs,
					database:          datamocks.NewDatabase(t),
					templateFS:        fstest.MapFS{},
					auditLogger:       al,
					permissionChecker: handlersmocks.NewPermissionChecker(t),
				})
			}},
		{name: "consent GET", method: http.MethodGet, path: "/auth/consent", accepted: ceremony.AuthStateRequiresConsent,
			build: func(t *testing.T, pr *handlersmocks.PageRenderer, cs CeremonyStore,
				al *handlersmocks.AuditLogger) http.Handler {
				return buildConsentGet(consentGetDeps{
					pageRenderer:  pr,
					ceremonyStore: cs,
					database:      datamocks.NewDatabase(t),
					auditLogger:   al,
				})
			}},
		{name: "consent POST", method: http.MethodPost, path: "/auth/consent", accepted: ceremony.AuthStateRequiresConsent,
			build: func(t *testing.T, pr *handlersmocks.PageRenderer, cs CeremonyStore,
				al *handlersmocks.AuditLogger) http.Handler {
				return buildConsentPost(consentPostDeps{
					pageRenderer:      pr,
					ceremonyStore:     cs,
					database:          datamocks.NewDatabase(t),
					templateFS:        fstest.MapFS{},
					auditLogger:       al,
					permissionChecker: handlersmocks.NewPermissionChecker(t),
				})
			}},
		{name: "issue", method: http.MethodGet, path: "/auth/issue", accepted: ceremony.AuthStateReadyToIssueCode,
			build: func(t *testing.T, pr *handlersmocks.PageRenderer, cs CeremonyStore,
				al *handlersmocks.AuditLogger) http.Handler {
				return buildIssueGet(issueGetDeps{
					pageRenderer:        pr,
					ceremonyStore:       cs,
					templateFS:          fstest.MapFS{},
					codeIssuer:          handlersmocks.NewCodeIssuer(t),
					implicitTokenIssuer: handlersmocks.NewImplicitTokenIssuer(t),
					database:            datamocks.NewDatabase(t),
					auditLogger:         al,
					userSessionManager:  handlersmocks.NewUserSessionManager(t),
					permissionChecker:   handlersmocks.NewPermissionChecker(t),
				})
			}},
	}
}

// Every gated route is judged by the ceremony it names, through loadAuthContext and the real ceremony
// store's read of it, before its state is looked at and before anything else is read: thirteen
// handlers, each in the state it accepts, so the only thing that can refuse them is the id (#246
// decision 22). Each case varies one thing from a
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
				pageRenderer := handlersmocks.NewPageRenderer(t)
				auditLogger := handlersmocks.NewAuditLogger(t)
				rr := httptest.NewRecorder()

				stored := &ceremony.AuthContext{CeremonyId: testCeremonyId, ClientId: "test-client", AuthState: step.accepted}
				ceremonyStore, cookies := holdingCeremony(t, stored)
				req = withCookies(req, cookies)
				expectCeremonyMismatchOf(t, pageRenderer, auditLogger, rr, req, stored)

				step.build(t, pageRenderer, ceremonyStore, auditLogger).ServeHTTP(rr, req)

				assert.Empty(t, rr.Result().Cookies(), "a refused request writes nothing to the browser session")
				assertStillHeld(t, ceremonyStore, cookies, stored)
			})
		}

		t.Run(step.name+" naming the stored ceremony reaches the state gate", func(t *testing.T) {
			pageRenderer := handlersmocks.NewPageRenderer(t)
			ceremonyStore := handlersmocks.NewCeremonyStore(t)
			auditLogger := handlersmocks.NewAuditLogger(t)
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
