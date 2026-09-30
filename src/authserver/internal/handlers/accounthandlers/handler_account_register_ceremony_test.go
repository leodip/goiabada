package accounthandlers

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/ceremony"
	mocks_data "github.com/leodip/goiabada/authserver/internal/data/mocks"
	mocks_accounthandlers "github.com/leodip/goiabada/authserver/internal/handlers/accounthandlers/mocks"
	mocks_handlers "github.com/leodip/goiabada/authserver/internal/handlers/mocks"
	"github.com/leodip/goiabada/authserver/internal/models"
	"github.com/leodip/goiabada/authserver/internal/reqctx"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// The password page's "Register" link carries the ceremony it was rendered for, and this page puts
// it back into its own "Sign in" link, so a visitor who registers nothing and goes back lands on the
// same sign-in's password form (#246 decision 22, #437 seam 4). The id arrives from the URL, so it is
// only ever echoed after its shape is checked, and a value of any other shape is dropped and never
// repeated into the page.

// aCeremonyId is an id of the shape ceremony.NewId draws.
const aCeremonyId = "aBcDeFgHiJkLmNoPqRsTuVwXyZ012345"

var registrationEchoCases = []struct {
	name  string
	query string
	want  string
}{
	{"an id of the right shape is kept", "?ceremony=" + aCeremonyId, aCeremonyId},
	{"an id with every punctuation character of the alphabet is kept", "?ceremony=aB-_.EfGhIjKlMnOpQrStUvWxYz01234", "aB-_.EfGhIjKlMnOpQrStUvWxYz01234"},
	{"no parameter leaves the link bare", "", ""},
	{"an empty parameter leaves the link bare", "?ceremony=", ""},
	{"one character short is dropped", "?ceremony=" + aCeremonyId[:ceremony.IdLength-1], ""},
	{"one character over is dropped", "?ceremony=" + aCeremonyId + "x", ""},
	{"far over is dropped", "?ceremony=" + strings.Repeat("a", 4096), ""},
	{"a character outside the alphabet is dropped", "?ceremony=" + aCeremonyId[:ceremony.IdLength-1] + "!", ""},
	{"markup is dropped", "?ceremony=" + url.QueryEscape(`"><script>alert(1)</script>`), ""},
	{"a URL is dropped", "?ceremony=" + url.QueryEscape("https://evil.example/"+strings.Repeat("a", 10)), ""},
	{"the form field's name is not the parameter", "?ceremonyId=" + aCeremonyId, ""},
	{"a repeated parameter reads the first copy", "?ceremony=" + aCeremonyId + "&ceremony=other", aCeremonyId},
}

func TestHandleAccountRegisterGet_EchoesOnlyAWellFormedCeremony(t *testing.T) {
	for _, tc := range registrationEchoCases {
		t.Run(tc.name, func(t *testing.T) {
			pageRenderer := mocks_handlers.NewPageRenderer(t)
			handler := HandleAccountRegisterGet(pageRenderer)

			req := httptest.NewRequest(http.MethodGet, "/account/register"+tc.query, nil)
			req = req.WithContext(reqctx.WithSettings(req.Context(), &models.Settings{SelfRegistrationEnabled: true}))
			rr := httptest.NewRecorder()

			pageRenderer.On("RenderTemplate", rr, req, "/layouts/auth_layout.html", "/account_register.html",
				mock.MatchedBy(func(data map[string]interface{}) bool {
					return data["ceremonyId"] == tc.want
				})).Return(nil).Once()

			handler.ServeHTTP(rr, req)

			assert.Equal(t, http.StatusOK, rr.Code)
		})
	}
}

// The form posts to action="", so the URL the page was loaded at, parameter included, is the one the
// submission has, and a refusal that redraws the form has to carry the id on or the second attempt
// would lose it. Driven through the refusal every mistyped submission takes first: no email.
func TestHandleAccountRegisterPost_TheRedrawnFormKeepsOnlyAWellFormedCeremony(t *testing.T) {
	for _, tc := range registrationEchoCases {
		t.Run(tc.name, func(t *testing.T) {
			pageRenderer := mocks_handlers.NewPageRenderer(t)
			handler := HandleAccountRegisterPost(pageRenderer, mocks_data.NewDatabase(t),
				mocks_accounthandlers.NewUserCreator(t), mocks_accounthandlers.NewEmailValidator(t),
				mocks_accounthandlers.NewPasswordValidator(t), mocks_accounthandlers.NewEmailSender(t),
				mocks_handlers.NewAuditLogger(t), testDataCipher, testBaseURL, testAdminConsoleBaseURL)

			req := httptest.NewRequest(http.MethodPost, "/account/register"+tc.query, strings.NewReader(""))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			req = req.WithContext(reqctx.WithSettings(req.Context(), &models.Settings{SelfRegistrationEnabled: true}))
			rr := httptest.NewRecorder()

			pageRenderer.On("RenderTemplate", rr, req, "/layouts/auth_layout.html", "/account_register.html",
				mock.MatchedBy(func(data map[string]interface{}) bool {
					return data["error"] == "Email is required." && data["ceremonyId"] == tc.want
				})).Return(nil).Once()

			handler.ServeHTTP(rr, req)

			assert.Equal(t, http.StatusOK, rr.Code)
		})
	}
}
