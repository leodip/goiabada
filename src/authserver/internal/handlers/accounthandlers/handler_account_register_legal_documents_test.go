package accounthandlers

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/ceremony"
	"github.com/leodip/goiabada/authserver/internal/data/mocks"
	"github.com/leodip/goiabada/authserver/internal/handlers/accounthandlers/mocks"
	"github.com/leodip/goiabada/authserver/internal/handlers/mocks"
	"github.com/leodip/goiabada/authserver/internal/legaldocuments"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/authserver/internal/render"
	"github.com/leodip/goiabada/authserver/internal/reqctx"
	"github.com/leodip/goiabada/authserver/internal/turnstile"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// The registration form links the legal documents where it collects the data (#622): those in
// effect for all apps, plus the app's own when registration came from a sign-in for that app, which
// is when the browser holds the sign-in the password page's Create an account link named.

func inEffect(shortName, title string) legaldocuments.InEffect {
	return legaldocuments.InEffect{
		Document: record.LegalDocument{ShortName: shortName},
		Current:  record.LegalDocumentVersion{VersionNumber: 1, Title: title},
	}
}

// shopDocuments is a privacy notice for all apps and the shop's own terms.
func shopDocuments(asked *[]string) legalDocumentsInEffect {
	return legalDocumentsInEffect{
		allApps:  []legaldocuments.InEffect{inEffect("privacy", "Privacy notice")},
		byClient: map[string][]legaldocuments.InEffect{"shop": {inEffect("shop-terms", "Shop terms")}},
		asked:    asked,
	}
}

func registerRequest(method, query string) *http.Request {
	req := httptest.NewRequest(method, "/account/register"+query, strings.NewReader(""))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return req.WithContext(reqctx.WithSettings(req.Context(), &record.Settings{SelfRegistrationEnabled: true}))
}

// renderedRegisterBind serves handler and answers the bind the form was drawn with.
func renderedRegisterBind(t *testing.T, pageRenderer *handlersmocks.PageRenderer, handler http.Handler, req *http.Request) map[string]interface{} {
	t.Helper()
	var bind map[string]interface{}
	pageRenderer.On("RenderTemplate", mock.Anything, req, "/layouts/auth_layout.html", "/account_register.html", mock.Anything).
		Run(func(args mock.Arguments) { bind = args.Get(4).(map[string]interface{}) }).Return(nil).Once()
	handler.ServeHTTP(httptest.NewRecorder(), req)
	require.NotNil(t, bind)
	return bind
}

func TestHandleRegisterGet_LinksTheAllAppsDocumentsAndTheSignInsApps(t *testing.T) {
	held := heldCeremonies{aCeremonyId: {CeremonyId: aCeremonyId, ClientId: "shop"}}
	otherHeld := heldCeremonies{"zBcDeFgHiJkLmNoPqRsTuVwXyZ012345": {ClientId: "blog"}}
	allApps := []render.LegalDocumentLink{{Title: "Privacy notice", ShortName: "privacy"}}
	withShop := append(append([]render.LegalDocumentLink{}, allApps...), render.LegalDocumentLink{Title: "Shop terms", ShortName: "shop-terms"})

	for _, tc := range []struct {
		name       string
		ceremonies heldCeremonies
		query      string
		client     string
		want       []render.LegalDocumentLink
	}{
		{"from the app's sign-in, held by the browser", held, "?ceremony=" + aCeremonyId, "shop", withShop},
		{"a sign-in this browser does not hold", otherHeld, "?ceremony=" + aCeremonyId, "", allApps},
		{"a browser holding no sign-in", heldCeremonies{}, "?ceremony=" + aCeremonyId, "", allApps},
		{"reached from anywhere else", held, "", "", allApps},
		{"a malformed id", held, "?ceremony=" + aCeremonyId + "x", "", allApps},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var asked []string
			pageRenderer := handlersmocks.NewPageRenderer(t)
			req := registerRequest(http.MethodGet, tc.query)
			bind := renderedRegisterBind(t, pageRenderer, HandleRegisterGet(pageRenderer, tc.ceremonies, shopDocuments(&asked)), req)

			assert.Equal(t, tc.want, bind["legalDocuments"])
			assert.Equal(t, tc.client, bind[render.LegalFooterClient], "the footer links the same app's documents")
			assert.Equal(t, []string{tc.client}, asked)
		})
	}
}

// A refused submission draws the form again with the same documents.
func TestHandleRegisterPost_TheRedrawnFormLinksTheSameDocuments(t *testing.T) {
	var asked []string
	held := heldCeremonies{aCeremonyId: {CeremonyId: aCeremonyId, ClientId: "shop"}}
	pageRenderer := handlersmocks.NewPageRenderer(t)
	handler := HandleRegisterPost(pageRenderer, held, shopDocuments(&asked), datamocks.NewDatabase(t),
		accounthandlersmocks.NewUserCreator(t), accounthandlersmocks.NewEmailValidator(t),
		accounthandlersmocks.NewPasswordValidator(t), accounthandlersmocks.NewEmailSender(t),
		handlersmocks.NewAuditLogger(t), &heldJobs{}, testDataCipher, testBaseURL, testAdminConsoleBaseURL)

	bind := renderedRegisterBind(t, pageRenderer, handler, registerRequest(http.MethodPost, "?ceremony="+aCeremonyId))

	assert.Equal(t, "Email is required.", bind["error"])
	assert.Equal(t, []render.LegalDocumentLink{
		{Title: "Privacy notice", ShortName: "privacy"}, {Title: "Shop terms", ShortName: "shop-terms"},
	}, bind["legalDocuments"])
	assert.Equal(t, "shop", bind[render.LegalFooterClient])
}

// A submission the Turnstile challenge refuses draws the form again with the same documents, as
// the handler's own refusals do (#642).
func TestRequireRegistrationChallenge_TheRedrawnFormLinksTheSameDocuments(t *testing.T) {
	var asked []string
	held := heldCeremonies{aCeremonyId: {CeremonyId: aCeremonyId, ClientId: "shop"}}
	pageRenderer := handlersmocks.NewPageRenderer(t)
	unreached := http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("a refused submission reached the handler")
	})
	handler := RequireRegistrationChallenge(pageRenderer, held, shopDocuments(&asked),
		refusingVerifier{})(unreached)
	req := registerRequest(http.MethodPost, "?ceremony="+aCeremonyId)
	req = req.WithContext(reqctx.WithSettings(req.Context(), &record.Settings{
		SelfRegistrationEnabled: true, TurnstileEnabled: true, TurnstileSiteKey: "1x00000000000000000000AA",
	}))

	bind := renderedRegisterBind(t, pageRenderer, handler, req)

	assert.Equal(t, "Complete the security check, then try again. The check needs JavaScript.", bind["error"])
	assert.Equal(t, []render.LegalDocumentLink{
		{Title: "Privacy notice", ShortName: "privacy"}, {Title: "Shop terms", ShortName: "shop-terms"},
	}, bind["legalDocuments"])
	assert.Equal(t, "shop", bind[render.LegalFooterClient])
	assert.Equal(t, "1x00000000000000000000AA", bind["turnstileSiteKey"], "the redrawn form carries a fresh widget")
}

// refusingVerifier refuses every token.
type refusingVerifier struct{}

func (refusingVerifier) Check(context.Context, *record.Settings, turnstile.Form, string) turnstile.Outcome {
	return turnstile.Refused
}

// A failed read of the documents, or of the browser's sign-ins, is the error page: the form is not
// drawn without the documents it links where it collects the data.
func TestHandleRegisterGet_AFailedReadIsTheErrorPage(t *testing.T) {
	failure := errors.New("database down")
	for name, tc := range map[string]struct {
		ceremonies registrationCeremonies
		documents  legalDocumentsInEffect
	}{
		"the documents":         {heldCeremonies{}, legalDocumentsInEffect{err: failure}},
		"the browser's session": {failingCeremonies{failure}, legalDocumentsInEffect{}},
	} {
		t.Run(name, func(t *testing.T) {
			pageRenderer := handlersmocks.NewPageRenderer(t)
			pageRenderer.On("InternalServerError", mock.Anything, mock.Anything, mock.MatchedBy(func(err error) bool {
				return errors.Is(err, failure)
			})).Return().Once()

			HandleRegisterGet(pageRenderer, tc.ceremonies, tc.documents).
				ServeHTTP(httptest.NewRecorder(), registerRequest(http.MethodGet, "?ceremony="+aCeremonyId))
		})
	}
}

// failingCeremonies fails every read of the browser's sign-ins.
type failingCeremonies struct{ err error }

func (f failingCeremonies) HeldAuthContext(*http.Request, string) (*ceremony.AuthContext, error) {
	return nil, f.err
}
