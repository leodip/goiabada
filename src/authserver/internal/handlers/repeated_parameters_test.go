package handlers

import (
	"go/ast"
	"go/parser"
	"go/token"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/leodip/goiabada/authserver/internal/ceremony"
	mocks_data "github.com/leodip/goiabada/authserver/internal/data/mocks"
	mocks_handlers "github.com/leodip/goiabada/authserver/internal/handlers/mocks"
	"github.com/leodip/goiabada/authserver/internal/models"
	"github.com/leodip/goiabada/authserver/internal/protocolvalidation"
	"github.com/leodip/goiabada/authserver/internal/reqctx"
	"github.com/leodip/goiabada/core/customerrors"
	"github.com/leodip/goiabada/core/i18n"
)

// These cases are the handlers' half of #437 decision 18: each shows an endpoint consulting
// protocolvalidation.ConflictingParameter on the path it owns, once to refuse and once to let
// through. What counts as a conflict is TestConflictingParameter's table, which owns every case.

// authorizeEndpoint is HandleAuthorizeGet over strict doubles: a call nothing registered fails the
// test, which is what shows a refusal read nothing past the point it refused at.
type authorizeEndpoint struct {
	pageRenderer       *mocks_handlers.PageRenderer
	ceremonyStore      *mocks_handlers.CeremonyStore
	userSessionManager *mocks_handlers.UserSessionManager
	database           *mocks_data.Database
	validator          *mocks_handlers.AuthorizeValidator
	handler            http.HandlerFunc
}

func newAuthorizeEndpoint(t *testing.T) *authorizeEndpoint {
	t.Helper()
	e := &authorizeEndpoint{
		pageRenderer:       mocks_handlers.NewPageRenderer(t),
		ceremonyStore:      mocks_handlers.NewCeremonyStore(t),
		userSessionManager: mocks_handlers.NewUserSessionManager(t),
		database:           mocks_data.NewDatabase(t),
		validator:          mocks_handlers.NewAuthorizeValidator(t),
	}
	e.handler = HandleAuthorizeGet(e.pageRenderer, e.ceremonyStore, e.userSessionManager, e.database, nil,
		e.validator, mocks_handlers.NewAuditLogger(t), mocks_handlers.NewPermissionChecker(t),
		mocks_handlers.NewTokenParser(t), testBaseURL)
	return e
}

// expectsPage registers the one refusal page the request must be answered with.
func (e *authorizeEndpoint) expectsPage(message string) {
	e.pageRenderer.On("RenderTemplate", mock.Anything, mock.Anything, "/layouts/no_menu_layout.html", "/auth_error.html",
		mock.MatchedBy(func(data map[string]interface{}) bool {
			return data["error"] == message && data["_httpStatus"] == http.StatusBadRequest
		})).Return(nil).Once()
}

// passesDeliveryChecks lets a request past the client and redirect URI checks to the validations
// that answer by redirect.
func (e *authorizeEndpoint) passesDeliveryChecks() {
	e.validator.On("ValidateClientAndRedirectURI", mock.Anything, mock.Anything).Return(nil)
	e.database.On("GetClientByClientIdentifier", mock.Anything, mock.Anything, "test-client").Return(
		&models.Client{Id: 1, ClientIdentifier: "test-client", DefaultAcrLevel: models.AcrLevel1}, nil)
	stubRegisteredRedirectURI(e.database, "https://example.com")
}

func (e *authorizeEndpoint) get(t *testing.T, query string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest("GET", "/authorize?"+query, nil)
	req = req.WithContext(reqctx.WithSettings(req.Context(), &models.Settings{}))
	rr := httptest.NewRecorder()
	e.handler.ServeHTTP(rr, req)
	return rr
}

func (e *authorizeEndpoint) post(t *testing.T, query, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest("POST", "/authorize?"+query, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req = req.WithContext(reqctx.WithSettings(req.Context(), &models.Settings{}))
	rr := httptest.NewRecorder()
	e.handler.ServeHTTP(rr, req)
	return rr
}

func (e *authorizeEndpoint) assertExpectations(t *testing.T) {
	e.pageRenderer.AssertExpectations(t)
	e.ceremonyStore.AssertExpectations(t)
	e.database.AssertExpectations(t)
	e.validator.AssertExpectations(t)
}

const validAuthorizeQuery = "client_id=test-client&redirect_uri=https%3A%2F%2Fexample.com&response_type=code&scope=openid"

// conflictMessage is the refusal page's text for name, computed as the handler computes it, so a
// catalog reword moves the page and the test together.
func conflictMessage(name string) string {
	return i18n.T(httptest.NewRequest("GET", "/", nil).Context(), "auth_error.conflicting_parameter.message",
		map[string]any{"parameter": name})
}

func TestHandleAuthorizeGet_AMalformedRequestIsAnsweredOnThePage(t *testing.T) {
	malformed := i18n.T(httptest.NewRequest("GET", "/", nil).Context(), "auth_error.malformed_request.message")

	// Before #228 the parse failure was ignored and the field holding the bad escape was dropped,
	// so the request went on as if the client had never sent it.
	t.Run("a bad escape in the query", func(t *testing.T) {
		e := newAuthorizeEndpoint(t)
		e.expectsPage(malformed)
		rr := e.get(t, validAuthorizeQuery+"&nonce=%zz")
		assert.Empty(t, rr.Header().Get("Location"))
		e.assertExpectations(t)
	})

	t.Run("a bad escape in a POST body", func(t *testing.T) {
		e := newAuthorizeEndpoint(t)
		e.expectsPage(malformed)
		rr := e.post(t, "", validAuthorizeQuery+"&state=%G1")
		assert.Empty(t, rr.Header().Get("Location"))
		e.assertExpectations(t)
	})
}

// A repeated client_id, redirect_uri, response_type or response_mode leaves no single answer to
// where a response goes or how it is encoded, so the page answers before the client is even looked
// up: the strict validator and database registered nothing, so reaching either fails the case.
func TestHandleAuthorizeGet_ADifferingDeliveryParameterIsAnsweredOnThePage(t *testing.T) {
	repeats := map[string]string{
		"client_id":     "client_id=other-client",
		"redirect_uri":  "redirect_uri=https%3A%2F%2Fattacker.example",
		"response_type": "response_type=token",
		"response_mode": "response_mode=fragment",
	}
	for _, name := range authorizeDeliveryParameters {
		t.Run(name, func(t *testing.T) {
			query := validAuthorizeQuery
			if name == "response_mode" {
				query += "&response_mode=query"
			}
			e := newAuthorizeEndpoint(t)
			e.expectsPage(conflictMessage(name))
			rr := e.get(t, query+"&"+repeats[name])
			assert.Empty(t, rr.Header().Get("Location"))
			e.assertExpectations(t)
		})
	}

	// One copy in the body and one in the query are the same violation: r.Form merges them.
	t.Run("one copy in the body and one in the query", func(t *testing.T) {
		e := newAuthorizeEndpoint(t)
		e.expectsPage(conflictMessage("client_id"))
		e.post(t, "client_id=other-client", validAuthorizeQuery)
		e.assertExpectations(t)
	})

	// Decision 18's leniency: identical copies leave one value, and the request goes on with it.
	t.Run("identical copies proceed with the one value", func(t *testing.T) {
		e := newAuthorizeEndpoint(t)
		e.validator.On("ValidateClientAndRedirectURI", mock.Anything,
			mock.MatchedBy(func(in *protocolvalidation.ValidateClientAndRedirectURIInput) bool {
				return in.ClientId == "test-client" && in.RedirectURI == "https://example.com"
			})).Return(i18n.NewLocalizedError(i18n.ErrCodeAuthorizeClientNotFound, nil))
		e.pageRenderer.On("RenderTemplate", mock.Anything, mock.Anything, "/layouts/no_menu_layout.html", "/auth_error.html",
			mock.Anything).Return(nil)
		e.get(t, validAuthorizeQuery+"&client_id=test-client&redirect_uri=https%3A%2F%2Fexample.com")
		e.assertExpectations(t)
	})
}

// Any other parameter repeated with differing values is invalid_request, answered through the
// deferral path as every redirecting refusal is (#213). The conflict is checked first, so the
// strict validator, which registers no ValidateUnsupportedRequestParameters, fails a case that
// reaches it.
func TestHandleAuthorizeGet_ADifferingRequestParameterIsInvalidRequest(t *testing.T) {
	// clientAnswer follows the redirect a session holder is answered with.
	clientAnswer := func(t *testing.T, query string) url.Values {
		t.Helper()
		e := newAuthorizeEndpoint(t)
		e.passesDeliveryChecks()
		stubAuthenticatedBrowser(e.database, e.userSessionManager)
		e.ceremonyStore.On("ClearAuthContext", mock.Anything, mock.Anything).Return(nil).Once()

		rr := e.get(t, query)

		require.Equal(t, http.StatusFound, rr.Code)
		location, err := url.Parse(rr.Header().Get("Location"))
		require.NoError(t, err)
		require.Equal(t, "example.com", location.Host)
		e.assertExpectations(t)
		return location.Query()
	}

	t.Run("answered at once to a session holder, naming the parameter", func(t *testing.T) {
		answer := clientAnswer(t, validAuthorizeQuery+"&state=s1&nonce=n1&nonce=n2")
		assert.Equal(t, "invalid_request", answer.Get("error"))
		assert.Equal(t, "The 'nonce' parameter was included more than once with different values.", answer.Get("error_description"))
		assert.Equal(t, []string{"s1"}, answer["state"])
	})

	// RFC 6749 4.1.2's "exact value received" has no answer when two arrived, so none is sent.
	t.Run("a differing state is left out of the answer", func(t *testing.T) {
		answer := clientAnswer(t, validAuthorizeQuery+"&state=s1&state=s2")
		assert.Equal(t, "invalid_request", answer.Get("error"))
		assert.Contains(t, answer.Get("error_description"), "'state'")
		assert.NotContains(t, answer, "state")
	})

	t.Run("identical state copies are echoed once", func(t *testing.T) {
		answer := clientAnswer(t, validAuthorizeQuery+"&state=s1&state=s1&nonce=n1&nonce=n2")
		assert.Equal(t, []string{"s1"}, answer["state"])
	})

	t.Run("parked behind a login for a browser with no session", func(t *testing.T) {
		e := newAuthorizeEndpoint(t)
		e.passesDeliveryChecks()
		e.database.On("GetUserSessionBySessionIdentifier", mock.Anything, mock.Anything, mock.Anything).Return(nil, nil)
		e.userSessionManager.On("HasValidUserSession", mock.Anything, mock.AnythingOfType("int"), mock.AnythingOfType("int"), mock.Anything).Return(false)
		e.ceremonyStore.On("SaveAuthContext", mock.Anything, mock.Anything, mock.MatchedBy(func(ac *ceremony.AuthContext) bool {
			return ac.DeferredErrorCode == "invalid_request" &&
				strings.Contains(ac.DeferredErrorDescription, "'state'") &&
				ac.State == ""
		})).Return(nil).Once()

		rr := e.get(t, validAuthorizeQuery+"&state=s1&state=s2")

		assert.Equal(t, testBaseURL+"/auth/level1", rr.Header().Get("Location"))
		e.assertExpectations(t)
	})

	// OIDC Core 3.1.2.3 forbids interacting with a request whose prompt carries none. A copy asking
	// for it is enough: the refusal is answered at once, with no session read and no login page.
	// Reading the first copy alone would have taken prompt=login and parked this behind a login.
	t.Run("a copy of prompt asking for none is answered at once", func(t *testing.T) {
		e := newAuthorizeEndpoint(t)
		e.passesDeliveryChecks()
		e.ceremonyStore.On("ClearAuthContext", mock.Anything, mock.Anything).Return(nil).Once()

		rr := e.get(t, validAuthorizeQuery+"&prompt=login&prompt=none")

		require.Equal(t, http.StatusFound, rr.Code)
		location, err := url.Parse(rr.Header().Get("Location"))
		require.NoError(t, err)
		assert.Equal(t, "example.com", location.Host)
		assert.Equal(t, "The 'prompt' parameter was included more than once with different values.",
			location.Query().Get("error_description"))
		e.assertExpectations(t)
	})
}

func TestHandleTokenPost_ADifferingParameterIsInvalidRequest(t *testing.T) {
	refused := func(name string) func(error) bool {
		return func(err error) bool {
			detail, ok := err.(*customerrors.ErrorDetail)
			return ok && detail.GetCode() == "invalid_request" &&
				detail.GetHttpStatusCode() == http.StatusBadRequest &&
				detail.GetDescription() == "The '"+name+"' parameter was included more than once with different values."
		}
	}

	// The strict validator registered nothing, so reaching it fails the case: a repeated grant_type
	// or credential is refused before either is read.
	for _, tc := range []struct{ name, form string }{
		{"grant_type", "grant_type=client_credentials&grant_type=password&client_id=c&client_secret=s"},
		{"client_secret", "grant_type=client_credentials&client_id=c&client_secret=s&client_secret=t"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			endpoint := newTokenEndpoint(t)
			endpoint.jsonWriter.On("JsonError", mock.Anything, mock.Anything, mock.MatchedBy(refused(tc.name))).Return().Once()
			endpoint.post(t, tc.form)
			endpoint.assertExpectations(t)
		})
	}

	// Decision 18's leniency, and the body is the whole of what is read: a copy in the query is not
	// one of the request's parameters here.
	for _, tc := range []struct{ name, query string }{
		{"identical copies proceed", ""},
		{"a copy in the query is not counted", "?client_id=other"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			endpoint := newTokenEndpoint(t)
			endpoint.validator.On("ValidateTokenRequest", mock.Anything, mock.Anything,
				mock.MatchedBy(func(in *protocolvalidation.ValidateTokenRequestInput) bool {
					return in.ClientId == "c" && in.ClientSecret == "s"
				})).Return(nil, customerrors.NewErrorDetail("invalid_client", "stop")).Once()
			endpoint.jsonWriter.On("JsonError", mock.Anything, mock.Anything, mock.Anything).Return().Once()

			req := httptest.NewRequest("POST", "/token"+tc.query,
				strings.NewReader("grant_type=client_credentials&client_id=c&client_id=c&client_secret=s&client_secret=s"))
			req = withSettings(req, endpoint.settings)
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			endpoint.handler.ServeHTTP(httptest.NewRecorder(), req)

			endpoint.assertExpectations(t)
		})
	}
}

// formReads answers every string literal the file reads a parameter by: a Get call on a receiver
// isReceiver accepts, or an index into one.
func formReads(t *testing.T, file string, isReceiver func(ast.Expr) bool) []string {
	t.Helper()
	parsed, err := parser.ParseFile(token.NewFileSet(), file, nil, 0)
	require.NoError(t, err)

	var reads []string
	literal := func(e ast.Expr) {
		if lit, ok := e.(*ast.BasicLit); ok && lit.Kind == token.STRING {
			value, err := strconv.Unquote(lit.Value)
			require.NoError(t, err)
			reads = append(reads, value)
		}
	}
	ast.Inspect(parsed, func(n ast.Node) bool {
		switch n := n.(type) {
		case *ast.CallExpr:
			if sel, ok := n.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "Get" && isReceiver(sel.X) && len(n.Args) == 1 {
				literal(n.Args[0])
			}
		case *ast.IndexExpr:
			if isReceiver(n.X) {
				literal(n.Index)
			}
		}
		return true
	})
	require.NotEmpty(t, reads, "the walk found no parameter read in %v, so it proves nothing", file)
	return reads
}

// A parameter read that is not listed is a parameter whose repeats are never checked, which is the
// defect #228 closes coming back one read at a time.
func TestAuthorizeRequestParameters_EveryReadIsListed(t *testing.T) {
	reads := formReads(t, "handler_authorize.go", func(e ast.Expr) bool {
		ident, ok := e.(*ast.Ident)
		return ok && ident.Name == "params"
	})
	for _, name := range reads {
		assert.Contains(t, authorizeRequestParameters, name, "handler_authorize.go reads %q", name)
	}
	for _, name := range authorizeDeliveryParameters {
		assert.Contains(t, authorizeRequestParameters, name)
	}
	for _, name := range authorizeRequestParameters {
		assert.True(t, slices.Contains(reads, name), "%q is listed but nothing reads it", name)
	}
}

func TestTokenRequestParameters_EveryReadIsListed(t *testing.T) {
	reads := formReads(t, "handler_token.go", func(e ast.Expr) bool {
		sel, ok := e.(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != "PostForm" {
			return false
		}
		ident, ok := sel.X.(*ast.Ident)
		return ok && ident.Name == "r"
	})
	assert.ElementsMatch(t, tokenRequestParameters, slices.Compact(slices.Sorted(slices.Values(reads))))
}
