package handlers

import (
	"context"
	"database/sql"
	"errors"
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
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/leodip/goiabada/authserver/internal/authorizerequest"
	"github.com/leodip/goiabada/authserver/internal/ceremony"
	"github.com/leodip/goiabada/authserver/internal/data/mocks"
	"github.com/leodip/goiabada/authserver/internal/handlers/mocks"
	"github.com/leodip/goiabada/authserver/internal/protocolvalidation"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/core/hashutil"
	"github.com/leodip/goiabada/core/i18n"
)

// These cases are the handlers' half of #437 decision 21 (#246): a POST to the authorization
// endpoint is parked and answered with a 303 to a GET, and the GET consumes the handle and runs the
// ceremony from what was parked. authorizerequest's own tests own the handle and the claim; the
// data tier owns the row. What is here is what only a handler does: which requests are refused
// before a row is written, what is parked, what the redirect carries, and that the GET reads the
// parked values as it reads a query.

// authorizePostEndpoint is HandleAuthorizePost over strict doubles: a call nothing registered
// fails the test, which is how a refusal that wrote no row, or read nothing past its gate, is shown.
type authorizePostEndpoint struct {
	pageRenderer *handlersmocks.PageRenderer
	validator    *handlersmocks.AuthorizeValidator
	database     *datamocks.Database
	handler      http.HandlerFunc
}

func newAuthorizePostEndpoint(t *testing.T) *authorizePostEndpoint {
	t.Helper()
	e := &authorizePostEndpoint{
		pageRenderer: handlersmocks.NewPageRenderer(t),
		validator:    handlersmocks.NewAuthorizeValidator(t),
		database:     datamocks.NewDatabase(t),
	}
	e.handler = HandleAuthorizePost(e.pageRenderer, e.validator, e.database, testBaseURL)
	return e
}

func (e *authorizePostEndpoint) post(query, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/auth/authorize?"+query, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	e.handler.ServeHTTP(rr, req)
	return rr
}

// expectsPage registers the one refusal page the request must be answered with.
func (e *authorizePostEndpoint) expectsPage(message string, status int) {
	e.pageRenderer.On("RenderTemplate", mock.Anything, mock.Anything, "/layouts/no_menu_layout.html", "/auth_error.html",
		mock.MatchedBy(func(data map[string]interface{}) bool {
			return data["error"] == message && data["_httpStatus"] == status
		})).Return(nil).Once()
}

// passesTheGate lets a request past the client and redirect URI check.
func (e *authorizePostEndpoint) passesTheGate() {
	e.validator.On("ValidateClientAndRedirectURI", mock.Anything, mock.Anything).Return(nil).Once()
}

// parks registers the insert and returns what it was handed.
func (e *authorizePostEndpoint) parks() **record.AuthorizeRequest {
	var stored *record.AuthorizeRequest
	e.database.On("CreateAuthorizeRequest", mock.Anything, (*sql.Tx)(nil), mock.Anything).
		Run(func(args mock.Arguments) { stored = args.Get(2).(*record.AuthorizeRequest) }).Return(nil).Once()
	return &stored
}

func TestHandleAuthorizePost_ParksTheRequestAndAnswersWithA303ToAGet(t *testing.T) {
	e := newAuthorizePostEndpoint(t)
	e.validator.On("ValidateClientAndRedirectURI", mock.Anything, &protocolvalidation.ValidateClientAndRedirectURIInput{
		ClientId: "test-client", RedirectURI: "https://example.com", ResponseType: "code",
	}).Return(nil).Once()
	stored := e.parks()

	before := time.Now().UTC()
	rr := e.post("state=from-query", validAuthorizeQuery+"&state=from-body&nonce=n")

	require.Equal(t, http.StatusSeeOther, rr.Code)
	location, err := url.Parse(rr.Header().Get("Location"))
	require.NoError(t, err)
	assert.Equal(t, testBaseURL+"/auth/authorize", location.Scheme+"://"+location.Host+location.Path)
	require.Len(t, location.Query(), 1, "the redirect carries the handle and nothing else")
	handle := location.Query().Get(authorizerequest.HandleParameter)
	assert.True(t, authorizerequest.IsWellFormedHandle(handle))

	require.NotNil(t, *stored)
	assert.Equal(t, hashutil.HashString(handle), (*stored).HandleHash, "the row is found by the digest of what the redirect carries")
	assert.False(t, (*stored).ExpiresAt.Before(before.Add(authorizerequest.Lifetime)))

	parked, err := url.ParseQuery((*stored).RequestForm)
	require.NoError(t, err)
	assert.Equal(t, "test-client", parked.Get("client_id"))
	assert.Equal(t, "https://example.com", parked.Get("redirect_uri"))
	assert.Equal(t, "code", parked.Get("response_type"))
	assert.Equal(t, "openid", parked.Get("scope"))
	assert.Equal(t, "n", parked.Get("nonce"))
	assert.Equal(t, []string{"from-body", "from-query"}, parked["state"],
		"the query and the body are one source, and every copy is parked so the GET refuses a conflict as the POST would have")

	// A cross-site POST carries no session cookie, so an answer that set one would put a new
	// cookie over the one the browser holds (#246). The handler has no ceremony store to touch.
	assert.Empty(t, rr.Header().Values("Set-Cookie"))
	assert.Equal(t, "no-store", rr.Header().Get("Cache-Control"), "the Location carries a live handle")
}

// What is parked is what the endpoint reads. Everything else is dropped rather than stored: a
// login_hint is an address for whoever reads the table, and a parked request can never name another
// (#246).
func TestHandleAuthorizePost_ParksOnlyWhatTheEndpointReads(t *testing.T) {
	e := newAuthorizePostEndpoint(t)
	e.passesTheGate()
	stored := e.parks()

	body := url.Values{
		"client_id":                      {"test-client"},
		"redirect_uri":                   {"https://example.com"},
		"response_type":                  {"code"},
		"id_token_hint":                  {"a.b.c"},
		"request":                        {"a-request-object"},
		"request_uri":                    {"https://example.com/ro"},
		"login_hint":                     {"someone@example.com"},
		"junk":                           {strings.Repeat("j", 1000)},
		authorizerequest.HandleParameter: {"another-parked-request"},
	}
	rr := e.post("", body.Encode())
	require.Equal(t, http.StatusSeeOther, rr.Code)

	parked, err := url.ParseQuery((*stored).RequestForm)
	require.NoError(t, err)
	assert.Equal(t, "a.b.c", parked.Get("id_token_hint"), "the hint is validated when the GET runs the ceremony")
	assert.Equal(t, "a-request-object", parked.Get("request"), "request and request_uri are read, to be refused")
	assert.Equal(t, "https://example.com/ro", parked.Get("request_uri"))
	assert.False(t, parked.Has("login_hint"))
	assert.False(t, parked.Has("junk"))
	assert.False(t, parked.Has(authorizerequest.HandleParameter))
	assert.NotContains(t, (*stored).RequestForm, "someone")
}

// A request the GET would refuse on the page is refused here, before a row is written, so a POST
// that could never begin a ceremony costs no row. The database double registered no insert, so an
// insert fails the case; each case varies one thing from a request that is parked, and names the
// gate that refuses it.
func TestHandleAuthorizePost_ARequestTheGetWouldRefuseOnThePageWritesNoRow(t *testing.T) {
	ctx := httptest.NewRequest(http.MethodGet, "/", nil).Context()
	malformed := i18n.T(ctx, "auth_error.malformed_request.message")
	unsupportedMode := i18n.T(ctx, "auth_error.unsupported_response_mode.message")
	localized := i18n.NewLocalizedError(i18n.ErrCodeAuthorizeClientNotFound, nil)

	t.Run("a body that does not parse", func(t *testing.T) {
		e := newAuthorizePostEndpoint(t)
		e.expectsPage(malformed, http.StatusBadRequest)
		rr := e.post("", validAuthorizeQuery+"&state=%G1")
		assert.Empty(t, rr.Header().Get("Location"))
	})

	t.Run("a delivery parameter repeated with differing values", func(t *testing.T) {
		e := newAuthorizePostEndpoint(t)
		e.expectsPage(repeatMessage("redirect_uri"), http.StatusBadRequest)
		rr := e.post("", validAuthorizeQuery+"&redirect_uri="+url.QueryEscape("https://evil.example"))
		assert.Empty(t, rr.Header().Get("Location"))
	})

	// Identical copies used to be parked as one value (#228).
	t.Run("a delivery parameter repeated with identical values", func(t *testing.T) {
		e := newAuthorizePostEndpoint(t)
		e.expectsPage(repeatMessage("redirect_uri"), http.StatusBadRequest)
		rr := e.post("", validAuthorizeQuery+"&redirect_uri="+url.QueryEscape("https://example.com"))
		assert.Empty(t, rr.Header().Get("Location"))
	})

	t.Run("a client or redirect URI the validator refuses is answered on the page, 200", func(t *testing.T) {
		e := newAuthorizePostEndpoint(t)
		e.validator.On("ValidateClientAndRedirectURI", mock.Anything, mock.Anything).Return(localized).Once()
		e.expectsPage(localized.Localize(ctx), http.StatusOK)
		rr := e.post("", validAuthorizeQuery)
		assert.Empty(t, rr.Header().Get("Location"))
	})

	t.Run("a fault inside the validator is a 500", func(t *testing.T) {
		e := newAuthorizePostEndpoint(t)
		fault := errors.New("database down")
		e.validator.On("ValidateClientAndRedirectURI", mock.Anything, mock.Anything).Return(fault).Once()
		e.pageRenderer.On("InternalServerError", mock.Anything, mock.Anything, fault).Once()
		rr := e.post("", validAuthorizeQuery)
		assert.Empty(t, rr.Header().Get("Location"))
	})

	t.Run("a response_mode this server cannot encode", func(t *testing.T) {
		e := newAuthorizePostEndpoint(t)
		e.passesTheGate()
		e.expectsPage(unsupportedMode, http.StatusBadRequest)
		rr := e.post("", validAuthorizeQuery+"&response_mode=web_message")
		assert.Empty(t, rr.Header().Get("Location"))
	})
}

func TestHandleAuthorizePost_AFailedInsertIsA500AndNoRedirect(t *testing.T) {
	e := newAuthorizePostEndpoint(t)
	e.passesTheGate()
	e.database.On("CreateAuthorizeRequest", mock.Anything, mock.Anything, mock.Anything).Return(errors.New("disk full")).Once()
	e.pageRenderer.On("InternalServerError", mock.Anything, mock.Anything, mock.Anything).Once()

	rr := e.post("", validAuthorizeQuery)

	assert.Empty(t, rr.Header().Get("Location"), "a link to a row that was never written would refuse the visitor for nothing")
	assert.Empty(t, rr.Header().Values("Set-Cookie"))
}

// The refusal page honours ui_locales from the POST body, as the GET does: the global locale
// middleware sees only the query string, so the handler refines the request's localizer itself.
func TestHandleAuthorizePost_TheRefusalPageHonoursUILocalesFromTheBody(t *testing.T) {
	portuguese := i18n.WithLocale(context.Background(), true, "pt-BR")
	english := i18n.T(context.Background(), "auth_error.unsupported_response_mode.message")
	inPortuguese := i18n.T(portuguese, "auth_error.unsupported_response_mode.message")
	require.NotEqual(t, english, inPortuguese, "the catalogs must differ or the case proves nothing")

	e := newAuthorizePostEndpoint(t)
	e.passesTheGate()
	e.expectsPage(inPortuguese, http.StatusBadRequest)

	e.post("", validAuthorizeQuery+"&response_mode=web_message&ui_locales=pt-BR")
}

func TestParkedAuthorizeForm(t *testing.T) {
	t.Run("keeps every copy of each listed parameter, in order", func(t *testing.T) {
		params := url.Values{"state": {"a", "b"}, "scope": {"openid"}, "prompt": {"login", "consent"}}
		assert.Equal(t, params, parkedAuthorizeForm(params))
	})

	t.Run("drops what nothing reads, and request_handle", func(t *testing.T) {
		form := parkedAuthorizeForm(url.Values{
			"client_id": {"c"}, "login_hint": {"x"}, "junk": {"y"}, authorizerequest.HandleParameter: {"z"},
		})
		assert.Equal(t, url.Values{"client_id": {"c"}}, form)
	})

	t.Run("keeps a listed parameter that was sent empty", func(t *testing.T) {
		assert.Equal(t, url.Values{"state": {""}}, parkedAuthorizeForm(url.Values{"state": {""}}),
			"an empty state is a value the ceremony reads, and a difference the GET must see")
	})

	t.Run("owns its slices", func(t *testing.T) {
		params := url.Values{"state": {"a"}}
		form := parkedAuthorizeForm(params)
		params["state"][0] = "changed"
		assert.Equal(t, "a", form.Get("state"))
	})
}

// The list of what is parked is held to the handler's reads, so a parameter read later cannot be
// left out and silently vanish between a POST and its GET. It is the parameters the endpoint reads
// (TestAuthorizeRequestParameters_EveryReadIsListed owns that list) and the two it reads only to
// refuse, and not the handle.
func TestAuthorizeParkedParameters_CoverEveryRead(t *testing.T) {
	isParams := func(e ast.Expr) bool {
		ident, ok := e.(*ast.Ident)
		return ok && ident.Name == "params"
	}
	reads := formReads(t, "handler_authorize.go", isParams)

	parsed, err := parser.ParseFile(token.NewFileSet(), "handler_authorize.go", nil, 0)
	require.NoError(t, err)
	var presence []string
	ast.Inspect(parsed, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != "Has" || !isParams(sel.X) || len(call.Args) != 1 {
			return true
		}
		if lit, ok := call.Args[0].(*ast.BasicLit); ok && lit.Kind == token.STRING {
			name, err := strconv.Unquote(lit.Value)
			require.NoError(t, err)
			presence = append(presence, name)
		}
		return true
	})
	require.ElementsMatch(t, []string{"request", "request_uri"}, presence,
		"the two parameters the handler reads only for their presence")

	for _, name := range append(slices.Clone(reads), presence...) {
		assert.Contains(t, authorizeParkedParameters, name, "handler_authorize.go reads %q", name)
	}
	assert.ElementsMatch(t, append(slices.Clone(authorizeRequestParameters), "request", "request_uri"), authorizeParkedParameters)
	assert.NotContains(t, authorizeParkedParameters, authorizerequest.HandleParameter)
}

// consumes registers the transaction, the read and the claim of the handle every case below holds.
func (e *authorizeEndpoint) consumes(handle string, form url.Values, claimed bool) {
	tx := &sql.Tx{}
	datamocks.ExpectRunInTransaction(e.database, tx)
	e.database.On("GetAuthorizeRequestByHandleHash", mock.Anything, tx, hashutil.HashString(handle), mock.Anything).
		Return(&record.AuthorizeRequest{Id: 41, HandleHash: hashutil.HashString(handle), RequestForm: form.Encode(),
			ExpiresAt: time.Now().UTC().Add(time.Minute)}, nil).Once()
	e.database.On("ClaimAuthorizeRequest", mock.Anything, tx, int64(41)).Return(claimed, nil).Once()
}

// parkedHandle is a well-formed handle: 32 bytes of zeros in the URL-safe alphabet.
var parkedHandle = strings.Repeat("A", 43)

func handleQuery(handle string) string {
	return url.Values{authorizerequest.HandleParameter: {handle}}.Encode()
}

// unusableHandlePage is the refusal page's text for a handle that cannot be used, computed as the
// handler computes it, so a catalog reword moves the page and the test together.
func unusableHandlePage() string {
	return i18n.T(httptest.NewRequest(http.MethodGet, "/", nil).Context(), "auth_error.request_handle_unusable.message")
}

// The GET a POST is answered with runs the ceremony from the parked request exactly as it would
// from the same parameters in a query string. The two are driven side by side over the real
// validator and compared: what is saved is the same, whatever the source.
func TestHandleAuthorizeGet_ARequestHandleRunsTheCeremonyFromTheParkedRequest(t *testing.T) {
	parked := url.Values{
		"client_id":     {"test-client"},
		"redirect_uri":  {"https://example.com"},
		"response_type": {"code"},
		"scope":         {"openid"},
		"state":         {"a state with spaces & symbols;=%"},
		"nonce":         {"n"},
		"acr_values":    {"urn:goiabada:level1"},
		"ui_locales":    {"pt-BR"},
	}

	var direct, replayed ceremony.AuthContext
	capture := func(into *ceremony.AuthContext) func(*testing.T, *authorizeEndpoint) {
		return func(t *testing.T, e *authorizeEndpoint) {
			e.ceremonyStore.On("SaveAuthContext", mock.Anything, mock.Anything, mock.MatchedBy(func(ac *ceremony.AuthContext) bool {
				*into = *ac
				return true
			})).Return(nil).Once()
		}
	}

	e := newBoundedAuthorizeEndpoint(t)
	e.stubLoggedOutBrowser()
	capture(&direct)(t, e)
	rr := e.get(t, parked.Encode())
	assertStepLocation(t, rr.Header().Get("Location"), "/auth/level1")

	e = newBoundedAuthorizeEndpoint(t)
	e.stubLoggedOutBrowser()
	capture(&replayed)(t, e)
	e.consumes(parkedHandle, parked, true)
	rr = e.get(t, handleQuery(parkedHandle))
	assertStepLocation(t, rr.Header().Get("Location"), "/auth/level1")
	e.assertExpectations(t)

	require.NotEmpty(t, direct.CeremonyId)
	require.NotEmpty(t, replayed.CeremonyId)
	assert.NotEqual(t, direct.CeremonyId, replayed.CeremonyId, "each ceremony is its own")
	direct.CeremonyId, replayed.CeremonyId = "", ""
	assert.Equal(t, direct, replayed)
	assert.Equal(t, parked.Get("state"), replayed.State, "the parked value comes back byte for byte")
	assert.Equal(t, []string{"pt-BR"}, replayed.UILocales)
}

// A handle beside any other authorization parameter is refused and never merged: which of the two
// a parameter came from would decide what the ceremony did. Each case varies one thing from the
// request that runs (the handle alone), and the strict database registered no read, so a refusal
// that consumed the handle first fails.
func TestHandleAuthorizeGet_ARequestHandleBesideAnotherParameterIsRefused(t *testing.T) {
	for _, name := range authorizeParkedParameters {
		t.Run(name, func(t *testing.T) {
			e := newAuthorizeEndpoint(t)
			e.expectsPage(unusableHandlePage())

			rr := e.get(t, handleQuery(parkedHandle)+"&"+url.Values{name: {"x"}}.Encode())

			assert.Empty(t, rr.Header().Get("Location"))
			e.assertExpectations(t)
		})
	}

	t.Run("even sent empty", func(t *testing.T) {
		e := newAuthorizeEndpoint(t)
		e.expectsPage(unusableHandlePage())
		e.get(t, handleQuery(parkedHandle)+"&state=")
		e.assertExpectations(t)
	})

	// A leniency on purpose: only authorization parameters count, so a proxy or a campaign tag
	// appended to a link the server issued does not break it. The server ignores parameters it does
	// not recognise everywhere else, and a link that cannot be followed for a stray one would be the
	// only place it did not (decision 21, #246).
	t.Run("a parameter the endpoint does not read is ignored", func(t *testing.T) {
		e := newBoundedAuthorizeEndpoint(t)
		e.stubLoggedOutBrowser()
		e.ceremonyStore.On("SaveAuthContext", mock.Anything, mock.Anything, mock.Anything).Return(nil).Once()
		e.consumes(parkedHandle, url.Values{
			"client_id": {"test-client"}, "redirect_uri": {"https://example.com"}, "response_type": {"code"}, "scope": {"openid"},
		}, true)

		rr := e.get(t, handleQuery(parkedHandle)+"&utm_source=newsletter")

		assertStepLocation(t, rr.Header().Get("Location"), "/auth/level1")
		e.assertExpectations(t)
	})
}

// A handle that is unknown, expired, already consumed or malformed gets the one answer, so the page
// says nothing about which it was. Unknown and expired both reach the handler as a read that found
// nothing; consumed is the loser of a claim; malformed never reaches the database.
func TestHandleAuthorizeGet_AnUnusableRequestHandleIsOneAnswer(t *testing.T) {
	t.Run("a read that finds nothing", func(t *testing.T) {
		e := newAuthorizeEndpoint(t)
		datamocks.ExpectRunInTransaction(e.database, &sql.Tx{})
		e.database.On("GetAuthorizeRequestByHandleHash", mock.Anything, mock.Anything, mock.Anything, mock.Anything).
			Return(nil, nil).Once()
		e.expectsPage(unusableHandlePage())

		rr := e.get(t, handleQuery(parkedHandle))

		assert.Empty(t, rr.Header().Get("Location"))
		e.assertExpectations(t)
	})

	t.Run("a claim another request won", func(t *testing.T) {
		e := newAuthorizeEndpoint(t)
		e.consumes(parkedHandle, url.Values{"client_id": {"test-client"}}, false)
		e.expectsPage(unusableHandlePage())

		rr := e.get(t, handleQuery(parkedHandle))

		assert.Empty(t, rr.Header().Get("Location"))
		e.assertExpectations(t)
	})

	t.Run("a handle that was never issued reads nothing", func(t *testing.T) {
		e := newAuthorizeEndpoint(t)
		e.expectsPage(unusableHandlePage())

		rr := e.get(t, handleQuery("not-a-handle"))

		assert.Empty(t, rr.Header().Get("Location"))
		e.assertExpectations(t)
	})

	t.Run("an empty handle", func(t *testing.T) {
		e := newAuthorizeEndpoint(t)
		e.expectsPage(unusableHandlePage())
		e.get(t, handleQuery(""))
		e.assertExpectations(t)
	})

	t.Run("two different handles name no single request", func(t *testing.T) {
		e := newAuthorizeEndpoint(t)
		e.expectsPage(unusableHandlePage())
		e.get(t, handleQuery(parkedHandle)+"&"+handleQuery(strings.Repeat("B", 43)))
		e.assertExpectations(t)
	})

	// Identical copies used to be taken as one handle (#228). The strict database registered no
	// claim, so a case that consumed the handle would fail.
	t.Run("two identical handles are refused, consuming nothing", func(t *testing.T) {
		e := newAuthorizeEndpoint(t)
		e.expectsPage(unusableHandlePage())

		rr := e.get(t, handleQuery(parkedHandle)+"&"+handleQuery(parkedHandle))

		assert.Empty(t, rr.Header().Get("Location"))
		e.assertExpectations(t)
	})
}

func TestHandleAuthorizeGet_AFaultConsumingTheRequestHandleIsA500NotARefusal(t *testing.T) {
	e := newAuthorizeEndpoint(t)
	datamocks.ExpectRunInTransaction(e.database, &sql.Tx{})
	fault := errors.New("connection reset")
	e.database.On("GetAuthorizeRequestByHandleHash", mock.Anything, mock.Anything, mock.Anything, mock.Anything).
		Return(nil, fault).Once()
	e.pageRenderer.On("InternalServerError", mock.Anything, mock.Anything, mock.Anything).Once()

	rr := e.get(t, handleQuery(parkedHandle))

	assert.Empty(t, rr.Header().Get("Location"))
	e.assertExpectations(t)
}
