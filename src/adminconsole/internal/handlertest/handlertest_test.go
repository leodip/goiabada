package handlertest

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/leodip/goiabada/adminconsole/internal/constants"
	mocks_handlerhelpers "github.com/leodip/goiabada/adminconsole/internal/handlerhelpers/mocks"
	"github.com/leodip/goiabada/core/errs"
	"github.com/leodip/goiabada/core/oauth"
	"github.com/leodip/goiabada/core/testutil"
)

// An option not given leaves its value off the request rather than putting an empty one there.
// That is the distinction the tables covering an unauthenticated visitor turn on, so it is pinned
// rather than assumed.
func TestRequest_AnOptionNotGivenLeavesTheValueOff(t *testing.T) {
	req := Request(http.MethodGet, "/admin/users")

	assert.Nil(t, req.Context().Value(constants.ContextKeyJwtInfo),
		"a request built without WithAccessToken must carry no JwtInfo at all")
	assert.Nil(t, req.Context().Value(constants.ContextKeySettings),
		"a request built without WithSettings must carry no settings at all")
	assert.Nil(t, req.Context().Value(chi.RouteCtxKey),
		"a request built without WithRouteParam must carry no route context at all")
	assert.Empty(t, req.Header.Get("Content-Type"))
}

func TestRequest_WithAccessTokenCarriesTheBearerTheHandlersRead(t *testing.T) {
	req := Request(http.MethodGet, "/admin/users", WithAccessToken())

	jwtInfo, ok := req.Context().Value(constants.ContextKeyJwtInfo).(oauth.JwtInfo)
	require.True(t, ok, "the context carries no oauth.JwtInfo")
	assert.Equal(t, AccessToken, jwtInfo.TokenResponse.AccessToken)
}

// Two parameters rather than one: the option accumulates, and an implementation that replaced the
// route context each time would pass with one.
func TestRequest_WithRouteParamIsReadableThroughChi(t *testing.T) {
	req := Request(http.MethodGet, "/admin/groups/3/attributes/9",
		WithRouteParam("groupId", "3"),
		WithRouteParam("attributeId", "9"))

	assert.Equal(t, "3", chi.URLParam(req, "groupId"))
	assert.Equal(t, "9", chi.URLParam(req, "attributeId"))
}

func TestRequest_WithSettingsPutsTheValueWhereTheMiddlewarePutsOne(t *testing.T) {
	settings := struct{ AppName string }{AppName: "Goiabada"}

	req := Request(http.MethodGet, "/account/profile", WithSettings(settings))

	assert.Equal(t, settings, req.Context().Value(constants.ContextKeySettings))
}

// PostFormValue rather than FormValue, because that is the accessor the handlers are held to and
// the one a form body has to satisfy (pattern 5).
func TestRequest_WithFormIsReadableThroughPostFormValue(t *testing.T) {
	req := Request(http.MethodPost, "/account/change-password",
		WithForm(url.Values{"newPassword": {"N3w!word"}}))

	assert.Equal(t, "application/x-www-form-urlencoded", req.Header.Get("Content-Type"))
	assert.Equal(t, "N3w!word", req.PostFormValue("newPassword"))
}

// A body without WithContentType declares none, which is what the AJAX endpoints receive and what
// an option that quietly defaulted the header would hide.
func TestRequest_WithBodyAloneDeclaresNoMediaType(t *testing.T) {
	req := Request(http.MethodPost, "/admin/users/7/attributes",
		WithBody(strings.NewReader(`{"attributeKey":"x"}`)))

	assert.Empty(t, req.Header.Get("Content-Type"))
	body, err := io.ReadAll(req.Body)
	require.NoError(t, err)
	assert.Equal(t, `{"attributeKey":"x"}`, string(body))
}

func TestRequest_WithContentTypeCarriesTheCallersOwnEncoding(t *testing.T) {
	req := Request(http.MethodPost, "/account/profile-picture",
		WithContentType("multipart/form-data; boundary=xyz"),
		WithBody(strings.NewReader("--xyz--")))

	assert.Equal(t, "multipart/form-data; boundary=xyz", req.Header.Get("Content-Type"))
	body, err := io.ReadAll(req.Body)
	require.NoError(t, err)
	assert.Equal(t, "--xyz--", string(body))
}

// The negative half of the case below: a handler that never faults must draw no report, or the
// expectation would fail every test that registers it.
func TestRefuseInternalServerError_SaysNothingWhenTheHandlerDoesNotFault(t *testing.T) {
	httpHelper := mocks_handlerhelpers.NewHttpHelper(t)

	report := testutil.RunGuard(func(reporter testutil.Reporter) {
		RefuseInternalServerError(reporter, httpHelper)
	})

	assert.Empty(t, report.Errors)
}

func TestRefuseInternalServerError_NamesTheErrorTheHandlerAnsweredWith(t *testing.T) {
	httpHelper := mocks_handlerhelpers.NewHttpHelper(t)

	report := testutil.RunGuard(func(reporter testutil.Reporter) {
		RefuseInternalServerError(reporter, httpHelper)
		httpHelper.InternalServerError(httptest.NewRecorder(),
			Request(http.MethodGet, "/admin/users"), errs.New("the api client is unreachable"))
	})

	require.Len(t, report.Errors, 1)
	assert.Contains(t, report.Errors[0], "the api client is unreachable",
		"the report must name the fault rather than the mocked method")
}

// Unbounded is the deliberate choice: a caller says Maybe() or Once() for itself, and this pins
// that ExpectRender adds neither on its behalf. Repeatability is testify's own record of that;
// Once() sets it to 1 and Maybe() leaves it at 0 while setting an unexported flag, so the zero
// here is read together with the call succeeding below.
func TestExpectRender_AdmitsTheNamedPageAndIsLeftUnbounded(t *testing.T) {
	httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
	call := ExpectRender(httpHelper, "/layouts/menu_layout.html", "/admin_users.html")

	assert.Equal(t, "RenderTemplate", call.Method)
	assert.Equal(t, 0, call.Repeatability, "ExpectRender must not bound the call itself")

	err := httpHelper.RenderTemplate(httptest.NewRecorder(), Request(http.MethodGet, "/admin/users"),
		"/layouts/menu_layout.html", "/admin_users.html", map[string]interface{}{})
	assert.NoError(t, err)
}

func TestBind_ReturnsTheMapTheHandlerRenderedWith(t *testing.T) {
	httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
	ExpectRender(httpHelper, mock.Anything, mock.Anything).Twice()

	req := Request(http.MethodGet, "/admin/users")
	//nolint:errcheck // the mock answers nil; the call is here to fill the log Bind reads.
	httpHelper.RenderTemplate(httptest.NewRecorder(), req, "a", "b", map[string]interface{}{"page": 1})
	//nolint:errcheck // as above.
	httpHelper.RenderTemplate(httptest.NewRecorder(), req, "a", "b", map[string]interface{}{"page": 2})

	// The last render, which is the page the visitor would have seen.
	assert.Equal(t, 2, Bind(t, httpHelper)["page"])
}

func TestBind_StopsTheTestWhenTheHandlerRenderedNothing(t *testing.T) {
	httpHelper := mocks_handlerhelpers.NewHttpHelper(t)

	report := testutil.RunGuard(func(reporter testutil.Reporter) {
		Bind(reporter, httpHelper)
	})

	assert.True(t, report.Stopped, "a bind read with nothing rendered must end the test")
	assert.Contains(t, report.Fatal, "rendered nothing")
}

// The AJAX half of the case above, and unbounded for the same reason.
func TestExpectEncodeJson_AdmitsTheCallAndIsLeftUnbounded(t *testing.T) {
	httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
	call := ExpectEncodeJson(httpHelper)

	assert.Equal(t, "EncodeJson", call.Method)
	assert.Equal(t, 0, call.Repeatability, "ExpectEncodeJson must not bound the call itself")

	httpHelper.EncodeJson(httptest.NewRecorder(), Request(http.MethodPost, "/account/sessions"),
		struct{ Success bool }{Success: true})
}

// Two things at once: the last answer is the one returned, and it arrives marshalled, so a field
// the handler left off its struct is absent from the map rather than present and false.
func TestEncoded_ReturnsTheLastAnswerAsTheBrowserReadsIt(t *testing.T) {
	httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
	ExpectEncodeJson(httpHelper).Twice()

	req := Request(http.MethodPost, "/account/sessions")
	httpHelper.EncodeJson(httptest.NewRecorder(), req, struct {
		Success          bool
		IsCurrentSession bool
	}{Success: false, IsCurrentSession: true})
	httpHelper.EncodeJson(httptest.NewRecorder(), req, struct{ Success bool }{Success: true})

	answer := Encoded(t, httpHelper)

	assert.Equal(t, true, answer["Success"])
	assert.NotContains(t, answer, "IsCurrentSession",
		"the last answer carried no such field, so the map must not either")
}

func TestEncoded_StopsTheTestWhenTheHandlerAnsweredNothing(t *testing.T) {
	httpHelper := mocks_handlerhelpers.NewHttpHelper(t)

	report := testutil.RunGuard(func(reporter testutil.Reporter) {
		Encoded(reporter, httpHelper)
	})

	assert.True(t, report.Stopped, "an answer read with nothing encoded must end the test")
	assert.Contains(t, report.Fatal, "encoded nothing")
}

// A value encoding/json cannot represent ends the test naming that, rather than returning an empty
// map a case would then assert against and pass.
func TestEncoded_StopsTheTestWhenTheAnswerDoesNotMarshal(t *testing.T) {
	httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
	ExpectEncodeJson(httpHelper).Once()

	httpHelper.EncodeJson(httptest.NewRecorder(), Request(http.MethodPost, "/account/sessions"),
		struct{ Ch chan int }{Ch: make(chan int)})

	report := testutil.RunGuard(func(reporter testutil.Reporter) {
		Encoded(reporter, httpHelper)
	})

	assert.True(t, report.Stopped, "an answer that does not marshal must end the test")
	assert.Contains(t, report.Fatal, "does not marshal")
}

// JSON null unmarshals into a map without an error and leaves it nil, so it arrives as an object
// with no keys unless the helper says otherwise. It is the one answer that reaches the map branch
// and is not a map, and a case asserting only that a field is absent would pass against a handler
// that answered nothing at all.
func TestEncoded_StopsTheTestWhenTheAnswerIsNull(t *testing.T) {
	httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
	ExpectEncodeJson(httpHelper).Once()

	httpHelper.EncodeJson(httptest.NewRecorder(), Request(http.MethodPost, "/account/sessions"), nil)

	report := testutil.RunGuard(func(reporter testutil.Reporter) {
		Encoded(reporter, httpHelper)
	})

	require.True(t, report.Stopped, "a null answer must end the test rather than read as an empty object")
	assert.Contains(t, report.Fatal, "JSON null")
}

// A handler that answers a bare array or a string is not one of these, and the failure says so
// rather than reporting a nil map the caller would index into.
func TestEncoded_StopsTheTestWhenTheAnswerIsNotAnObject(t *testing.T) {
	httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
	ExpectEncodeJson(httpHelper).Once()

	httpHelper.EncodeJson(httptest.NewRecorder(), Request(http.MethodPost, "/account/sessions"),
		[]int{1, 2, 3})

	report := testutil.RunGuard(func(reporter testutil.Reporter) {
		Encoded(reporter, httpHelper)
	})

	assert.True(t, report.Stopped, "an answer that is not an object must end the test")
	assert.Contains(t, report.Fatal, "not a JSON object")
}
