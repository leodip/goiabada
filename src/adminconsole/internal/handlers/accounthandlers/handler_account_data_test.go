package accounthandlers

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/leodip/goiabada/adminconsole/internal/apiclient"
	"github.com/leodip/goiabada/adminconsole/internal/handlers/mocks"
	"github.com/leodip/goiabada/adminconsole/internal/handlertest"
	"github.com/leodip/goiabada/adminconsole/internal/oauthclient"
	"github.com/leodip/goiabada/core/errs"
)

// The Your data page (#782 decision 6): Download my data posts to the page, whose POST passes the
// user's own export through as the administrator's download passes it, and a sign-in the Account
// API finds too old or too weak sends the browser through the console's sign-in again, with
// prompt=login and acr_values, and back to the page with a notice (decision 1).

const accountDataPath = "/account/data"

// dataSignInScope is the scope the routes hand the page for its sign-in, the account pages' own.
const dataSignInScope = "authserver:manage-account email openid profile"

// accountExportAPI answers the page's port with export or err, and records the token it was
// called with and how many times.
type accountExportAPI struct {
	export *apiclient.UserExport
	err    error

	calls      int
	sentBearer string
}

func (a *accountExportAPI) GetAccountExport(_ context.Context, accessToken string) (*apiclient.UserExport, error) {
	a.calls++
	a.sentBearer = accessToken
	return a.export, a.err
}

// signInRecorder records the sign-in the page sends the browser through, and answers with err.
// Like the real helper it redirects when it succeeds, so a handler that wrote anything of its own
// afterwards would show in the recorder.
type signInRecorder struct {
	err error

	calls        int
	client       string
	scope        string
	redirectBack string
	options      oauthclient.SignInOptions
}

func (s *signInRecorder) RedirToAuthorizeWith(w http.ResponseWriter, r *http.Request, clientIdentifier string,
	scope string, redirectBack string, options oauthclient.SignInOptions) error {

	s.calls++
	s.client, s.scope, s.redirectBack, s.options = clientIdentifier, scope, redirectBack, options
	if s.err != nil {
		return s.err
	}
	http.Redirect(w, r, "https://auth.example.test/auth/authorize?from=the-helper", http.StatusFound)
	return nil
}

// bodyCloseRecorder is an export's body that records being closed.
type bodyCloseRecorder struct {
	io.Reader
	closed bool
}

func (b *bodyCloseRecorder) Close() error {
	b.closed = true
	return nil
}

func dataPostRequest(opts ...handlertest.Option) *http.Request {
	return handlertest.Request(http.MethodPost, accountDataPath, append([]handlertest.Option{handlertest.WithAccessToken()}, opts...)...)
}

func serveDataPost(httpHelper *handlersmocks.HttpHelper, client *accountExportAPI, signIn *signInRecorder,
	req *http.Request) *httptest.ResponseRecorder {

	rec := httptest.NewRecorder()
	HandleDataPost(httpHelper, client, signIn, dataSignInScope, consoleBaseURL).ServeHTTP(rec, req)
	return rec
}

// The page draws its form, with no notice and no refusal on an ordinary visit, the menu marking it
// from the request's path.
func TestHandleDataGet_DrawsThePage(t *testing.T) {
	httpHelper := handlersmocks.NewHttpHelper(t)
	handlertest.RefuseInternalServerError(t, httpHelper)
	handlertest.ExpectRender(httpHelper, "/layouts/menu_layout.html", "/account_data.html").Once()

	HandleDataGet(httpHelper).ServeHTTP(httptest.NewRecorder(),
		handlertest.Request(http.MethodGet, accountDataPath, handlertest.WithAccessToken()))

	bind := handlertest.Bind(t, httpHelper)
	assert.Equal(t, false, bind["signedInAgain"], "no notice on an ordinary visit")
	assert.Nil(t, bind["error"])
}

// Back from the sign-in the page sent the browser through, it says so above the button: press it
// again (decision 6).
func TestHandleDataGet_BackFromTheSignInShowsTheNotice(t *testing.T) {
	httpHelper := handlersmocks.NewHttpHelper(t)
	handlertest.RefuseInternalServerError(t, httpHelper)
	handlertest.ExpectRender(httpHelper, "/layouts/menu_layout.html", "/account_data.html").Once()

	HandleDataGet(httpHelper).ServeHTTP(httptest.NewRecorder(),
		handlertest.Request(http.MethodGet, accountDataPath+"?signed_in_again=1", handlertest.WithAccessToken()))

	assert.Equal(t, true, handlertest.Bind(t, httpHelper)["signedInAgain"])
}

// The answer reaches the browser as the auth server sent it, as the administrator's download
// passes it (decision 3): the bytes still compressed, the encoding, the length and the file name
// the auth server chose, never stored by a cache, on the user's own token.
func TestHandleDataPost_PassesTheExportThroughUntouched(t *testing.T) {
	httpHelper := handlersmocks.NewHttpHelper(t)
	handlertest.RefuseInternalServerError(t, httpHelper)

	compressed := []byte{0x1f, 0x8b, 0x08, 0x00, 'c', 'o', 'm', 'p', 'r', 'e', 's', 's', 'e', 'd'}
	body := &bodyCloseRecorder{Reader: bytes.NewReader(compressed)}
	client := &accountExportAPI{export: &apiclient.UserExport{
		ContentType:        "application/json",
		ContentEncoding:    "gzip",
		ContentLength:      "14",
		ContentDisposition: `attachment; filename="user-7-2026-11-07.json"`,
		Body:               body,
	}}
	signIn := &signInRecorder{}

	rec := serveDataPost(httpHelper, client, signIn, dataPostRequest())

	assert.Equal(t, 1, client.calls)
	assert.Equal(t, handlertest.AccessToken, client.sentBearer, "the user's own token")
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, compressed, rec.Body.Bytes(), "the bytes as the auth server sent them")
	assert.Equal(t, "application/json", rec.Header().Get("Content-Type"))
	assert.Equal(t, "gzip", rec.Header().Get("Content-Encoding"))
	assert.Equal(t, "14", rec.Header().Get("Content-Length"))
	assert.Equal(t, `attachment; filename="user-7-2026-11-07.json"`, rec.Header().Get("Content-Disposition"))
	assert.Equal(t, "no-store", rec.Header().Get("Cache-Control"))
	assert.True(t, body.closed, "the export's body is closed once copied")
	assert.Zero(t, signIn.calls, "nobody is sent to sign in")
}

// dataDeadlineRecorder is a response recorder that, like a real connection, takes a write deadline.
type dataDeadlineRecorder struct {
	*httptest.ResponseRecorder
	deadlines []time.Time
}

func (d *dataDeadlineRecorder) SetWriteDeadline(deadline time.Time) error {
	d.deadlines = append(d.deadlines, deadline)
	return nil
}

// The file has five minutes to reach the browser, the administrator's download's bound.
func TestHandleDataPost_LiftsTheWriteDeadlineToFiveMinutes(t *testing.T) {
	httpHelper := handlersmocks.NewHttpHelper(t)
	handlertest.RefuseInternalServerError(t, httpHelper)
	client := &accountExportAPI{export: &apiclient.UserExport{
		ContentType: "application/json",
		Body:        io.NopCloser(bytes.NewReader([]byte(`{"formatVersion":1}`))),
	}}

	rec := &dataDeadlineRecorder{ResponseRecorder: httptest.NewRecorder()}
	before := time.Now()
	HandleDataPost(httpHelper, client, &signInRecorder{}, dataSignInScope, consoleBaseURL).ServeHTTP(rec, dataPostRequest())
	after := time.Now()

	assert.Equal(t, http.StatusOK, rec.Code)
	require.Len(t, rec.deadlines, 1)
	assert.False(t, rec.deadlines[0].Before(before.Add(5*time.Minute)) || rec.deadlines[0].After(after.Add(5*time.Minute)),
		"the deadline %v is not five minutes after the request", rec.deadlines[0])
}

// stepUpRefusal is the Account API's RFC 9470 refusal of a sign-in too old or too weak for the
// download, as the console's client parses it.
var stepUpRefusal = &apiclient.APIError{Code: "INSUFFICIENT_USER_AUTHENTICATION",
	Message:    "The download needs a sign-in within the last 300 seconds at urn:goiabada:level2_optional.",
	StatusCode: http.StatusUnauthorized}

// The step-up 401 is not a session that ended: the browser goes through the console's own sign-in
// for the account pages' scope, asking for a fresh sign-in (prompt=login) at
// urn:goiabada:level2_optional, with no max_age, and comes back to the page with its notice
// (decision 1). Nothing else is written, and the session-ended page is not where it goes.
func TestHandleDataPost_TheStepUpRefusalSendsTheBrowserToSignInAgain(t *testing.T) {
	httpHelper := handlersmocks.NewHttpHelper(t)
	handlertest.RefuseInternalServerError(t, httpHelper)
	client := &accountExportAPI{err: stepUpRefusal}
	signIn := &signInRecorder{}

	rec := serveDataPost(httpHelper, client, signIn, dataPostRequest())

	require.Equal(t, 1, signIn.calls, "one sign-in")
	assert.Equal(t, "admin-console-client", signIn.client)
	assert.Equal(t, dataSignInScope, signIn.scope)
	assert.Equal(t, oauthclient.SignInOptions{Prompt: "login", AcrValues: "urn:goiabada:level2_optional"}, signIn.options)
	assert.Equal(t, consoleBaseURL+"/account/data?signed_in_again=1", signIn.redirectBack,
		"back to the page, with its notice")

	assert.Equal(t, http.StatusFound, rec.Code)
	assert.Equal(t, "https://auth.example.test/auth/authorize?from=the-helper", rec.Header().Get("Location"),
		"the sign-in's redirect, not the session-ended page")
	assert.Empty(t, rec.Header().Get("Content-Disposition"), "no file is offered")
}

// A sign-in redirect that cannot be made, as when the handshake cannot be sealed, is the error
// page, and nothing else is written.
func TestHandleDataPost_ASignInThatCannotStartIsAnError(t *testing.T) {
	httpHelper := handlersmocks.NewHttpHelper(t)
	var answered error
	httpHelper.On("InternalServerError", mock.Anything, mock.Anything, mock.Anything).
		Run(func(args mock.Arguments) { answered = args.Error(2) }).Return().Once()
	signIn := &signInRecorder{err: errs.New("the handshake is too long")}

	rec := serveDataPost(httpHelper, &accountExportAPI{err: stepUpRefusal}, signIn, dataPostRequest())

	require.Error(t, answered)
	require.ErrorIs(t, answered, signIn.err)
	assert.Empty(t, rec.Header().Get("Location"))
}

// Five downloads an hour is the user's to wait out: the page is drawn again with the console's own
// sentence in the page's language, as the other account pages draw it (decision 6).
func TestHandleDataPost_ARateLimitIsShownOnThePage(t *testing.T) {
	httpHelper := handlersmocks.NewHttpHelper(t)
	handlertest.RefuseInternalServerError(t, httpHelper)
	handlertest.ExpectRender(httpHelper, "/layouts/menu_layout.html", "/account_data.html").Once()
	client := &accountExportAPI{err: &apiclient.APIError{Code: "TOO_MANY_REQUESTS",
		Message: "Too many requests. Please try again later.", StatusCode: http.StatusTooManyRequests}}
	signIn := &signInRecorder{}

	rec := serveDataPost(httpHelper, client, signIn, dataPostRequest(handlertest.WithLocale("pt-BR")))

	bind := handlertest.Bind(t, httpHelper)
	assert.Equal(t, "Chegaram muitas solicitações deste navegador, ou para esta conta, em pouco tempo. Aguarde alguns minutos e tente novamente.",
		bind["error"])
	assert.Equal(t, false, bind["signedInAgain"])
	assert.Empty(t, rec.Header().Get("Location"), "drawn again, not redirected")
	assert.Zero(t, signIn.calls)
}

// Any other 401 is a session that ended, as everywhere in the console: the browser goes to the
// session-ended page, not through a sign-in that asks for more.
func TestHandleDataPost_AnyOther401StillEndsTheSession(t *testing.T) {
	httpHelper := handlersmocks.NewHttpHelper(t)
	handlertest.RefuseInternalServerError(t, httpHelper)
	client := &accountExportAPI{err: &apiclient.APIError{Code: "invalid_token",
		Message: "The access token is invalid.", StatusCode: http.StatusUnauthorized}}
	signIn := &signInRecorder{}

	rec := serveDataPost(httpHelper, client, signIn, dataPostRequest())

	assert.Equal(t, http.StatusFound, rec.Code)
	assert.Equal(t, "/auth/session-ended", rec.Header().Get("Location"))
	assert.Zero(t, signIn.calls, "no step-up sign-in for an ended session")
}

// The step-up code on another status is not the step-up challenge: RFC 9470 section 3 answers it
// with 401 alone.
func TestHandleDataPost_TheStepUpCodeCountsOnlyOnA401(t *testing.T) {
	httpHelper := handlersmocks.NewHttpHelper(t)
	httpHelper.On("InternalServerError", mock.Anything, mock.Anything, mock.Anything).Return().Once()
	client := &accountExportAPI{err: &apiclient.APIError{Code: "INSUFFICIENT_USER_AUTHENTICATION",
		Message: "no", StatusCode: http.StatusForbidden}}
	signIn := &signInRecorder{}

	serveDataPost(httpHelper, client, signIn, dataPostRequest())

	assert.Zero(t, signIn.calls)
}

// A refusal the user can't act on, such as the auth server refusing the console's own client, is a
// fault for the classifier, and no file is offered.
func TestHandleDataPost_AnyOtherRefusalGoesThroughTheClassifier(t *testing.T) {
	httpHelper := handlersmocks.NewHttpHelper(t)
	var answered error
	httpHelper.On("InternalServerError", mock.Anything, mock.Anything, mock.Anything).
		Run(func(args mock.Arguments) { answered = args.Error(2) }).Return().Once()
	client := &accountExportAPI{err: &apiclient.APIError{Code: "CLIENT_NOT_ALLOWED",
		Message: "This operation is not available to this client.", StatusCode: http.StatusForbidden}}
	signIn := &signInRecorder{}

	rec := serveDataPost(httpHelper, client, signIn, dataPostRequest())

	require.Error(t, answered)
	assert.Contains(t, answered.Error(), "CLIENT_NOT_ALLOWED")
	assert.Empty(t, rec.Header().Get("Content-Disposition"), "no file is offered")
	assert.Zero(t, signIn.calls)
}
