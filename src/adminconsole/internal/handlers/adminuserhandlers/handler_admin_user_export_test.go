package adminuserhandlers

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
)

// userExportApiClient answers the export the Download data button asks for, with export or err,
// and records which user's export was asked for and whether its body was closed.
type userExportApiClient struct {
	export *apiclient.UserExport
	err    error

	askedFor []int64
}

func (c *userExportApiClient) GetUserExport(_ context.Context, accessToken string, userId int64) (*apiclient.UserExport, error) {
	if accessToken != handlertest.AccessToken {
		panic("the download must forward the signed-in administrator's token")
	}
	c.askedFor = append(c.askedFor, userId)
	return c.export, c.err
}

// closeRecorder is an export's body that records being closed.
type closeRecorder struct {
	io.Reader
	closed bool
}

func (b *closeRecorder) Close() error {
	b.closed = true
	return nil
}

// The answer reaches the browser as the auth server sent it (#781 decisions 5 and 7): the bytes,
// still compressed, with the encoding that lets the browser unpack them, the file name the auth
// server chose, and never stored by a cache.
func TestHandleExportPost_PassesTheExportThroughUntouched(t *testing.T) {
	httpHelper := handlersmocks.NewHttpHelper(t)
	handlertest.RefuseInternalServerError(t, httpHelper)

	compressed := []byte{0x1f, 0x8b, 0x08, 0x00, 'c', 'o', 'm', 'p', 'r', 'e', 's', 's', 'e', 'd'}
	body := &closeRecorder{Reader: bytes.NewReader(compressed)}
	apiClient := &userExportApiClient{export: &apiclient.UserExport{
		ContentType:        "application/json",
		ContentEncoding:    "gzip",
		ContentLength:      "14",
		ContentDisposition: `attachment; filename="user-7-2026-11-05.json"`,
		Body:               body,
	}}

	rec := httptest.NewRecorder()
	req := handlertest.Request(http.MethodPost, "/admin/users/7/export",
		handlertest.WithAccessToken(), handlertest.WithPathValue("userId", "7"))
	HandleExportPost(httpHelper, apiClient).ServeHTTP(rec, req)

	assert.Equal(t, []int64{7}, apiClient.askedFor)
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, compressed, rec.Body.Bytes(), "the bytes as the auth server sent them")
	assert.Equal(t, "application/json", rec.Header().Get("Content-Type"))
	assert.Equal(t, "gzip", rec.Header().Get("Content-Encoding"))
	assert.Equal(t, "14", rec.Header().Get("Content-Length"))
	assert.Equal(t, `attachment; filename="user-7-2026-11-05.json"`, rec.Header().Get("Content-Disposition"))
	assert.Equal(t, "no-store", rec.Header().Get("Cache-Control"))
	assert.True(t, body.closed, "the export's body is closed once copied")
}

// deadlineRecorder is a response recorder that, like a real connection, takes a write deadline.
type deadlineRecorder struct {
	*httptest.ResponseRecorder
	deadlines []time.Time
}

func (d *deadlineRecorder) SetWriteDeadline(deadline time.Time) error {
	d.deadlines = append(d.deadlines, deadline)
	return nil
}

// The console's listener gives this answer five minutes to reach the browser, in place of its 60
// seconds, as the auth server's does (decision 5).
func TestHandleExportPost_LiftsTheWriteDeadlineToFiveMinutes(t *testing.T) {
	httpHelper := handlersmocks.NewHttpHelper(t)
	handlertest.RefuseInternalServerError(t, httpHelper)
	apiClient := &userExportApiClient{export: &apiclient.UserExport{
		ContentType: "application/json",
		Body:        io.NopCloser(bytes.NewReader([]byte(`{"formatVersion":1}`))),
	}}

	rec := &deadlineRecorder{ResponseRecorder: httptest.NewRecorder()}
	req := handlertest.Request(http.MethodPost, "/admin/users/7/export",
		handlertest.WithAccessToken(), handlertest.WithPathValue("userId", "7"))
	before := time.Now()
	HandleExportPost(httpHelper, apiClient).ServeHTTP(rec, req)
	after := time.Now()

	assert.Equal(t, http.StatusOK, rec.Code)
	require.Len(t, rec.deadlines, 1)
	assert.False(t, rec.deadlines[0].Before(before.Add(5*time.Minute)) || rec.deadlines[0].After(after.Add(5*time.Minute)),
		"the deadline %v is not five minutes after the request", rec.deadlines[0])
}

// A plain answer is passed on plain: no encoding is claimed for bytes that carry none, and no
// length for an answer that named none.
func TestHandleExportPost_ClaimsNoEncodingTheAuthServerDidNot(t *testing.T) {
	httpHelper := handlersmocks.NewHttpHelper(t)
	handlertest.RefuseInternalServerError(t, httpHelper)

	apiClient := &userExportApiClient{export: &apiclient.UserExport{
		ContentType:        "application/json",
		ContentDisposition: `attachment; filename="user-7-2026-11-05.json"`,
		Body:               io.NopCloser(bytes.NewReader([]byte(`{"formatVersion":1}`))),
	}}

	rec := httptest.NewRecorder()
	req := handlertest.Request(http.MethodPost, "/admin/users/7/export",
		handlertest.WithAccessToken(), handlertest.WithPathValue("userId", "7"))
	HandleExportPost(httpHelper, apiClient).ServeHTTP(rec, req)

	assert.Equal(t, `{"formatVersion":1}`, rec.Body.String())
	assert.NotContains(t, rec.Header(), "Content-Encoding")
	assert.NotContains(t, rec.Header(), "Content-Length")
	assert.Equal(t, "no-store", rec.Header().Get("Cache-Control"))
}

// A failed export goes through the console's API error classifier like any other call (decision
// 7): an ended session to the session-ended page, a user who no longer exists to the not-found
// page, anything else to the error page.
func TestHandleExportPost_AFailedExportGoesThroughTheClassifier(t *testing.T) {
	t.Run("an ended session", func(t *testing.T) {
		httpHelper := handlersmocks.NewHttpHelper(t)
		handlertest.RefuseInternalServerError(t, httpHelper)
		apiClient := &userExportApiClient{err: &apiclient.APIError{Code: "invalid_token", Message: "ended", StatusCode: http.StatusUnauthorized}}

		rec := httptest.NewRecorder()
		req := handlertest.Request(http.MethodPost, "/admin/users/7/export",
			handlertest.WithAccessToken(), handlertest.WithPathValue("userId", "7"))
		HandleExportPost(httpHelper, apiClient).ServeHTTP(rec, req)

		assert.Equal(t, http.StatusFound, rec.Code)
		assert.Equal(t, "/auth/session-ended", rec.Header().Get("Location"))
		assert.Empty(t, rec.Header().Get("Content-Disposition"), "no file is offered")
	})

	t.Run("a user who no longer exists", func(t *testing.T) {
		httpHelper := handlersmocks.NewHttpHelper(t)
		handlertest.RefuseInternalServerError(t, httpHelper)
		httpHelper.On("NotFound", mock.Anything, mock.Anything).Return().Once()
		apiClient := &userExportApiClient{err: &apiclient.APIError{Code: "NOT_FOUND", Message: "User not found", StatusCode: http.StatusNotFound}}

		rec := httptest.NewRecorder()
		req := handlertest.Request(http.MethodPost, "/admin/users/7/export",
			handlertest.WithAccessToken(), handlertest.WithPathValue("userId", "7"))
		HandleExportPost(httpHelper, apiClient).ServeHTTP(rec, req)

		assert.Empty(t, rec.Header().Get("Content-Disposition"), "no file is offered")
	})

	t.Run("anything else", func(t *testing.T) {
		httpHelper := handlersmocks.NewHttpHelper(t)
		var answered error
		httpHelper.On("InternalServerError", mock.Anything, mock.Anything, mock.Anything).
			Run(func(args mock.Arguments) { answered = args.Error(2) }).Return().Once()
		apiClient := &userExportApiClient{err: &apiclient.APIError{Code: "INSUFFICIENT_SCOPE", Message: "no", StatusCode: http.StatusForbidden}}

		rec := httptest.NewRecorder()
		req := handlertest.Request(http.MethodPost, "/admin/users/7/export",
			handlertest.WithAccessToken(), handlertest.WithPathValue("userId", "7"))
		HandleExportPost(httpHelper, apiClient).ServeHTTP(rec, req)

		require.Error(t, answered)
		assert.Contains(t, answered.Error(), "INSUFFICIENT_SCOPE")
		assert.Empty(t, rec.Header().Get("Content-Disposition"), "no file is offered")
	})
}

// An address that is not a user id is the not-found page, and no export is asked for.
func TestHandleExportPost_AnAddressThatIsNotAnIdIsNotFound(t *testing.T) {
	httpHelper := handlersmocks.NewHttpHelper(t)
	handlertest.RefuseInternalServerError(t, httpHelper)
	httpHelper.On("NotFound", mock.Anything, mock.Anything).Return().Once()
	apiClient := &userExportApiClient{}

	req := handlertest.Request(http.MethodPost, "/admin/users/abc/export",
		handlertest.WithAccessToken(), handlertest.WithPathValue("userId", "abc"))
	HandleExportPost(httpHelper, apiClient).ServeHTTP(httptest.NewRecorder(), req)

	assert.Empty(t, apiClient.askedFor)
}
