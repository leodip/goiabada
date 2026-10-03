package accounthandlers

import (
	"bytes"
	"context"
	"errors"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/leodip/goiabada/adminconsole/internal/apiclient"
	mocks_handlers "github.com/leodip/goiabada/adminconsole/internal/handlers/mocks"
	"github.com/leodip/goiabada/adminconsole/internal/handlertest"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/customerrors"
	"github.com/leodip/goiabada/core/errs"
)

// The account picture page dropped a failed picture read and drew the account as having no
// picture, so a broken API looked exactly like an empty profile. An account with no picture is a
// 200 from the API with HasPicture false, so every error here is a real one, and it now goes
// through the classifier (#425).
type accountPictureApiClient struct {
	picture *api.ProfilePictureInfoResponse
	err     error
}

func (c *accountPictureApiClient) GetAccountProfilePicture(_ context.Context, accessToken string) (*api.ProfilePictureInfoResponse, error) {
	return c.picture, c.err
}

func TestHandleAccountPictureGet_AnswersAFailedPictureRead(t *testing.T) {
	testCases := []struct {
		name         string
		picture      *api.ProfilePictureInfoResponse
		err          error
		wantNotFound bool
		wantError    bool
		// wantUrlPrefix is what profilePictureUrl must start with; empty means it must be empty.
		wantUrlPrefix string
	}{
		{
			name:         "a 404 from the API renders the 404 page",
			err:          &apiclient.APIError{Code: "NOT_FOUND", Message: "User not found", StatusCode: http.StatusNotFound},
			wantNotFound: true,
		},
		{
			name:      "a 500 from the API renders the 500 page",
			err:       &apiclient.APIError{Code: "INTERNAL_SERVER_ERROR", Message: "the database is on fire", StatusCode: http.StatusInternalServerError},
			wantError: true,
		},
		{
			name:      "a transport error renders the 500 page",
			err:       errs.New("connection refused"),
			wantError: true,
		},
		{
			name:          "a picture renders the page with its address",
			picture:       &api.ProfilePictureInfoResponse{HasPicture: true, PictureUrl: "https://auth.example/account/picture"},
			wantUrlPrefix: "https://auth.example/account/picture?t=",
		},
		{
			name:    "no picture renders the page without one",
			picture: &api.ProfilePictureInfoResponse{HasPicture: false},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			httpHelper := mocks_handlers.NewHttpHelper(t)
			switch {
			case testCase.wantNotFound:
				httpHelper.On("NotFound", mock.Anything, mock.Anything).Return().Once()
			case testCase.wantError:
				httpHelper.On("InternalServerError", mock.Anything, mock.Anything, mock.Anything).Return().Once()
			default:
				handlertest.RefuseInternalServerError(t, httpHelper)
				handlertest.ExpectRender(httpHelper, "/layouts/menu_layout.html", "/account_picture.html").Once()
			}

			HandleAccountPictureGet(httpHelper, &accountPictureApiClient{picture: testCase.picture, err: testCase.err}).
				ServeHTTP(httptest.NewRecorder(),
					handlertest.Request(http.MethodGet, "/account/picture", handlertest.WithAccessToken()))

			httpHelper.AssertExpectations(t)
			if testCase.wantNotFound || testCase.wantError {
				httpHelper.AssertNotCalled(t, "RenderTemplate", mock.Anything, mock.Anything, mock.Anything,
					mock.Anything, mock.Anything)
				return
			}

			url, _ := handlertest.Bind(t, httpHelper)["profilePictureUrl"].(string)
			if testCase.wantUrlPrefix == "" {
				assert.Empty(t, url)
			} else {
				assert.True(t, strings.HasPrefix(url, testCase.wantUrlPrefix), "got %q", url)
			}
		})
	}
}

// The upload handlers wrote their own JSON error bodies until #279, and every row here was
// answered by a hand-rolled {"success": false, "error": <message>} the shared writers now own.
//
// Three of the rows are behaviour changes rather than refactors. The generic failure used to put
// err.Error() on the wire at 500 and log nothing, so an internal message reached the browser and no
// operator ever saw the fault; it is now JsonError's generic arm, which logs once with a stack and
// answers a request id. The missing JWT context used to answer 401, alone among the 100 sites that
// guard the same middleware invariant, and is now the 500 they all answer. And a multipart form
// that will not parse used to carry err.Error() into the modal, where it now carries the console's
// own sentence.
//
// The 400 rows are the point of the whole stage: a request the browser got wrong is answered as
// the browser's mistake. The 500 rows are what stops that from becoming "everything is a 4xx".
type pictureApiClient struct {
	response *api.ProfilePictureUploadResponse
	err      error
}

func (c *pictureApiClient) UploadAccountProfilePicture(_ context.Context, accessToken string, pictureData []byte, filename string) (*api.ProfilePictureUploadResponse, error) {
	return c.response, c.err
}

func (c *pictureApiClient) DeleteAccountProfilePicture(_ context.Context, accessToken string) error {
	return c.err
}

// multipartPicture builds a valid one-field multipart body, and returns it with its content type.
func multipartPicture(t *testing.T, fieldName string) (*bytes.Buffer, string) {
	t.Helper()
	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)
	part, err := writer.CreateFormFile(fieldName, "image.jpg")
	require.NoError(t, err)
	_, err = part.Write([]byte("not really a jpeg, but bytes are bytes here"))
	require.NoError(t, err)
	require.NoError(t, writer.Close())
	return body, writer.FormDataContentType()
}

func TestAccountProfilePicturePost_AnswersThroughTheSharedJsonWriters(t *testing.T) {
	testCases := []struct {
		name string
		// fieldName is the multipart field the request carries; the handler reads "picture".
		fieldName string
		// rawBody, when set, replaces the multipart body entirely.
		rawBody     string
		contentType string
		withJwt     bool
		apiErr      error
		// wantStatus is the status that must reach the browser; 0 means JsonError's generic 500
		// arm, with the detail going to the log.
		wantStatus int
		wantCode   string
	}{
		{
			name:        "a body that is not a multipart form",
			rawBody:     "this is not multipart",
			contentType: "multipart/form-data; boundary=nothing-matches-this",
			withJwt:     true,
			wantStatus:  http.StatusBadRequest,
			wantCode:    "invalid_request_body",
		},
		{
			name:       "a multipart form with no picture in it",
			fieldName:  "somethingElse",
			withJwt:    true,
			wantStatus: http.StatusBadRequest,
			wantCode:   "invalid_request_body",
		},
		{
			name:       "a picture the API refuses",
			fieldName:  "picture",
			withJwt:    true,
			apiErr:     &apiclient.APIError{Code: "FILE_TOO_LARGE", Message: "The picture is too large", StatusCode: http.StatusBadRequest},
			wantStatus: http.StatusBadRequest,
			wantCode:   "FILE_TOO_LARGE",
		},
		{
			name:      "no JWT info in context, which is a middleware invariant and is a 500",
			fieldName: "picture",
			withJwt:   false,
		},
		{
			name:      "a server fault behind the upload, which is logged rather than shown",
			fieldName: "picture",
			withJwt:   true,
			apiErr:    &apiclient.APIError{Code: "INTERNAL_SERVER_ERROR", Message: "the disk is full", StatusCode: http.StatusInternalServerError},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			httpHelper := mocks_handlers.NewHttpHelper(t)
			var captured error
			httpHelper.On("JsonError", mock.Anything, mock.Anything, mock.Anything).
				Run(func(args mock.Arguments) {
					captured, _ = args.Get(2).(error)
				}).Return().Once()

			body, contentType := io.Reader(strings.NewReader(testCase.rawBody)), testCase.contentType
			if testCase.rawBody == "" {
				body, contentType = multipartPicture(t, testCase.fieldName)
			}
			opts := []handlertest.Option{
				handlertest.WithBody(body),
				handlertest.WithContentType(contentType),
			}
			if testCase.withJwt {
				opts = append(opts, handlertest.WithAccessToken())
			}
			req := handlertest.Request(http.MethodPost, "/account/picture", opts...)

			handler := HandleAccountProfilePicturePost(httpHelper, &pictureApiClient{err: testCase.apiErr})
			handler.ServeHTTP(httptest.NewRecorder(), req)

			httpHelper.AssertExpectations(t)
			require.NotNil(t, captured, "the handler answered nothing")

			var detail *customerrors.ErrorDetail
			if testCase.wantStatus == 0 {
				assert.False(t, errors.As(captured, &detail),
					"expected JsonError's generic 500 arm, got a status-carrying %v", captured)
				return
			}
			require.True(t, errors.As(captured, &detail),
				"expected an *ErrorDetail carrying a status, got %v", captured)
			assert.Equal(t, testCase.wantStatus, detail.GetHttpStatusCode())
			assert.Equal(t, testCase.wantCode, detail.GetCode())
		})
	}
}

// uploadRecorder is an API client that keeps the picture it was handed.
type uploadRecorder struct {
	picture []byte
}

func (c *uploadRecorder) UploadAccountProfilePicture(_ context.Context, _ string, pictureData []byte, _ string) (*api.ProfilePictureUploadResponse, error) {
	c.picture = pictureData
	return &api.ProfilePictureUploadResponse{Success: true, PictureUrl: "https://auth.example.com/userinfo/picture/a-subject"}, nil
}

// The rest of the ports uploadRecorder is passed to, which no test here reaches.

func (*uploadRecorder) DeleteAccountProfilePicture(context.Context, string) error {
	panic("unexpected call to DeleteAccountProfilePicture")
}

// A multipart body the request-body limit cut short answers the JSON 400 an unparseable form
// already answers, the page's own modal reading it, and nothing is forwarded to the API (#426
// decision 6). The same body under a limit equal to its length is read whole and forwarded.
func TestAccountProfilePicturePost_ABodyTheLimitCut(t *testing.T) {
	form, contentType := multipartPicture(t, "picture")
	body := form.Bytes()

	serve := func(t *testing.T, limit int, httpHelper *mocks_handlers.HttpHelper, apiClient *uploadRecorder) *httptest.ResponseRecorder {
		rr := httptest.NewRecorder()
		req := handlertest.Request(http.MethodPost, "/account/picture",
			handlertest.WithContentType(contentType), handlertest.WithAccessToken())
		req.Body = http.MaxBytesReader(rr, io.NopCloser(bytes.NewReader(body)), int64(limit))

		HandleAccountProfilePicturePost(httpHelper, apiClient).ServeHTTP(rr, req)
		return rr
	}

	t.Run("at exactly the limit the picture is forwarded", func(t *testing.T) {
		apiClient := &uploadRecorder{}

		rr := serve(t, len(body), mocks_handlers.NewHttpHelper(t), apiClient)

		assert.Equal(t, http.StatusOK, rr.Code)
		assert.Equal(t, []byte("not really a jpeg, but bytes are bytes here"), apiClient.picture)
	})

	t.Run("one byte short it is the JSON 400 and nothing is forwarded", func(t *testing.T) {
		httpHelper := mocks_handlers.NewHttpHelper(t)
		httpHelper.On("JsonError", mock.Anything, mock.Anything, mock.MatchedBy(func(err error) bool {
			var detail *customerrors.ErrorDetail
			return errors.As(err, &detail) && detail.GetCode() == "invalid_request_body" &&
				detail.GetHttpStatusCode() == http.StatusBadRequest
		})).Return().Once()
		apiClient := &uploadRecorder{}

		serve(t, len(body)-1, httpHelper, apiClient)

		httpHelper.AssertExpectations(t)
		assert.Nil(t, apiClient.picture)
	})
}

// TestAccountProfilePictureDelete_AnswersThroughTheSharedJsonWriters covers the handler that did
// not take an httpHelper at all before #279, which is why its errors were hand-rolled: there was
// nothing else to answer with.
func TestAccountProfilePictureDelete_AnswersThroughTheSharedJsonWriters(t *testing.T) {
	testCases := []struct {
		name       string
		withJwt    bool
		apiErr     error
		wantStatus int
	}{
		{
			name:       "a picture that is already gone",
			withJwt:    true,
			apiErr:     &apiclient.APIError{Code: "NOT_FOUND", Message: "No picture", StatusCode: http.StatusNotFound},
			wantStatus: http.StatusNotFound,
		},
		{
			name:    "no JWT info in context",
			withJwt: false,
		},
		{
			name:    "a server fault behind the delete",
			withJwt: true,
			apiErr:  &apiclient.APIError{Code: "INTERNAL_SERVER_ERROR", Message: "the disk is full", StatusCode: http.StatusInternalServerError},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			httpHelper := mocks_handlers.NewHttpHelper(t)
			var captured error
			httpHelper.On("JsonError", mock.Anything, mock.Anything, mock.Anything).
				Run(func(args mock.Arguments) {
					captured, _ = args.Get(2).(error)
				}).Return().Once()

			var opts []handlertest.Option
			if testCase.withJwt {
				opts = append(opts, handlertest.WithAccessToken())
			}
			req := handlertest.Request(http.MethodDelete, "/account/picture", opts...)

			handler := HandleAccountProfilePictureDelete(httpHelper, &pictureApiClient{err: testCase.apiErr})
			handler.ServeHTTP(httptest.NewRecorder(), req)

			httpHelper.AssertExpectations(t)
			require.NotNil(t, captured, "the handler answered nothing")

			var detail *customerrors.ErrorDetail
			if testCase.wantStatus == 0 {
				assert.False(t, errors.As(captured, &detail),
					"expected JsonError's generic 500 arm, got a status-carrying %v", captured)
				return
			}
			require.True(t, errors.As(captured, &detail),
				"expected an *ErrorDetail carrying a status, got %v", captured)
			assert.Equal(t, testCase.wantStatus, detail.GetHttpStatusCode())
		})
	}
}
