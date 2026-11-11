package adminsettingshandlers

import (
	"bytes"
	"context"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/leodip/goiabada/adminconsole/internal/handlers/mocks"
	"github.com/leodip/goiabada/adminconsole/internal/handlertest"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/oauth"
)

// The brand editor's uploads (#813 decision 1): a file picked at a slot's field is sent to the
// console's upload route of its kind, which hands it to the admin API as a brand asset of that kind and
// answers the stored asset as JSON, or the refusal, for the editor to show at the field.

// brandAssetAPI is the auth server as an upload sees it: it records what it was sent, and answers the
// asset, or err when it is set.
type brandAssetAPI struct {
	err error

	kind     string
	data     []byte
	filename string
}

func (a *brandAssetAPI) UploadBrandAsset(_ context.Context, _ string, kind string, data []byte, filename string) (*api.BrandAssetResponse, error) {
	a.kind, a.data, a.filename = kind, data, filename
	if a.err != nil {
		return nil, a.err
	}
	return &api.BrandAssetResponse{Id: 41, Kind: kind, Url: "https://auth.example.test/brand-assets/41?v=ab",
		ContentType: "image/webp", Width: 1600, Height: 900}, nil
}

// uploadRequest is the editor's upload: the file in the multipart field field, as filename.
func uploadRequest(t *testing.T, kind, field, filename string, data []byte) *http.Request {
	t.Helper()
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	part, err := writer.CreateFormFile(field, filename)
	require.NoError(t, err)
	_, err = part.Write(data)
	require.NoError(t, err)
	require.NoError(t, writer.Close())
	return handlertest.Request(http.MethodPost, "/admin/settings/branding/assets/"+kind, handlertest.WithAccessToken(),
		handlertest.WithBody(&body), handlertest.WithContentType(writer.FormDataContentType()))
}

// jsonErrorOf is the refusal a handler answered through JSONError.
func jsonErrorOf(t *testing.T, httpHelper *handlersmocks.HttpHelper) *oauth.ErrorDetail {
	t.Helper()
	for _, call := range httpHelper.Calls {
		if call.Method == "JSONError" {
			var detail *oauth.ErrorDetail
			require.ErrorAs(t, call.Arguments.Error(2), &detail, "the answer is a refusal")
			return detail
		}
	}
	t.Fatal("the handler answered no refusal")
	return nil
}

// Each kind's route sends the file to the admin API as an asset of that kind, as it came, and answers
// the stored asset for the editor to draw and name in the slot.
func TestHandleBrandAssetPost_UploadsTheFileAsAnAssetOfItsKind(t *testing.T) {
	for _, kind := range []string{"logo", "favicon", "background", "font"} {
		t.Run(kind, func(t *testing.T) {
			httpHelper := handlersmocks.NewHttpHelper(t)
			handlertest.ExpectEncodeJSON(httpHelper).Once()
			apiClient := &brandAssetAPI{}

			HandleBrandAssetPost(httpHelper, apiClient, kind).ServeHTTP(httptest.NewRecorder(),
				uploadRequest(t, kind, "file", "beach.webp", []byte("the-file-bytes")))

			assert.Equal(t, kind, apiClient.kind)
			assert.Equal(t, []byte("the-file-bytes"), apiClient.data)
			assert.Equal(t, "beach.webp", apiClient.filename)
			assert.Equal(t, map[string]any{"brandAsset": map[string]any{
				"id": float64(41), "kind": kind, "url": "https://auth.example.test/brand-assets/41?v=ab",
				"contentType": "image/webp", "width": float64(1600), "height": float64(900),
			}}, handlertest.Encoded(t, httpHelper))
		})
	}
}

// A file the admin API refuses, for its type, its size, its pixels or its animation, is answered with
// the API's code and sentence, for the editor to show at the field.
func TestHandleBrandAssetPost_AnswersTheAPIsRefusal(t *testing.T) {
	httpHelper := handlersmocks.NewHttpHelper(t)
	httpHelper.On("JSONError", mock.Anything, mock.Anything, mock.Anything).Return().Once()
	apiClient := &brandAssetAPI{err: refusal("validator.image.animated", "Animated images are not allowed. Upload a still image.")}

	HandleBrandAssetPost(httpHelper, apiClient, "logo").ServeHTTP(httptest.NewRecorder(),
		uploadRequest(t, "logo", "file", "spinner.png", []byte("an-animated-png")))

	refused := jsonErrorOf(t, httpHelper)
	assert.Equal(t, "validator.image.animated", refused.Code())
	assert.Equal(t, "Animated images are not allowed. Upload a still image.", refused.Description())
	assert.Equal(t, http.StatusBadRequest, refused.HTTPStatus())
}

// A file larger than the console's request-body table lets through never reaches the admin API: it is
// refused as the API refuses one over the kind's limit, naming the limit (#813 decision 3).
func TestHandleBrandAssetPost_AFileOverTheBodyLimitIsRefusedWithItsKindsLimit(t *testing.T) {
	for _, tc := range []struct {
		kind, code, description string
	}{
		{"logo", "validator.image.too_large", "The image can be at most 1048576 bytes."},
		{"favicon", "validator.image.too_large", "The image can be at most 1048576 bytes."},
		{"background", "validator.image.too_large", "The image can be at most 2097152 bytes."},
		{"font", "validator.font.too_large", "The font can be at most 2097152 bytes."},
	} {
		t.Run(tc.kind, func(t *testing.T) {
			httpHelper := handlersmocks.NewHttpHelper(t)
			httpHelper.On("JSONError", mock.Anything, mock.Anything, mock.Anything).Return().Once()
			apiClient := &brandAssetAPI{}
			w := httptest.NewRecorder()
			r := uploadRequest(t, tc.kind, "file", "big.bin", bytes.Repeat([]byte("x"), 4096))
			// The table's bound, as httpmw.BodyLimit sets it, here smaller than the file.
			r.Body = http.MaxBytesReader(w, r.Body, 1024)

			HandleBrandAssetPost(httpHelper, apiClient, tc.kind).ServeHTTP(w, r)

			refused := jsonErrorOf(t, httpHelper)
			assert.Equal(t, tc.code, refused.Code())
			assert.Equal(t, tc.description, refused.Description())
			assert.Equal(t, http.StatusBadRequest, refused.HTTPStatus())
			assert.Empty(t, apiClient.kind, "nothing reached the admin API")
		})
	}
}

// An upload without the file in its field is a malformed request, refused before the admin API.
func TestHandleBrandAssetPost_AnUploadWithoutTheFileIsRefused(t *testing.T) {
	httpHelper := handlersmocks.NewHttpHelper(t)
	httpHelper.On("JSONError", mock.Anything, mock.Anything, mock.Anything).Return().Once()
	apiClient := &brandAssetAPI{}

	HandleBrandAssetPost(httpHelper, apiClient, "logo").ServeHTTP(httptest.NewRecorder(),
		uploadRequest(t, "logo", "picture", "logo.png", []byte("the-file-bytes")))

	assert.Equal(t, http.StatusBadRequest, jsonErrorOf(t, httpHelper).HTTPStatus())
	assert.Empty(t, apiClient.kind, "nothing reached the admin API")
}
