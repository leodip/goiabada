package imageupload

import (
	"bytes"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// multipartRequest is a POST carrying data as the file in field.
func multipartRequest(t *testing.T, field string, data []byte) *http.Request {
	t.Helper()
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	part, err := writer.CreateFormFile(field, "upload.png")
	require.NoError(t, err)
	_, err = part.Write(data)
	require.NoError(t, err)
	require.NoError(t, writer.Close())

	req := httptest.NewRequest(http.MethodPost, "/upload", &body)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	return req
}

// TestRead owns Read's two sentinels and its bound: the image size plus multipartOverhead, over
// the whole body, so a file of exactly the configured size still reads.
func TestRead(t *testing.T) {
	const maxSize = 1000
	fits := bytes.Repeat([]byte{0xAB}, maxSize)

	t.Run("a file of exactly the configured size reads whole", func(t *testing.T) {
		data, err := Read(httptest.NewRecorder(), multipartRequest(t, "picture", fits), "picture", maxSize)

		require.NoError(t, err)
		assert.Equal(t, fits, data)
	})

	t.Run("the field named by the caller is the one read", func(t *testing.T) {
		data, err := Read(httptest.NewRecorder(), multipartRequest(t, "logo", fits), "logo", maxSize)

		require.NoError(t, err)
		assert.Equal(t, fits, data)
	})

	t.Run("a body past the bound is too large", func(t *testing.T) {
		tooLarge := bytes.Repeat([]byte{0xAB}, maxSize+multipartOverhead+1)

		data, err := Read(httptest.NewRecorder(), multipartRequest(t, "picture", tooLarge), "picture", maxSize)

		assert.ErrorIs(t, err, ErrUploadTooLarge)
		assert.Nil(t, data)
	})

	t.Run("a body that is not a multipart form answers as too large, as it always has", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/upload", strings.NewReader(`{"picture":"x"}`))
		req.Header.Set("Content-Type", "application/json")

		data, err := Read(httptest.NewRecorder(), req, "picture", maxSize)

		assert.ErrorIs(t, err, ErrUploadTooLarge)
		assert.Nil(t, data)
	})

	t.Run("a form without the field has no upload", func(t *testing.T) {
		data, err := Read(httptest.NewRecorder(), multipartRequest(t, "other", fits), "picture", maxSize)

		assert.ErrorIs(t, err, ErrNoUpload)
		assert.Nil(t, data)
	})
}
