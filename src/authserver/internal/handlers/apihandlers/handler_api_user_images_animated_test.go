package apihandlers

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"image"
	"image/color"
	"image/gif"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	datamocks "github.com/leodip/goiabada/authserver/internal/data/mocks"
	"github.com/leodip/goiabada/authserver/internal/fake"
	handlersmocks "github.com/leodip/goiabada/authserver/internal/handlers/mocks"
	"github.com/leodip/goiabada/authserver/internal/record"
)

// animatedGIF is a GIF of two frames, which every browser plays as an animation.
func animatedGIF(width, height int) []byte {
	animation := &gif.GIF{}
	for _, shade := range []uint8{0, 255} {
		frame := image.NewPaletted(image.Rect(0, 0, width, height), color.Palette{color.Gray{Y: shade}, color.White})
		animation.Image = append(animation.Image, frame)
		animation.Delay = append(animation.Delay, 10)
	}
	var buf bytes.Buffer
	_ = gif.EncodeAll(&buf, animation)
	return buf.Bytes()
}

// The three endpoints that store a client logo or a profile picture refuse an animated GIF, PNG or
// WebP, as a brand's image uploads do: a client's logo is drawn beside the sign-in form, where a
// looping animation has no pause control, and a profile picture is held to the same rule. The
// refusal is the validator's, in the request's language, and nothing is written: the strict mocks
// carry only the read that finds the client or the user.
func TestUserImageUploads_RefuseAnAnimatedImage(t *testing.T) {
	formats := map[string][]byte{
		"GIF":  animatedGIF(100, 100),
		"PNG":  assetAPNG(100, 100),
		"WebP": assetAnimatedWebP(100, 100),
	}
	endpoints := []struct {
		name  string
		serve func(t *testing.T, data []byte) *httptest.ResponseRecorder
	}{
		{"POST /api/v1/admin/clients/{id}/logo", func(t *testing.T, data []byte) *httptest.ResponseRecorder {
			database := datamocks.NewDatabase(t)
			database.On("GetClientById", mock.Anything, (*sql.Tx)(nil), int64(123)).
				Return(&record.Client{Id: 123, ClientIdentifier: "my-app"}, nil)
			req, err := createMultipartRequest("POST", "/api/v1/admin/clients/123/logo", "picture", data)
			require.NoError(t, err)
			req.SetPathValue("id", "123")
			rr := httptest.NewRecorder()
			HandleClientLogoPost(database, handlersmocks.NewAuditLogger(t), testBaseURL, testMaxUploadBytes).ServeHTTP(rr, req)
			return rr
		}},
		{"POST /api/v1/admin/users/{id}/profile-picture", func(t *testing.T, data []byte) *httptest.ResponseRecorder {
			database := datamocks.NewDatabase(t)
			database.On("GetUserById", mock.Anything, (*sql.Tx)(nil), int64(123)).
				Return(&record.User{Id: 123, Subject: fake.UUID(), Enabled: true}, nil)
			req, err := createMultipartRequest("POST", "/api/v1/admin/users/123/profile-picture", "picture", data)
			require.NoError(t, err)
			req.SetPathValue("id", "123")
			rr := httptest.NewRecorder()
			HandleUserProfilePicturePost(database, handlersmocks.NewAuditLogger(t), testBaseURL, testMaxUploadBytes).ServeHTTP(rr, req)
			return rr
		}},
		{"POST /api/v1/account/profile-picture", func(t *testing.T, data []byte) *httptest.ResponseRecorder {
			sub := fake.UUID()
			database := datamocks.NewDatabase(t)
			database.On("GetUserBySubject", mock.Anything, (*sql.Tx)(nil), sub).
				Return(&record.User{Id: 1, Subject: sub, Enabled: true}, nil)
			req, err := createMultipartRequest("POST", "/api/v1/account/profile-picture", "picture", data)
			require.NoError(t, err)
			req = setTokenContext(req, sub)
			rr := httptest.NewRecorder()
			HandleAccountProfilePicturePost(database, handlersmocks.NewAuditLogger(t), testBaseURL, testMaxUploadBytes).ServeHTTP(rr, req)
			return rr
		}},
	}

	for _, endpoint := range endpoints {
		for format, data := range formats {
			t.Run(endpoint.name+"/an animated "+format, func(t *testing.T) {
				rr := endpoint.serve(t, data)

				assert.Equal(t, http.StatusBadRequest, rr.Code)
				var response map[string]any
				require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &response))
				assert.Equal(t, "validator.image.animated", response["error_code"])
				assert.Equal(t, "Animated images are not allowed. Upload a still image.", response["error_description"])
			})
		}
	}
}
