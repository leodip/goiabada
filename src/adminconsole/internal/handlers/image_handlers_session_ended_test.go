package handlers_test

import (
	"bytes"
	"context"
	"encoding/json"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/leodip/goiabada/adminconsole/internal/apiclient"
	"github.com/leodip/goiabada/adminconsole/internal/handlerhelpers"
	"github.com/leodip/goiabada/adminconsole/internal/handlers"
	"github.com/leodip/goiabada/adminconsole/internal/handlers/accounthandlers"
	"github.com/leodip/goiabada/adminconsole/internal/handlers/adminclienthandlers"
	"github.com/leodip/goiabada/adminconsole/internal/handlers/adminuserhandlers"
	"github.com/leodip/goiabada/adminconsole/internal/handlertest"
	adminmiddleware "github.com/leodip/goiabada/adminconsole/internal/middleware"
	web "github.com/leodip/goiabada/adminconsole/web"
	"github.com/leodip/goiabada/core/api"
)

// refusingImageAPI answers every call the three image pages make with the admin API's 401, which
// is what RequireValidSession answers once the administrator's session has ended.
type refusingImageAPI struct{}

func sessionRefusal() error {
	return &apiclient.APIError{Code: "invalid_token", Message: "Session has been terminated", StatusCode: http.StatusUnauthorized}
}

func (refusingImageAPI) UploadAccountProfilePicture(context.Context, string, []byte, string) (*apiclient.ProfilePictureUploadResponse, error) {
	return nil, sessionRefusal()
}

func (refusingImageAPI) DeleteAccountProfilePicture(context.Context, string) error {
	return sessionRefusal()
}

func (refusingImageAPI) UploadUserProfilePicture(context.Context, string, int64, []byte, string) (*apiclient.ProfilePictureUploadResponse, error) {
	return nil, sessionRefusal()
}

func (refusingImageAPI) DeleteUserProfilePicture(context.Context, string, int64) error {
	return sessionRefusal()
}

func (refusingImageAPI) UploadClientLogo(context.Context, string, int64, []byte, string) (*apiclient.ClientLogoUploadResponse, error) {
	return nil, sessionRefusal()
}

func (refusingImageAPI) DeleteClientLogo(context.Context, string, int64) error {
	return sessionRefusal()
}

func (refusingImageAPI) GetClientById(context.Context, string, int64) (*api.ClientResponse, error) {
	return nil, sessionRefusal()
}

func (refusingImageAPI) GetClientLogo(context.Context, string, int64) (*apiclient.ClientLogoInfo, error) {
	return nil, sessionRefusal()
}

// pictureForm is a one-file multipart body under the field all three upload handlers read.
func pictureForm(t *testing.T) []handlertest.Option {
	t.Helper()
	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)
	part, err := writer.CreateFormFile("picture", "image.jpg")
	require.NoError(t, err)
	_, err = part.Write([]byte("bytes the API never looks at here"))
	require.NoError(t, err)
	require.NoError(t, writer.Close())
	return []handlertest.Option{handlertest.WithBody(body), handlertest.WithContentType(writer.FormDataContentType())}
}

// The six image handlers are the ones that answer through HandleAPIErrorJson to image-upload.js,
// which follows the session-ended code rather than reading the status. This is the Go half of that
// contract at each of them, through the production JSON writer, so what is asserted is the wire: a
// 403 whose body carries the code (#427 decisions 17 and 18; plan review round 2, finding 1).
func TestImageHandlers_AnAdminAPI401IsAnsweredAsTheSessionEnded(t *testing.T) {
	type build func(httpHelper handlers.HttpHelper) http.HandlerFunc

	testCases := []struct {
		name       string
		handler    build
		method     string
		upload     bool
		routeParam [2]string
	}{
		{
			name: "HandleAccountProfilePicturePost",
			handler: func(h handlers.HttpHelper) http.HandlerFunc {
				return accounthandlers.HandleAccountProfilePicturePost(h, refusingImageAPI{})
			},
			method: http.MethodPost,
			upload: true,
		},
		{
			name: "HandleAccountProfilePictureDelete",
			handler: func(h handlers.HttpHelper) http.HandlerFunc {
				return accounthandlers.HandleAccountProfilePictureDelete(h, refusingImageAPI{})
			},
			method: http.MethodDelete,
		},
		{
			name: "HandleAdminUserProfilePicturePost",
			handler: func(h handlers.HttpHelper) http.HandlerFunc {
				return adminuserhandlers.HandleAdminUserProfilePicturePost(h, refusingImageAPI{})
			},
			method:     http.MethodPost,
			upload:     true,
			routeParam: [2]string{"userId", "7"},
		},
		{
			name: "HandleAdminUserProfilePictureDelete",
			handler: func(h handlers.HttpHelper) http.HandlerFunc {
				return adminuserhandlers.HandleAdminUserProfilePictureDelete(h, refusingImageAPI{})
			},
			method:     http.MethodDelete,
			routeParam: [2]string{"userId", "7"},
		},
		{
			name: "HandleAdminClientLogoPost",
			handler: func(h handlers.HttpHelper) http.HandlerFunc {
				return adminclienthandlers.HandleAdminClientLogoPost(h, refusingImageAPI{})
			},
			method:     http.MethodPost,
			upload:     true,
			routeParam: [2]string{"clientId", "3"},
		},
		{
			name: "HandleAdminClientLogoDelete",
			handler: func(h handlers.HttpHelper) http.HandlerFunc {
				return adminclienthandlers.HandleAdminClientLogoDelete(h, refusingImageAPI{})
			},
			method:     http.MethodDelete,
			routeParam: [2]string{"clientId", "3"},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			opts := []handlertest.Option{handlertest.WithAccessToken()}
			if testCase.upload {
				opts = append(opts, pictureForm(t)...)
			}
			if testCase.routeParam[0] != "" {
				opts = append(opts, handlertest.WithRouteParam(testCase.routeParam[0], testCase.routeParam[1]))
			}

			w := httptest.NewRecorder()
			httpHelper := handlerhelpers.NewHttpHelper(web.TemplateFS(), adminmiddleware.SettingsReader{})
			testCase.handler(httpHelper).ServeHTTP(w, handlertest.Request(testCase.method, "/image", opts...))

			assert.Equal(t, http.StatusForbidden, w.Code)
			var envelope map[string]string
			require.NoError(t, json.Unmarshal(w.Body.Bytes(), &envelope), "the body is the JSON envelope: %s", w.Body.String())
			assert.Equal(t, "session_ended", envelope["error"], "the code image-upload.js follows")
			assert.Equal(t, "Your sign-in has ended. Sign in again.", envelope["error_description"])
		})
	}
}
