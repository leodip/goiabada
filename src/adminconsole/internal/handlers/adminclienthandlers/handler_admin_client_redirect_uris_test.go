package adminclienthandlers

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/go-chi/chi/v5"
	"github.com/gorilla/securecookie"
	"github.com/gorilla/sessions"
	"github.com/leodip/goiabada/adminconsole/internal/apiclient"
	"github.com/leodip/goiabada/adminconsole/internal/handlers"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/handlerhelpers"
	"github.com/leodip/goiabada/core/oauth"
)

// stubApiClient embeds apiclient.ApiClient so its hundred-odd other methods come for free
// and any of them that a test does not stub panics on a nil interface, which is the right
// outcome for a call the test did not expect. There is no generated mock: adminconsole has
// no .mockery.yaml.
type stubApiClient struct {
	apiclient.ApiClient
	updateErr error
	client    *api.ClientResponse
	settings  *api.SettingsGeneralResponse
}

func (s *stubApiClient) UpdateClientRedirectURIs(accessToken string, clientId int64,
	request *api.UpdateClientRedirectURIsRequest) (*api.ClientResponse, error) {
	return nil, s.updateErr
}

func (s *stubApiClient) GetClientById(accessToken string, clientId int64) (*api.ClientResponse, error) {
	return s.client, nil
}

func (s *stubApiClient) GetSettingsGeneral(accessToken string) (*api.SettingsGeneralResponse, error) {
	return s.settings, nil
}

// stubHttpHelper captures the bind instead of rendering it. The template is proved separately,
// in rendertest, from a bind the test hands it; that case cannot see whether this handler built
// the bind correctly, which is what these cases are for.
type stubHttpHelper struct {
	handlers.HttpHelper
	bind map[string]interface{}
	err  error
}

func (s *stubHttpHelper) RenderTemplate(w http.ResponseWriter, r *http.Request, layoutName string,
	templateName string, data map[string]interface{}) error {
	s.bind = data
	return nil
}

func (s *stubHttpHelper) InternalServerError(w http.ResponseWriter, r *http.Request, err error) {
	s.err = err
	w.WriteHeader(http.StatusInternalServerError)
}

// The auth server refuses a redirect URI with a 400 whose description names the offending
// value. The administrator has to be able to read that sentence: it is the only thing that
// says which of their URIs was rejected and why, and the page's own new URL() check accepts
// values the server now refuses, so this is a first-try path rather than an edge case (#122).
//
// The rows for the other statuses are what keeps the forwarding narrow: a genuine server
// fault must stay a generic 500 with its detail in the log, not be reported to the
// administrator as their own mistake.
func TestHandleAdminClientRedirectURIsPost_APIErrorReachesTheBrowser(t *testing.T) {

	const refusal = "Redirect URI must be an absolute URI (a scheme is required, a fragment " +
		"is not permitted, percent-escapes must be well formed, and an http or https URI must " +
		"name a host): https:///evil.example/cb"

	const generic = "An unexpected server error has occurred"

	testCases := []struct {
		name            string
		apiErr          error
		wantStatus      int
		wantError       string
		wantDescription string
	}{
		{
			name:            "a 400 is forwarded with its status and description",
			apiErr:          &apiclient.APIError{Code: "VALIDATION_ERROR", Message: refusal, StatusCode: http.StatusBadRequest},
			wantStatus:      http.StatusBadRequest,
			wantError:       "VALIDATION_ERROR",
			wantDescription: refusal,
		},
		{
			name:            "a 500 from the API stays generic",
			apiErr:          &apiclient.APIError{Code: "SERVER_ERROR", Message: "the database is on fire", StatusCode: http.StatusInternalServerError},
			wantStatus:      http.StatusInternalServerError,
			wantError:       "server_error",
			wantDescription: generic,
		},
		{
			name:            "a 403 from the API stays generic",
			apiErr:          &apiclient.APIError{Code: "FORBIDDEN", Message: "insufficient permissions", StatusCode: http.StatusForbidden},
			wantStatus:      http.StatusInternalServerError,
			wantError:       "server_error",
			wantDescription: generic,
		},
		{
			name:            "a transport error stays generic",
			apiErr:          errors.New("connection refused"),
			wantStatus:      http.StatusInternalServerError,
			wantError:       "server_error",
			wantDescription: generic,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {

			// templateFS is nil because JsonError renders no template. This is the real
			// helper rather than a mock so the assertions below are on the bytes the
			// browser receives.
			httpHelper := handlerhelpers.NewHttpHelper(nil)

			body := `{"clientId":1,"redirectURIs":["https:///evil.example/cb"]}`
			req := httptest.NewRequest(http.MethodPost, "/admin/clients/1/redirect-uris",
				bytes.NewBufferString(body))
			req = req.WithContext(context.WithValue(req.Context(), constants.ContextKeyJwtInfo,
				oauth.JwtInfo{TokenResponse: oauth.TokenResponse{AccessToken: "an-access-token"}}))

			rec := httptest.NewRecorder()

			// httpSession is nil: every case here returns before the session is touched.
			handler := HandleAdminClientRedirectURIsPost(httpHelper, nil, &stubApiClient{updateErr: tc.apiErr})
			handler.ServeHTTP(rec, req)

			assert.Equal(t, tc.wantStatus, rec.Code)

			var response map[string]string
			err := json.Unmarshal(rec.Body.Bytes(), &response)
			assert.NoError(t, err)

			assert.Equal(t, tc.wantError, response["error"])
			assert.Contains(t, response["error_description"], tc.wantDescription)

			if tc.wantStatus != http.StatusBadRequest {
				// The generic branch must not leak the API's message either: that is
				// what sends it to the log rather than the screen.
				assert.NotContains(t, response["error_description"], tc.apiErr.Error())
			}
		})
	}
}

func boolPtr(b bool) *bool { return &b }

// Redirect URIs belong to whichever redirect-based flow the client uses, and implicit is one of
// them, so the page is gated on either rather than on the authorization code flow alone (#250).
// Implicit is three-state, a per-client override over a global default, and the handler is what
// resolves it: the template is handed one boolean and never learns the rule.
//
// AuthorizationCodeEnabled is false on every row deliberately. Varying it as well would let a
// case pass with the implicit half of the condition deleted.
func TestHandleAdminClientRedirectURIsGet_ResolvesRedirectFlows(t *testing.T) {

	testCases := []struct {
		name           string
		clientImplicit *bool
		globalImplicit bool
		wantCanManage  bool
	}{
		{
			name:           "implicit switched on for the client, global off",
			clientImplicit: boolPtr(true),
			globalImplicit: false,
			wantCanManage:  true,
		},
		{
			name:           "implicit inherited from a global that is on",
			clientImplicit: nil,
			globalImplicit: true,
			wantCanManage:  true,
		},
		{
			name:           "implicit switched off over a global that is on",
			clientImplicit: boolPtr(false),
			globalImplicit: true,
			wantCanManage:  false,
		},
		{
			name:           "neither redirect-based flow",
			clientImplicit: nil,
			globalImplicit: false,
			wantCanManage:  false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {

			httpHelper := &stubHttpHelper{}
			apiClient := &stubApiClient{
				client: &api.ClientResponse{
					Id:                       7,
					ClientIdentifier:         "an-implicit-app",
					AuthorizationCodeEnabled: false,
					ImplicitGrantEnabled:     tc.clientImplicit,
				},
				settings: &api.SettingsGeneralResponse{ImplicitFlowEnabled: tc.globalImplicit},
			}

			req := httptest.NewRequest(http.MethodGet, "/admin/clients/7/redirect-uris", nil)
			rctx := chi.NewRouteContext()
			rctx.URLParams.Add("clientId", "7")
			ctx := context.WithValue(req.Context(), chi.RouteCtxKey, rctx)
			ctx = context.WithValue(ctx, constants.ContextKeyJwtInfo,
				oauth.JwtInfo{TokenResponse: oauth.TokenResponse{AccessToken: "an-access-token"}})
			req = req.WithContext(ctx)

			httpSession := sessions.NewCookieStore(securecookie.GenerateRandomKey(64))

			handler := HandleAdminClientRedirectURIsGet(httpHelper, httpSession, apiClient)
			handler.ServeHTTP(httptest.NewRecorder(), req)

			assert.NoError(t, httpHelper.err)
			assert.NotNil(t, httpHelper.bind, "the handler rendered nothing")

			client := httpHelper.bind["client"]
			field := reflect.ValueOf(client).FieldByName("CanManageRedirectURIs")
			assert.True(t, field.IsValid(), "the bind carries no CanManageRedirectURIs")
			assert.Equal(t, tc.wantCanManage, field.Bool())
		})
	}
}
