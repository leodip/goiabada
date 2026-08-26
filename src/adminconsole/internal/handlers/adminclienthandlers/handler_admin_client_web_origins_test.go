package adminclienthandlers

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/gorilla/securecookie"
	"github.com/gorilla/sessions"
	"github.com/leodip/goiabada/adminconsole/internal/apiclient"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/handlerhelpers"
	"github.com/leodip/goiabada/core/models"
	"github.com/leodip/goiabada/core/oauth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// stubAllClientsApiClient answers both reads the Web Origins page performs. It is separate from
// stubApiClient next door only because that one stubs GetSettingsGeneral, which this page has no
// business calling: leaving it embedded and unstubbed means a call to it panics, which is the
// right outcome for a fetch this page should not be making.
type stubAllClientsApiClient struct {
	stubApiClient
	allClients []api.ClientResponse
}

func (s *stubAllClientsApiClient) GetAllClients(accessToken string) ([]api.ClientResponse, error) {
	return s.allClients, nil
}

func (s *stubAllClientsApiClient) UpdateClientWebOrigins(accessToken string, clientId int64,
	request *api.UpdateClientWebOriginsRequest) (*api.ClientResponse, error) {
	return nil, s.updateErr
}

// The page's effective list is the server-wide one, and this handler is what assembles it.
//
// MiddlewareCors checks an incoming Origin against every row in web_origins whatever client it
// was registered against, because a CORS preflight carries no client identity, so an origin
// registered on the least-trusted client is permitted for every client. Showing only this
// client's rows implied a scoping the server does not honour and left an administrator unable to
// answer "what may call these endpoints from a browser today" without opening every client in
// turn (#250 decision 9(b)).
//
// This is the half a rendertest case cannot see. rendertest hands the template a bind the test
// wrote, so deleting the GetAllClients call here would leave every rendertest case green with the
// page showing nothing but this client's rows (plan review round 1, finding 3).
func TestHandleAdminClientWebOriginsGet_AssemblesTheServerWideList(t *testing.T) {

	httpHelper := &stubHttpHelper{}
	apiClient := &stubAllClientsApiClient{
		stubApiClient: stubApiClient{
			client: &api.ClientResponse{
				Id:               7,
				ClientIdentifier: "this-app",
				WebOrigins: []models.WebOrigin{
					{Id: 2, ClientId: 7, Origin: "https://mine-b.example.com"},
					{Id: 1, ClientId: 7, Origin: "https://mine-a.example.com"},
				},
			},
		},
		allClients: []api.ClientResponse{
			{
				Id:               7,
				ClientIdentifier: "this-app",
				WebOrigins: []models.WebOrigin{
					{Id: 2, ClientId: 7, Origin: "https://mine-b.example.com"},
					{Id: 1, ClientId: 7, Origin: "https://mine-a.example.com"},
				},
			},
			{
				Id:               9,
				ClientIdentifier: "another-app",
				WebOrigins: []models.WebOrigin{
					{Id: 3, ClientId: 9, Origin: "https://theirs.example.com"},
				},
			},
			{Id: 11, ClientIdentifier: "no-origins-app"},
		},
	}

	req := httptest.NewRequest(http.MethodGet, "/admin/clients/7/web-origins", nil)
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("clientId", "7")
	ctx := context.WithValue(req.Context(), chi.RouteCtxKey, rctx)
	ctx = context.WithValue(ctx, constants.ContextKeyJwtInfo,
		oauth.JwtInfo{TokenResponse: oauth.TokenResponse{AccessToken: "an-access-token"}})
	req = req.WithContext(ctx)

	httpSession := sessions.NewCookieStore(securecookie.GenerateRandomKey(64))

	handler := HandleAdminClientWebOriginsGet(httpHelper, httpSession, apiClient)
	handler.ServeHTTP(httptest.NewRecorder(), req)

	assert.NoError(t, httpHelper.err)
	require.NotNil(t, httpHelper.bind, "the handler rendered nothing")

	bound := reflect.ValueOf(httpHelper.bind["client"])

	effective := bound.FieldByName("EffectiveWebOrigins")
	require.True(t, effective.IsValid(), "the bind carries no EffectiveWebOrigins")
	require.Equal(t, 3, effective.Len(), "every registered origin belongs in the effective list")

	// Sorted by origin, so the list reads as one answer rather than as a per-client grouping,
	// and another client's origin appears in it. That last row is the whole point: it is the
	// one an administrator could not see before.
	type row struct{ origin, client string }
	var got []row
	for i := 0; i < effective.Len(); i++ {
		got = append(got, row{
			origin: effective.Index(i).FieldByName("Origin").String(),
			client: effective.Index(i).FieldByName("ClientIdentifier").String(),
		})
	}
	assert.Equal(t, []row{
		{"https://mine-a.example.com", "this-app"},
		{"https://mine-b.example.com", "this-app"},
		{"https://theirs.example.com", "another-app"},
	}, got)

	// Only this client's rows stay editable: the editable map is what the page's JavaScript
	// loads and posts back, and another client's origin appearing in it would let this page
	// delete a row it does not own.
	editable := bound.FieldByName("WebOrigins")
	require.True(t, editable.IsValid(), "the bind carries no WebOrigins")
	assert.Equal(t, 2, editable.Len())
	assert.Equal(t, "https://mine-a.example.com", editable.MapIndex(reflect.ValueOf(int64(1))).String())
	assert.Equal(t, "https://mine-b.example.com", editable.MapIndex(reflect.ValueOf(int64(2))).String())

	// The page no longer gates on the authorization code flow, so the bind does not carry it.
	// A field nothing reads is how the deleted gate would grow back.
	assert.False(t, bound.FieldByName("AuthorizationCodeEnabled").IsValid(),
		"the bind still carries AuthorizationCodeEnabled")
}

// The API's refusal has to reach the administrator's screen.
//
// This handler passed the error to httpHelper.JsonError directly, which preserves a status and a
// description only for a *customerrors.ErrorDetail. An *apiclient.APIError took the generic branch,
// so a 400 became "An unexpected server error has occurred" and the sentence naming the offending
// value went to the log. That is #122's defect, fixed there for the Redirect URIs page and missed
// here, and #250 is what makes it bite: the API now refuses shapes this page's own
// new URL().origin produces happily, such as a non-ASCII host or an IPv6 literal, so an
// administrator can be refused on a first try with no idea what to type instead.
//
// The 500 row is what keeps the forwarding narrow: a genuine server fault must not be reported to
// the administrator as their own mistake.
func TestHandleAdminClientWebOriginsPost_APIRefusalReachesTheBrowser(t *testing.T) {

	const refusal = "Invalid web origin: https://[2001:db8::1]. A web origin is a scheme, a host " +
		"and an optional port, with nothing after the host"

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
			wantDescription: "An unexpected server error has occurred",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {

			// The real helper rather than a mock, so the assertions are on the bytes the
			// browser receives. templateFS is nil because JsonError renders no template.
			httpHelper := handlerhelpers.NewHttpHelper(nil)

			body := `{"clientId":1,"webOrigins":["https://[2001:db8::1]"]}`
			req := httptest.NewRequest(http.MethodPost, "/admin/clients/1/web-origins",
				bytes.NewBufferString(body))
			req = req.WithContext(context.WithValue(req.Context(), constants.ContextKeyJwtInfo,
				oauth.JwtInfo{TokenResponse: oauth.TokenResponse{AccessToken: "an-access-token"}}))

			rec := httptest.NewRecorder()

			// httpSession is nil: both cases return before the session is touched.
			handler := HandleAdminClientWebOriginsPost(httpHelper, nil,
				&stubAllClientsApiClient{stubApiClient: stubApiClient{updateErr: tc.apiErr}})
			handler.ServeHTTP(rec, req)

			assert.Equal(t, tc.wantStatus, rec.Code)

			var response map[string]string
			require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &response))
			assert.Equal(t, tc.wantError, response["error"])
			assert.Contains(t, response["error_description"], tc.wantDescription)

			if tc.wantStatus != http.StatusBadRequest {
				assert.NotContains(t, response["error_description"], "the database is on fire")
			}
		})
	}
}
