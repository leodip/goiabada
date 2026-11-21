package adminclienthandlers

import (
	"bytes"
	"context"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/leodip/goiabada/adminconsole/internal/handlers/mocks"
	"github.com/leodip/goiabada/adminconsole/internal/handlertest"
	"github.com/leodip/goiabada/adminconsole/internal/oauthclient"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/errs"
	"github.com/leodip/goiabada/core/oauth"
)

// Seam 4 for the client pages whose calls have moved (#386). See accounthandlers' file of the same
// name for what this owns and why the context is the assertion.
//
// GetClientByID and GetClientPermissions record and then succeed rather than refusing, because
// nearly every page here reads one of them first and everything below it would otherwise be
// unreachable. Every write records its name as well, so a case whose request stops short of its
// write fails rather than passing on the read alone (#477).

type clientCtxMarkerKey struct{}

type ctxRecordingAPIClient struct {
	seen   []context.Context
	writes []string
}

func (s *ctxRecordingAPIClient) record(ctx context.Context) error {
	s.seen = append(s.seen, ctx)
	return errs.New("the auth server refused")
}

func (s *ctxRecordingAPIClient) recordWrite(ctx context.Context, name string) error {
	s.writes = append(s.writes, name)
	return s.record(ctx)
}

// GetClientByID records and then succeeds rather than refusing, because nearly every page here
// reads it first and everything below it would otherwise be unreachable.
func (s *ctxRecordingAPIClient) GetClientByID(ctx context.Context, _ string, clientID int64) (*api.ClientResponse, error) {
	s.seen = append(s.seen, ctx)
	return &api.ClientResponse{ID: clientID, ClientIdentifier: "a-client"}, nil
}

func (s *ctxRecordingAPIClient) GetAllClients(ctx context.Context, _ string) ([]api.ClientResponse, error) {
	return nil, s.record(ctx)
}

// GetClientPermissions records and succeeds for the same reason: the delete page reads it before
// the identifier check and the delete below it.
func (s *ctxRecordingAPIClient) GetClientPermissions(ctx context.Context, _ string, clientID int64) (*api.ClientResponse, []api.PermissionResponse, error) {
	s.seen = append(s.seen, ctx)
	return &api.ClientResponse{ID: clientID, ClientIdentifier: "a-client"}, nil, nil
}

// GetClientIntrospectionResources records and succeeds for the same reason: the Introspection tab
// reads it first, and the resources to choose from below it.
func (s *ctxRecordingAPIClient) GetClientIntrospectionResources(ctx context.Context, _ string, clientID int64) (*api.ClientResponse, []api.ResourceResponse, error) {
	s.seen = append(s.seen, ctx)
	return &api.ClientResponse{ID: clientID, ClientIdentifier: "a-client"}, nil, nil
}

func (s *ctxRecordingAPIClient) GetClientLogo(ctx context.Context, _ string, _ int64) (*api.ClientLogoInfoResponse, error) {
	return nil, s.record(ctx)
}

func (s *ctxRecordingAPIClient) DeleteClient(ctx context.Context, _ string, _ int64) error {
	return s.recordWrite(ctx, "DeleteClient")
}

func (s *ctxRecordingAPIClient) GetSettingsGeneral(ctx context.Context, _ string) (*api.SettingsGeneralResponse, error) {
	s.seen = append(s.seen, ctx)
	return nil, errs.New("the auth server refused")
}

// GetSettingsTokens records and refuses, as the general settings read does: the tokens tab reads it
// after the client, before it draws.
func (s *ctxRecordingAPIClient) GetSettingsTokens(ctx context.Context, _ string) (*api.SettingsTokensResponse, error) {
	s.seen = append(s.seen, ctx)
	return nil, errs.New("the auth server refused")
}

// GetClientSessionsByClientID records and succeeds rather than refusing, because the session
// delete below it is reached only through the page it answers.
func (s *ctxRecordingAPIClient) GetClientSessionsByClientID(ctx context.Context, _ string, _ int64, _, _ int) (*api.GetClientSessionsResponse, error) {
	s.seen = append(s.seen, ctx)
	return &api.GetClientSessionsResponse{
		Sessions: []api.UserSessionDetailResponse{{ID: 31, UserID: 42}},
	}, nil
}

func (s *ctxRecordingAPIClient) DeleteUserSessionByID(ctx context.Context, _ string, _ int64) error {
	return s.recordWrite(ctx, "DeleteUserSessionByID")
}

func (s *ctxRecordingAPIClient) CreateClient(ctx context.Context, _ string, _ *api.CreateClientRequest) (*api.ClientResponse, error) {
	return nil, s.recordWrite(ctx, "CreateClient")
}

func (s *ctxRecordingAPIClient) DeleteClientLogo(ctx context.Context, _ string, _ int64) error {
	return s.recordWrite(ctx, "DeleteClientLogo")
}

func (s *ctxRecordingAPIClient) GetAllResources(ctx context.Context, _ string) ([]api.ResourceResponse, error) {
	return nil, s.record(ctx)
}

func (s *ctxRecordingAPIClient) UpdateClient(ctx context.Context, _ string, _ int64, _ *api.UpdateClientSettingsRequest) (*api.ClientResponse, error) {
	return nil, s.recordWrite(ctx, "UpdateClient")
}

func (s *ctxRecordingAPIClient) GetAllBrands(ctx context.Context, _ string) ([]api.BrandResponse, error) {
	return nil, s.record(ctx)
}

func (s *ctxRecordingAPIClient) UpdateClientBrand(ctx context.Context, _ string, _ int64, _ *api.UpdateClientBrandRequest) (*api.ClientResponse, error) {
	return nil, s.recordWrite(ctx, "UpdateClientBrand")
}

func (s *ctxRecordingAPIClient) UpdateClientAdministrativeScopes(ctx context.Context, _ string, _ int64, _ *api.UpdateClientAdministrativeScopesRequest) (*api.ClientResponse, error) {
	return nil, s.recordWrite(ctx, "UpdateClientAdministrativeScopes")
}

func (s *ctxRecordingAPIClient) UpdateClientAuthentication(ctx context.Context, _ string, _ int64, _ *api.UpdateClientAuthenticationRequest) (*api.ClientResponse, error) {
	return nil, s.recordWrite(ctx, "UpdateClientAuthentication")
}

func (s *ctxRecordingAPIClient) UpdateClientOAuth2Flows(ctx context.Context, _ string, _ int64, _ *api.UpdateClientOAuth2FlowsRequest) (*api.ClientResponse, error) {
	return nil, s.recordWrite(ctx, "UpdateClientOAuth2Flows")
}

func (s *ctxRecordingAPIClient) UpdateClientPermissions(ctx context.Context, _ string, _ int64, _ *api.UpdateClientPermissionsRequest) error {
	return s.recordWrite(ctx, "UpdateClientPermissions")
}

func (s *ctxRecordingAPIClient) UpdateClientIntrospectionResources(ctx context.Context, _ string, _ int64, _ *api.UpdateClientIntrospectionResourcesRequest) error {
	return s.recordWrite(ctx, "UpdateClientIntrospectionResources")
}

func (s *ctxRecordingAPIClient) UpdateClientRedirectURIs(ctx context.Context, _ string, _ int64, _ *api.UpdateClientRedirectURIsRequest) (*api.ClientResponse, error) {
	return nil, s.recordWrite(ctx, "UpdateClientRedirectURIs")
}

func (s *ctxRecordingAPIClient) UpdateClientPostLogoutRedirectURIs(ctx context.Context, _ string, _ int64, _ *api.UpdateClientPostLogoutRedirectURIsRequest) (*api.ClientResponse, error) {
	return nil, s.recordWrite(ctx, "UpdateClientPostLogoutRedirectURIs")
}

func (s *ctxRecordingAPIClient) UpdateClientBackchannelLogout(ctx context.Context, _ string, _ int64, _ *api.UpdateClientBackchannelLogoutRequest) (*api.ClientResponse, error) {
	return nil, s.recordWrite(ctx, "UpdateClientBackchannelLogout")
}

func (s *ctxRecordingAPIClient) UpdateClientTokens(ctx context.Context, _ string, _ int64, _ *api.UpdateClientTokensRequest) (*api.ClientResponse, error) {
	return nil, s.recordWrite(ctx, "UpdateClientTokens")
}

func (s *ctxRecordingAPIClient) UpdateClientDPoP(ctx context.Context, _ string, _ int64, _ *api.UpdateClientDPoPRequest) (*api.ClientResponse, error) {
	return nil, s.recordWrite(ctx, "UpdateClientDPoP")
}

func (s *ctxRecordingAPIClient) UpdateClientWebOrigins(ctx context.Context, _ string, _ int64, _ *api.UpdateClientWebOriginsRequest) (*api.ClientResponse, error) {
	return nil, s.recordWrite(ctx, "UpdateClientWebOrigins")
}

func (s *ctxRecordingAPIClient) UploadClientLogo(ctx context.Context, _ string, _ int64, _ []byte, _ string) (*api.ClientLogoUploadResponse, error) {
	return nil, s.recordWrite(ctx, "UploadClientLogo")
}

func TestAdminClientHandlers_TheMovedCallsCarryTheRequestsContext(t *testing.T) {
	testCases := []struct {
		name  string
		build func(httpHelper *handlersmocks.HTTPHelper, apiClient *ctxRecordingAPIClient) http.HandlerFunc
		// write is the one write the request must reach, empty for a page that only reads.
		write   string
		request *http.Request
	}{
		{
			name: "HandleListGet",
			build: func(h *handlersmocks.HTTPHelper, c *ctxRecordingAPIClient) http.HandlerFunc {
				return HandleListGet(h, c)
			},
			request: handlertest.Request(http.MethodGet, "/admin/clients", handlertest.WithAccessToken()),
		},
		{
			name: "HandlePermissionsGet",
			build: func(h *handlersmocks.HTTPHelper, c *ctxRecordingAPIClient) http.HandlerFunc {
				return HandlePermissionsGet(h, newTestSessionStore(), c)
			},
			request: handlertest.Request(http.MethodGet, "/admin/clients/3/permissions",
				handlertest.WithAccessToken(), handlertest.WithPathValue("clientId", "3")),
		},
		{
			name: "HandleIntrospectionGet",
			build: func(h *handlersmocks.HTTPHelper, c *ctxRecordingAPIClient) http.HandlerFunc {
				return HandleIntrospectionGet(h, newTestSessionStore(), c)
			},
			request: handlertest.Request(http.MethodGet, "/admin/clients/3/introspection",
				handlertest.WithAccessToken(), handlertest.WithPathValue("clientId", "3")),
		},
		{
			name: "HandleLogoGet",
			build: func(h *handlersmocks.HTTPHelper, c *ctxRecordingAPIClient) http.HandlerFunc {
				return HandleLogoGet(h, c)
			},
			request: handlertest.Request(http.MethodGet, "/admin/clients/3/logo",
				handlertest.WithAccessToken(), handlertest.WithPathValue("clientId", "3")),
		},
		{
			name: "HandleDeleteGet",
			build: func(h *handlersmocks.HTTPHelper, c *ctxRecordingAPIClient) http.HandlerFunc {
				return HandleDeleteGet(h, c)
			},
			request: handlertest.Request(http.MethodGet, "/admin/clients/3/delete",
				handlertest.WithAccessToken(), handlertest.WithPathValue("clientId", "3")),
		},
		{
			name: "HandleTokensGet",
			build: func(h *handlersmocks.HTTPHelper, c *ctxRecordingAPIClient) http.HandlerFunc {
				return HandleTokensGet(h, newTestSessionStore(), c)
			},
			request: handlertest.Request(http.MethodGet, "/admin/clients/3/tokens",
				handlertest.WithAccessToken(), handlertest.WithPathValue("clientId", "3")),
		},
		{
			name: "HandleSettingsGet",
			build: func(h *handlersmocks.HTTPHelper, c *ctxRecordingAPIClient) http.HandlerFunc {
				return HandleSettingsGet(h, newTestSessionStore(), c)
			},
			request: handlertest.Request(http.MethodGet, "/admin/clients/3/settings",
				handlertest.WithAccessToken(), handlertest.WithPathValue("clientId", "3")),
		},
		{
			name: "HandleOAuth2FlowsGet",
			build: func(h *handlersmocks.HTTPHelper, c *ctxRecordingAPIClient) http.HandlerFunc {
				return HandleOAuth2FlowsGet(h, nil, c)
			},
			request: handlertest.Request(http.MethodGet, "/admin/clients/3/oauth2-flows",
				handlertest.WithAccessToken(), handlertest.WithPathValue("clientId", "3")),
		},
		{
			name: "HandleRedirectURIsGet",
			build: func(h *handlersmocks.HTTPHelper, c *ctxRecordingAPIClient) http.HandlerFunc {
				return HandleRedirectURIsGet(h, nil, c)
			},
			request: handlertest.Request(http.MethodGet, "/admin/clients/3/redirect-uris",
				handlertest.WithAccessToken(), handlertest.WithPathValue("clientId", "3")),
		},
		{
			name: "HandleSignOutRedirectURIsGet",
			build: func(h *handlersmocks.HTTPHelper, c *ctxRecordingAPIClient) http.HandlerFunc {
				return HandleSignOutRedirectURIsGet(h, nil, c)
			},
			request: handlertest.Request(http.MethodGet, "/admin/clients/3/sign-out-redirect-uris",
				handlertest.WithAccessToken(), handlertest.WithPathValue("clientId", "3")),
		},
		{
			name: "HandleBackchannelLogoutGet",
			build: func(h *handlersmocks.HTTPHelper, c *ctxRecordingAPIClient) http.HandlerFunc {
				return HandleBackchannelLogoutGet(h, nil, c)
			},
			request: handlertest.Request(http.MethodGet, "/admin/clients/3/backchannel-logout",
				handlertest.WithAccessToken(), handlertest.WithPathValue("clientId", "3")),
		},
		{
			name: "HandleUserSessionsGet",
			build: func(h *handlersmocks.HTTPHelper, c *ctxRecordingAPIClient) http.HandlerFunc {
				return HandleUserSessionsGet(h, c)
			},
			request: handlertest.Request(http.MethodGet, "/admin/clients/3/user-sessions",
				handlertest.WithAccessToken(), handlertest.WithPathValue("clientId", "3")),
		},
		{
			name: "HandleUserSessionsPost",
			build: func(h *handlersmocks.HTTPHelper, c *ctxRecordingAPIClient) http.HandlerFunc {
				return HandleUserSessionsPost(h, c)
			},
			write: "DeleteUserSessionByID",
			request: handlertest.Request(http.MethodPost, "/admin/clients/3/user-sessions",
				handlertest.WithAccessToken(), handlertest.WithPathValue("clientId", "3"),
				handlertest.WithBody(strings.NewReader(`{"userSessionId":31}`)),
				handlertest.WithContentType("application/json")),
		},
		{
			name: "HandleNewPost",
			build: func(h *handlersmocks.HTTPHelper, c *ctxRecordingAPIClient) http.HandlerFunc {
				return HandleNewPost(h, c, consoleBaseURL)
			},
			write: "CreateClient",
			request: handlertest.Request(http.MethodPost, "/admin/clients/new",
				handlertest.WithAccessToken(),
				handlertest.WithForm(url.Values{"clientIdentifier": {"a-client"}, "displayName": {"A client"}})),
		},
		{
			name: "HandleSettingsPost",
			build: func(h *handlersmocks.HTTPHelper, c *ctxRecordingAPIClient) http.HandlerFunc {
				return HandleSettingsPost(h, newTestSessionStore(), c, &invalidationRecorder{}, consoleBaseURL)
			},
			write: "UpdateClient",
			request: handlertest.Request(http.MethodPost, "/admin/clients/3/settings",
				handlertest.WithAccessToken(), handlertest.WithPathValue("clientId", "3"),
				handlertest.WithForm(url.Values{"clientIdentifier": {"a-client"}, "enabled": {"on"}})),
		},
		{
			name: "HandleAuthenticationPost",
			build: func(h *handlersmocks.HTTPHelper, c *ctxRecordingAPIClient) http.HandlerFunc {
				return HandleAuthenticationPost(h, newTestSessionStore(), c, consoleBaseURL)
			},
			write: "UpdateClientAuthentication",
			request: handlertest.Request(http.MethodPost, "/admin/clients/3/authentication",
				handlertest.WithAccessToken(), handlertest.WithPathValue("clientId", "3"),
				handlertest.WithForm(url.Values{"publicConfidential": {"confidential"}, "clientSecret": {"a-secret"}})),
		},
		{
			name: "HandleOAuth2FlowsPost",
			build: func(h *handlersmocks.HTTPHelper, c *ctxRecordingAPIClient) http.HandlerFunc {
				return HandleOAuth2FlowsPost(h, newTestSessionStore(), c, consoleBaseURL)
			},
			write: "UpdateClientOAuth2Flows",
			request: handlertest.Request(http.MethodPost, "/admin/clients/3/oauth2-flows",
				handlertest.WithAccessToken(), handlertest.WithPathValue("clientId", "3"),
				handlertest.WithForm(url.Values{"authCodeEnabled": {"on"}})),
		},
		{
			name: "HandleRedirectURIsPost",
			build: func(h *handlersmocks.HTTPHelper, c *ctxRecordingAPIClient) http.HandlerFunc {
				return HandleRedirectURIsPost(h, newTestSessionStore(), c)
			},
			write: "UpdateClientRedirectURIs",
			request: handlertest.Request(http.MethodPost, "/admin/clients/3/redirect-uris",
				handlertest.WithAccessToken(), handlertest.WithPathValue("clientId", "3"),
				handlertest.WithBody(strings.NewReader(
					`{"clientId":3,"redirectURIs":["https://app.example.test/callback"],"expectedRedirectURIs":[]}`)),
				handlertest.WithContentType("application/json")),
		},
		{
			name: "HandleSignOutRedirectURIsPost",
			build: func(h *handlersmocks.HTTPHelper, c *ctxRecordingAPIClient) http.HandlerFunc {
				return HandleSignOutRedirectURIsPost(h, newTestSessionStore(), c)
			},
			write: "UpdateClientPostLogoutRedirectURIs",
			request: handlertest.Request(http.MethodPost, "/admin/clients/3/sign-out-redirect-uris",
				handlertest.WithAccessToken(), handlertest.WithPathValue("clientId", "3"),
				handlertest.WithBody(strings.NewReader(
					`{"clientId":3,"signOutRedirectURIs":["https://app.example.test/signed-out"],"expectedSignOutRedirectURIs":[]}`)),
				handlertest.WithContentType("application/json")),
		},
		{
			name: "HandleBackchannelLogoutPost",
			build: func(h *handlersmocks.HTTPHelper, c *ctxRecordingAPIClient) http.HandlerFunc {
				return HandleBackchannelLogoutPost(h, newTestSessionStore(), c, consoleBaseURL)
			},
			write: "UpdateClientBackchannelLogout",
			request: handlertest.Request(http.MethodPost, "/admin/clients/3/backchannel-logout",
				handlertest.WithAccessToken(), handlertest.WithPathValue("clientId", "3"),
				handlertest.WithForm(url.Values{"backchannelLogoutUri": {"https://app.example.test/bcl"}})),
		},
		{
			name: "HandleWebOriginsPost",
			build: func(h *handlersmocks.HTTPHelper, c *ctxRecordingAPIClient) http.HandlerFunc {
				return HandleWebOriginsPost(h, newTestSessionStore(), c)
			},
			write: "UpdateClientWebOrigins",
			request: handlertest.Request(http.MethodPost, "/admin/clients/3/web-origins",
				handlertest.WithAccessToken(), handlertest.WithPathValue("clientId", "3"),
				handlertest.WithBody(strings.NewReader(
					`{"clientId":3,"webOrigins":["https://app.example.test"],"expectedWebOrigins":[]}`)),
				handlertest.WithContentType("application/json")),
		},
		{
			name: "HandleTokensPost",
			build: func(h *handlersmocks.HTTPHelper, c *ctxRecordingAPIClient) http.HandlerFunc {
				return HandleTokensPost(h, newTestSessionStore(), c, consoleBaseURL)
			},
			write: "UpdateClientTokens",
			request: handlertest.Request(http.MethodPost, "/admin/clients/3/tokens",
				handlertest.WithAccessToken(), handlertest.WithPathValue("clientId", "3"),
				handlertest.WithForm(url.Values{
					"tokenExpirationInSeconds":                {"300"},
					"refreshTokenOfflineIdleTimeoutInSeconds": {"3600"},
					"refreshTokenOfflineMaxLifetimeInSeconds": {"86400"},
					"includeOpenIDConnectClaimsInAccessToken": {"default"},
					"includeOpenIDConnectClaimsInIdToken":     {"default"},
				})),
		},
		{
			name: "HandlePermissionsPost",
			build: func(h *handlersmocks.HTTPHelper, c *ctxRecordingAPIClient) http.HandlerFunc {
				return HandlePermissionsPost(h, newTestSessionStore(), c)
			},
			write: "UpdateClientPermissions",
			request: handlertest.Request(http.MethodPost, "/admin/clients/3/permissions",
				handlertest.WithAccessToken(), handlertest.WithPathValue("clientId", "3"),
				handlertest.WithBody(strings.NewReader(
					`{"clientId":3,"assignedPermissionsIds":[5],"expectedPermissionIds":[]}`)),
				handlertest.WithContentType("application/json")),
		},
		{
			name: "HandleIntrospectionPost",
			build: func(h *handlersmocks.HTTPHelper, c *ctxRecordingAPIClient) http.HandlerFunc {
				return HandleIntrospectionPost(h, newTestSessionStore(), c)
			},
			write: "UpdateClientIntrospectionResources",
			request: handlertest.Request(http.MethodPost, "/admin/clients/3/introspection",
				handlertest.WithAccessToken(), handlertest.WithPathValue("clientId", "3"),
				handlertest.WithBody(strings.NewReader(`{"resourceIds":[5],"expectedResourceIds":[]}`)),
				handlertest.WithContentType("application/json")),
		},
		{
			name: "HandleDeletePost",
			build: func(h *handlersmocks.HTTPHelper, c *ctxRecordingAPIClient) http.HandlerFunc {
				return HandleDeletePost(h, c, consoleBaseURL)
			},
			write: "DeleteClient",
			request: handlertest.Request(http.MethodPost, "/admin/clients/3/delete",
				handlertest.WithAccessToken(), handlertest.WithPathValue("clientId", "3"),
				handlertest.WithForm(url.Values{"clientIdentifier": {"a-client"}})),
		},
		{
			name: "HandleLogoPost",
			build: func(h *handlersmocks.HTTPHelper, c *ctxRecordingAPIClient) http.HandlerFunc {
				return HandleLogoPost(h, c)
			},
			write:   "UploadClientLogo",
			request: logoUpload("3"),
		},
		{
			name: "HandleLogoDelete",
			build: func(h *handlersmocks.HTTPHelper, c *ctxRecordingAPIClient) http.HandlerFunc {
				return HandleLogoDelete(h, c)
			},
			write: "DeleteClientLogo",
			request: handlertest.Request(http.MethodDelete, "/admin/clients/3/logo",
				handlertest.WithAccessToken(), handlertest.WithPathValue("clientId", "3")),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			httpHelper := handlersmocks.NewHTTPHelper(t)
			httpHelper.On("InternalServerError", mock.Anything, mock.Anything, mock.Anything).Maybe()
			httpHelper.On("JSONError", mock.Anything, mock.Anything, mock.Anything).Maybe()
			httpHelper.On("EncodeJSON", mock.Anything, mock.Anything, mock.Anything).Maybe()
			httpHelper.On("NotFound", mock.Anything, mock.Anything).Maybe()
			httpHelper.On("RenderTemplate", mock.Anything, mock.Anything, mock.Anything,
				mock.Anything, mock.Anything).Return(nil).Maybe()

			apiClient := &ctxRecordingAPIClient{}

			marked := tc.request.WithContext(
				context.WithValue(tc.request.Context(), clientCtxMarkerKey{}, tc.name))

			tc.build(httpHelper, apiClient).ServeHTTP(httptest.NewRecorder(), marked)

			require.NotEmpty(t, apiClient.seen, "the handler must consult its API client")
			for i, seen := range apiClient.seen {
				assert.Equal(t, tc.name, seen.Value(clientCtxMarkerKey{}),
					"call %d carried a context that is not the request's", i)
			}

			var wantWrites []string
			if tc.write != "" {
				wantWrites = []string{tc.write}
			}
			assert.Equal(t, wantWrites, apiClient.writes,
				"the request must reach the page's write, and only that one")
		})
	}
}

// The settings save makes a second write, the administrative-scopes allowance, only once UpdateClient
// has succeeded and only when an administrator holding authserver:manage switches it. The table's
// case stops at UpdateClient, which refuses there, so this one reaches the second write as well.
func TestAdminClientHandlers_TheAllowanceWriteCarriesTheRequestsContext(t *testing.T) {
	httpHelper := handlersmocks.NewHTTPHelper(t)
	httpHelper.On("InternalServerError", mock.Anything, mock.Anything, mock.Anything).Maybe()
	httpHelper.On("RenderTemplate", mock.Anything, mock.Anything, mock.Anything,
		mock.Anything, mock.Anything).Return(nil).Maybe()

	apiClient := &allowanceWriteAPIClient{}

	// GetClientByID answers a client whose allowance is off, so the switch submitted on is a change.
	request := handlertest.Request(http.MethodPost, "/admin/clients/3/settings",
		handlertest.WithJWTInfo(oauthclient.JWTInfo{TokenResponse: oauth.TokenResponse{
			AccessToken: handlertest.AccessToken, Scope: manageGrant}}),
		handlertest.WithPathValue("clientId", "3"),
		handlertest.WithForm(url.Values{"clientIdentifier": {"a-client"}, "administrativeScopesAllowed": {"on"}}))
	marked := request.WithContext(context.WithValue(request.Context(), clientCtxMarkerKey{}, "allowance"))

	HandleSettingsPost(httpHelper, newTestSessionStore(), apiClient, &invalidationRecorder{}, consoleBaseURL).ServeHTTP(httptest.NewRecorder(), marked)

	assert.Equal(t, []string{"UpdateClient", "UpdateClientAdministrativeScopes"}, apiClient.writes,
		"the save must reach both of its writes")
	require.NotEmpty(t, apiClient.seen, "the handler must consult its API client")
	for i, seen := range apiClient.seen {
		assert.Equal(t, "allowance", seen.Value(clientCtxMarkerKey{}),
			"call %d carried a context that is not the request's", i)
	}
}

// allowanceWriteAPIClient lets UpdateClient record and then succeed, so the allowance write below it
// is reached at all.
type allowanceWriteAPIClient struct {
	ctxRecordingAPIClient
}

func (s *allowanceWriteAPIClient) UpdateClient(ctx context.Context, _ string, clientID int64, _ *api.UpdateClientSettingsRequest) (*api.ClientResponse, error) {
	s.seen = append(s.seen, ctx)
	s.writes = append(s.writes, "UpdateClient")
	return &api.ClientResponse{ID: clientID, ClientIdentifier: "a-client"}, nil
}

// logoUpload is the one request here that is not form-encoded or JSON: the upload handler reads a
// multipart "picture" part and refuses anything else before it reaches the API.
func logoUpload(clientID string) *http.Request {
	var buf bytes.Buffer
	writer := multipart.NewWriter(&buf)
	part, err := writer.CreateFormFile("picture", "logo.png")
	if err == nil {
		_, _ = part.Write([]byte("the-logo-bytes"))
	}
	_ = writer.Close()

	return handlertest.Request(http.MethodPost, "/admin/clients/"+clientID+"/logo",
		handlertest.WithAccessToken(), handlertest.WithPathValue("clientId", clientID),
		handlertest.WithContentType(writer.FormDataContentType()),
		handlertest.WithBody(bytes.NewReader(buf.Bytes())))
}

func (s *ctxRecordingAPIClient) GetClientSecret(ctx context.Context, _ string, _ int64) (string, error) {
	return "", s.record(ctx)
}
