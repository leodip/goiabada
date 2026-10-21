package apihandlers

import (
	"database/sql"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/mock"

	datamocks "github.com/leodip/goiabada/authserver/internal/data/mocks"
	handlersmocks "github.com/leodip/goiabada/authserver/internal/handlers/mocks"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/authserver/internal/reqctx"
	"github.com/leodip/goiabada/core/builtin"
	"github.com/leodip/goiabada/core/inputvalidation"
)

// The refusals of clients, their redirect URIs, web origins, permissions, tokens and
// administrative scopes, served once with no language and once in pt-BR through
// assertRefusalLanguages (#559 decisions 1 and 2). The missing or malformed ids, the body that does
// not parse and the missing expectedRedirectURIs, expectedWebOrigins and expectedPermissionIds are
// an integrator's, and stay English. The logo's refusals were already catalog keys. Every other
// refusal answers its catalog key as its error_code, which the console reads the field off (#617).

// clientRefusalRequest is a request to one client endpoint, for the client with id 7, under a manage
// token and the settings the redirect URIs' flow gate reads.
func clientRefusalRequest(method, target, body, acceptLanguage string) *http.Request {
	r := httptest.NewRequest(method, target, strings.NewReader(body))
	r = r.WithContext(reqctx.WithSettings(r.Context(), &record.Settings{}))
	r = setTokenContextWithClaims(r, map[string]interface{}{"scope": "authserver:manage"})
	return inRequestLanguage(setChiURLParam(r, "id", "7"), acceptLanguage)
}

// serveClient answers one request to the handler built over a database holding stored as client 7,
// and expecting what expect registers.
func serveClient(method, target, body string, stored *record.Client, expect func(database *datamocks.Database),
	handler func(database *datamocks.Database, auditLogger *handlersmocks.AuditLogger) http.Handler,
) func(*testing.T, string) *httptest.ResponseRecorder {
	return func(t *testing.T, acceptLanguage string) *httptest.ResponseRecorder {
		database := datamocks.NewDatabase(t)
		if stored != nil {
			database.On("GetClientById", mock.Anything, (*sql.Tx)(nil), int64(7)).Return(stored, nil).Once()
		}
		if expect != nil {
			expect(database)
		}
		rr := httptest.NewRecorder()
		handler(database, handlersmocks.NewAuditLogger(t)).ServeHTTP(rr, clientRefusalRequest(method, target, body, acceptLanguage))
		return rr
	}
}

// TestClientRefusals_AreInTheRequestsLanguage covers creating, updating, deleting a client, its
// authentication and its administrative scopes.
func TestClientRefusals_AreInTheRequestsLanguage(t *testing.T) {
	stored := func() *record.Client {
		return &record.Client{Id: 7, ClientIdentifier: "a-client", AuthorizationCodeEnabled: true}
	}
	create := func(body string, expect func(database *datamocks.Database)) func(*testing.T, string) *httptest.ResponseRecorder {
		return serveClient(http.MethodPost, "/api/v1/admin/clients", body, nil, expect,
			func(database *datamocks.Database, auditLogger *handlersmocks.AuditLogger) http.Handler {
				return HandleClientCreatePost(database, inputvalidation.NewIdentifierValidator(), auditLogger, nil)
			})
	}
	update := func(client *record.Client, body string, expect func(database *datamocks.Database)) func(*testing.T, string) *httptest.ResponseRecorder {
		return serveClient(http.MethodPut, "/api/v1/admin/clients/7", body, client, expect,
			func(database *datamocks.Database, auditLogger *handlersmocks.AuditLogger) http.Handler {
				return HandleClientUpdatePut(database, inputvalidation.NewIdentifierValidator(), auditLogger)
			})
	}
	identifierHeldBy := func(identifier string, holder *record.Client) func(database *datamocks.Database) {
		return func(database *datamocks.Database) {
			database.On("GetClientByClientIdentifier", mock.Anything, (*sql.Tx)(nil), identifier).Return(holder, nil).Once()
		}
	}
	long := func(n int) string { return strings.Repeat("a", n) }

	assertRefusalLanguages(t, []refusalCase{
		{
			name:       "create with no identifier",
			serve:      create(`{"clientIdentifier":" "}`, nil),
			status:     http.StatusBadRequest,
			code:       "handler.client.identifier_required",
			english:    "Client identifier is required.",
			portuguese: "O identificador do cliente é obrigatório.",
		},
		{
			name:       "create with a description past the bound",
			serve:      create(`{"clientIdentifier":"a-client","description":"`+long(101)+`"}`, nil),
			status:     http.StatusBadRequest,
			code:       "handler.client.description_too_long",
			english:    "The description cannot exceed a maximum length of 100 characters.",
			portuguese: "A descrição não pode ter mais que 100 caracteres.",
		},
		{
			name:       "create with a display name past the bound",
			serve:      create(`{"clientIdentifier":"a-client","displayName":"`+long(101)+`"}`, nil),
			status:     http.StatusBadRequest,
			code:       "handler.client.display_name_too_long",
			english:    "The display name cannot exceed a maximum length of 100 characters.",
			portuguese: "O nome de exibição não pode ter mais que 100 caracteres.",
		},
		{
			name:       "create with an identifier in use",
			serve:      create(`{"clientIdentifier":"a-client"}`, identifierHeldBy("a-client", stored())),
			status:     http.StatusBadRequest,
			code:       "handler.client.identifier_in_use",
			english:    "The client identifier is already in use.",
			portuguese: "O identificador do cliente já está em uso.",
		},
		{
			name: "create naming a resource's identifier",
			serve: create(`{"clientIdentifier":"a-client"}`, func(database *datamocks.Database) {
				database.On("GetClientByClientIdentifier", mock.Anything, (*sql.Tx)(nil), "a-client").Return(nil, nil).Once()
				database.On("GetResourceByResourceIdentifier", mock.Anything, (*sql.Tx)(nil), "a-client").Return(&record.Resource{Id: 4, ResourceIdentifier: "a-client"}, nil).Once()
			}),
			status:     http.StatusBadRequest,
			code:       "handler.client.identifier_names_resource",
			english:    "The client identifier is already in use by a resource.",
			portuguese: "O identificador do cliente já está em uso por um recurso.",
		},
		{
			name:       "update with no identifier",
			serve:      update(stored(), `{"clientIdentifier":""}`, nil),
			status:     http.StatusBadRequest,
			code:       "handler.client.identifier_required",
			english:    "Client identifier is required.",
			portuguese: "O identificador do cliente é obrigatório.",
		},
		{
			name:       "update with a description past the bound",
			serve:      update(stored(), `{"clientIdentifier":"a-client","description":"`+long(101)+`"}`, nil),
			status:     http.StatusBadRequest,
			code:       "handler.client.description_too_long",
			english:    "The description cannot exceed a maximum length of 100 characters.",
			portuguese: "A descrição não pode ter mais que 100 caracteres.",
		},
		{
			name: "renaming the system-level client",
			serve: update(&record.Client{Id: 7, ClientIdentifier: builtin.AdminConsoleClientIdentifier},
				`{"clientIdentifier":"renamed"}`, nil),
			status:     http.StatusBadRequest,
			code:       "handler.client.system_level_identifier_fixed",
			english:    "The identifier of a system-level client cannot be changed.",
			portuguese: "O identificador de um cliente em nível de sistema não pode ser alterado.",
		},
		{
			name: "renaming a self-registered client",
			serve: update(&record.Client{Id: 7, ClientIdentifier: "dcr_a", CreatedViaDCR: true},
				`{"clientIdentifier":"renamed"}`, nil),
			status:     http.StatusBadRequest,
			code:       "handler.client.self_registered_identifier_fixed",
			english:    "The identifier of a self-registered client cannot be changed.",
			portuguese: "O identificador de um cliente autorregistrado não pode ser alterado.",
		},
		{
			name: "update onto another client's identifier",
			serve: update(stored(), `{"clientIdentifier":"other-client"}`,
				identifierHeldBy("other-client", &record.Client{Id: 8, ClientIdentifier: "other-client"})),
			status:     http.StatusBadRequest,
			code:       "handler.client.identifier_in_use",
			english:    "The client identifier is already in use.",
			portuguese: "O identificador do cliente já está em uso.",
		},
		{
			name: "update onto a resource's identifier",
			serve: update(stored(), `{"clientIdentifier":"named-like-a-resource"}`, func(database *datamocks.Database) {
				database.On("GetClientByClientIdentifier", mock.Anything, (*sql.Tx)(nil), "named-like-a-resource").Return(nil, nil).Once()
				database.On("GetResourceByResourceIdentifier", mock.Anything, (*sql.Tx)(nil), "named-like-a-resource").Return(&record.Resource{Id: 9, ResourceIdentifier: "named-like-a-resource"}, nil).Once()
			}),
			status:     http.StatusBadRequest,
			code:       "handler.client.identifier_names_resource",
			english:    "The client identifier is already in use by a resource.",
			portuguese: "O identificador do cliente já está em uso por um recurso.",
		},
		{
			name: "a default ACR level with the authorization code flow off",
			serve: update(&record.Client{Id: 7, ClientIdentifier: "a-client"},
				`{"clientIdentifier":"a-client","defaultAcrLevel":"urn:goiabada:level1"}`, nil),
			status:     http.StatusBadRequest,
			code:       "handler.client.default_acr_not_applicable",
			english:    "Default ACR level is not applicable when authorization code flow is disabled.",
			portuguese: "O nível ACR padrão não se aplica quando o fluxo authorization code está desabilitado.",
		},
		{
			name:       "a website URL past the bound",
			serve:      update(stored(), `{"clientIdentifier":"a-client","websiteUrl":"https://example.com/`+long(240)+`"}`, nil),
			status:     http.StatusBadRequest,
			code:       "handler.client.website_url_too_long",
			english:    "The website URL cannot exceed a maximum length of 256 characters.",
			portuguese: "A URL do site não pode ter mais que 256 caracteres.",
		},
		{
			name:       "a website URL that does not parse",
			serve:      update(stored(), `{"clientIdentifier":"a-client","websiteUrl":"not a url"}`, nil),
			status:     http.StatusBadRequest,
			code:       "handler.client.website_url_invalid",
			english:    "Invalid website URL.",
			portuguese: "URL do site inválida.",
		},
		{
			name:       "a website URL with another scheme",
			serve:      update(stored(), `{"clientIdentifier":"a-client","websiteUrl":"ftp://example.com"}`, nil),
			status:     http.StatusBadRequest,
			code:       "handler.client.website_url_scheme_invalid",
			english:    "Website URL must use http or https scheme.",
			portuguese: "A URL do site precisa usar o esquema http ou https.",
		},
		{
			name:       "update with a display name past the bound",
			serve:      update(stored(), `{"clientIdentifier":"a-client","displayName":"`+long(101)+`"}`, nil),
			status:     http.StatusBadRequest,
			code:       "handler.client.display_name_too_long",
			english:    "The display name cannot exceed a maximum length of 100 characters.",
			portuguese: "O nome de exibição não pode ter mais que 100 caracteres.",
		},
		{
			name:       "a default ACR level that is no level",
			serve:      update(stored(), `{"clientIdentifier":"a-client","defaultAcrLevel":"level9"}`, nil),
			status:     http.StatusBadRequest,
			code:       "handler.client.default_acr_invalid",
			english:    "Invalid default ACR level",
			portuguese: "Nível ACR padrão inválido",
		},
		{
			name: "deleting the system-level client",
			serve: serveClient(http.MethodDelete, "/api/v1/admin/clients/7", "",
				&record.Client{Id: 7, ClientIdentifier: builtin.AdminConsoleClientIdentifier}, nil,
				func(database *datamocks.Database, auditLogger *handlersmocks.AuditLogger) http.Handler {
					return HandleClientDelete(database, auditLogger)
				}),
			status:     http.StatusBadRequest,
			code:       "handler.client.system_level_delete_not_allowed",
			english:    "Trying to delete a system level client",
			portuguese: "Tentativa de excluir um cliente em nível de sistema",
		},
		{
			name: "a confidential client with a weak secret",
			serve: serveClient(http.MethodPut, "/api/v1/admin/clients/7/authentication", `{"isPublic":false,"clientSecret":"short"}`,
				stored(), nil,
				func(database *datamocks.Database, auditLogger *handlersmocks.AuditLogger) http.Handler {
					return HandleClientAuthenticationPut(database, auditLogger, nil)
				}),
			status:     http.StatusBadRequest,
			code:       "handler.client.secret_invalid",
			english:    "Invalid client secret. Please generate a new one.",
			portuguese: "Segredo do cliente inválido. Gere um novo.",
		},
		{
			name: "the administrative scopes with no allowed",
			serve: serveClient(http.MethodPut, "/api/v1/admin/clients/7/administrative-scopes", `{}`, stored(), nil,
				func(database *datamocks.Database, auditLogger *handlersmocks.AuditLogger) http.Handler {
					return HandleClientAdministrativeScopesPut(database, auditLogger)
				}),
			status:     http.StatusBadRequest,
			code:       "handler.client_administrative_scopes.allowed_required",
			english:    "allowed is required.",
			portuguese: "allowed é obrigatório.",
		},
		{
			name: "the admin console's client denied the administrative scopes",
			serve: serveClient(http.MethodPut, "/api/v1/admin/clients/7/administrative-scopes", `{"allowed":false}`,
				&record.Client{Id: 7, ClientIdentifier: builtin.AdminConsoleClientIdentifier}, nil,
				func(database *datamocks.Database, auditLogger *handlersmocks.AuditLogger) http.Handler {
					return HandleClientAdministrativeScopesPut(database, auditLogger)
				}),
			status:     http.StatusBadRequest,
			code:       "handler.client_administrative_scopes.console_always_allowed",
			english:    "The admin console's client is always allowed to request the administrative scopes.",
			portuguese: "O cliente do console de administração sempre pode solicitar os escopos administrativos.",
		},
	})
}

// TestClientPermissionRefusals_AreInTheRequestsLanguage covers the client permissions save.
func TestClientPermissionRefusals_AreInTheRequestsLanguage(t *testing.T) {
	assertRefusalLanguages(t, []refusalCase{
		{
			name: "permissions with the client credentials flow off",
			serve: serveClient(http.MethodPut, "/api/v1/admin/clients/7/permissions", `{"permissionIds":[],"expectedPermissionIds":[]}`,
				&record.Client{Id: 7, ClientIdentifier: "a-client"}, nil,
				func(database *datamocks.Database, auditLogger *handlersmocks.AuditLogger) http.Handler {
					return HandleClientPermissionsPut(database, auditLogger)
				}),
			status:     http.StatusBadRequest,
			code:       "handler.client_permissions.client_credentials_disabled",
			english:    "Client permissions can only be configured when client credentials flow is enabled",
			portuguese: "As permissões do cliente só podem ser configuradas quando o fluxo client credentials está habilitado",
		},
	})
}

// TestClientRedirectURIRefusals_AreInTheRequestsLanguage covers the redirect URIs save, whose
// refusals name the value refused.
func TestClientRedirectURIRefusals_AreInTheRequestsLanguage(t *testing.T) {
	save := func(client *record.Client, uris []string) func(*testing.T, string) *httptest.ResponseRecorder {
		return func(t *testing.T, acceptLanguage string) *httptest.ResponseRecorder {
			return serveClient(http.MethodPut, "/api/v1/admin/clients/7/redirect-uris", redirectURIsBody(t, uris, []string{}),
				client, nil,
				func(database *datamocks.Database, auditLogger *handlersmocks.AuditLogger) http.Handler {
					return HandleClientRedirectURIsPut(database, auditLogger)
				})(t, acceptLanguage)
		}
	}
	codeFlow := func() *record.Client { return &record.Client{Id: 7, AuthorizationCodeEnabled: true} }
	tooMany := make([]string, record.RedirectURIsMaxPerClient+1)
	for i := range tooMany {
		tooMany[i] = "https://example.com/cb"
	}
	overlong := "https://example.com/" + strings.Repeat("x", record.RedirectURIMaxBytes)

	assertRefusalLanguages(t, []refusalCase{
		{
			name:       "a client with no redirect-based flow",
			serve:      save(&record.Client{Id: 7}, []string{"https://example.com/cb"}),
			status:     http.StatusBadRequest,
			code:       "handler.client_redirect_uris.no_redirect_flow",
			english:    "Redirect URIs are used by the authorization code with PKCE flow and by the implicit flow, and neither is enabled for this client.",
			portuguese: "URIs de redirecionamento são usadas pelo fluxo authorization code com PKCE e pelo fluxo implicit, e nenhum deles está habilitado para este cliente.",
		},
		{
			name:       "more redirect URIs than a client holds",
			serve:      save(codeFlow(), tooMany),
			status:     http.StatusBadRequest,
			code:       "handler.client_redirect_uris.too_many",
			english:    "A client can have at most 60 redirect URIs, and this list has 61.",
			portuguese: "Um cliente pode ter no máximo 60 URIs de redirecionamento, e esta lista tem 61.",
		},
		{
			name:       "an empty redirect URI",
			serve:      save(codeFlow(), []string{" "}),
			status:     http.StatusBadRequest,
			code:       "handler.client_redirect_uris.empty",
			english:    "Redirect URI cannot be empty",
			portuguese: "A URI de redirecionamento não pode ficar vazia",
		},
		{
			name:       "a redirect URI past the bound",
			serve:      save(codeFlow(), []string{overlong}),
			status:     http.StatusBadRequest,
			code:       "handler.client_redirect_uris.too_long",
			english:    "Redirect URI is too long (2068 bytes, the maximum is 2048): https://example.com/" + strings.Repeat("x", 60) + "...",
			portuguese: "A URI de redirecionamento é longa demais (2068 bytes, o máximo é 2048): https://example.com/" + strings.Repeat("x", 60) + "...",
		},
		{
			name:       "a redirect URI that does not parse",
			serve:      save(codeFlow(), []string{"not a uri"}),
			status:     http.StatusBadRequest,
			code:       "handler.client_redirect_uris.invalid",
			english:    "Invalid redirect URI: not a uri",
			portuguese: "URI de redirecionamento inválida: not a uri",
		},
		{
			name:       "a redirect URI that is not absolute",
			serve:      save(codeFlow(), []string{"https://example.com/cb#fragment"}),
			status:     http.StatusBadRequest,
			code:       "handler.client_redirect_uris.not_absolute",
			english:    "Redirect URI must be an absolute URI (a scheme is required, a fragment is not permitted, percent-escapes must be well formed, and an http or https URI must name a host): https://example.com/cb#fragment",
			portuguese: "A URI de redirecionamento precisa ser absoluta (o esquema é obrigatório, fragmentos não são permitidos, os escapes por porcentagem precisam estar bem formados e uma URI http ou https precisa nomear um host): https://example.com/cb#fragment",
		},
		{
			name:       "a plain-http redirect URI on a host other than loopback",
			serve:      save(codeFlow(), []string{"http://app.example.com/cb"}),
			status:     http.StatusBadRequest,
			code:       "handler.client_redirect_uris.insecure_http",
			english:    "Redirect URI must not use plain http on a host other than the loopback interface (127.0.0.1, [::1] or localhost): http://app.example.com/cb",
			portuguese: "A URI de redirecionamento não pode usar http simples em um host que não seja a interface de loopback (127.0.0.1, [::1] ou localhost): http://app.example.com/cb",
		},
		{
			name:       "a redirect URI twice",
			serve:      save(codeFlow(), []string{"https://example.com/cb", "https://example.com/cb"}),
			status:     http.StatusBadRequest,
			code:       "handler.client_redirect_uris.duplicate",
			english:    "Duplicate redirect URIs are not allowed",
			portuguese: "URIs de redirecionamento duplicadas não são permitidas",
		},
	})
}

// TestClientWebOriginRefusals_AreInTheRequestsLanguage covers the web origins save, whose
// refusals name the value refused.
func TestClientWebOriginRefusals_AreInTheRequestsLanguage(t *testing.T) {
	save := func(origins, expected []string) func(*testing.T, string) *httptest.ResponseRecorder {
		return func(t *testing.T, acceptLanguage string) *httptest.ResponseRecorder {
			return serveClient(http.MethodPut, "/api/v1/admin/clients/7/web-origins", webOriginsBody(t, origins, expected),
				&record.Client{Id: 7}, nil,
				func(database *datamocks.Database, auditLogger *handlersmocks.AuditLogger) http.Handler {
					return HandleClientWebOriginsPut(database, auditLogger)
				})(t, acceptLanguage)
		}
	}
	// 268 bytes, one past record.WebOriginMaxBytes, already canonical.
	overlong := "https://" + strings.Repeat("a", 63) + "." + strings.Repeat("a", 63) + "." + strings.Repeat("a", 63) + "." + strings.Repeat("b", 62) + ":65535"

	assertRefusalLanguages(t, []refusalCase{
		{
			name:       "an empty web origin",
			serve:      save([]string{" "}, []string{}),
			status:     http.StatusBadRequest,
			code:       "handler.client_web_origins.empty",
			english:    "Web origin cannot be empty",
			portuguese: "A origem web não pode ficar vazia",
		},
		{
			name:    "a web origin carrying user information",
			serve:   save([]string{"https://user@example.com"}, []string{}),
			status:  http.StatusBadRequest,
			code:    "handler.client_web_origins.invalid",
			english: "Invalid web origin: https://user@example.com. A web origin is a scheme, a host and an optional port, with nothing after the host: for example https://www.example.com or https://myapp:8080. The scheme must be http or https; the host must be ASCII, must carry no user information, and must not be an IPv6 literal or an abbreviated IPv4 address; and a port, if present, must be plain decimal below 65536 with no leading zero.",
			portuguese: "Origem web inválida: https://user@example.com. Uma origem web é um esquema, um host e uma porta opcional, sem nada depois do host: por exemplo https://www.example.com ou https://myapp:8080. " +
				"O esquema precisa ser http ou https; o host precisa ser ASCII, não pode conter informações de usuário e não pode ser um literal IPv6 nem um endereço IPv4 abreviado; e a porta, se houver, precisa ser decimal simples abaixo de 65536, sem zero à esquerda.",
		},
		{
			name:       "a web origin past the bound",
			serve:      save([]string{overlong}, []string{}),
			status:     http.StatusBadRequest,
			code:       "handler.client_web_origins.too_long",
			english:    "Web origin is too long (268 characters, the maximum is 267): " + overlong,
			portuguese: "A origem web é longa demais (268 caracteres, o máximo é 267): " + overlong,
		},
		{
			name:       "a web origin twice",
			serve:      save([]string{"https://example.com", "https://example.com/"}, []string{}),
			status:     http.StatusBadRequest,
			code:       "handler.client_web_origins.duplicate",
			english:    "Duplicate web origins are not allowed",
			portuguese: "Origens web duplicadas não são permitidas",
		},
		{
			name:       "a loaded web origin that is no origin",
			serve:      save([]string{"https://example.com"}, []string{"ftp://example.com"}),
			status:     http.StatusBadRequest,
			code:       "handler.client_web_origins.expected_invalid",
			english:    "Invalid web origin in expectedWebOrigins: ftp://example.com. Send the web origins exactly as you last read them.",
			portuguese: "Origem web inválida em expectedWebOrigins: ftp://example.com. Envie as origens web exatamente como as leu pela última vez.",
		},
	})
}

// TestClientTokenRefusals_AreInTheRequestsLanguage covers the client tokens save.
func TestClientTokenRefusals_AreInTheRequestsLanguage(t *testing.T) {
	save := func(body string) func(*testing.T, string) *httptest.ResponseRecorder {
		return serveClient(http.MethodPut, "/api/v1/admin/clients/7/tokens", body, &record.Client{Id: 7}, nil,
			func(database *datamocks.Database, auditLogger *handlersmocks.AuditLogger) http.Handler {
				return HandleClientTokensPut(database, auditLogger)
			})
	}
	valid := `"includeOpenIDConnectClaimsInAccessToken":"default","includeOpenIDConnectClaimsInIdToken":"default"`

	assertRefusalLanguages(t, []refusalCase{
		{
			name:       "a token expiration past the bound",
			serve:      save(`{"tokenExpirationInSeconds":160000001,` + valid + `}`),
			status:     http.StatusBadRequest,
			code:       "handler.client_tokens.token_expiration_out_of_range",
			english:    "Token lifetime must be between 0 and 160000000 seconds.",
			portuguese: "A duração do token precisa estar entre 0 e 160000000 segundos.",
		},
		{
			name:       "a negative offline idle timeout",
			serve:      save(`{"refreshTokenOfflineIdleTimeoutInSeconds":-1,` + valid + `}`),
			status:     http.StatusBadRequest,
			code:       "handler.client_tokens.offline_idle_timeout_out_of_range",
			english:    "Offline idle timeout must be between 0 and 160000000 seconds.",
			portuguese: "O tempo ocioso offline precisa estar entre 0 e 160000000 segundos.",
		},
		{
			name:       "an offline max lifetime past the bound",
			serve:      save(`{"refreshTokenOfflineMaxLifetimeInSeconds":160000001,` + valid + `}`),
			status:     http.StatusBadRequest,
			code:       "handler.client_tokens.offline_max_lifetime_out_of_range",
			english:    "Offline maximum lifetime must be between 0 and 160000000 seconds.",
			portuguese: "A duração máxima offline precisa estar entre 0 e 160000000 segundos.",
		},
		{
			name:       "an offline idle timeout above the max lifetime",
			serve:      save(`{"refreshTokenOfflineIdleTimeoutInSeconds":20,"refreshTokenOfflineMaxLifetimeInSeconds":10,` + valid + `}`),
			status:     http.StatusBadRequest,
			code:       "handler.client_tokens.offline_idle_timeout_above_max_lifetime",
			english:    "The offline idle timeout can't be longer than the offline maximum lifetime.",
			portuguese: "O tempo ocioso offline não pode ser maior que a duração máxima offline.",
		},
		{
			name:       "an unknown value for the access token's claims",
			serve:      save(`{"includeOpenIDConnectClaimsInAccessToken":"sometimes","includeOpenIDConnectClaimsInIdToken":"default"}`),
			status:     http.StatusBadRequest,
			code:       "handler.client_tokens.include_claims_in_access_token_invalid",
			english:    "Invalid value for includeOpenIDConnectClaimsInAccessToken.",
			portuguese: "Valor inválido para includeOpenIDConnectClaimsInAccessToken.",
		},
		{
			name:       "an unknown value for the ID token's claims",
			serve:      save(`{"includeOpenIDConnectClaimsInAccessToken":"default","includeOpenIDConnectClaimsInIdToken":"sometimes"}`),
			status:     http.StatusBadRequest,
			code:       "handler.client_tokens.include_claims_in_id_token_invalid",
			english:    "Invalid value for includeOpenIDConnectClaimsInIdToken.",
			portuguese: "Valor inválido para includeOpenIDConnectClaimsInIdToken.",
		},
	})
}
