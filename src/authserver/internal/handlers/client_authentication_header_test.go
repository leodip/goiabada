package handlers

import (
	"encoding/base64"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/leodip/goiabada/authserver/internal/data/mocks"
	"github.com/leodip/goiabada/authserver/internal/handlers/mocks"
	"github.com/leodip/goiabada/authserver/internal/introspectionmetrics"
	"github.com/leodip/goiabada/authserver/internal/protocolvalidation"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/authserver/internal/render"
	"github.com/leodip/goiabada/authserver/internal/revocationmetrics"
	"github.com/leodip/goiabada/core/logging/logtest"
	"github.com/leodip/goiabada/core/metrics"
	"github.com/leodip/goiabada/core/oauth"
)

// How the three endpoints that authenticate their caller, the token, revocation and introspection
// endpoints, read the Authorization header (#707 decisions 8, 9 and 12): one or more spaces may follow
// Basic (RFC 9110 section 11.4); two or more Authorization fields are refused 400 invalid_request
// before any credential is read (RFC 9110 section 5.3, RFC 6749 section 5.2); and a Basic header whose
// credentials cannot be read is refused 401 invalid_client with the Basic challenge, the body unread
// (RFC 6749 section 5.2). Every database is a strict mock, so a client lookup nothing armed fails the
// test: a refusal here is made before any client is read.

const (
	headerClientIdentifier = "the-client"
	headerClientSecret     = "the-secret"
)

// unreadableBasicDescription is decision 12's description, written out.
const unreadableBasicDescription = "Client authentication failed: the Basic credentials in the Authorization header could not be read."

// twoAuthorizationFieldsDescription is the description of a request with two Authorization fields.
const twoAuthorizationFieldsDescription = "The request included more than one Authorization header. Send one."

// headerEndpoint is one of the three endpoints, driven over HTTP through the real JSON writer.
type headerEndpoint struct {
	name string
	// path is the endpoint's route, for the request.
	path string
	// warning is the message of the endpoint's client authentication refusal record.
	warning string
	// handler builds the endpoint over database, which nothing is armed on.
	handler func(t *testing.T, database *datamocks.Database) http.HandlerFunc
	// form is a request that reaches client authentication, without credentials.
	form url.Values
}

func headerEndpoints() []headerEndpoint {
	return []headerEndpoint{
		{
			name: "token", path: "/auth/token", warning: "client authentication refused at the token endpoint",
			handler: func(t *testing.T, database *datamocks.Database) http.HandlerFunc {
				return HandleTokenPost(render.New(nil, nil), datamocks.NewDatabase(t), handlersmocks.NewTokenIssuer(t),
					protocolvalidation.NewTokenValidator(database, nil, nil, testDataCipher),
					handlersmocks.NewAuditLogger(t), noCredentialFailures{}, testTokenMetrics())
			},
			form: url.Values{"grant_type": {"client_credentials"}},
		},
		{
			name: "revocation", path: "/auth/revoke", warning: "client authentication refused at the revocation endpoint",
			handler: func(t *testing.T, database *datamocks.Database) http.HandlerFunc {
				return HandleRevokePost(render.New(nil, nil), database, handlersmocks.NewTokenParser(t), testDataCipher,
					handlersmocks.NewAuditLogger(t), revocationmetrics.Register(metrics.NewRegistry()))
			},
			form: url.Values{"token": {"the.presented.token"}},
		},
		{
			name: "introspection", path: "/auth/introspect", warning: "client authentication refused at the introspection endpoint",
			handler: func(t *testing.T, database *datamocks.Database) http.HandlerFunc {
				return HandleIntrospectPost(render.New(nil, nil), database, handlersmocks.NewTokenParser(t), testDataCipher,
					introspectionmetrics.Register(metrics.NewRegistry()))
			},
			form: url.Values{"token": {"the.presented.token"}},
		},
	}
}

// postWithAuthorization posts form to handler with one Authorization field per value in fields.
func postWithAuthorization(handler http.HandlerFunc, path string, form url.Values, fields ...string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for _, field := range fields {
		req.Header.Add("Authorization", field)
	}
	req = withSettings(req, &record.Settings{Id: 1})
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	return rr
}

func encodedBasic(credentials string) string {
	return base64.StdEncoding.EncodeToString([]byte(credentials))
}

// withBodyCredentials is form with the client's identifier and secret in the body as well.
func withBodyCredentials(form url.Values) url.Values {
	withCredentials := url.Values{}
	for name, values := range form {
		withCredentials[name] = values
	}
	withCredentials.Set("client_id", headerClientIdentifier)
	withCredentials.Set("client_secret", headerClientSecret)
	return withCredentials
}

// Decision 9: two or more Authorization fields are refused 400 invalid_request before any credential
// is read, whether they agree or not, and whatever the body holds. No challenge: no client failed to
// authenticate.
func TestClientAuthentication_TwoAuthorizationFieldsAreRefused(t *testing.T) {
	basic := "Basic " + encodedBasic(headerClientIdentifier+":"+headerClientSecret)
	cases := []struct {
		name   string
		fields []string
		body   bool
	}{
		{"two Basic fields that agree", []string{basic, basic}, false},
		{"two Basic fields that disagree", []string{basic, "Basic " + encodedBasic("another-client:another-secret")}, false},
		{"a Basic field and a Bearer field", []string{basic, "Bearer a-token"}, false},
		{"a Bearer field and a Basic field", []string{"Bearer a-token", basic}, false},
		{"two Bearer fields beside body credentials", []string{"Bearer a-token", "Bearer another-token"}, true},
		{"three Basic fields", []string{basic, basic, basic}, false},
	}
	for _, endpoint := range headerEndpoints() {
		for _, tc := range cases {
			t.Run(endpoint.name+", "+tc.name, func(t *testing.T) {
				handler := endpoint.handler(t, datamocks.NewDatabase(t))
				form := endpoint.form
				if tc.body {
					form = withBodyCredentials(form)
				}

				rr := postWithAuthorization(handler, endpoint.path, form, tc.fields...)

				assertErrorAnswer(t, rr, http.StatusBadRequest, "invalid_request", twoAuthorizationFieldsDescription)
				assert.Empty(t, rr.Header().Get("WWW-Authenticate"))
			})
		}
	}
}

// Decision 12: a Basic header with no credentials, or with credentials that are not base64 or have no
// colon, is refused 401 invalid_client with the Basic challenge, and the body is not consulted: its
// credentials neither authenticate the client nor make the request one of two methods. The refusal
// writes the endpoint's Warn record, as every invalid_client does, naming no client.
func TestClientAuthentication_UnreadableBasicCredentialsAreInvalidClient(t *testing.T) {
	cases := []struct {
		name  string
		field string
	}{
		{"a bare Basic", "Basic"},
		{"a bare lowercase basic", "basic"},
		{"Basic and spaces alone", "Basic   "},
		{"credentials that are not base64", "Basic not-valid-base64!"},
		{"base64 with a space inside", "Basic " + encodedBasic("the-client:the")[:8] + " " + encodedBasic("the-client:the")[8:]},
		{"decoded credentials with no colon", "Basic " + encodedBasic("no-colon-here")},
		{"no colon, after two spaces", "Basic  " + encodedBasic("no-colon-here")},
	}
	for _, endpoint := range headerEndpoints() {
		for _, tc := range cases {
			for _, body := range []bool{false, true} {
				name := endpoint.name + ", " + tc.name
				form := endpoint.form
				if body {
					name += ", body credentials beside it"
					form = withBodyCredentials(form)
				}
				t.Run(name, func(t *testing.T) {
					handler := endpoint.handler(t, datamocks.NewDatabase(t))
					logged := logtest.CaptureSlog(t)

					rr := postWithAuthorization(handler, endpoint.path, form, tc.field)

					assertErrorAnswer(t, rr, http.StatusUnauthorized, "invalid_client", unreadableBasicDescription)
					assert.Equal(t, `Basic realm="goiabada"`, rr.Header().Get("WWW-Authenticate"))

					records := logged.Records()
					require.Len(t, records, 1, logged.Text())
					assert.Equal(t, slog.LevelWarn, records[0].Level)
					assert.Equal(t, endpoint.warning, records[0].Message)
					assert.Equal(t, unreadableBasicDescription, records[0].Attrs["reason"])
					assert.Empty(t, records[0].Attrs["client_identifier"])
					assert.Equal(t, "client_secret_basic", records[0].Attrs["client_auth_method"])
				})
			}
		}
	}
}

// An Authorization header of another scheme stays ignored, and the body's credentials are read
// (decision 12's rejected alternative): a Bearer header beside a body naming no client is the body's
// missing client_id, not an unreadable Basic header. So is a scheme whose name only begins with Basic.
func TestClientAuthentication_AnotherSchemeIsIgnored(t *testing.T) {
	for _, endpoint := range headerEndpoints() {
		for _, field := range []string{"Bearer a-token", "Basicx " + encodedBasic("a:b")} {
			t.Run(endpoint.name+", "+field, func(t *testing.T) {
				handler := endpoint.handler(t, datamocks.NewDatabase(t))

				rr := postWithAuthorization(handler, endpoint.path, endpoint.form, field)

				assertErrorAnswer(t, rr, http.StatusBadRequest, "invalid_request", "Missing required client_id parameter.")
			})
		}
	}
}

// Decision 8: one or more spaces may follow Basic, whatever the scheme's case, and the header's
// credentials are the client's. Each endpoint gets past client authentication: the token endpoint's
// validator is handed the header's identifier and secret, and revocation and introspection, which
// authenticate the caller themselves, find it and go on to the missing token.
func TestClientAuthentication_SpacesAfterBasic(t *testing.T) {
	encrypted, err := testDataCipher.Encrypt(headerClientSecret)
	require.NoError(t, err)
	client := &record.Client{Id: 31, ClientIdentifier: headerClientIdentifier, Enabled: true,
		ClientCredentialsEnabled: true, ClientSecretEncrypted: encrypted}
	credentials := encodedBasic(headerClientIdentifier + ":" + headerClientSecret)

	fields := map[string]string{
		"one space":                   "Basic " + credentials,
		"two spaces":                  "Basic  " + credentials,
		"three spaces":                "Basic   " + credentials,
		"two spaces, uppercase BASIC": "BASIC  " + credentials,
	}
	for name, field := range fields {
		t.Run("token, "+name, func(t *testing.T) {
			validator := handlersmocks.NewTokenValidator(t)
			validator.On("ValidateTokenRequest", mock.Anything, mock.Anything,
				mock.MatchedBy(func(input *protocolvalidation.ValidateTokenRequestInput) bool {
					return input.ClientId == headerClientIdentifier && input.ClientSecret == headerClientSecret
				})).Return(nil, oauth.NewErrorDetailWithHTTPStatus("unauthorized_client", "Stops here.", http.StatusBadRequest)).Once()
			handler := HandleTokenPost(render.New(nil, nil), datamocks.NewDatabase(t), handlersmocks.NewTokenIssuer(t),
				validator, handlersmocks.NewAuditLogger(t), noCredentialFailures{}, testTokenMetrics())

			rr := postWithAuthorization(handler, "/auth/token", url.Values{"grant_type": {"client_credentials"}}, field)

			assertErrorAnswer(t, rr, http.StatusBadRequest, "unauthorized_client", "Stops here.")
		})

		for _, endpoint := range headerEndpoints()[1:] {
			t.Run(endpoint.name+", "+name, func(t *testing.T) {
				database := datamocks.NewDatabase(t)
				database.On("GetClientByClientIdentifier", mock.Anything, mock.Anything, headerClientIdentifier).
					Return(client, nil).Once()
				handler := endpoint.handler(t, database)

				rr := postWithAuthorization(handler, endpoint.path, url.Values{}, field)

				assertErrorAnswer(t, rr, http.StatusBadRequest, "invalid_request", "Missing required token parameter.")
			})
		}
	}
}
