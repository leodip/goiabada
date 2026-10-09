package handlers

import (
	"encoding/base64"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/data/mocks"
	"github.com/leodip/goiabada/authserver/internal/handlers/mocks"
	"github.com/leodip/goiabada/authserver/internal/protocolvalidation"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/authserver/internal/reqctx"
	"github.com/leodip/goiabada/core/logging/logtest"
	"github.com/leodip/goiabada/core/oauth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// A token request whose client could not be authenticated is answered 401 invalid_client, and until
// the demo's openid-client sign-in was refused with nothing in the log to say why, the request
// log's status was all the server recorded. Each refusal now writes one Warn record naming the
// reason, the identifier as sent and how the credentials came, and still no audit event: the
// identifier is the caller's own. Driven through the real validator, so the reason is the one the
// client is answered with.
func TestHandleTokenPost_ClientAuthenticationRefusalIsLogged(t *testing.T) {
	secretEncrypted, err := testDataCipher.Encrypt("the-right-secret")
	require.NoError(t, err)
	confidential := &record.Client{Id: 7, ClientIdentifier: "my-service", Enabled: true,
		ClientCredentialsEnabled: true, ClientSecretEncrypted: secretEncrypted}

	cases := []struct {
		name       string
		identifier string
		client     *record.Client
		basic      bool
		secret     string
		reason     string
		method     string
	}{
		{"an unknown client, through the Authorization header", "no-such-client", nil, true, "a-secret",
			"Client does not exist.", "client_secret_basic"},
		{"a wrong secret, in the body", "my-service", confidential, false, "a-wrong-secret",
			"Client authentication failed. Please review your client_secret.", "client_secret_post"},
		{"a confidential client with no secret", "my-service", confidential, false, "",
			"This client is configured as confidential (not public), which means a client_secret is required for authentication. Please provide a valid client_secret to proceed.",
			"none"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			database := datamocks.NewDatabase(t)
			database.On("GetClientByClientIdentifier", mock.Anything, mock.Anything, tc.identifier).
				Return(tc.client, nil).Once()
			jsonWriter := handlersmocks.NewJSONWriter(t)
			jsonWriter.On("JSONError", mock.Anything, mock.Anything, mock.MatchedBy(func(err error) bool {
				var detail *oauth.ErrorDetail
				return errors.As(err, &detail) && detail.Code() == "invalid_client" && detail.Description() == tc.reason
			})).Return().Once()
			// No expectation is set, so any audit event fails the test.
			auditLogger := handlersmocks.NewAuditLogger(t)

			handler := HandleTokenPost(jsonWriter, database, handlersmocks.NewTokenIssuer(t),
				protocolvalidation.NewTokenValidator(database, nil, nil, testDataCipher),
				auditLogger, noCredentialFailures{}, testTokenMetrics())

			form := url.Values{"grant_type": {"client_credentials"}}
			if !tc.basic {
				form.Set("client_id", tc.identifier)
				if tc.secret != "" {
					form.Set("client_secret", tc.secret)
				}
			}
			req := httptest.NewRequest(http.MethodPost, "/auth/token", strings.NewReader(form.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			if tc.basic {
				req.Header.Set("Authorization", "Basic "+
					base64.StdEncoding.EncodeToString([]byte(tc.identifier+":"+tc.secret)))
			}
			req = req.WithContext(reqctx.WithSettings(req.Context(), &record.Settings{Id: 1}))

			logged := logtest.CaptureSlog(t)
			handler.ServeHTTP(httptest.NewRecorder(), req)

			records := logged.Records()
			require.Len(t, records, 1)
			assert.Equal(t, slog.LevelWarn, records[0].Level)
			assert.Equal(t, "client authentication refused at the token endpoint", records[0].Message)
			assert.Equal(t, tc.reason, records[0].Attrs["reason"])
			assert.Equal(t, tc.identifier, records[0].Attrs["client_identifier"])
			assert.Equal(t, tc.method, records[0].Attrs["client_auth_method"])
			assert.Equal(t, "client_credentials", records[0].Attrs["grant_type"])
		})
	}

	// The identifier is whatever the caller sent, so the record carries it escaped: a line break in
	// it cannot start a forged line of its own.
	t.Run("the identifier is escaped", func(t *testing.T) {
		database := datamocks.NewDatabase(t)
		database.On("GetClientByClientIdentifier", mock.Anything, mock.Anything, "app\nlevel=ERROR").
			Return(nil, nil).Once()
		jsonWriter := handlersmocks.NewJSONWriter(t)
		jsonWriter.On("JSONError", mock.Anything, mock.Anything, mock.Anything).Return().Once()

		handler := HandleTokenPost(jsonWriter, database, handlersmocks.NewTokenIssuer(t),
			protocolvalidation.NewTokenValidator(database, nil, nil, testDataCipher),
			handlersmocks.NewAuditLogger(t), noCredentialFailures{}, testTokenMetrics())

		form := url.Values{"grant_type": {"client_credentials"}, "client_id": {"app\nlevel=ERROR"}}
		req := httptest.NewRequest(http.MethodPost, "/auth/token", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req = req.WithContext(reqctx.WithSettings(req.Context(), &record.Settings{Id: 1}))

		logged := logtest.CaptureSlog(t)
		handler.ServeHTTP(httptest.NewRecorder(), req)

		records := logged.Records()
		require.Len(t, records, 1)
		assert.NotContains(t, records[0].Attrs["client_identifier"], "\n")
	})
}
