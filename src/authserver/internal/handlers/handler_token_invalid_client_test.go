package handlers

import (
	"encoding/base64"
	"encoding/json"
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
	"github.com/leodip/goiabada/authserver/internal/protocolvalidation"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/authserver/internal/render"
)

// TestHandleTokenPost_InvalidClientOnTheWire is the token endpoint's invalid_client as a client
// receives it, for both ways a client can present its credentials: 401, WWW-Authenticate: Basic
// realm="goiabada" and the description, whether the credentials came in the Authorization header or
// in the form body. Before #437 a form-body caller got no challenge, a Basic caller a bare "Basic",
// and an unknown or disabled client 400 with another error code.
//
// The endpoint runs with the real writer and the real validator, the database mocked beneath it,
// because the claim is the bytes on the wire: a mock writer proves the detail was handed over, not
// that its challenge became a header. The validator's own table covers every refusal's detail; this
// covers that each shape reaches the wire from either transport (decision 9).
func TestHandleTokenPost_InvalidClientOnTheWire(t *testing.T) {
	const theSecret = "the_client_secret"
	encryptedSecret, err := testDataCipher.Encrypt(theSecret)
	require.NoError(t, err)

	confidential := func(enabled bool) *record.Client {
		return &record.Client{Id: 7, ClientIdentifier: "the_client", Enabled: enabled,
			ClientCredentialsEnabled: true, ClientSecretEncrypted: encryptedSecret}
	}

	rows := []struct {
		name   string
		client *record.Client
		secret string
		want   string
	}{
		{"unknown client", nil, theSecret, "Client does not exist."},
		{"disabled client", confidential(false), theSecret, "Client is disabled."},
		{"wrong secret", confidential(true), "not_the_secret", "Client authentication failed. Please review your client_secret."},
	}

	for _, r := range rows {
		for _, basic := range []bool{false, true} {
			transport := "form body"
			if basic {
				transport = "Basic"
			}
			t.Run(r.name+", "+transport, func(t *testing.T) {
				validatorDB := datamocks.NewDatabase(t)
				validatorDB.On("GetClientByClientIdentifier", mock.Anything, mock.Anything, "the_client").
					Return(r.client, nil).Once()
				handler := HandleTokenPost(render.New(nil), datamocks.NewDatabase(t),
					handlersmocks.NewTokenIssuer(t),
					protocolvalidation.NewTokenValidator(validatorDB, nil, nil, testDataCipher),
					handlersmocks.NewAuditLogger(t), noCredentialFailures{}, testTokenMetrics())

				form := url.Values{"grant_type": {"client_credentials"}}
				if !basic {
					form.Set("client_id", "the_client")
					form.Set("client_secret", r.secret)
				}
				req, err := http.NewRequest("POST", "/auth/token", strings.NewReader(form.Encode()))
				require.NoError(t, err)
				req = withSettings(req, &record.Settings{})
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				if basic {
					req.Header.Set("Authorization", "Basic "+
						base64.StdEncoding.EncodeToString([]byte("the_client:"+r.secret)))
				}

				rr := httptest.NewRecorder()
				handler.ServeHTTP(rr, req)

				assert.Equal(t, http.StatusUnauthorized, rr.Code)
				assert.Equal(t, `Basic realm="goiabada"`, rr.Header().Get("WWW-Authenticate"))
				var body map[string]string
				require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &body), "the body must be JSON: %q", rr.Body.String())
				assert.Equal(t, "invalid_client", body["error"])
				assert.Equal(t, r.want, body["error_description"])
			})
		}
	}

	// The control: a request naming no client stays invalid_request, 400, with no challenge, since
	// no client failed to authenticate.
	t.Run("missing client_id", func(t *testing.T) {
		handler := HandleTokenPost(render.New(nil), datamocks.NewDatabase(t),
			handlersmocks.NewTokenIssuer(t),
			protocolvalidation.NewTokenValidator(datamocks.NewDatabase(t), nil, nil, testDataCipher),
			handlersmocks.NewAuditLogger(t), noCredentialFailures{}, testTokenMetrics())

		req, err := http.NewRequest("POST", "/auth/token", strings.NewReader("grant_type=client_credentials"))
		require.NoError(t, err)
		req = withSettings(req, &record.Settings{})
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusBadRequest, rr.Code)
		assert.Empty(t, rr.Header().Get("WWW-Authenticate"))
		var body map[string]string
		require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &body))
		assert.Equal(t, "invalid_request", body["error"])
	})
}
