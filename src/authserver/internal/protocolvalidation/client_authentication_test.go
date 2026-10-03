package protocolvalidation

import (
	"context"
	"database/sql"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/leodip/goiabada/authserver/internal/data/mocks"
	"github.com/leodip/goiabada/authserver/internal/oidc"
	"github.com/leodip/goiabada/authserver/internal/protocolvalidation/mocks"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/core/oauth"
)

// TestValidateTokenRequest_ClientAuthentication is authenticateClient's table, one row per grant
// that authenticates and per way a secret can be wrong. It is driven through the exported method
// (seam 2), so every row also proves where in its grant's order authentication sits: each grant's
// fixture arms only the reads that come before it, and a row that passes arms the one read or
// refusal that comes next.
//
// Every grant answers a wrong secret with the one text, and every invalid_client carries
// BasicChallenge. How the secret arrived, the Authorization header or the form body, no longer
// reaches the validator, so it is not a column here; the handler's and the integration tier's
// cases cover both transports (#437).
func TestValidateTokenRequest_ClientAuthentication(t *testing.T) {
	const theSecret = "the_client_secret"

	type refusal struct {
		code        string
		description string
		status      int
		challenge   string
	}

	// A grant's fixture: arrange arms every read before authentication and fills in the request's
	// grant-specific fields; passed arms what comes after and asserts that authentication let the
	// request through to it.
	type grantFixture struct {
		grant   oidc.GrantType
		arrange func(t *testing.T, mockDB *datamocks.Database, client *record.Client, input *ValidateTokenRequestInput)
		passed  func(t *testing.T, mockDB *datamocks.Database, client *record.Client,
			result TokenGrant, err error)
	}

	refusedWith := func(t *testing.T, err error, want refusal) {
		t.Helper()
		var detail *oauth.ErrorDetail
		require.ErrorAs(t, err, &detail)
		assert.Equal(t, want.code, detail.Code())
		assert.Equal(t, want.description, detail.Description())
		assert.Equal(t, want.status, detail.HTTPStatus())
		assert.Equal(t, want.challenge, detail.WWWAuthenticate())
	}

	fixtures := []grantFixture{
		{
			grant: oidc.GrantTypeAuthorizationCode,
			arrange: func(t *testing.T, mockDB *datamocks.Database, client *record.Client, input *ValidateTokenRequestInput) {
				client.AuthorizationCodeEnabled = true
				input.Code = "the_code"
				input.RedirectURI = "https://example.com/callback"
				// A verifier for a code that stored no challenge: the first refusal below
				// authentication for a confidential client, so a passing row needs no further read.
				input.CodeVerifier = "a_verifier"
				code := &record.Code{
					RedirectURI: "https://example.com/callback",
					Client:      record.Client{ClientIdentifier: client.ClientIdentifier},
					User:        record.User{Enabled: true},
					CreatedAt:   sql.NullTime{Time: time.Now().UTC(), Valid: true},
				}
				mockDB.On("GetCodeByCodeHash", mock.Anything, mock.Anything, mock.Anything, false).Return(code, nil).Once()
				mockDB.On("CodeLoadClient", mock.Anything, mock.Anything, code).Return(nil).Once()
				mockDB.On("CodeLoadUser", mock.Anything, mock.Anything, code).Return(nil).Once()
			},
			passed: func(t *testing.T, _ *datamocks.Database, client *record.Client, result TokenGrant, err error) {
				assert.Nil(t, result)
				if client.IsPublic {
					refusedWith(t, err, refusal{"invalid_grant",
						"This code was issued without PKCE, and public clients are required to use PKCE. Please start a new authorization request with a code_challenge.",
						http.StatusBadRequest, ""})
					return
				}
				refusedWith(t, err, refusal{"invalid_request",
					"The code_verifier parameter was provided, but PKCE was not used during authorization.",
					http.StatusBadRequest, ""})
			},
		},
		{
			grant: oidc.GrantTypeClientCredentials,
			arrange: func(t *testing.T, _ *datamocks.Database, client *record.Client, _ *ValidateTokenRequestInput) {
				client.ClientCredentialsEnabled = true
			},
			passed: func(t *testing.T, mockDB *datamocks.Database, client *record.Client, result TokenGrant, err error) {
				require.NoError(t, err)
				require.NotNil(t, result)
				assert.Same(t, client, grantAs[*ClientCredentialsGrant](t, result).Client)
			},
		},
		{
			grant: oidc.GrantTypeRefreshToken,
			// Authentication is the first thing the refresh grant does; no refresh_token is sent,
			// so the refusal that follows it is the missing parameter.
			arrange: func(*testing.T, *datamocks.Database, *record.Client, *ValidateTokenRequestInput) {},
			passed: func(t *testing.T, _ *datamocks.Database, _ *record.Client, result TokenGrant, err error) {
				assert.Nil(t, result)
				refusedWith(t, err, refusal{"invalid_request", "Missing required refresh_token parameter.",
					http.StatusBadRequest, ""})
			},
		},
		{
			grant: oidc.GrantTypePassword,
			arrange: func(t *testing.T, _ *datamocks.Database, client *record.Client, input *ValidateTokenRequestInput) {
				enabled := true
				client.ResourceOwnerPasswordCredentialsEnabled = &enabled
				input.Username = "someone@example.com"
				input.Password = "a password"
			},
			passed: func(t *testing.T, _ *datamocks.Database, _ *record.Client, result TokenGrant, err error) {
				assert.Nil(t, result)
				refusedWith(t, err, refusal{"invalid_grant", "Invalid resource owner credentials.",
					http.StatusBadRequest, ""})
			},
		},
	}

	type row struct {
		name     string
		isPublic bool
		secret   string
		// want is the refusal authentication gives; nil means it lets the request through.
		want *refusal
	}

	required := &refusal{"invalid_client", "This client is configured as confidential (not public), which means a client_secret is required for authentication. Please provide a valid client_secret to proceed.",
		http.StatusUnauthorized, `Basic realm="goiabada"`}
	// The one wrong-secret answer, for every grant (#437 decision 8).
	wrong := &refusal{"invalid_client", "Client authentication failed. Please review your client_secret.",
		http.StatusUnauthorized, `Basic realm="goiabada"`}
	// A public client that sends a secret is refused without a challenge, because it is not a
	// failed authentication (#245 decision 11).
	superfluous := &refusal{"invalid_request", clientSecretNotRequiredErrorMsg, http.StatusBadRequest, ""}

	rows := []row{
		{"confidential, no secret", false, "", required},
		{"confidential, wrong secret", false, "not_the_secret", wrong},
		// One byte short and one byte over: the comparison is of the whole value.
		{"confidential, secret missing its last byte", false, theSecret[:len(theSecret)-1], wrong},
		{"confidential, secret with a byte appended", false, theSecret + "x", wrong},
		{"confidential, right secret", false, theSecret, nil},
		{"public, superfluous secret", true, "any_secret", superfluous},
		{"public, no secret", true, "", nil},
	}

	for _, f := range fixtures {
		for _, r := range rows {
			t.Run(f.grant.String()+": "+r.name, func(t *testing.T) {
				mockDB := datamocks.NewDatabase(t)
				validator := NewTokenValidator(mockDB, protocolvalidationmocks.NewTokenParser(t),
					protocolvalidationmocks.NewPermissionChecker(t), testDataCipher)

				encryptedSecret, err := testDataCipher.Encrypt(theSecret)
				require.NoError(t, err)
				client := &record.Client{
					Id:                    7,
					ClientIdentifier:      "the_client",
					Enabled:               true,
					IsPublic:              r.isPublic,
					ClientSecretEncrypted: encryptedSecret,
				}
				input := &ValidateTokenRequestInput{
					GrantType:    f.grant,
					ClientId:     "the_client",
					ClientSecret: r.secret,
				}
				settings := &record.Settings{ResourceOwnerPasswordCredentialsEnabled: true}

				mockDB.On("GetClientByClientIdentifier", mock.Anything, mock.Anything, "the_client").Return(client, nil).Once()
				f.arrange(t, mockDB, client, input)

				// The client credentials grant refuses a public client before it authenticates,
				// so its public rows never reach authenticateClient (#437).
				if f.grant == oidc.GrantTypeClientCredentials && r.isPublic {
					result, refusedErr := validator.ValidateTokenRequest(context.Background(), settings, input)
					assert.Nil(t, result)
					refusedWith(t, refusedErr, refusal{"unauthorized_client",
						"A public client is not eligible for the client credentials flow. Please review the client configuration.",
						http.StatusBadRequest, ""})
					return
				}

				want := r.want
				if want == nil && f.grant == oidc.GrantTypeClientCredentials {
					mockDB.On("ClientLoadPermissions", mock.Anything, mock.Anything, client).Return(nil).Once()
					mockDB.On("PermissionsLoadResources", mock.Anything, mock.Anything, mock.Anything).Return(nil).Once()
				}
				if want == nil && f.grant == oidc.GrantTypePassword {
					mockDB.On("GetUserByEmail", mock.Anything, mock.Anything, "someone@example.com").Return(nil, nil).Once()
				}

				result, err := validator.ValidateTokenRequest(context.Background(), settings, input)

				if want == nil {
					f.passed(t, mockDB, client, result, err)
					return
				}
				assert.Nil(t, result)
				refusedWith(t, err, *want)
			})
		}
	}
}

// TestValidateTokenRequest_PreludeInvalidClient pins the checks ValidateTokenRequest runs before it
// looks at the grant: an unknown and a disabled client are invalid_client, 401, with the Basic
// challenge and their descriptions unchanged, for every grant and for a grant the token endpoint
// does not accept, which shows the prelude answers ahead of the grant check. A missing client_id is
// the one prelude refusal that stays invalid_request, 400, with no challenge: no client was named, so
// none failed to authenticate (#437 decision 9).
func TestValidateTokenRequest_PreludeInvalidClient(t *testing.T) {
	const basicChallenge = `Basic realm="goiabada"`

	grants := []oidc.GrantType{
		oidc.GrantTypeAuthorizationCode,
		oidc.GrantTypeClientCredentials,
		oidc.GrantTypeRefreshToken,
		oidc.GrantTypePassword,
		oidc.GrantTypeImplicit,
		"not_a_grant",
	}

	rows := []struct {
		name string
		// client is what the lookup returns; nil is an unknown client.
		client      *record.Client
		code        string
		description string
		status      int
		challenge   string
	}{
		{"unknown client", nil,
			"invalid_client", "Client does not exist.", http.StatusUnauthorized, basicChallenge},
		{"disabled confidential client", &record.Client{ClientIdentifier: "the_client", Enabled: false},
			"invalid_client", "Client is disabled.", http.StatusUnauthorized, basicChallenge},
		// A public client has no secret to fail, and is still refused the same way when disabled.
		{"disabled public client", &record.Client{ClientIdentifier: "the_client", Enabled: false, IsPublic: true},
			"invalid_client", "Client is disabled.", http.StatusUnauthorized, basicChallenge},
		// The passing control: the same client enabled gets past the prelude, to the grant check
		// for a grant the endpoint does not accept.
		{"enabled client, unaccepted grant", &record.Client{ClientIdentifier: "the_client", Enabled: true},
			"unsupported_grant_type", "Unsupported grant_type.", http.StatusBadRequest, ""},
	}

	for _, grant := range grants {
		for _, r := range rows {
			if r.code == "unsupported_grant_type" && grant.AcceptedAtTokenEndpoint() {
				continue
			}
			t.Run(grant.String()+": "+r.name, func(t *testing.T) {
				mockDB := datamocks.NewDatabase(t)
				validator := NewTokenValidator(mockDB, protocolvalidationmocks.NewTokenParser(t),
					protocolvalidationmocks.NewPermissionChecker(t), testDataCipher)
				mockDB.On("GetClientByClientIdentifier", mock.Anything, mock.Anything, "the_client").Return(r.client, nil).Once()

				result, err := validator.ValidateTokenRequest(context.Background(), &record.Settings{},
					&ValidateTokenRequestInput{GrantType: grant, ClientId: "the_client", ClientSecret: "a_secret"})

				assert.Nil(t, result)
				var detail *oauth.ErrorDetail
				require.ErrorAs(t, err, &detail)
				assert.Equal(t, r.code, detail.Code())
				assert.Equal(t, r.description, detail.Description())
				assert.Equal(t, r.status, detail.HTTPStatus())
				assert.Equal(t, r.challenge, detail.WWWAuthenticate())
			})
		}

		t.Run(grant.String()+": missing client_id", func(t *testing.T) {
			mockDB := datamocks.NewDatabase(t)
			validator := NewTokenValidator(mockDB, protocolvalidationmocks.NewTokenParser(t),
				protocolvalidationmocks.NewPermissionChecker(t), testDataCipher)

			result, err := validator.ValidateTokenRequest(context.Background(), &record.Settings{},
				&ValidateTokenRequestInput{GrantType: grant, ClientSecret: "a_secret"})

			assert.Nil(t, result)
			var detail *oauth.ErrorDetail
			require.ErrorAs(t, err, &detail)
			assert.Equal(t, "invalid_request", detail.Code())
			assert.Equal(t, "Missing required client_id parameter.", detail.Description())
			assert.Equal(t, http.StatusBadRequest, detail.HTTPStatus())
			assert.Empty(t, detail.WWWAuthenticate())
		})
	}
}
