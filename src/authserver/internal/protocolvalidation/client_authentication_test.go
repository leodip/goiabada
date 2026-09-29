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

	mocks_data "github.com/leodip/goiabada/authserver/internal/data/mocks"
	"github.com/leodip/goiabada/authserver/internal/models"
	"github.com/leodip/goiabada/authserver/internal/oidc"
	mocks_protocolvalidation "github.com/leodip/goiabada/authserver/internal/protocolvalidation/mocks"
	"github.com/leodip/goiabada/core/customerrors"
)

// TestValidateTokenRequest_ClientAuthentication is authenticateClient's table, one row per grant
// that authenticates, per way a secret can be wrong, and per way it can arrive (the Authorization
// header or the form body). It is driven through the exported method (seam 2), so every row also
// proves where in its grant's order authentication sits: each grant's fixture arms only the reads
// that come before it, and a row that passes arms the one read or refusal that comes next.
//
// The texts are today's, two of them per grant pair: client credentials and password answer a
// wrong secret with the short one, authorization code and refresh token with the long one (#437).
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
		grant          oidc.GrantType
		wrongSecretMsg string
		arrange        func(t *testing.T, mockDB *mocks_data.Database, client *models.Client, input *ValidateTokenRequestInput)
		passed         func(t *testing.T, mockDB *mocks_data.Database, client *models.Client,
			result TokenGrant, err error)
	}

	refusedWith := func(t *testing.T, err error, want refusal) {
		t.Helper()
		var detail *customerrors.ErrorDetail
		require.ErrorAs(t, err, &detail)
		assert.Equal(t, want.code, detail.GetCode())
		assert.Equal(t, want.description, detail.GetDescription())
		assert.Equal(t, want.status, detail.GetHttpStatusCode())
		assert.Equal(t, want.challenge, detail.GetWWWAuthenticate())
	}

	fixtures := []grantFixture{
		{
			grant:          oidc.GrantTypeAuthorizationCode,
			wrongSecretMsg: "Client authentication failed. Please review your client_secret.",
			arrange: func(t *testing.T, mockDB *mocks_data.Database, client *models.Client, input *ValidateTokenRequestInput) {
				client.AuthorizationCodeEnabled = true
				input.Code = "the_code"
				input.RedirectURI = "https://example.com/callback"
				// A verifier for a code that stored no challenge: the first refusal below
				// authentication for a confidential client, so a passing row needs no further read.
				input.CodeVerifier = "a_verifier"
				code := &models.Code{
					RedirectURI: "https://example.com/callback",
					Client:      models.Client{ClientIdentifier: client.ClientIdentifier},
					User:        models.User{Enabled: true},
					CreatedAt:   sql.NullTime{Time: time.Now().UTC(), Valid: true},
				}
				mockDB.On("GetCodeByCodeHash", mock.Anything, mock.Anything, mock.Anything, false).Return(code, nil).Once()
				mockDB.On("CodeLoadClient", mock.Anything, mock.Anything, code).Return(nil).Once()
				mockDB.On("CodeLoadUser", mock.Anything, mock.Anything, code).Return(nil).Once()
			},
			passed: func(t *testing.T, _ *mocks_data.Database, client *models.Client, result TokenGrant, err error) {
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
			grant:          oidc.GrantTypeClientCredentials,
			wrongSecretMsg: "Client authentication failed.",
			arrange: func(t *testing.T, _ *mocks_data.Database, client *models.Client, _ *ValidateTokenRequestInput) {
				client.ClientCredentialsEnabled = true
			},
			passed: func(t *testing.T, mockDB *mocks_data.Database, client *models.Client, result TokenGrant, err error) {
				require.NoError(t, err)
				require.NotNil(t, result)
				assert.Same(t, client, grantAs[*ClientCredentialsGrant](t, result).Client)
			},
		},
		{
			grant:          oidc.GrantTypeRefreshToken,
			wrongSecretMsg: "Client authentication failed. Please review your client_secret.",
			// Authentication is the first thing the refresh grant does; no refresh_token is sent,
			// so the refusal that follows it is the missing parameter.
			arrange: func(*testing.T, *mocks_data.Database, *models.Client, *ValidateTokenRequestInput) {},
			passed: func(t *testing.T, _ *mocks_data.Database, _ *models.Client, result TokenGrant, err error) {
				assert.Nil(t, result)
				refusedWith(t, err, refusal{"invalid_request", "Missing required refresh_token parameter.",
					http.StatusBadRequest, ""})
			},
		},
		{
			grant:          oidc.GrantTypePassword,
			wrongSecretMsg: "Client authentication failed.",
			arrange: func(t *testing.T, _ *mocks_data.Database, client *models.Client, input *ValidateTokenRequestInput) {
				enabled := true
				client.ResourceOwnerPasswordCredentialsEnabled = &enabled
				input.Username = "someone@example.com"
				input.Password = "a password"
			},
			passed: func(t *testing.T, _ *mocks_data.Database, _ *models.Client, result TokenGrant, err error) {
				assert.Nil(t, result)
				refusedWith(t, err, refusal{"invalid_grant", "Invalid resource owner credentials.",
					http.StatusBadRequest, ""})
			},
		},
	}

	type row struct {
		name      string
		isPublic  bool
		secret    string
		basicAuth bool
		// want is the refusal authentication gives; nil means it lets the request through.
		want func(f grantFixture) *refusal
	}

	required := func(challenge string) func(grantFixture) *refusal {
		return func(grantFixture) *refusal {
			return &refusal{"invalid_client", clientSecretRequiredErrorMsg, http.StatusUnauthorized, challenge}
		}
	}
	wrong := func(challenge string) func(grantFixture) *refusal {
		return func(f grantFixture) *refusal {
			return &refusal{"invalid_client", f.wrongSecretMsg, http.StatusUnauthorized, challenge}
		}
	}
	superfluous := func(grantFixture) *refusal {
		return &refusal{"invalid_request", clientSecretNotRequiredErrorMsg, http.StatusBadRequest, ""}
	}
	through := func(grantFixture) *refusal { return nil }

	rows := []row{
		{"confidential, no secret, form body", false, "", false, required("")},
		{"confidential, no secret, Basic", false, "", true, required("Basic")},
		{"confidential, wrong secret, form body", false, "not_the_secret", false, wrong("")},
		{"confidential, wrong secret, Basic", false, "not_the_secret", true, wrong("Basic")},
		// One byte short and one byte over: the comparison is of the whole value.
		{"confidential, secret missing its last byte", false, theSecret[:len(theSecret)-1], false, wrong("")},
		{"confidential, secret with a byte appended", false, theSecret + "x", false, wrong("")},
		{"confidential, right secret, form body", false, theSecret, false, through},
		{"confidential, right secret, Basic", false, theSecret, true, through},
		// A public client that sends a secret is refused whichever way it arrived, and without a
		// challenge, because it is not a failed authentication (#245 decision 11).
		{"public, superfluous secret, form body", true, "any_secret", false, superfluous},
		{"public, superfluous secret, Basic", true, "any_secret", true, superfluous},
		{"public, no secret", true, "", false, through},
	}

	for _, f := range fixtures {
		for _, r := range rows {
			t.Run(f.grant.String()+": "+r.name, func(t *testing.T) {
				mockDB := mocks_data.NewDatabase(t)
				validator := NewTokenValidator(mockDB, mocks_protocolvalidation.NewTokenParser(t),
					mocks_protocolvalidation.NewPermissionChecker(t), testDataCipher)

				encryptedSecret, err := testDataCipher.Encrypt(theSecret)
				require.NoError(t, err)
				client := &models.Client{
					Id:                    7,
					ClientIdentifier:      "the_client",
					Enabled:               true,
					IsPublic:              r.isPublic,
					ClientSecretEncrypted: encryptedSecret,
				}
				input := &ValidateTokenRequestInput{
					GrantType:     f.grant,
					ClientId:      "the_client",
					ClientSecret:  r.secret,
					UsedBasicAuth: r.basicAuth,
				}
				settings := &models.Settings{ResourceOwnerPasswordCredentialsEnabled: true}

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

				want := r.want(f)
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
