package protocolvalidation

import (
	"context"
	"database/sql"
	"errors"
	"log/slog"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	datamocks "github.com/leodip/goiabada/authserver/internal/data/mocks"
	protocolvalidationmocks "github.com/leodip/goiabada/authserver/internal/protocolvalidation/mocks"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/authserver/internal/signingkeys"
	"github.com/leodip/goiabada/core/hashutil"
	"github.com/leodip/goiabada/core/logging/logtest"
)

// A client set to "Require DPoP for token requests" is refused a token request that carries no DPoP
// proof, 400 invalid_dpop_proof (RFC 9449 section 5.2: the authorization server MUST reject token
// requests from such a client that do not contain the DPoP header), with a Warn record, as a refused
// client authentication is (#42 decision 12). On every grant it is decided right after the client
// authenticates: a wrong secret is still invalid_client, so a stranger cannot learn the setting, and
// nothing of the grant is looked at first, so no password is compared and no refresh token read.
// A request with a proof goes on to the grant's own next check.

var requiresDPoPRefusal = wantRefusal{
	code:        "invalid_dpop_proof",
	description: "This client requires a DPoP proof with every token request.",
	status:      http.StatusBadRequest,
}

// requirementGrant is one grant as a client requiring DPoP asks for it: the input, the reads the
// grant makes before it authenticates the client, and the refusal its next check gives a request
// that carries a proof, which every case below arranges to fail.
type requirementGrant struct {
	name    string
	public  bool
	input   ValidateTokenRequestInput
	arrange func(mockDB *datamocks.Database, parser *protocolvalidationmocks.TokenParser, client *record.Client)
	// afterTheRequirement is the refusal a request with a proof meets next.
	afterTheRequirement wantRefusal
}

func TestValidateTokenRequest_AClientRequiringDPoPIsRefusedWithoutAProof(t *testing.T) {
	const clientSecret = "client_secret"
	ropcOn := true
	stopped := errors.New("the grant's next read")

	grants := []requirementGrant{
		{
			name:  "client_credentials",
			input: ValidateTokenRequestInput{GrantType: "client_credentials"},
			arrange: func(mockDB *datamocks.Database, _ *protocolvalidationmocks.TokenParser, client *record.Client) {
				client.ClientCredentialsEnabled = true
				mockDB.On("ClientLoadPermissions", mock.Anything, mock.Anything, client).Return(stopped).Maybe()
			},
		},
		{
			name: "authorization_code",
			input: ValidateTokenRequestInput{GrantType: "authorization_code", Code: "the_code",
				RedirectURI: "https://example.com/callback"},
			arrange: func(mockDB *datamocks.Database, _ *protocolvalidationmocks.TokenParser, client *record.Client) {
				code := &record.Code{Id: 11, ClientId: client.Id, RedirectURI: "https://example.com/callback",
					CodeChallenge: sql.NullString{String: "challenge", Valid: true}}
				mockDB.On("GetCodeByCodeHash", mock.Anything, mock.Anything, hashutil.HashString("the_code"), false).Return(code, nil).Once()
				mockDB.On("CodeLoadClient", mock.Anything, mock.Anything, code).
					Run(func(args mock.Arguments) { args.Get(2).(*record.Code).Client = *client }).Return(nil).Once()
				mockDB.On("CodeLoadUser", mock.Anything, mock.Anything, code).Return(nil).Once()
			},
			// The verifier is left out, so a request with a proof meets the PKCE check next.
			afterTheRequirement: wantRefusal{code: "invalid_request", description: "Missing required code_verifier parameter.",
				status: http.StatusBadRequest},
		},
		{
			name:  "refresh_token",
			input: ValidateTokenRequestInput{GrantType: "refresh_token", RefreshToken: "the_refresh_token"},
			arrange: func(_ *datamocks.Database, parser *protocolvalidationmocks.TokenParser, _ *record.Client) {
				parser.On("DecodeAndValidateTokenString", mock.Anything, "the_refresh_token", true).
					Return(nil, signingkeys.ErrTokenRefused).Maybe()
			},
			afterTheRequirement: wantRefusal{code: "invalid_grant", description: "The refresh token is invalid.",
				status: http.StatusBadRequest},
		},
		{
			name:   "refresh_token, a public client",
			public: true,
			input:  ValidateTokenRequestInput{GrantType: "refresh_token", RefreshToken: "the_refresh_token"},
			arrange: func(_ *datamocks.Database, parser *protocolvalidationmocks.TokenParser, _ *record.Client) {
				parser.On("DecodeAndValidateTokenString", mock.Anything, "the_refresh_token", true).
					Return(nil, signingkeys.ErrTokenRefused).Maybe()
			},
			afterTheRequirement: wantRefusal{code: "invalid_grant", description: "The refresh token is invalid.",
				status: http.StatusBadRequest},
		},
		{
			name:  "password",
			input: ValidateTokenRequestInput{GrantType: "password", Username: "someone@example.com", Password: "a password"},
			arrange: func(_ *datamocks.Database, _ *protocolvalidationmocks.TokenParser, client *record.Client) {
				client.ResourceOwnerPasswordCredentialsEnabled = &ropcOn
				// A mandatory second factor, which the password grant refuses next, before any
				// account is looked up.
				client.AuthorizationCodeEnabled = true
				client.DefaultAcrLevel = record.AcrLevel2Mandatory
			},
			afterTheRequirement: wantRefusal{code: "unauthorized_client", status: http.StatusBadRequest,
				description: "Resource owner password credentials grant is not available for a client whose " +
					"default ACR level is urn:goiabada:level2_mandatory. Please use the authorization code flow instead."},
		},
	}

	attempts := []struct {
		name        string
		thumbprint  string
		wrongSecret bool
	}{
		{name: "no proof"},
		{name: "no proof and the wrong secret", wrongSecret: true},
		{name: "a proof", thumbprint: boundKey},
	}

	for _, g := range grants {
		for _, a := range attempts {
			if g.public && a.wrongSecret {
				continue
			}
			t.Run(g.name+", "+a.name, func(t *testing.T) {
				mockDB := datamocks.NewDatabase(t)
				parser := protocolvalidationmocks.NewTokenParser(t)
				validator := NewTokenValidator(mockDB, parser, protocolvalidationmocks.NewPermissionChecker(t), testDataCipher)

				client := &record.Client{Id: 1, ClientIdentifier: "requires-dpop", Enabled: true,
					AuthorizationCodeEnabled: true, IsPublic: g.public, DPoPBoundAccessTokens: true}
				input := g.input
				input.ClientId = client.ClientIdentifier
				input.DPoPThumbprint = a.thumbprint
				if !g.public {
					encrypted, err := testDataCipher.Encrypt(clientSecret)
					require.NoError(t, err)
					client.ClientSecretEncrypted = encrypted
					input.ClientSecret = clientSecret
					if a.wrongSecret {
						input.ClientSecret = "not_the_secret"
					}
				}
				mockDB.On("GetClientByClientIdentifier", mock.Anything, mock.Anything, client.ClientIdentifier).Return(client, nil).Once()
				g.arrange(mockDB, parser, client)

				capture := logtest.CaptureSlog(t)
				grant, err := validator.ValidateTokenRequest(context.Background(), &record.Settings{}, &input)
				assert.Nil(t, grant)

				var records []logtest.CapturedRecord
				for _, r := range capture.Records() {
					if r.Message == "token request refused: the client requires dpop" {
						records = append(records, r)
					}
				}

				switch {
				case a.wrongSecret:
					assertRefusal(t, err, wantRefusal{code: "invalid_client",
						description: "Client authentication failed. Please review your client_secret.", status: http.StatusUnauthorized})
					assert.Empty(t, records)
				case a.thumbprint == "":
					assertRefusal(t, err, requiresDPoPRefusal)
					require.Len(t, records, 1, "one Warn record of the refusal")
					assert.Equal(t, slog.LevelWarn, records[0].Level)
					assert.Equal(t, "requires-dpop", records[0].Attrs["client_identifier"])
					assert.Equal(t, string(g.input.GrantType), records[0].Attrs["grant_type"])
					parser.AssertNotCalled(t, "DecodeAndValidateTokenString", mock.Anything, mock.Anything, mock.Anything)
					mockDB.AssertNotCalled(t, "ClientLoadPermissions", mock.Anything, mock.Anything, mock.Anything)
					mockDB.AssertNotCalled(t, "GetUserByEmail", mock.Anything, mock.Anything, mock.Anything)
				default:
					assert.Empty(t, records, "a request with a proof meets the grant's own checks")
					if g.afterTheRequirement.code == "" {
						assert.ErrorIs(t, err, stopped)
						return
					}
					assertRefusal(t, err, g.afterTheRequirement)
				}
			})
		}
	}
}

// A client that does not require DPoP is answered as before without a proof: the grant's own next
// check is what refuses these requests.
func TestValidateTokenRequest_AClientNotRequiringDPoPNeedsNoProof(t *testing.T) {
	mockDB := datamocks.NewDatabase(t)
	parser := protocolvalidationmocks.NewTokenParser(t)
	validator := NewTokenValidator(mockDB, parser, protocolvalidationmocks.NewPermissionChecker(t), testDataCipher)
	client := &record.Client{Id: 1, ClientIdentifier: "no-dpop", Enabled: true, IsPublic: true}
	mockDB.On("GetClientByClientIdentifier", mock.Anything, mock.Anything, "no-dpop").Return(client, nil).Once()
	parser.On("DecodeAndValidateTokenString", mock.Anything, "the_refresh_token", true).
		Return(nil, signingkeys.ErrTokenRefused).Once()

	grant, err := validator.ValidateTokenRequest(context.Background(), &record.Settings{},
		&ValidateTokenRequestInput{GrantType: "refresh_token", ClientId: "no-dpop", RefreshToken: "the_refresh_token"})

	assert.Nil(t, grant)
	assertRefusal(t, err, wantRefusal{code: "invalid_grant", description: "The refresh token is invalid.", status: http.StatusBadRequest})
}
