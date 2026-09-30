package protocolvalidation

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	mocks_data "github.com/leodip/goiabada/authserver/internal/data/mocks"
	"github.com/leodip/goiabada/authserver/internal/models"
	mocks_protocolvalidation "github.com/leodip/goiabada/authserver/internal/protocolvalidation/mocks"
	"github.com/leodip/goiabada/core/customerrors"
	"github.com/leodip/goiabada/core/oauth"
)

// accountState is what has happened to a grant's user, or to the code itself, since the grant was
// issued. untouched is the control every other state is compared with.
type accountState string

const (
	stateUntouched  accountState = "untouched"
	stateDisabled   accountState = "user disabled"
	stateSuperseded accountState = "generation moved"
	stateExpired    accountState = "code expired"
)

// wantRefusal is one refusal as the client reads it, plus whether it is the disabled-user wrapper
// the handler writes AuditUserDisabled from.
type wantRefusal struct {
	code         string
	description  string
	status       int
	userDisabled bool
}

// assertRefusal checks err is exactly want: the code, the description, the status, and whether the
// user's state is what produced it.
func assertRefusal(t *testing.T, err error, want wantRefusal) {
	t.Helper()

	var detail *customerrors.ErrorDetail
	require.ErrorAs(t, err, &detail)
	assert.Equal(t, want.code, detail.GetCode())
	assert.Equal(t, want.description, detail.GetDescription())
	assert.Equal(t, want.status, detail.GetHttpStatusCode())

	var disabled *UserDisabledError
	assert.Equal(t, want.userDisabled, errors.As(err, &disabled),
		"whether the refusal is the disabled-user wrapper")
}

// TestValidateTokenRequest_CodeGrantAccountStateAfterProof is #137's acceptance on the code grant:
// a code exchange that has not proved it may redeem the code gets the same answer whatever became
// of the account or of the code's age, and one that has gets each state's own refusal.
//
// Every row of a proof that fails expects exactly the refusal the untouched row gets, so a check
// moved back above client authentication or PKCE changes that row's answer to the state's own
// refusal and fails it. The rows with the right credentials are the negative controls' other half:
// they show each state IS refused once reached, so the failing-proof rows are not passing merely
// because the state is ignored.
func TestValidateTokenRequest_CodeGrantAccountStateAfterProof(t *testing.T) {
	const (
		clientSecret = "client_secret"
		verifier     = "code_verifier"
		redirectURI  = "https://example.com/callback"
	)

	type proof struct {
		name         string
		clientSecret string
		codeVerifier string
		// refusal is what the request is answered with whatever the state, when it fails
		// the proof. Nil means the request proves it may redeem the code.
		refusal *wantRefusal
	}

	proofs := []proof{
		{
			name: "wrong verifier", clientSecret: clientSecret, codeVerifier: "not_the_verifier",
			refusal: &wantRefusal{code: "invalid_grant", description: "Invalid code_verifier (PKCE).", status: http.StatusBadRequest},
		},
		{
			name: "missing verifier", clientSecret: clientSecret, codeVerifier: "",
			refusal: &wantRefusal{code: "invalid_request", description: "Missing required code_verifier parameter.", status: http.StatusBadRequest},
		},
		{
			name: "wrong secret", clientSecret: "not_the_secret", codeVerifier: verifier,
			refusal: &wantRefusal{code: "invalid_client", description: "Client authentication failed. Please review your client_secret.", status: http.StatusUnauthorized},
		},
		{
			name: "missing secret", clientSecret: "", codeVerifier: verifier,
			refusal: &wantRefusal{code: "invalid_client", description: "This client is configured as confidential (not public), which means a client_secret is required for authentication. Please provide a valid client_secret to proceed.", status: http.StatusUnauthorized},
		},
		{name: "right secret and verifier", clientSecret: clientSecret, codeVerifier: verifier},
	}

	// Each state's own answer once the request has proved it may redeem the code. Nil means the
	// code is redeemed.
	stateRefusals := map[accountState]*wantRefusal{
		stateUntouched:  nil,
		stateDisabled:   {code: "invalid_grant", description: "Code is invalid.", status: http.StatusBadRequest, userDisabled: true},
		stateSuperseded: {code: "invalid_grant", description: "Code is invalid.", status: http.StatusBadRequest},
		stateExpired:    {code: "invalid_grant", description: "Code has expired.", status: http.StatusBadRequest},
	}

	for _, state := range []accountState{stateUntouched, stateDisabled, stateSuperseded, stateExpired} {
		for _, p := range proofs {
			t.Run(string(state)+", "+p.name, func(t *testing.T) {
				mockDB := mocks_data.NewDatabase(t)
				validator := NewTokenValidator(mockDB, mocks_protocolvalidation.NewTokenParser(t),
					mocks_protocolvalidation.NewPermissionChecker(t), testDataCipher)

				clientSecretEncrypted, err := testDataCipher.Encrypt(clientSecret)
				require.NoError(t, err)
				client := &models.Client{
					Id:                       1,
					ClientIdentifier:         "client1",
					Enabled:                  true,
					AuthorizationCodeEnabled: true,
					IsPublic:                 false,
					ClientSecretEncrypted:    clientSecretEncrypted,
				}

				// No session identifier, so the ownership check reads nothing; the subject
				// here is the order of the account-state checks, not ownership.
				codeEntity := &models.Code{
					CodeHash:            "hash_of_valid_code",
					RedirectURI:         redirectURI,
					CodeChallenge:       sql.NullString{String: oauth.GeneratePKCECodeChallenge(verifier), Valid: true},
					AuthStateGeneration: 3,
					UserId:              7,
					Client:              models.Client{ClientIdentifier: "client1"},
					User:                models.User{Id: 7, Enabled: true, AuthStateGeneration: 3},
					CreatedAt:           sql.NullTime{Time: time.Now().UTC(), Valid: true},
				}
				switch state {
				case stateDisabled:
					codeEntity.User.Enabled = false
				case stateSuperseded:
					codeEntity.User.AuthStateGeneration = 4
				case stateExpired:
					codeEntity.CreatedAt.Time = time.Now().UTC().Add(-2 * time.Minute)
				}

				mockDB.On("GetClientByClientIdentifier", mock.Anything, mock.Anything, "client1").Return(client, nil).Once()
				mockDB.On("GetCodeByCodeHash", mock.Anything, mock.Anything, mock.AnythingOfType("string"), false).
					Return(codeEntity, nil).Once()
				mockDB.On("CodeLoadClient", mock.Anything, mock.Anything, codeEntity).Return(nil).Once()
				mockDB.On("CodeLoadUser", mock.Anything, mock.Anything, codeEntity).Return(nil).Once()
				expectRedirectURIStillRegistered(mockDB, redirectURI)

				grant, err := validator.ValidateTokenRequest(context.Background(), &models.Settings{},
					&ValidateTokenRequestInput{
						GrantType:    "authorization_code",
						ClientId:     "client1",
						ClientSecret: p.clientSecret,
						Code:         "valid_code",
						RedirectURI:  redirectURI,
						CodeVerifier: p.codeVerifier,
					})

				want := p.refusal
				if want == nil {
					want = stateRefusals[state]
				}
				if want == nil {
					require.NoError(t, err)
					assert.Same(t, codeEntity, grantAs[*AuthorizationCodeGrant](t, grant).Code)
					return
				}
				assert.Nil(t, grant)
				assertRefusal(t, err, *want)
			})
		}
	}
}

// TestValidateTokenRequest_RefreshGrantAccountStateAfterProof is #137's acceptance on both shapes of
// refresh token: one presented under a client it does not belong to, or with a wrong secret, gets
// the same answer whatever became of its user, and one presented by its own client gets each
// state's own refusal.
//
// A public client_id is no secret, so the wrong-owner row is the one an attacker holding a stolen
// token can always reach; until #137 it answered "The user account is disabled." for a disabled
// user. The rows are built as the code grant's are: each failing-proof row expects exactly the
// untouched row's refusal, and the own-client rows show each state is refused once reached.
func TestValidateTokenRequest_RefreshGrantAccountStateAfterProof(t *testing.T) {
	const clientSecret = "client_secret"

	type proof struct {
		name             string
		clientIdentifier string
		clientSecret     string
		refusal          *wantRefusal
	}

	proofs := []proof{
		{
			name: "another client's token", clientIdentifier: "client2",
			refusal: &wantRefusal{code: "invalid_request", description: "The refresh token is invalid because it does not belong to the client.", status: http.StatusBadRequest},
		},
		{
			name: "wrong secret", clientIdentifier: "client1", clientSecret: "not_the_secret",
			refusal: &wantRefusal{code: "invalid_client", description: "Client authentication failed. Please review your client_secret.", status: http.StatusUnauthorized},
		},
		{name: "own client", clientIdentifier: "client1", clientSecret: clientSecret},
	}

	// Each state's own answer once the token's own client presents it. The untouched row with the
	// right client is left out: it goes on to the session, consent and permission checks, which
	// this test is not about and the success cases elsewhere in this package cover.
	stateRefusals := map[accountState]wantRefusal{
		stateDisabled:   {code: "invalid_grant", description: "The refresh token is invalid.", status: http.StatusBadRequest, userDisabled: true},
		stateSuperseded: {code: "invalid_grant", description: "The refresh token is invalid because it was superseded.", status: http.StatusBadRequest},
	}

	for _, ropc := range []bool{false, true} {
		shape := "code-descended token"
		if ropc {
			shape = "password grant token"
		}
		for _, state := range []accountState{stateUntouched, stateDisabled, stateSuperseded} {
			for _, p := range proofs {
				if state == stateUntouched && p.refusal == nil {
					continue
				}
				t.Run(shape+", "+string(state)+", "+p.name, func(t *testing.T) {
					mockDB := mocks_data.NewDatabase(t)
					mockTokenParser := mocks_protocolvalidation.NewTokenParser(t)
					validator := NewTokenValidator(mockDB, mockTokenParser,
						mocks_protocolvalidation.NewPermissionChecker(t), testDataCipher)

					clientSecretEncrypted, err := testDataCipher.Encrypt(clientSecret)
					require.NoError(t, err)
					clients := map[string]*models.Client{
						// The token's own client, confidential.
						"client1": {Id: 1, ClientIdentifier: "client1", Enabled: true,
							AuthorizationCodeEnabled: true, ClientSecretEncrypted: clientSecretEncrypted},
						// Any public client: it authenticates with nothing, which is what
						// makes the ownership check the whole of the proof for it.
						"client2": {Id: 2, ClientIdentifier: "client2", Enabled: true,
							AuthorizationCodeEnabled: true, IsPublic: true},
					}

					user := models.User{Id: 7, Enabled: true, AuthStateGeneration: 3}
					switch state {
					case stateDisabled:
						user.Enabled = false
					case stateSuperseded:
						user.AuthStateGeneration = 4
					}

					refreshToken := &models.RefreshToken{RefreshTokenJti: "the_jti", AuthStateGeneration: 3}
					if ropc {
						refreshToken.ClientId = sql.NullInt64{Int64: 1, Valid: true}
						refreshToken.UserId = sql.NullInt64{Int64: 7, Valid: true}
						refreshToken.User = user
					} else {
						refreshToken.CodeId = sql.NullInt64{Int64: 11, Valid: true}
						refreshToken.Code = models.Code{Id: 11, ClientId: 1, UserId: 7, User: user}
					}

					mockDB.On("GetClientByClientIdentifier", mock.Anything, mock.Anything, p.clientIdentifier).
						Return(clients[p.clientIdentifier], nil).Once()
					mockTokenParser.On("DecodeAndValidateTokenString", mock.Anything, "the_refresh_token", true).
						Return(&oauth.JwtToken{Claims: jwt.MapClaims{"jti": "the_jti", "typ": "Refresh"}}, nil).Maybe()
					mockDB.On("GetRefreshTokenByJti", mock.Anything, mock.Anything, "the_jti").Return(refreshToken, nil).Maybe()
					if ropc {
						mockDB.On("RefreshTokenLoadUser", mock.Anything, mock.Anything, refreshToken).Return(nil).Maybe()
						mockDB.On("RefreshTokenLoadClient", mock.Anything, mock.Anything, refreshToken).Return(nil).Maybe()
					} else {
						mockDB.On("RefreshTokenLoadCode", mock.Anything, mock.Anything, refreshToken).Return(nil).Maybe()
						mockDB.On("CodeLoadUser", mock.Anything, mock.Anything, &refreshToken.Code).Return(nil).Maybe()
					}

					grant, err := validator.ValidateTokenRequest(context.Background(), &models.Settings{},
						&ValidateTokenRequestInput{
							GrantType:    "refresh_token",
							ClientId:     p.clientIdentifier,
							ClientSecret: p.clientSecret,
							RefreshToken: "the_refresh_token",
						})

					want := stateRefusals[state]
					if p.refusal != nil {
						want = *p.refusal
					}
					assert.Nil(t, grant)
					assertRefusal(t, err, want)
				})
			}
		}
	}
}
