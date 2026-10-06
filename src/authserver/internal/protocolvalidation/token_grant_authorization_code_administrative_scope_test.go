package protocolvalidation

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/core/builtin"
	"github.com/leodip/goiabada/core/oauth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/leodip/goiabada/authserver/internal/data/mocks"
	"github.com/leodip/goiabada/authserver/internal/protocolvalidation/mocks"
)

// codeGrant is the stored state of an authorization code redemption, as an administrative-scope
// case varies it.
type codeGrant struct {
	clientIdentifier            string
	administrativeScopesAllowed bool
	scope                       string
	revoked                     bool
	// clientSecret is what the request presents; the client's own secret is "client_secret".
	clientSecret string
}

// newCodeGrantRedemption is a confidential client redeeming a live code that carries no PKCE
// challenge, so neither the PKCE boundary nor any flat refusal pre-empts the subject. registered
// says the redemption reaches the registration boundary at the end of the arm: only then is
// ClientLoadRedirectURIs expected, and the strict double fails a case that reads it anyway.
func newCodeGrantRedemption(t *testing.T, grant codeGrant, registered bool) (*TokenValidator, *record.Settings, *ValidateTokenRequestInput) {
	t.Helper()

	mockDB := datamocks.NewDatabase(t)
	validator := NewTokenValidator(mockDB, protocolvalidationmocks.NewTokenParser(t),
		protocolvalidationmocks.NewPermissionChecker(t), testDataCipher)

	clientSecretEncrypted, err := testDataCipher.Encrypt("client_secret")
	require.NoError(t, err)

	client := &record.Client{
		Id:                          1,
		ClientIdentifier:            grant.clientIdentifier,
		Enabled:                     true,
		AuthorizationCodeEnabled:    true,
		ClientSecretEncrypted:       clientSecretEncrypted,
		AdministrativeScopesAllowed: grant.administrativeScopesAllowed,
	}
	const redirectURI = "https://example.com/callback"
	codeEntity := &record.Code{
		CodeHash:    "hash_of_valid_code",
		RedirectURI: redirectURI,
		Scope:       grant.scope,
		Revoked:     grant.revoked,
		UserId:      7,
		Client:      record.Client{ClientIdentifier: grant.clientIdentifier},
		User:        record.User{Id: 7, Enabled: true},
		CreatedAt:   sql.NullTime{Time: time.Now().UTC(), Valid: true},
	}

	mockDB.On("GetClientByClientIdentifier", mock.Anything, mock.Anything, grant.clientIdentifier).Return(client, nil).Once()
	mockDB.On("GetCodeByCodeHash", mock.Anything, mock.Anything, mock.AnythingOfType("string"), false).
		Return(codeEntity, nil).Once()
	mockDB.On("CodeLoadClient", mock.Anything, mock.Anything, codeEntity).Return(nil).Once()
	mockDB.On("CodeLoadUser", mock.Anything, mock.Anything, codeEntity).Return(nil).Once()
	if registered {
		mockDB.On("ClientLoadRedirectURIs", mock.Anything, mock.Anything, client).Run(func(args mock.Arguments) {
			args.Get(2).(*record.Client).RedirectURIs = []record.RedirectURI{{URI: redirectURI}}
		}).Return(nil).Once()
	}

	clientSecret := grant.clientSecret
	if clientSecret == "" {
		clientSecret = "client_secret"
	}
	input := &ValidateTokenRequestInput{
		GrantType:    "authorization_code",
		ClientId:     grant.clientIdentifier,
		ClientSecret: clientSecret,
		Code:         "valid_code",
		RedirectURI:  redirectURI,
	}
	return validator, &record.Settings{}, input
}

// A code carrying an administrative scope is redeemed only by a client allowed to request one, read
// at redemption and not when the code was minted: /auth/issue is the last check before the code
// exists, so a code minted just before an operator withdraws the allowance is otherwise redeemed
// for a fresh administrative token within its 60 second life (#499 decision 6). It answers
// invalid_grant carrying the sentence every checkpoint gives (decision 7), and below the flat
// refusals and above the registration read, which the refused rows show by expecting no such read.
func TestValidateTokenRequest_AuthorizationCode_AdministrativeScope(t *testing.T) {
	const sentence = "The client is not allowed to request the administrative scope '%v'."

	testCases := []struct {
		name  string
		grant codeGrant
		// wantRefused is the administrative scopes refused, nil when the code is redeemed.
		wantRefused []string
	}{
		{
			// The allowance withdrawn between /auth/issue and the redemption.
			name:        "a client not allowed",
			grant:       codeGrant{clientIdentifier: "client1", scope: "openid profile authserver:manage"},
			wantRefused: []string{"authserver:manage"},
		},
		{
			// Every administrative scope on the code is recorded; the answer names the first.
			name:        "two administrative scopes",
			grant:       codeGrant{clientIdentifier: "client1", scope: "openid authserver:admin-read authserver:manage-users"},
			wantRefused: []string{"authserver:admin-read", "authserver:manage-users"},
		},
		{
			name:  "an allowed client",
			grant: codeGrant{clientIdentifier: "client1", scope: "openid authserver:manage", administrativeScopesAllowed: true},
		},
		{
			// Allowed by its identifier, whatever its row holds.
			name:  "the admin console's client",
			grant: codeGrant{clientIdentifier: builtin.AdminConsoleClientIdentifier, scope: "openid authserver:manage"},
		},
		{
			// manage-account is not administrative (decision 2).
			name:  "manage-account is not refused",
			grant: codeGrant{clientIdentifier: "client1", scope: "openid authserver:manage-account"},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			validator, settings, input := newCodeGrantRedemption(t, tc.grant, tc.wantRefused == nil)

			result, err := validator.ValidateTokenRequest(context.Background(), settings, input)

			if tc.wantRefused == nil {
				require.NoError(t, err)
				assert.NotNil(t, result)
				return
			}

			assert.Nil(t, result)
			var refused *AdministrativeScopeRefusedError
			require.ErrorAs(t, err, &refused)
			assert.Equal(t, tc.wantRefused, refused.Scopes)
			assert.Equal(t, int64(1), refused.Client.Id)
			assert.Equal(t, "client1", refused.Client.ClientIdentifier)
			assert.Equal(t, int64(7), refused.UserId)

			var customErr *oauth.ErrorDetail
			require.ErrorAs(t, err, &customErr)
			assert.Equal(t, "invalid_grant", customErr.Code())
			assert.Equal(t, http.StatusBadRequest, customErr.HTTPStatus())
			assert.Equal(t, fmt.Sprintf(sentence, tc.wantRefused[0]), customErr.Description())
		})
	}

	// The ordering cases. Neither reaches the registration read, and neither may say why the client
	// would be refused: a presenter that has not authenticated learns nothing of the client, and a
	// revoked code keeps the flat answer every refusal of the grant's state gives (#137).
	t.Run("a wrong client secret is answered first", func(t *testing.T) {
		validator, settings, input := newCodeGrantRedemption(t,
			codeGrant{clientIdentifier: "client1", scope: "openid authserver:manage", clientSecret: "wrong_secret"}, false)

		result, err := validator.ValidateTokenRequest(context.Background(), settings, input)

		assert.Nil(t, result)
		var refused *AdministrativeScopeRefusedError
		assert.False(t, errors.As(err, &refused))
		var customErr *oauth.ErrorDetail
		require.ErrorAs(t, err, &customErr)
		assert.Equal(t, "invalid_client", customErr.Code())
	})

	t.Run("a revoked code keeps the flat answer", func(t *testing.T) {
		validator, settings, input := newCodeGrantRedemption(t,
			codeGrant{clientIdentifier: "client1", scope: "openid authserver:manage", revoked: true}, false)

		result, err := validator.ValidateTokenRequest(context.Background(), settings, input)

		assert.Nil(t, result)
		var refused *AdministrativeScopeRefusedError
		assert.False(t, errors.As(err, &refused))
		var customErr *oauth.ErrorDetail
		require.ErrorAs(t, err, &customErr)
		assert.Equal(t, "invalid_grant", customErr.Code())
		assert.Equal(t, "Code is invalid.", customErr.Description())
	})
}
