package protocolvalidation

import (
	"context"
	"net/http"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/passwordhash"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/core/builtin"
	"github.com/leodip/goiabada/core/oauth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/leodip/goiabada/authserver/internal/data/mocks"
	"github.com/leodip/goiabada/authserver/internal/protocolvalidation/mocks"
)

// The password grant refuses an administrative scope for a client that may not request one with
// invalid_scope, as it answers a scope the user does not hold, and with the sentence the
// authorization endpoint gives the same condition (#499 decisions 6 and 7). The refusal comes
// before the scope is resolved or the user's permissions are asked about: the strict mocks have no
// expectation for either, so a case that reaches them fails.
func TestValidateTokenRequest_ROPC_AdministrativeScope(t *testing.T) {
	testCases := []struct {
		name    string
		allowed bool
		scope   string
		// wantRefused is the administrative scopes refused, nil when the grant is accepted.
		wantRefused []string
		wantDesc    string
		// granted, on an accepted grant, is the one authserver scope resolved and asked about.
		granted string
	}{
		{
			name:        "an ordinary client asking for manage",
			scope:       "openid authserver:manage",
			wantRefused: []string{"authserver:manage"},
			wantDesc:    "The client is not allowed to request the administrative scope 'authserver:manage'.",
		},
		{
			name:        "every administrative scope asked for is recorded, the first named",
			scope:       "openid authserver:browser-sessions authserver:manage-settings",
			wantRefused: []string{"authserver:browser-sessions", "authserver:manage-settings"},
			wantDesc:    "The client is not allowed to request the administrative scope 'authserver:browser-sessions'.",
		},
		{
			name:    "an allowed client obtains it",
			allowed: true,
			scope:   "openid authserver:manage",
			granted: "authserver:manage",
		},
		{
			name:    "manage-account is not refused",
			scope:   "openid authserver:manage-account",
			granted: "authserver:manage-account",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			mockDB := datamocks.NewDatabase(t)
			mockPermissionChecker := protocolvalidationmocks.NewPermissionChecker(t)
			validator := NewTokenValidator(mockDB, protocolvalidationmocks.NewTokenParser(t), mockPermissionChecker, testDataCipher)

			passwordHash, err := passwordhash.Hash("correctpassword")
			require.NoError(t, err)
			user := &record.User{Id: 7, Email: "user@example.com", PasswordHash: passwordHash, Enabled: true}

			ropcEnabled := true
			client := &record.Client{
				Id:                                      3,
				ClientIdentifier:                        "ropc-client",
				Enabled:                                 true,
				IsPublic:                                true,
				ResourceOwnerPasswordCredentialsEnabled: &ropcEnabled,
				AdministrativeScopesAllowed:             tc.allowed,
			}

			mockDB.On("GetClientByClientIdentifier", mock.Anything, mock.Anything, "ropc-client").Return(client, nil).Once()
			mockDB.On("GetUserByEmail", mock.Anything, mock.Anything, "user@example.com").Return(user, nil).Once()
			mockDB.On("UserLoadPermissions", mock.Anything, mock.Anything, user).Return(nil).Once()
			mockDB.On("UserLoadGroups", mock.Anything, mock.Anything, user).Return(nil).Once()
			if tc.granted != "" {
				builtIns := make([]record.Permission, 0, len(builtin.AuthServerPermissionIdentifiers()))
				for i, identifier := range builtin.AuthServerPermissionIdentifiers() {
					builtIns = append(builtIns, record.Permission{Id: int64(40 + i), PermissionIdentifier: identifier, ResourceId: 4})
				}
				mockDB.On("GetResourceByResourceIdentifier", mock.Anything, mock.Anything, builtin.AuthServerResourceIdentifier).
					Return(&record.Resource{Id: 4, ResourceIdentifier: builtin.AuthServerResourceIdentifier}, nil).Once()
				mockDB.On("GetPermissionsByResourceId", mock.Anything, mock.Anything, int64(4)).Return(builtIns, nil).Once()
				mockPermissionChecker.On("UserHasScopePermission", mock.Anything, int64(7), tc.granted).Return(true, nil).Once()
			}

			result, err := validator.ValidateTokenRequest(context.Background(), &record.Settings{ResourceOwnerPasswordCredentialsEnabled: true},
				&ValidateTokenRequestInput{
					GrantType: "password",
					ClientId:  "ropc-client",
					Username:  "user@example.com",
					Password:  "correctpassword",
					Scope:     tc.scope,
				})

			if tc.wantRefused == nil {
				require.NoError(t, err)
				assert.Equal(t, tc.scope, grantAs[*PasswordGrant](t, result).Scope)
				return
			}

			assert.Nil(t, result)
			var refused *AdministrativeScopeRefusedError
			require.ErrorAs(t, err, &refused)
			assert.Equal(t, tc.wantRefused, refused.Scopes)
			assert.Same(t, client, refused.Client)
			assert.Equal(t, int64(7), refused.UserId)

			var customErr *oauth.ErrorDetail
			require.ErrorAs(t, err, &customErr)
			assert.Equal(t, "invalid_scope", customErr.Code())
			assert.Equal(t, tc.wantDesc, customErr.Description())
			assert.Equal(t, http.StatusBadRequest, customErr.HTTPStatus())
		})
	}
}
