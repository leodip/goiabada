package protocolvalidation

import (
	"context"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	mocks_data "github.com/leodip/goiabada/authserver/internal/data/mocks"
	"github.com/leodip/goiabada/authserver/internal/models"
	"github.com/leodip/goiabada/authserver/internal/passwordhash"
	mocks_protocolvalidation "github.com/leodip/goiabada/authserver/internal/protocolvalidation/mocks"
	"github.com/leodip/goiabada/core/customerrors"
)

// The bounds are storage's (models.StateMaxBytes, NonceMaxBytes, ScopeMaxBytes): the widths of the
// columns the values are stored in, which the data tier writes to every engine at exactly that many
// bytes. What follows holds the validators to them, on both sides of the edge and in bytes (#437).

// boundedValue is a candidate value for a bounded parameter.
type boundedValue struct {
	name    string
	value   string
	refused bool
}

// boundedValues returns the values every bounded parameter is held to: each side of the bound in
// one-byte characters, then filling and passing it in two- and four-byte characters, where a count
// of characters and a count of bytes part ways. A bound counted in characters would accept the two
// "one over" rows below, since each holds fewer characters than the bound.
func boundedValues(t *testing.T, bound int) []boundedValue {
	t.Helper()
	require.Zero(t, bound%4, "the two- and four-byte rows need a bound both widths divide")
	return []boundedValue{
		{"absent", "", false},
		{"one byte", "a", false},
		{"one byte under the bound", strings.Repeat("a", bound-1), false},
		{"exactly the bound", strings.Repeat("a", bound), false},
		{"one byte over the bound", strings.Repeat("a", bound+1), true},
		{"twice the bound", strings.Repeat("a", 2*bound), true},
		{"two-byte characters filling the bound", strings.Repeat("é", bound/2), false},
		{"one two-byte character over the bound", strings.Repeat("é", bound/2+1), true},
		{"four-byte characters filling the bound", strings.Repeat("😀", bound/4), false},
		{"one four-byte character over the bound", strings.Repeat("😀", bound/4+1), true},
	}
}

// requireTooLong asserts that err is the bound's refusal for a value of length bytes: the code, the
// 400, the exact text, and that the text carries no part of the value.
func requireTooLong(t *testing.T, err error, code, parameter string, length, bound int, value string) {
	t.Helper()
	var detail *customerrors.ErrorDetail
	require.ErrorAs(t, err, &detail)
	assert.Equal(t, code, detail.GetCode())
	assert.Equal(t, http.StatusBadRequest, detail.GetHttpStatusCode())
	assert.Equal(t, fmt.Sprintf("The '%s' parameter is too long (%d bytes, the maximum is %d).", parameter, length, bound),
		detail.GetDescription())
	assert.NotContains(t, detail.GetDescription(), value[:8], "the description must not repeat the value")
}

// claimScopesOfBytes returns a scope of exactly n bytes made only of the claim scopes openid and
// email, which are accepted without a lookup. The duplicates are deliberate: ValidateScopes counts
// the string it is handed, and every caller that stores a scope has already dropped them.
func claimScopesOfBytes(t *testing.T, n int) string {
	t.Helper()
	// Each token costs its length plus one separator, less one for the last: n+1 = 7a + 6b.
	for a := 0; a < 6; a++ {
		if rest := n + 1 - 7*a; rest >= 0 && rest%6 == 0 {
			tokens := slices.Concat(slices.Repeat([]string{"openid"}, a), slices.Repeat([]string{"email"}, rest/6))
			scope := strings.Join(tokens, " ")
			require.Len(t, scope, n)
			return scope
		}
	}
	require.FailNow(t, "no scope of claim scopes has that many bytes", "%d", n)
	return ""
}

func validCodeFlowInput() ValidateRequestInput {
	return ValidateRequestInput{
		ResponseType:        "code",
		CodeChallengeMethod: "S256",
		CodeChallenge:       "a_valid_code_challenge_that_meets_length_requirements",
		ResponseMode:        "query",
		Scope:               "openid",
	}
}

// TestValidateRequest_StateAndNonceAreBoundedInBytes is the authorization endpoint's half of the
// state and nonce bound: a value over the width of its column is invalid_request, counted in bytes,
// and one that fits goes on. Each refused row differs from a passing row in the one parameter it
// names, and the gate that refuses it is the bound.
func TestValidateRequest_StateAndNonceAreBoundedInBytes(t *testing.T) {
	validator := NewAuthorizeValidator(mocks_data.NewDatabase(t))

	for _, parameter := range []struct {
		name  string
		bound int
		set   func(*ValidateRequestInput, string)
	}{
		{"state", models.StateMaxBytes, func(in *ValidateRequestInput, v string) { in.State = v }},
		{"nonce", models.NonceMaxBytes, func(in *ValidateRequestInput, v string) { in.Nonce = v }},
	} {
		for _, candidate := range boundedValues(t, parameter.bound) {
			t.Run(parameter.name+"/"+candidate.name, func(t *testing.T) {
				input := validCodeFlowInput()
				parameter.set(&input, candidate.value)

				err := validator.ValidateRequest(&input)

				if !candidate.refused {
					assert.NoError(t, err)
					return
				}
				requireTooLong(t, err, "invalid_request", parameter.name, len(candidate.value), parameter.bound, candidate.value)
			})
		}
	}
}

// The ceremony carries state and nonce whatever the response type, so the bound is not the code
// flow's alone: an implicit request that works with a short value is refused with a long one, and
// served at the bound.
func TestValidateRequest_StateAndNonceBoundHoldsForImplicitRequests(t *testing.T) {
	validator := NewAuthorizeValidator(mocks_data.NewDatabase(t))
	implicit := func(responseType, state, nonce string) *ValidateRequestInput {
		return &ValidateRequestInput{
			ResponseType:         responseType,
			ImplicitGrantEnabled: true,
			Scope:                "openid",
			State:                state,
			Nonce:                nonce,
		}
	}
	over := func(bound int) string { return strings.Repeat("a", bound+1) }
	atTheBound := func(bound int) string { return strings.Repeat("a", bound) }

	for _, tc := range []struct {
		name         string
		input        *ValidateRequestInput
		wantRefusing string
	}{
		{"token, state at the bound", implicit("token", atTheBound(models.StateMaxBytes), ""), ""},
		{"token, state over", implicit("token", over(models.StateMaxBytes), ""), "state"},
		{"id_token, nonce at the bound", implicit("id_token", "", atTheBound(models.NonceMaxBytes)), ""},
		{"id_token, nonce over", implicit("id_token", "", over(models.NonceMaxBytes)), "nonce"},
		{"id_token token, both at the bound", implicit("id_token token", atTheBound(models.StateMaxBytes), atTheBound(models.NonceMaxBytes)), ""},
		{"id_token token, state over beside a nonce that fits", implicit("id_token token", over(models.StateMaxBytes), "n"), "state"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := validator.ValidateRequest(tc.input)

			if tc.wantRefusing == "" {
				assert.NoError(t, err)
				return
			}
			var detail *customerrors.ErrorDetail
			require.ErrorAs(t, err, &detail)
			assert.Equal(t, "invalid_request", detail.GetCode())
			assert.Contains(t, detail.GetDescription(), "The '"+tc.wantRefusing+"' parameter is too long")
		})
	}
}

// TestValidateScopes_BoundIsInBytesAndComesBeforeAnyLookup holds the authorization endpoint to the
// scope bound. The strict database registers nothing in the refusing rows, so a lookup made before
// the bound fails the case, and the accepting rows show a scope filling the bound is resolved
// whole.
func TestValidateScopes_BoundIsInBytesAndComesBeforeAnyLookup(t *testing.T) {
	t.Run("distinct resource:permission scopes filling the bound are resolved and accepted", func(t *testing.T) {
		// 255 scopes of seven bytes and one of eight, joined by 255 spaces.
		permissionList := make([]models.Permission, 0, 256)
		scopes := make([]string, 0, 256)
		for i := 0; i < 255; i++ {
			identifier := fmt.Sprintf("p%04d", i)
			scopes = append(scopes, "r:"+identifier)
			permissionList = append(permissionList, models.Permission{PermissionIdentifier: identifier})
		}
		scopes = append(scopes, "r:p00255")
		permissionList = append(permissionList, models.Permission{PermissionIdentifier: "p00255"})
		scope := strings.Join(scopes, " ")
		require.Len(t, scope, models.ScopeMaxBytes, "the fixture is off the bound, so the case no longer observes the edge")

		mockDB := mocks_data.NewDatabase(t)
		mockDB.On("GetResourceByResourceIdentifier", mock.Anything, mock.Anything, "r").
			Return(&models.Resource{Id: 1, ResourceIdentifier: "r"}, nil)
		mockDB.On("GetPermissionsByResourceId", mock.Anything, mock.Anything, int64(1)).Return(permissionList, nil)

		assert.NoError(t, NewAuthorizeValidator(mockDB).ValidateScopes(context.Background(), scope))
	})

	t.Run("claim scopes filling the bound are accepted", func(t *testing.T) {
		scope := claimScopesOfBytes(t, models.ScopeMaxBytes)
		assert.NoError(t, NewAuthorizeValidator(mocks_data.NewDatabase(t)).ValidateScopes(context.Background(), scope))
	})

	t.Run("one byte over the bound is invalid_scope before any lookup", func(t *testing.T) {
		scope := claimScopesOfBytes(t, models.ScopeMaxBytes+1)
		err := NewAuthorizeValidator(mocks_data.NewDatabase(t)).ValidateScopes(context.Background(), scope)
		requireTooLong(t, err, "invalid_scope", "scope", models.ScopeMaxBytes+1, models.ScopeMaxBytes, scope)
	})

	t.Run("an over-long scope of resource:permission scopes is refused without resolving any", func(t *testing.T) {
		scopes := make([]string, 0, 300)
		for i := 0; i < 300; i++ {
			scopes = append(scopes, fmt.Sprintf("r:p%04d", i))
		}
		scope := strings.Join(scopes, " ")
		require.Greater(t, len(scope), models.ScopeMaxBytes)

		err := NewAuthorizeValidator(mocks_data.NewDatabase(t)).ValidateScopes(context.Background(), scope)

		requireTooLong(t, err, "invalid_scope", "scope", len(scope), models.ScopeMaxBytes, scope)
	})

	// A count of characters would accept the second row (1025 characters); a count of bytes refuses
	// it. The first fills the bound in bytes, so it passes the bound and is then refused for what it
	// is: not a scope in resource:permission form. That is a different error, which is the proof
	// that the bound admitted it.
	t.Run("bytes are counted, not characters", func(t *testing.T) {
		filling := strings.Repeat("é", models.ScopeMaxBytes/2)
		err := NewAuthorizeValidator(mocks_data.NewDatabase(t)).ValidateScopes(context.Background(), filling)
		var detail *customerrors.ErrorDetail
		require.ErrorAs(t, err, &detail)
		assert.Equal(t, "invalid_scope", detail.GetCode())
		assert.Contains(t, detail.GetDescription(), "Invalid scope format", "the bound admitted it, so the refusal is the format's")

		over := strings.Repeat("é", models.ScopeMaxBytes/2+1)
		err = NewAuthorizeValidator(mocks_data.NewDatabase(t)).ValidateScopes(context.Background(), over)
		requireTooLong(t, err, "invalid_scope", "scope", len(over), models.ScopeMaxBytes, over)
	})
}

// TestValidateTokenRequest_ROPC_ScopeBound is the scope bound's other door. The bound sits in the
// scope validation, which the password grant reaches only once the client and the password are
// proved, so a request that has not proved them is told nothing about its scope: a wrong password
// with an over-long scope is invalid_grant, exactly as with a short one, and is charged as one
// (#137, #219).
func TestValidateTokenRequest_ROPC_ScopeBound(t *testing.T) {
	setup := func(t *testing.T) (*TokenValidator, *mocks_data.Database, *models.Settings) {
		t.Helper()
		mockDB := mocks_data.NewDatabase(t)
		validator := NewTokenValidator(mockDB, mocks_protocolvalidation.NewTokenParser(t),
			mocks_protocolvalidation.NewPermissionChecker(t), testDataCipher)

		passwordHash, err := passwordhash.Hash("correctpassword")
		require.NoError(t, err)
		user := &models.User{Id: 1, Email: "user@example.com", PasswordHash: passwordHash, Enabled: true}
		ropcEnabled := true
		client := &models.Client{
			Id: 1, ClientIdentifier: "ropc-client", Enabled: true, IsPublic: true,
			ResourceOwnerPasswordCredentialsEnabled: &ropcEnabled,
		}
		mockDB.On("GetClientByClientIdentifier", mock.Anything, mock.Anything, "ropc-client").Return(client, nil).Once()
		mockDB.On("GetUserByEmail", mock.Anything, mock.Anything, "user@example.com").Return(user, nil).Once()
		return validator, mockDB, &models.Settings{ResourceOwnerPasswordCredentialsEnabled: true}
	}
	request := func(password, scope string) *ValidateTokenRequestInput {
		return &ValidateTokenRequestInput{
			GrantType: "password", ClientId: "ropc-client", Username: "user@example.com",
			Password: password, Scope: scope,
		}
	}

	t.Run("a scope filling the bound is granted whole", func(t *testing.T) {
		validator, mockDB, settings := setup(t)
		mockDB.On("UserLoadPermissions", mock.Anything, mock.Anything, mock.Anything).Return(nil).Once()
		mockDB.On("UserLoadGroups", mock.Anything, mock.Anything, mock.Anything).Return(nil).Once()
		scope := claimScopesOfBytes(t, models.ScopeMaxBytes)

		result, err := validator.ValidateTokenRequest(context.Background(), settings, request("correctpassword", scope))

		require.NoError(t, err)
		assert.Equal(t, scope, grantAs[*PasswordGrant](t, result).Scope)
	})

	t.Run("one byte over the bound, with the right password, is invalid_scope", func(t *testing.T) {
		validator, mockDB, settings := setup(t)
		mockDB.On("UserLoadPermissions", mock.Anything, mock.Anything, mock.Anything).Return(nil).Once()
		mockDB.On("UserLoadGroups", mock.Anything, mock.Anything, mock.Anything).Return(nil).Once()
		scope := claimScopesOfBytes(t, models.ScopeMaxBytes+1)

		result, err := validator.ValidateTokenRequest(context.Background(), settings, request("correctpassword", scope))

		assert.Nil(t, result)
		requireTooLong(t, err, "invalid_scope", "scope", models.ScopeMaxBytes+1, models.ScopeMaxBytes, scope)
	})

	t.Run("one byte over the bound, with a wrong password, is still invalid_grant", func(t *testing.T) {
		validator, _, settings := setup(t)
		scope := claimScopesOfBytes(t, models.ScopeMaxBytes+1)

		result, err := validator.ValidateTokenRequest(context.Background(), settings, request("wrongpassword", scope))

		assert.Nil(t, result)
		var detail *customerrors.ErrorDetail
		require.ErrorAs(t, err, &detail)
		assert.Equal(t, "invalid_grant", detail.GetCode())
		assert.Equal(t, "Invalid resource owner credentials.", detail.GetDescription())
	})
}
