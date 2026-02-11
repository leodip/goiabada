package constants

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestGranularScopeConstants verifies that granular scope constants are correctly defined
// and follow the expected naming conventions
func TestGranularScopeConstants(t *testing.T) {
	// Verify the constants exist and have expected values
	assert.Equal(t, "admin-read", AdminReadPermissionIdentifier)
	assert.Equal(t, "manage-users", ManageUsersPermissionIdentifier)
	assert.Equal(t, "manage-clients", ManageClientsPermissionIdentifier)
	assert.Equal(t, "manage-settings", ManageSettingsPermissionIdentifier)

	// Verify backwards-compatible manage permission
	assert.Equal(t, "manage", ManagePermissionIdentifier)

	// Verify authserver resource identifier (used to construct full scope)
	assert.Equal(t, "authserver", AuthServerResourceIdentifier)
}

// TestScopeConstantsAreUnique verifies that all permission identifiers are unique
func TestScopeConstantsAreUnique(t *testing.T) {
	permissions := []string{
		UserinfoPermissionIdentifier,
		ManageAccountPermissionIdentifier,
		ManagePermissionIdentifier,
		AdminReadPermissionIdentifier,
		ManageUsersPermissionIdentifier,
		ManageClientsPermissionIdentifier,
		ManageSettingsPermissionIdentifier,
	}

	seen := make(map[string]bool)
	for _, perm := range permissions {
		assert.False(t, seen[perm], "Duplicate permission identifier found: %s", perm)
		seen[perm] = true
	}
}

// TestAuditEventTypes_Uniqueness verifies all event types are unique (no duplicates)
func TestAuditEventTypes_Uniqueness(t *testing.T) {
	seen := make(map[string]bool)
	for _, evt := range AuditEventTypes {
		if seen[evt] {
			t.Errorf("Duplicate audit event type found: %s", evt)
		}
		seen[evt] = true
	}
}

// TestAuditEventTypes_NonEmpty verifies no empty strings in the slice
func TestAuditEventTypes_NonEmpty(t *testing.T) {
	for i, evt := range AuditEventTypes {
		assert.NotEmpty(t, evt, "AuditEventTypes[%d] is empty", i)
	}
}

// TestAuditEventTypes_Count acts as a drift guard - update expected count when adding/removing audit events
func TestAuditEventTypes_Count(t *testing.T) {
	expectedCount := 89
	actualCount := len(AuditEventTypes)

	require.Equal(t, expectedCount, actualCount,
		"AuditEventTypes count mismatch. Expected %d, got %d.\n"+
			"If you added/removed audit event constants, update this test's expectedCount.\n"+
			"Also ensure the new constant is added to/removed from the AuditEventTypes slice in constants.go",
		expectedCount, actualCount)
}

// TestAuditEventTypes_ContainsCriticalEvents verifies critical audit events are present
func TestAuditEventTypes_ContainsCriticalEvents(t *testing.T) {
	criticalEvents := []string{
		AuditAuthSuccessPwd,
		AuditAuthFailedPwd,
		AuditAuthSuccessOtp,
		AuditAuthFailedOtp,
		AuditCreatedUser,
		AuditDeletedUser,
		AuditCreatedClient,
		AuditDeletedClient,
		AuditTokenIssuedAuthorizationCodeResponse,
		AuditTokenIssuedClientCredentialsResponse,
		AuditTokenIssuedRefreshTokenResponse,
		AuditUpdatedSMTPSettings,
		AuditUpdatedGeneralSettings,
		AuditUpdatedSessionsSettings,
		AuditUpdatedTokensSettings,
		AuditUpdatedAuditLogsSettings,
		AuditRotatedKeys,
		AuditRevokedKey,
		AuditDynamicClientRegistration,
	}

	for _, critical := range criticalEvents {
		assert.Contains(t, AuditEventTypes, critical,
			"Critical audit event %s not found in AuditEventTypes slice", critical)
	}
}

// TestAuditEventTypes_Alphabetical verifies the slice is in alphabetical order
func TestAuditEventTypes_Alphabetical(t *testing.T) {
	for i := 1; i < len(AuditEventTypes); i++ {
		prev := AuditEventTypes[i-1]
		curr := AuditEventTypes[i]

		if prev > curr {
			t.Errorf("AuditEventTypes is not in alphabetical order: %s should come after %s", prev, curr)
		}
	}
}

// TestAuditEventTypes_MatchesConstants verifies AuditEventTypes contains all audit constants
func TestAuditEventTypes_MatchesConstants(t *testing.T) {
	// List of all audit constants - manually maintain when adding new ones
	allAuditConstants := []string{
		AuditActivatedAccount,
		AuditAddedGroupAttribute,
		AuditAddedGroupPermission,
		AuditAddedUserAttribute,
		AuditAddedUserPermission,
		AuditAuthFailedOtp,
		AuditAuthFailedPwd,
		AuditAuthSuccessOtp,
		AuditAuthSuccessPwd,
		AuditAutoRefreshedToken,
		AuditBumpedUserSession,
		AuditChangedPassword,
		AuditCreatedAuthCode,
		AuditCreatedClient,
		AuditCreatedGroup,
		AuditCreatedPreRegistration,
		AuditCreatedResource,
		AuditCreatedUser,
		AuditDeletedClient,
		AuditDeletedClientLogo,
		AuditDeletedGroup,
		AuditDeletedGroupPermission,
		AuditDeletedOwnProfilePicture,
		AuditDeletedOwnUserConsent,
		AuditDeletedResource,
		AuditDeletedUser,
		AuditDeletedUserConsent,
		AuditDeletedUserPermission,
		AuditDeletedUserProfilePicture,
		AuditDeletedUserSession,
		AuditDeletedUserSessionClient,
		AuditDeleteGroupAttribute,
		AuditDeleteUserAttribute,
		AuditDisabledOTP,
		AuditDynamicClientRegistration,
		AuditEnabledOTP,
		AuditFailedEmailVerificationCode,
		AuditGeneratedEmailVerificationCode,
		AuditLogout,
		AuditROPCAuthFailed,
		AuditRevokedKey,
		AuditRotatedKeys,
		AuditSavedConsent,
		AuditSentEmailVerificationMessage,
		AuditSentPhoneVerificationMessage,
		AuditSentTestEmail,
		AuditStartedNewUserSesson,
		AuditTokenIssuedAuthorizationCodeResponse,
		AuditTokenIssuedClientCredentialsResponse,
		AuditTokenIssuedImplicitResponse,
		AuditTokenIssuedRefreshTokenResponse,
		AuditTokenIssuedROPCResponse,
		AuditUpdatedAuditLogsSettings,
		AuditUpdatedClientAuthentication,
		AuditUpdatedClientLogo,
		AuditUpdatedClientOAuth2Flows,
		AuditUpdatedClientPermissions,
		AuditUpdatedClientSettings,
		AuditUpdatedClientTokens,
		AuditUpdatedGeneralSettings,
		AuditUpdatedGroup,
		AuditUpdatedGroupAttribute,
		AuditUpdatedOwnAddress,
		AuditUpdatedOwnEmail,
		AuditUpdatedOwnPhone,
		AuditUpdatedOwnProfile,
		AuditUpdatedOwnProfilePicture,
		AuditUpdatedRedirectURIs,
		AuditUpdatedResource,
		AuditUpdatedResourcePermissions,
		AuditUpdatedSessionsSettings,
		AuditUpdatedSMSSettings,
		AuditUpdatedSMTPSettings,
		AuditUpdatedTokensSettings,
		AuditUpdatedUIThemeSettings,
		AuditUpdatedUserAddress,
		AuditUpdatedUserAttribute,
		AuditUpdatedUserAuthentication,
		AuditUpdatedUserDetails,
		AuditUpdatedUserEmail,
		AuditUpdatedUserPhone,
		AuditUpdatedUserProfile,
		AuditUpdatedUserProfilePicture,
		AuditUpdatedWebOrigins,
		AuditUserAddedToGroup,
		AuditUserDisabled,
		AuditUserRemovedFromGroup,
		AuditVerifiedEmail,
		AuditVerifiedPhone,
	}

	constantsMap := make(map[string]bool)
	for _, constant := range allAuditConstants {
		constantsMap[constant] = true
	}

	typesMap := make(map[string]bool)
	for _, typ := range AuditEventTypes {
		typesMap[typ] = true
	}

	// Check if all constants are in AuditEventTypes
	for _, constant := range allAuditConstants {
		assert.True(t, typesMap[constant],
			"Audit constant %s is defined but not in AuditEventTypes slice", constant)
	}

	// Check if all AuditEventTypes are actual constants
	for _, typ := range AuditEventTypes {
		assert.True(t, constantsMap[typ],
			"AuditEventTypes contains %s but it's not defined as a constant", typ)
	}

	// Verify counts match
	assert.Equal(t, len(allAuditConstants), len(AuditEventTypes),
		"Mismatch between number of constants and AuditEventTypes entries")
}
