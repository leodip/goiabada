package audit

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// The four properties of the catalog that hold whatever the declarations say, moved here from
// core/constants with the names themselves (#351). The two that used to sit beside them are
// gone rather than moved: TestAuditEventTypes_Count pinned a hand-bumped expectedCount, and
// TestAuditEventTypes_MatchesConstants compared the catalog against allAuditConstants, a third
// hand-maintained list living inside the test file. Both are replaced by
// TestAuditCatalog_MatchesTheDeclarations, which derives its expectation from the declarations
// rather than from a list somebody has to remember to edit (#209, #351 decision 10).

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
		// Records that a credential change invalidated a user's live authentication state
		// (#106). Security-relevant in the same class as key revocation: if this event ever
		// stopped being emitted, a forced logout would leave no trace.
		AuditRevokedUserAuthState,
		// Records that ending one session durably cut off the grants it authorized (#129). Same
		// class as the event above, and for the same reason: deleted_user_session survives
		// either way, so if this one stopped being emitted the security action would leave only
		// a lifecycle record behind and nothing attesting what it revoked.
		AuditTerminatedUserSession,
		// Records that flipping a client to public cut off every grant that client held (#245).
		// Same class again: the flip's other effects are all visible on the client row, so if
		// this event stopped being emitted the revocation would be the one part of the action
		// leaving no trace at all.
		AuditRevokedClientGrants,
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

// TestAuditEventTypes_CriticalEventValuesAreWireValues pins the stored spelling of the events an
// operator alerts on, as literals rather than through the constants that declare them.
//
// Every other test in this file, and the guard beside it, names the constant, so all of them
// keep passing if a value is edited: they compare the declaration against itself. The value is
// not an implementation detail. It is what is written to the audit_logs table's audit_event
// column and what the admin API's auditEvent filter matches, so editing one orphans every row
// already carrying it and silently breaks whatever alert was watching for it.
//
// The roster is the one TestAuditEventTypes_ContainsCriticalEvents already treats as worth
// naming individually, and it stops there on purpose: a literal for all 100 would be a fourth
// hand-maintained list, which is the liability #351 decision 10 just removed. What these
// thirteen buy is that a value cannot drift without a test saying so (#351).
func TestAuditEventTypes_CriticalEventValuesAreWireValues(t *testing.T) {
	for _, tc := range []struct {
		name     string
		constant string
		want     string
	}{
		{"AuditAuthSuccessPwd", AuditAuthSuccessPwd, "auth_success_pwd"},
		{"AuditAuthFailedPwd", AuditAuthFailedPwd, "auth_failed_pwd"},
		{"AuditAuthSuccessOtp", AuditAuthSuccessOtp, "auth_success_otp"},
		{"AuditAuthFailedOtp", AuditAuthFailedOtp, "auth_failed_otp"},
		{"AuditRevokedUserAuthState", AuditRevokedUserAuthState, "revoked_user_auth_state"},
		{"AuditTerminatedUserSession", AuditTerminatedUserSession, "terminated_user_session"},
		{"AuditRevokedClientGrants", AuditRevokedClientGrants, "revoked_client_grants"},
		{"AuditRotatedKeys", AuditRotatedKeys, "rotated_keys"},
		{"AuditRevokedKey", AuditRevokedKey, "revoked_key"},
		{"AuditAuthCodeReuseDetected", AuditAuthCodeReuseDetected, "auth_code_reuse_detected"},
		{"AuditRefreshTokenReplayDetected", AuditRefreshTokenReplayDetected,
			"refresh_token_replay_detected"},
		{"AuditOTPCodeReplayDetected", AuditOTPCodeReplayDetected, "otp_code_replay_detected"},
		{"AuditTokenIssuedAuthorizationCodeResponse", AuditTokenIssuedAuthorizationCodeResponse,
			"token_issued_authorization_code_response"},
	} {
		assert.Equal(t, tc.want, tc.constant,
			"%s is stored data; changing it orphans every audit_logs row carrying it", tc.name)
		assert.Contains(t, AuditEventTypes, tc.want,
			"%s is not in the catalog, so the filter dropdown cannot offer it", tc.name)
	}
}
