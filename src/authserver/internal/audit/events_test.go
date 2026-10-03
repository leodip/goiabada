package audit

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The four properties of the catalog that hold whatever the declarations say, moved here from
// core/constants with the names themselves (#351). The two that used to sit beside them are
// gone rather than moved: TestAuditEventTypes_Count pinned a hand-bumped expectedCount, and
// TestAuditEventTypes_MatchesConstants compared the catalog against allAuditConstants, a third
// hand-maintained list living inside the test file. Both are replaced by
// TestAuditCatalog_MatchesTheDeclarations, which derives its expectation from the declarations
// rather than from a list somebody has to remember to edit (#209, #351 decision 10).

// TestEventTypes_Uniqueness verifies all event types are unique (no duplicates)
func TestEventTypes_Uniqueness(t *testing.T) {
	seen := make(map[string]bool)
	for _, evt := range EventTypes() {
		if seen[evt] {
			t.Errorf("Duplicate audit event type found: %s", evt)
		}
		seen[evt] = true
	}
}

// TestEventTypes_NonEmpty verifies no empty strings in the slice
func TestEventTypes_NonEmpty(t *testing.T) {
	for i, evt := range EventTypes() {
		assert.NotEmpty(t, evt, "EventTypes[%d] is empty", i)
	}
}

// TestEventTypes_ContainsCriticalEvents verifies critical audit events are present
func TestEventTypes_ContainsCriticalEvents(t *testing.T) {
	criticalEvents := []string{
		EventAuthSuccessPwd,
		EventAuthFailedPwd,
		EventAuthSuccessOtp,
		EventAuthFailedOtp,
		EventCreatedUser,
		EventDeletedUser,
		EventCreatedClient,
		EventDeletedClient,
		EventTokenIssuedAuthorizationCodeResponse,
		EventTokenIssuedClientCredentialsResponse,
		EventTokenIssuedRefreshTokenResponse,
		EventUpdatedSMTPSettings,
		EventUpdatedGeneralSettings,
		EventUpdatedSessionsSettings,
		EventUpdatedTokensSettings,
		EventUpdatedAuditLogsSettings,
		EventRotatedKeys,
		EventRevokedKey,
		EventDynamicClientRegistration,
		// Records that a credential change invalidated a user's live authentication state
		// (#106). Security-relevant in the same class as key revocation: if this event ever
		// stopped being emitted, a forced logout would leave no trace.
		EventRevokedUserAuthState,
		// Records that ending one session durably cut off the grants it authorized (#129). Same
		// class as the event above, and for the same reason: deleted_user_session survives
		// either way, so if this one stopped being emitted the security action would leave only
		// a lifecycle record behind and nothing attesting what it revoked.
		EventTerminatedUserSession,
		// Records that flipping a client to public cut off every grant that client held (#245).
		// Same class again: the flip's other effects are all visible on the client row, so if
		// this event stopped being emitted the revocation would be the one part of the action
		// leaving no trace at all.
		EventRevokedClientGrants,
	}

	for _, critical := range criticalEvents {
		assert.Contains(t, EventTypes(), critical,
			"Critical audit event %s not found in EventTypes slice", critical)
	}
}

// TestEventTypes_ReturnsACopy pins that a caller cannot edit the catalog through the slice it
// was handed: the admin API serves the catalog on every request, so one handler sorting or
// truncating its copy would otherwise change what every later request receives (#433).
func TestEventTypes_ReturnsACopy(t *testing.T) {
	first := EventTypes()
	require.NotEmpty(t, first)
	original := first[0]

	first[0] = "tampered"
	_ = append(first[:1], "appended")

	second := EventTypes()
	assert.Equal(t, original, second[0])
	assert.Len(t, second, len(auditEventTypes))
	assert.NotContains(t, second, "tampered")
	assert.NotContains(t, second, "appended")
}

// TestEventTypes_Alphabetical verifies the slice is in alphabetical order
func TestEventTypes_Alphabetical(t *testing.T) {
	types := EventTypes()
	for i := 1; i < len(types); i++ {
		prev := types[i-1]
		curr := types[i]

		if prev > curr {
			t.Errorf("EventTypes is not in alphabetical order: %s should come after %s", prev, curr)
		}
	}
}

// TestEventTypes_CriticalEventValuesAreWireValues pins the stored spelling of the events an
// operator alerts on, as literals rather than through the constants that declare them.
//
// Every other test in this file, and the guard beside it, names the constant, so all of them
// keep passing if a value is edited: they compare the declaration against itself. The value is
// not an implementation detail. It is what is written to the audit_logs table's audit_event
// column and what the admin API's auditEvent filter matches, so editing one orphans every row
// already carrying it and silently breaks whatever alert was watching for it.
//
// The roster is the one TestEventTypes_ContainsCriticalEvents already treats as worth
// naming individually, and it stops there on purpose: a literal for all 100 would be a fourth
// hand-maintained list, which is the liability #351 decision 10 just removed. What these
// fourteen buy is that a value cannot drift without a test saying so (#351).
//
// EventStartedNewUserSession is the one row not on that roster. Its name was misspelled until
// #443 corrected it, and its value never was, so it is the value a reader would be tempted to
// change to match a name.
func TestEventTypes_CriticalEventValuesAreWireValues(t *testing.T) {
	for _, tc := range []struct {
		name     string
		constant string
		want     string
	}{
		{"EventAuthSuccessPwd", EventAuthSuccessPwd, "auth_success_pwd"},
		{"EventAuthFailedPwd", EventAuthFailedPwd, "auth_failed_pwd"},
		{"EventAuthSuccessOtp", EventAuthSuccessOtp, "auth_success_otp"},
		{"EventAuthFailedOtp", EventAuthFailedOtp, "auth_failed_otp"},
		{"EventRevokedUserAuthState", EventRevokedUserAuthState, "revoked_user_auth_state"},
		{"EventTerminatedUserSession", EventTerminatedUserSession, "terminated_user_session"},
		{"EventRevokedClientGrants", EventRevokedClientGrants, "revoked_client_grants"},
		{"EventRotatedKeys", EventRotatedKeys, "rotated_keys"},
		{"EventRevokedKey", EventRevokedKey, "revoked_key"},
		{"EventAuthCodeReuseDetected", EventAuthCodeReuseDetected, "auth_code_reuse_detected"},
		{"EventRefreshTokenReplayDetected", EventRefreshTokenReplayDetected,
			"refresh_token_replay_detected"},
		{"EventOTPCodeReplayDetected", EventOTPCodeReplayDetected, "otp_code_replay_detected"},
		{"EventTokenIssuedAuthorizationCodeResponse", EventTokenIssuedAuthorizationCodeResponse,
			"token_issued_authorization_code_response"},
		{"EventStartedNewUserSession", EventStartedNewUserSession, "started_new_user_session"},
	} {
		assert.Equal(t, tc.want, tc.constant,
			"%s is stored data; changing it orphans every audit_logs row carrying it", tc.name)
		assert.Contains(t, EventTypes(), tc.want,
			"%s is not in the catalog, so the filter dropdown cannot offer it", tc.name)
	}
}
