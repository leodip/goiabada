package handlers

import (
	"testing"

	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Every arm /auth/completed can bind a ceremony through, and what each arm does beyond its core
// write. The handler cases show each arm reaching its act; which arm a ceremony takes is decided
// here (#437 seam 1).
func TestDecideCompletion(t *testing.T) {
	testCases := []struct {
		name  string
		facts completionFacts
		want  completionPlan
	}{
		// Reuse: the arrived-with session is valid and the ceremony's (#133).
		{
			name:  "a valid owned session is reused, with nothing else to do for an SSO pass",
			facts: completionFacts{sessionPresent: true, sessionValid: true, sessionOwned: true, target: record.AcrLevel1},
			want:  completionPlan{arm: completionArmReuse},
		},
		{
			// Reuse asks nothing of level 1: an SSO pass never saw the password form.
			name:  "reuse does not need level 1 completed in this ceremony",
			facts: completionFacts{sessionPresent: true, sessionValid: true, sessionOwned: true, level1Completed: false},
			want:  completionPlan{arm: completionArmReuse},
		},
		{
			name:  "a bump that raises a privilege rotates the identifier first",
			facts: completionFacts{sessionPresent: true, sessionValid: true, sessionOwned: true, raisesPrivilege: true},
			want:  completionPlan{arm: completionArmReuse, rotateIdentifier: true},
		},
		{
			name:  "a credential entered in this ceremony refreshes AuthTime",
			facts: completionFacts{sessionPresent: true, sessionValid: true, sessionOwned: true, credentialEntered: true},
			want:  completionPlan{arm: completionArmReuse, refreshAuthTime: true},
		},
		{
			name: "a captured OTP generation is promoted for level2_optional",
			facts: completionFacts{sessionPresent: true, sessionValid: true, sessionOwned: true,
				otpConfigGenerationCaptured: true, target: record.AcrLevel2Optional},
			want: completionPlan{arm: completionArmReuse, promoteOtpConfigGeneration: true},
		},
		{
			name: "a captured OTP generation is promoted for level2_mandatory",
			facts: completionFacts{sessionPresent: true, sessionValid: true, sessionOwned: true,
				otpConfigGenerationCaptured: true, target: record.AcrLevel2Mandatory},
			want: completionPlan{arm: completionArmReuse, promoteOtpConfigGeneration: true},
		},
		{
			// The password handler captures too, and a level 1 target never addressed level 2 (#242
			// decision 3).
			name: "a captured OTP generation is not promoted for a level 1 target",
			facts: completionFacts{sessionPresent: true, sessionValid: true, sessionOwned: true,
				otpConfigGenerationCaptured: true, target: record.AcrLevel1},
			want: completionPlan{arm: completionArmReuse},
		},
		{
			name:  "nothing is promoted without a capture, whatever the target",
			facts: completionFacts{sessionPresent: true, sessionValid: true, sessionOwned: true, target: record.AcrLevel2Mandatory},
			want:  completionPlan{arm: completionArmReuse},
		},
		{
			name: "every reuse flag at once",
			facts: completionFacts{sessionPresent: true, sessionValid: true, sessionOwned: true, raisesPrivilege: true,
				credentialEntered: true, otpConfigGenerationCaptured: true, target: record.AcrLevel2Optional},
			want: completionPlan{arm: completionArmReuse, rotateIdentifier: true, refreshAuthTime: true,
				promoteOtpConfigGeneration: true},
		},

		// Restart: no reusable session and no level 1 in this ceremony (#129 decision 6).
		{
			name:  "no session and no level 1 restarts",
			facts: completionFacts{},
			want:  completionPlan{arm: completionArmRestart},
		},
		{
			// AuthenticatedAt has two writers, and OTP alone is not level 1 (#129 decision 15).
			name:  "a credential entered without level 1 still restarts",
			facts: completionFacts{credentialEntered: true, otpConfigGenerationCaptured: true, target: record.AcrLevel2Optional},
			want:  completionPlan{arm: completionArmRestart},
		},
		{
			name:  "an expired owned session without level 1 restarts, and is not replaced",
			facts: completionFacts{sessionPresent: true, sessionValid: false, sessionOwned: true},
			want:  completionPlan{arm: completionArmRestart},
		},
		{
			// Destroying somebody's session must follow a real authentication in this ceremony.
			name:  "a foreign session without level 1 restarts, and is not terminated",
			facts: completionFacts{sessionPresent: true, sessionValid: true, sessionOwned: false},
			want:  completionPlan{arm: completionArmRestart},
		},

		// Create: no reusable session, level 1 done in this ceremony.
		{
			name:  "no session with level 1 creates one, terminating and replacing nothing",
			facts: completionFacts{level1Completed: true},
			want:  completionPlan{arm: completionArmCreate},
		},
		{
			name:  "a valid foreign session is terminated before the new one is created",
			facts: completionFacts{sessionPresent: true, sessionValid: true, sessionOwned: false, level1Completed: true},
			want:  completionPlan{arm: completionArmCreate, terminateForeignSession: true},
		},
		{
			// A row that can never be resumed is still a cookie in this browser with grants behind it.
			name:  "an expired foreign session is terminated as well",
			facts: completionFacts{sessionPresent: true, sessionValid: false, sessionOwned: false, level1Completed: true},
			want:  completionPlan{arm: completionArmCreate, terminateForeignSession: true},
		},
		{
			name:  "an expired owned session is replaced by the new one, not terminated",
			facts: completionFacts{sessionPresent: true, sessionValid: false, sessionOwned: true, level1Completed: true},
			want:  completionPlan{arm: completionArmCreate, replaceOwnSession: true},
		},
		{
			name: "the reuse flags stay off on the create arm",
			facts: completionFacts{level1Completed: true, raisesPrivilege: true, credentialEntered: true,
				otpConfigGenerationCaptured: true, target: record.AcrLevel2Mandatory},
			want: completionPlan{arm: completionArmCreate},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, decideCompletion(tc.facts))
		})
	}
}

// What /auth/completed does with the ceremony's user before an arm binds a session (#522 decision
// 6). The ceremony authenticated at generation 7.
func TestDecideBeforeBinding(t *testing.T) {
	testCases := []struct {
		name string
		user *record.User
		want beforeBindingAnswer
	}{
		{name: "an enabled user at the ceremony's generation is bound",
			user: &record.User{Enabled: true, AuthStateGeneration: 7}, want: beforeBindingBind},
		{name: "a missing user", user: nil, want: beforeBindingUserMissing},
		{name: "a disabled user is refused",
			user: &record.User{Enabled: false, AuthStateGeneration: 7}, want: beforeBindingUserDisabled},
		{
			// A disable moves the generation on too, and the client is owed access_denied.
			name: "a disabled user is refused before the generation is compared",
			user: &record.User{Enabled: false, AuthStateGeneration: 8}, want: beforeBindingUserDisabled,
		},
		{name: "a generation moved on restarts",
			user: &record.User{Enabled: true, AuthStateGeneration: 8}, want: beforeBindingGenerationMoved},
		{
			// Any difference, not only a later one: the comparison is the token endpoint's.
			name: "a generation behind the ceremony's restarts as well",
			user: &record.User{Enabled: true, AuthStateGeneration: 6}, want: beforeBindingGenerationMoved,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, decideBeforeBinding(tc.user, 7))
		})
	}
}

// afterBindingWorld is what HandleAuthCompletedGet would load after binding, answered from the row.
type afterBindingWorld struct {
	promptConsent   bool
	consentRequired bool
	effectiveScope  string
}

// driveAfterBinding runs decideAfterBinding as HandleAuthCompletedGet does, loading each fact it
// asks for from the world, and answers the answer and the facts in the order they were asked for.
func driveAfterBinding(t *testing.T, world afterBindingWorld) (afterBindingAnswer, []afterBindingFact) {
	t.Helper()

	facts := afterBindingFacts{
		promptConsent:   world.promptConsent,
		consentRequired: world.consentRequired,
	}
	var asked []afterBindingFact
	for {
		answer, need := decideAfterBinding(facts)
		if need == afterBindingFactNone {
			require.NotEqual(t, afterBindingUndecided, answer, "a decided ceremony has an answer")
			return answer, asked
		}
		require.NotContains(t, asked, need, "each fact is loaded once")
		asked = append(asked, need)

		switch need {
		case afterBindingFactEffectiveScope:
			scope := world.effectiveScope
			facts.effectiveScope = &scope
		default:
			require.FailNow(t, "an unknown fact", "%v", need)
		}
	}
}

// Where a ceremony bound to a session goes, and whether the scope is filtered on the way.
func TestDecideAfterBinding(t *testing.T) {
	const scope = afterBindingFactEffectiveScope

	testCases := []struct {
		name       string
		world      afterBindingWorld
		wantAnswer afterBindingAnswer
		wantReads  []afterBindingFact
	}{
		{
			name:       "a user holding none of the scopes is refused",
			world:      afterBindingWorld{effectiveScope: ""},
			wantAnswer: afterBindingNoScope,
			wantReads:  []afterBindingFact{scope},
		},
		{
			name:       "no scope is refused before prompt=consent is honoured",
			world:      afterBindingWorld{promptConsent: true, effectiveScope: ""},
			wantAnswer: afterBindingNoScope,
			wantReads:  []afterBindingFact{scope},
		},
		{
			name:       "prompt=consent goes to the consent screen",
			world:      afterBindingWorld{promptConsent: true, effectiveScope: "openid"},
			wantAnswer: afterBindingConsent,
			wantReads:  []afterBindingFact{scope},
		},
		{
			name:       "a client requiring consent goes to the consent screen",
			world:      afterBindingWorld{consentRequired: true, effectiveScope: "openid"},
			wantAnswer: afterBindingConsent,
			wantReads:  []afterBindingFact{scope},
		},
		{
			name:       "offline_access in the effective scope goes to the consent screen",
			world:      afterBindingWorld{effectiveScope: "openid offline_access"},
			wantAnswer: afterBindingConsent,
			wantReads:  []afterBindingFact{scope},
		},
		{
			name:       "no consent needed goes to issuance",
			world:      afterBindingWorld{effectiveScope: "openid profile"},
			wantAnswer: afterBindingIssue,
			wantReads:  []afterBindingFact{scope},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			answer, reads := driveAfterBinding(t, tc.world)
			assert.Equal(t, tc.wantAnswer, answer)
			assert.Equal(t, tc.wantReads, reads)
		})
	}
}
