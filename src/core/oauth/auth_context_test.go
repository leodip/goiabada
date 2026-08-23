package oauth

import (
	"testing"

	"github.com/leodip/goiabada/core/enums"
	"github.com/leodip/goiabada/core/models"
	"github.com/stretchr/testify/assert"
)

func TestHasPromptValue_EmptyPrompt(t *testing.T) {
	ac := &AuthContext{Prompt: ""}

	assert.False(t, ac.HasPromptValue("login"))
	assert.False(t, ac.HasPromptValue("none"))
	assert.False(t, ac.HasPromptValue("consent"))
}

func TestHasPromptValue_SingleValue_Match(t *testing.T) {
	ac := &AuthContext{Prompt: "login"}

	assert.True(t, ac.HasPromptValue("login"))
	assert.False(t, ac.HasPromptValue("none"))
	assert.False(t, ac.HasPromptValue("consent"))
}

func TestHasPromptValue_SingleValue_None(t *testing.T) {
	ac := &AuthContext{Prompt: "none"}

	assert.True(t, ac.HasPromptValue("none"))
	assert.False(t, ac.HasPromptValue("login"))
	assert.False(t, ac.HasPromptValue("consent"))
}

func TestHasPromptValue_MultipleValues_LoginConsent(t *testing.T) {
	ac := &AuthContext{Prompt: "login consent"}

	assert.True(t, ac.HasPromptValue("login"))
	assert.True(t, ac.HasPromptValue("consent"))
	assert.False(t, ac.HasPromptValue("none"))
}

func TestHasPromptValue_MultipleValues_ConsentLogin(t *testing.T) {
	// Order shouldn't matter
	ac := &AuthContext{Prompt: "consent login"}

	assert.True(t, ac.HasPromptValue("login"))
	assert.True(t, ac.HasPromptValue("consent"))
	assert.False(t, ac.HasPromptValue("none"))
}

func TestHasPromptValue_PartialMatch_ShouldNotMatch(t *testing.T) {
	ac := &AuthContext{Prompt: "login"}

	// "log" is a substring of "login" but shouldn't match
	assert.False(t, ac.HasPromptValue("log"))
	assert.False(t, ac.HasPromptValue("ogin"))
}

func TestHasPromptValue_CaseSensitive(t *testing.T) {
	ac := &AuthContext{Prompt: "login"}

	assert.True(t, ac.HasPromptValue("login"))
	assert.False(t, ac.HasPromptValue("LOGIN"))
	assert.False(t, ac.HasPromptValue("Login"))
}

func TestHasPromptValue_WhitespaceHandling(t *testing.T) {
	// strings.Fields handles multiple spaces correctly
	ac := &AuthContext{Prompt: "login  consent"}

	assert.True(t, ac.HasPromptValue("login"))
	assert.True(t, ac.HasPromptValue("consent"))
}

// =============================================================================
// Tests for GetTargetAcrLevel / parseAcrValuesFromAuthorizeRequest
//
// The target ACR level is what decides whether OTP is required for a request:
// handler_auth_level1.go, handler_auth_level2.go and handler_auth_completed.go
// all branch on it. Per OIDC, acr_values is a space-separated list in order of
// preference, so the FIRST recognized value wins. A regression that picked a
// different element, or that failed to ignore unknown values, would silently
// change whether two-factor authentication is enforced.
// =============================================================================

// The nine (requested, client default) pairs. A request can raise the authentication level and
// never lower it, so the target is the higher of the first recognized acr_values entry and the
// client's configured level.
//
// The grid is explicit rather than derived, because the two halves fail in opposite directions and
// a derived expectation would hide one of them: see the "keep this" notes on the step-up rows.
func TestGetTargetAcrLevel_SingleValue(t *testing.T) {
	testCases := []struct {
		name          string
		acrValues     string
		clientDefault enums.AcrLevel
		want          enums.AcrLevel
		note          string
	}{
		{
			name:          "level1 requested at a level1 client",
			acrValues:     "urn:goiabada:level1",
			clientDefault: enums.AcrLevel1,
			want:          enums.AcrLevel1,
			note:          "at the floor",
		},
		{
			name:          "level1 requested at a level2_optional client is raised",
			acrValues:     "urn:goiabada:level1",
			clientDefault: enums.AcrLevel2Optional,
			want:          enums.AcrLevel2Optional,
			note:          "clamped",
		},
		{
			name:          "level1 requested at a level2_mandatory client is raised",
			acrValues:     "urn:goiabada:level1",
			clientDefault: enums.AcrLevel2Mandatory,
			want:          enums.AcrLevel2Mandatory,
			// This row is the defect itself: before the floor existed, appending
			// &acr_values=urn:goiabada:level1 to the authorization URL turned off the second
			// factor of a client configured to demand one (#240).
			note: "clamped, the bypass",
		},
		{
			name:          "level2_optional requested at a level1 client is honoured",
			acrValues:     "urn:goiabada:level2_optional",
			clientDefault: enums.AcrLevel1,
			want:          enums.AcrLevel2Optional,
			// KEEP THIS ROW. It, and the two below it, are the regression guard against
			// implementing the floor as "the client default always wins". That mistake leaves
			// step-up broken while every clamped row above still passes, so nothing else here
			// would notice it.
			note: "step-up preserved",
		},
		{
			name:          "level2_optional requested at a level2_optional client",
			acrValues:     "urn:goiabada:level2_optional",
			clientDefault: enums.AcrLevel2Optional,
			want:          enums.AcrLevel2Optional,
			note:          "at the floor",
		},
		{
			name:          "level2_optional requested at a level2_mandatory client is raised",
			acrValues:     "urn:goiabada:level2_optional",
			clientDefault: enums.AcrLevel2Mandatory,
			want:          enums.AcrLevel2Mandatory,
			note:          "clamped",
		},
		{
			name:          "level2_mandatory requested at a level1 client is honoured",
			acrValues:     "urn:goiabada:level2_mandatory",
			clientDefault: enums.AcrLevel1,
			want:          enums.AcrLevel2Mandatory,
			note:          "step-up preserved, see the KEEP note above",
		},
		{
			name:          "level2_mandatory requested at a level2_optional client is honoured",
			acrValues:     "urn:goiabada:level2_mandatory",
			clientDefault: enums.AcrLevel2Optional,
			want:          enums.AcrLevel2Mandatory,
			note:          "step-up preserved, see the KEEP note above",
		},
		{
			name:          "level2_mandatory requested at a level2_mandatory client",
			acrValues:     "urn:goiabada:level2_mandatory",
			clientDefault: enums.AcrLevel2Mandatory,
			want:          enums.AcrLevel2Mandatory,
			note:          "at the floor",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ac := &AuthContext{AcrValuesFromAuthorizeRequest: tc.acrValues}

			assert.Equal(t, tc.want, ac.GetTargetAcrLevel(tc.clientDefault), tc.note)
		})
	}
}

// The first recognized acr_values entry still decides which level the request asked for. It is
// then raised to the client's configured level, so a later entry in the list is never reached
// even when it is higher.
func TestGetTargetAcrLevel_FirstRecognizedValueWins(t *testing.T) {
	testCases := []struct {
		name          string
		acrValues     string
		clientDefault enums.AcrLevel
		want          enums.AcrLevel
	}{
		{
			name:          "level1 listed first",
			acrValues:     "urn:goiabada:level1 urn:goiabada:level2_mandatory",
			clientDefault: enums.AcrLevel1,
			want:          enums.AcrLevel1,
		},
		{
			name:          "level2_mandatory listed first",
			acrValues:     "urn:goiabada:level2_mandatory urn:goiabada:level1",
			clientDefault: enums.AcrLevel1,
			want:          enums.AcrLevel2Mandatory,
		},
		{
			name:          "level2_optional listed first",
			acrValues:     "urn:goiabada:level2_optional urn:goiabada:level1 urn:goiabada:level2_mandatory",
			clientDefault: enums.AcrLevel1,
			want:          enums.AcrLevel2Optional,
		},
		{
			name:          "unrecognized value ahead of a valid one is skipped",
			acrValues:     "urn:example:unknown urn:goiabada:level2_mandatory",
			clientDefault: enums.AcrLevel1,
			want:          enums.AcrLevel2Mandatory,
		},
		{
			// KEEP THIS EXPECTATION. level2_mandatory is listed and is NOT the answer: the first
			// recognized entry is level1, which the client's level2_optional floor raises to
			// level2_optional, and the list is not walked for a better match. Walking it would
			// push a user with no authenticator into enrolment on the strength of the ordering
			// of a list in a URL they never saw, which is why this is the expected value rather
			// than a mistake (#240).
			name:          "the floor answers, not a higher value listed later",
			acrValues:     "urn:goiabada:level1 urn:goiabada:level2_mandatory",
			clientDefault: enums.AcrLevel2Optional,
			want:          enums.AcrLevel2Optional,
		},
		{
			name:          "unrecognized value skipped, then the survivor is raised",
			acrValues:     "urn:example:unknown urn:goiabada:level1",
			clientDefault: enums.AcrLevel2Optional,
			want:          enums.AcrLevel2Optional,
		},
		{
			name:          "duplicate entries collapse, then the survivor is raised",
			acrValues:     "urn:goiabada:level1 urn:goiabada:level1",
			clientDefault: enums.AcrLevel2Optional,
			want:          enums.AcrLevel2Optional,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ac := &AuthContext{AcrValuesFromAuthorizeRequest: tc.acrValues}

			assert.Equal(t, tc.want, ac.GetTargetAcrLevel(tc.clientDefault),
				"the first recognized acr_values entry wins, raised to the client's configured level")
		})
	}
}

// When acr_values is absent, unparseable, or contains nothing recognized, the
// client's configured DefaultAcrLevel applies.
//
// Nothing parses on any of these inputs, so the floor never fires and this path is unchanged by
// it. That is why the cases here pass a bare client default and the two functions above own the
// (requested, client default) grid instead: a third table asserting the same rule would be
// duplication rather than coverage.
func TestGetTargetAcrLevel_FallsBackToClientDefault(t *testing.T) {
	testCases := []struct {
		name      string
		acrValues string
	}{
		{"empty", ""},
		{"whitespace only", "   "},
		{"single unrecognized value", "urn:example:unknown"},
		{"several unrecognized values", "foo bar baz"},
		{"wrong case", "URN:GOIABADA:LEVEL1"},
		{"almost right", "urn:goiabada:level3"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ac := &AuthContext{AcrValuesFromAuthorizeRequest: tc.acrValues}

			assert.Equal(t, enums.AcrLevel2Mandatory, ac.GetTargetAcrLevel(enums.AcrLevel2Mandatory))
			assert.Equal(t, enums.AcrLevel1, ac.GetTargetAcrLevel(enums.AcrLevel1))
		})
	}
}

// The target is snapshotted when the authorization request is accepted, so a client row edited
// while the ceremony is in flight cannot change what that ceremony was required to do (#240).
func TestGetTargetAcrLevel_SnapshotWinsOverTheLiveClientDefault(t *testing.T) {
	t.Run("a client default raised mid-ceremony does not raise the target", func(t *testing.T) {
		ac := &AuthContext{}
		ac.SetTargetAcrLevel(enums.AcrLevel1)

		// The administrator raises the row after the ceremony started. Reading it here is what
		// would stamp an acr naming a second factor the user never performed.
		assert.Equal(t, enums.AcrLevel1, ac.GetTargetAcrLevel(enums.AcrLevel2Mandatory))
	})

	t.Run("a client default lowered mid-ceremony does not lower the target", func(t *testing.T) {
		ac := &AuthContext{}
		ac.SetTargetAcrLevel(enums.AcrLevel2Mandatory)

		// Reading the lowered row here is what takes /auth/level2's switch to its default branch
		// and answers 500.
		assert.Equal(t, enums.AcrLevel2Mandatory, ac.GetTargetAcrLevel(enums.AcrLevel1))
	})

	t.Run("the snapshot carries the floor, not the raw request", func(t *testing.T) {
		ac := &AuthContext{AcrValuesFromAuthorizeRequest: "urn:goiabada:level1"}
		ac.SetTargetAcrLevel(enums.AcrLevel2Mandatory)

		assert.Equal(t, enums.AcrLevel2Mandatory.String(), ac.TargetAcrLevel)
		assert.Equal(t, enums.AcrLevel2Mandatory, ac.GetTargetAcrLevel(enums.AcrLevel1))
	})
}

// A context written before this field existed carries no snapshot, and a later release could in
// principle drop a level and leave one unreadable. Both fall back to computing the target from the
// client's current row, which is the behaviour every handler had before the snapshot and is never
// below what the request asked for.
func TestGetTargetAcrLevel_UnusableSnapshotFallsBackToTheClientDefault(t *testing.T) {
	testCases := []struct {
		name     string
		snapshot string
	}{
		{"absent, as an older cookie unmarshals it", ""},
		{"unparsable, as a dropped level would leave it", "urn:goiabada:level4"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ac := &AuthContext{
				AcrValuesFromAuthorizeRequest: "urn:goiabada:level1",
				TargetAcrLevel:                tc.snapshot,
			}

			// The floor still applies on the fallback arm, so the answer is the client's level
			// and not the level1 the request asked for.
			assert.Equal(t, enums.AcrLevel2Optional, ac.GetTargetAcrLevel(enums.AcrLevel2Optional))
		})
	}
}

// SetTargetAcrLevel and GetTargetAcrLevel are pinned to each other rather than each only to
// itself: whatever the writer stores, the reader must give back unchanged for every level.
func TestSetTargetAcrLevel_RoundTripsEveryLevel(t *testing.T) {
	for _, clientDefault := range []enums.AcrLevel{enums.AcrLevel1, enums.AcrLevel2Optional, enums.AcrLevel2Mandatory} {
		t.Run(clientDefault.String(), func(t *testing.T) {
			ac := &AuthContext{}
			ac.SetTargetAcrLevel(clientDefault)

			assert.Equal(t, clientDefault.String(), ac.TargetAcrLevel)
			// Read back against a client default that differs from the snapshot wherever it can,
			// so a reader ignoring the snapshot answers something else.
			other := enums.AcrLevel1
			if clientDefault == enums.AcrLevel1 {
				other = enums.AcrLevel2Mandatory
			}
			assert.Equal(t, clientDefault, ac.GetTargetAcrLevel(other))
		})
	}
}

func TestParseAcrValuesFromAuthorizeRequest(t *testing.T) {
	t.Run("collapses repeated whitespace", func(t *testing.T) {
		ac := &AuthContext{
			AcrValuesFromAuthorizeRequest: "urn:goiabada:level1     urn:goiabada:level2_mandatory",
		}

		result := ac.parseAcrValuesFromAuthorizeRequest()

		assert.Equal(t, []enums.AcrLevel{enums.AcrLevel1, enums.AcrLevel2Mandatory}, result)
	})

	t.Run("deduplicates repeated values preserving first position", func(t *testing.T) {
		ac := &AuthContext{
			AcrValuesFromAuthorizeRequest: "urn:goiabada:level2_optional urn:goiabada:level1 urn:goiabada:level2_optional",
		}

		result := ac.parseAcrValuesFromAuthorizeRequest()

		assert.Equal(t, []enums.AcrLevel{enums.AcrLevel2Optional, enums.AcrLevel1}, result)
	})

	t.Run("drops unrecognized values", func(t *testing.T) {
		ac := &AuthContext{
			AcrValuesFromAuthorizeRequest: "nonsense urn:goiabada:level1 more-nonsense",
		}

		result := ac.parseAcrValuesFromAuthorizeRequest()

		assert.Equal(t, []enums.AcrLevel{enums.AcrLevel1}, result)
	})

	t.Run("empty input yields an empty slice", func(t *testing.T) {
		ac := &AuthContext{AcrValuesFromAuthorizeRequest: ""}

		result := ac.parseAcrValuesFromAuthorizeRequest()

		assert.Empty(t, result)
	})

	t.Run("all values unrecognized yields an empty slice", func(t *testing.T) {
		ac := &AuthContext{AcrValuesFromAuthorizeRequest: "a b c"}

		result := ac.parseAcrValuesFromAuthorizeRequest()

		assert.Empty(t, result)
	})
}

// =============================================================================
// Tests for SetAcrLevel
//
// The ACR written into the token is max(target, session), so an authenticated
// session is never downgraded partway through.
// =============================================================================

func TestSetAcrLevel_NoSessionUsesTarget(t *testing.T) {
	for _, target := range []enums.AcrLevel{enums.AcrLevel1, enums.AcrLevel2Optional, enums.AcrLevel2Mandatory} {
		t.Run(target.String(), func(t *testing.T) {
			ac := &AuthContext{}

			err := ac.SetAcrLevel(target, nil)

			assert.NoError(t, err)
			assert.Equal(t, target.String(), ac.AcrLevel)
		})
	}
}

func TestSetAcrLevel_UsesHigherOfTargetAndSession(t *testing.T) {
	testCases := []struct {
		name        string
		target      enums.AcrLevel
		sessionAcr  enums.AcrLevel
		wantAcr     enums.AcrLevel
		description string
	}{
		{
			name:        "session higher than target is kept",
			target:      enums.AcrLevel1,
			sessionAcr:  enums.AcrLevel2Mandatory,
			wantAcr:     enums.AcrLevel2Mandatory,
			description: "a level2 session must not be downgraded by a level1 request",
		},
		{
			name:        "target higher than session wins",
			target:      enums.AcrLevel2Mandatory,
			sessionAcr:  enums.AcrLevel1,
			wantAcr:     enums.AcrLevel2Mandatory,
			description: "a step-up request must raise the ACR",
		},
		{
			name:        "equal levels",
			target:      enums.AcrLevel2Optional,
			sessionAcr:  enums.AcrLevel2Optional,
			wantAcr:     enums.AcrLevel2Optional,
			description: "matching levels stay put",
		},
		{
			name:        "optional session with mandatory target",
			target:      enums.AcrLevel2Mandatory,
			sessionAcr:  enums.AcrLevel2Optional,
			wantAcr:     enums.AcrLevel2Mandatory,
			description: "mandatory outranks optional",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ac := &AuthContext{}
			session := &models.UserSession{AcrLevel: tc.sessionAcr.String()}

			err := ac.SetAcrLevel(tc.target, session)

			assert.NoError(t, err)
			assert.Equal(t, tc.wantAcr.String(), ac.AcrLevel, tc.description)
		})
	}
}

// A session row carrying an unrecognized ACR string must surface an error rather
// than silently defaulting to some level.
func TestSetAcrLevel_InvalidSessionAcrReturnsError(t *testing.T) {
	ac := &AuthContext{}
	session := &models.UserSession{AcrLevel: "urn:goiabada:bogus"}

	err := ac.SetAcrLevel(enums.AcrLevel1, session)

	assert.Error(t, err)
	assert.Equal(t, "", ac.AcrLevel, "the ACR must not be set when the session level cannot be parsed")
}

// =============================================================================
// Tests for OwnsSession
//
// The predicate every ambient-session read consults: a ceremony may reuse the
// browser's session only when that session belongs to the user the ceremony
// authenticated. Both zero cases are false, so this table is exhaustive over
// the two inputs and no caller re-tests the combinations.
// =============================================================================

func TestOwnsSession(t *testing.T) {
	testCases := []struct {
		name          string
		contextUserId int64
		session       *models.UserSession
		want          bool
		description   string
	}{
		{
			name:          "nil session with a known user",
			contextUserId: 1,
			session:       nil,
			want:          false,
			description:   "there is no session to own",
		},
		{
			name:          "nil session with no user",
			contextUserId: 0,
			session:       nil,
			want:          false,
			description:   "neither side is known",
		},
		{
			name:          "both zero",
			contextUserId: 0,
			session:       &models.UserSession{UserId: 0},
			want:          false,
			description:   "two zeros are not a match: an unidentified ceremony must not match an unsaved session",
		},
		{
			name:          "no user with a real session",
			contextUserId: 0,
			session:       &models.UserSession{UserId: 1},
			want:          false,
			description:   "a ceremony that has not authenticated anyone owns nothing",
		},
		{
			name:          "same user",
			contextUserId: 1,
			session:       &models.UserSession{UserId: 1},
			want:          true,
			description:   "the ordinary SSO path, the only true row",
		},
		{
			name:          "different user",
			contextUserId: 2,
			session:       &models.UserSession{UserId: 1},
			want:          false,
			description:   "B's ceremony must not reuse A's session",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ac := &AuthContext{UserId: tc.contextUserId}

			assert.Equal(t, tc.want, ac.OwnsSession(tc.session), tc.description)
		})
	}
}

// =============================================================================
// Tests for ParseRequestedMaxAge
//
// max_age arrives as a raw query-string value and feeds
// UserSessionManager.HasValidUserSession, where it caps how old an existing
// session may be. A nil result means "no max_age was requested", so the
// distinction between nil and a parsed zero matters.
// =============================================================================

func TestParseRequestedMaxAge(t *testing.T) {
	testCases := []struct {
		name   string
		maxAge string
		want   *int
	}{
		{"absent", "", nil},
		{"typical value", "3600", intPtr(3600)},
		{"zero means reauthenticate now", "0", intPtr(0)},
		{"large value", "86400", intPtr(86400)},
		{"non-numeric is ignored", "abc", nil},
		{"partially numeric is ignored", "10s", nil},
		{"float is ignored", "3600.5", nil},
		{"surrounding whitespace is not trimmed, so it is ignored", " 3600 ", nil},
		{"negative value is accepted as-is", "-1", intPtr(-1)},
		{"overflowing value is ignored", "99999999999999999999", nil},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ac := &AuthContext{MaxAge: tc.maxAge}

			got := ac.ParseRequestedMaxAge()

			if tc.want == nil {
				assert.Nil(t, got)
				return
			}
			assert.NotNil(t, got)
			assert.Equal(t, *tc.want, *got)
		})
	}
}

// "0" must not collapse to nil: nil means no max_age was requested, whereas 0
// means the session must be treated as too old and the user re-authenticated.
func TestParseRequestedMaxAge_ZeroIsDistinctFromAbsent(t *testing.T) {
	zero := (&AuthContext{MaxAge: "0"}).ParseRequestedMaxAge()
	absent := (&AuthContext{MaxAge: ""}).ParseRequestedMaxAge()

	assert.NotNil(t, zero)
	assert.Equal(t, 0, *zero)
	assert.Nil(t, absent)
}

func intPtr(i int) *int {
	return &i
}

// =============================================================================
// Tests for AddAuthMethod
//
// AuthMethods becomes the "amr" claim. It must stay free of duplicates, since
// clients read it to decide whether a second factor was used.
// =============================================================================

func TestAddAuthMethod_FirstMethod(t *testing.T) {
	ac := &AuthContext{}

	ac.AddAuthMethod("pwd")

	assert.Equal(t, "pwd", ac.AuthMethods)
}

func TestAddAuthMethod_AppendsSecondMethod(t *testing.T) {
	ac := &AuthContext{}

	ac.AddAuthMethod("pwd")
	ac.AddAuthMethod("otp")

	assert.Equal(t, "pwd otp", ac.AuthMethods)
}

func TestAddAuthMethod_IgnoresEmptyAndWhitespaceOnly(t *testing.T) {
	testCases := []string{"", "   ", "\t", "\n"}

	for _, method := range testCases {
		t.Run("input:"+method, func(t *testing.T) {
			ac := &AuthContext{AuthMethods: "pwd"}

			ac.AddAuthMethod(method)

			assert.Equal(t, "pwd", ac.AuthMethods, "an empty method must be a no-op")
		})
	}
}

func TestAddAuthMethod_EmptyMethodOnEmptyContextStaysEmpty(t *testing.T) {
	ac := &AuthContext{}

	ac.AddAuthMethod("")

	assert.Equal(t, "", ac.AuthMethods)
}

func TestAddAuthMethod_NormalizesInput(t *testing.T) {
	ac := &AuthContext{}

	ac.AddAuthMethod("  PWD  ")

	assert.Equal(t, "pwd", ac.AuthMethods, "methods are lowercased and trimmed")
}

func TestAddAuthMethod_SuppressesDuplicates(t *testing.T) {
	testCases := []struct {
		name     string
		existing string
		add      string
		want     string
	}{
		{"exact duplicate", "pwd", "pwd", "pwd"},
		{"duplicate differing in case", "pwd", "PWD", "pwd"},
		{"duplicate with whitespace", "pwd", "  pwd  ", "pwd"},
		{"duplicate of the second method", "pwd otp", "otp", "pwd otp"},
		{"duplicate of the first method", "pwd otp", "pwd", "pwd otp"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ac := &AuthContext{AuthMethods: tc.existing}

			ac.AddAuthMethod(tc.add)

			assert.Equal(t, tc.want, ac.AuthMethods)
		})
	}
}

// The duplicate check is case-insensitive, but an existing value's original
// casing is left untouched when a new method is appended.
func TestAddAuthMethod_PreservesExistingCasingWhenAppending(t *testing.T) {
	ac := &AuthContext{AuthMethods: "PWD"}

	ac.AddAuthMethod("otp")

	assert.Equal(t, "PWD otp", ac.AuthMethods)
}

func TestAddAuthMethod_RepeatedCallsStayIdempotent(t *testing.T) {
	ac := &AuthContext{}

	for i := 0; i < 5; i++ {
		ac.AddAuthMethod("pwd")
		ac.AddAuthMethod("otp")
	}

	assert.Equal(t, "pwd otp", ac.AuthMethods)
}

// =============================================================================
// Tests for SetScope / HasScope
// =============================================================================

func TestSetScope_NormalizesWhitespaceAndDuplicates(t *testing.T) {
	testCases := []struct {
		name  string
		input string
		want  string
	}{
		{"already normalized", "openid profile", "openid profile"},
		{"repeated spaces", "openid    profile", "openid profile"},
		{"leading and trailing spaces", "  openid profile  ", "openid profile"},
		{"duplicate scopes", "openid openid profile", "openid profile"},
		{"tabs and newlines", "openid\tprofile\nemail", "openid profile email"},
		{"empty", "", ""},
		{"whitespace only", "   ", ""},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ac := &AuthContext{}

			ac.SetScope(tc.input)

			assert.Equal(t, tc.want, ac.Scope)
		})
	}
}

func TestAuthContext_HasScope(t *testing.T) {
	testCases := []struct {
		name  string
		scope string
		query string
		want  bool
	}{
		{"present among several", "openid profile email", "profile", true},
		{"first element", "openid profile", "openid", true},
		{"last element", "openid profile", "profile", true},
		{"only element", "openid", "openid", true},
		{"absent", "openid profile", "email", false},
		{"empty scope", "", "openid", false},
		{"empty query against empty scope", "", "", false},
		{"prefix must not match", "openid profile", "open", false},
		{"suffix must not match", "openid profile", "id", false},
		{"resource scope present", "openid backend-svc:read", "backend-svc:read", true},
		{"resource scope absent", "openid backend-svc:read", "backend-svc:write", false},
		{"case sensitive", "openid", "OPENID", false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ac := &AuthContext{Scope: tc.scope}

			assert.Equal(t, tc.want, ac.HasScope(tc.query))
		})
	}
}
