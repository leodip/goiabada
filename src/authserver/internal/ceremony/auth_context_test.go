package ceremony

import (
	"math"
	"strings"
	"testing"
	"time"

	"github.com/leodip/goiabada/authserver/internal/oidc"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
	// The shared splitter handles multiple spaces correctly
	ac := &AuthContext{Prompt: "login  consent"}

	assert.True(t, ac.HasPromptValue("login"))
	assert.True(t, ac.HasPromptValue("consent"))
}

// / HasPromptValue reads the stored prompt with the splitter every space-delimited parameter is read
// with (#244), so it agrees with ValidatePrompt, which normalized what it reads, and with the
// handler's silence test. Only a space separates: a tab, a newline or a no-break space joins two
// words into one value that is neither, and nothing is trimmed off a value's edges.
func TestHasPromptValue_SharedSeparators(t *testing.T) {
	testCases := []struct {
		name   string
		prompt string
		value  string
		want   bool
	}{
		{"a space separates, the first word", "login consent", "login", true},
		{"a space separates, the second word", "login consent", "consent", true},
		{"a tab does not separate", "login\tconsent", "consent", false},
		{"a newline does not separate", "login\nconsent", "login", false},
		{"a form feed does not separate", "login\fconsent", "consent", false},
		{"a carriage return does not separate", "login\rconsent", "login", false},
		{"a no-break space does not separate, the first word", "login\u00a0consent", "login", false},
		{"a no-break space does not separate, the second word", "login\u00a0consent", "consent", false},
		{"a vertical tab does not separate", "login\vconsent", "login", false},
		{"a next-line character does not separate", "login\u0085consent", "consent", false},
		{"a value padded with a no-break space is not that value", "login\u00a0", "login", false},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ac := &AuthContext{Prompt: tc.prompt}

			assert.Equal(t, tc.want, ac.HasPromptValue(tc.value))
		})
	}
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
		clientDefault record.AcrLevel
		want          record.AcrLevel
		note          string
	}{
		{
			name:          "level1 requested at a level1 client",
			acrValues:     "urn:goiabada:level1",
			clientDefault: record.AcrLevel1,
			want:          record.AcrLevel1,
			note:          "at the floor",
		},
		{
			name:          "level1 requested at a level2_optional client is raised",
			acrValues:     "urn:goiabada:level1",
			clientDefault: record.AcrLevel2Optional,
			want:          record.AcrLevel2Optional,
			note:          "clamped",
		},
		{
			name:          "level1 requested at a level2_mandatory client is raised",
			acrValues:     "urn:goiabada:level1",
			clientDefault: record.AcrLevel2Mandatory,
			want:          record.AcrLevel2Mandatory,
			// This row is the defect itself: before the floor existed, appending
			// &acr_values=urn:goiabada:level1 to the authorization URL turned off the second
			// factor of a client configured to demand one (#240).
			note: "clamped, the bypass",
		},
		{
			name:          "level2_optional requested at a level1 client is honoured",
			acrValues:     "urn:goiabada:level2_optional",
			clientDefault: record.AcrLevel1,
			want:          record.AcrLevel2Optional,
			// KEEP THIS ROW. It, and the two below it, are the regression guard against
			// implementing the floor as "the client default always wins". That mistake leaves
			// step-up broken while every clamped row above still passes, so nothing else here
			// would notice it.
			note: "step-up preserved",
		},
		{
			name:          "level2_optional requested at a level2_optional client",
			acrValues:     "urn:goiabada:level2_optional",
			clientDefault: record.AcrLevel2Optional,
			want:          record.AcrLevel2Optional,
			note:          "at the floor",
		},
		{
			name:          "level2_optional requested at a level2_mandatory client is raised",
			acrValues:     "urn:goiabada:level2_optional",
			clientDefault: record.AcrLevel2Mandatory,
			want:          record.AcrLevel2Mandatory,
			note:          "clamped",
		},
		{
			name:          "level2_mandatory requested at a level1 client is honoured",
			acrValues:     "urn:goiabada:level2_mandatory",
			clientDefault: record.AcrLevel1,
			want:          record.AcrLevel2Mandatory,
			note:          "step-up preserved, see the KEEP note above",
		},
		{
			name:          "level2_mandatory requested at a level2_optional client is honoured",
			acrValues:     "urn:goiabada:level2_mandatory",
			clientDefault: record.AcrLevel2Optional,
			want:          record.AcrLevel2Mandatory,
			note:          "step-up preserved, see the KEEP note above",
		},
		{
			name:          "level2_mandatory requested at a level2_mandatory client",
			acrValues:     "urn:goiabada:level2_mandatory",
			clientDefault: record.AcrLevel2Mandatory,
			want:          record.AcrLevel2Mandatory,
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
		clientDefault record.AcrLevel
		want          record.AcrLevel
	}{
		{
			name:          "level1 listed first",
			acrValues:     "urn:goiabada:level1 urn:goiabada:level2_mandatory",
			clientDefault: record.AcrLevel1,
			want:          record.AcrLevel1,
		},
		{
			name:          "level2_mandatory listed first",
			acrValues:     "urn:goiabada:level2_mandatory urn:goiabada:level1",
			clientDefault: record.AcrLevel1,
			want:          record.AcrLevel2Mandatory,
		},
		{
			name:          "level2_optional listed first",
			acrValues:     "urn:goiabada:level2_optional urn:goiabada:level1 urn:goiabada:level2_mandatory",
			clientDefault: record.AcrLevel1,
			want:          record.AcrLevel2Optional,
		},
		{
			name:          "unrecognized value ahead of a valid one is skipped",
			acrValues:     "urn:example:unknown urn:goiabada:level2_mandatory",
			clientDefault: record.AcrLevel1,
			want:          record.AcrLevel2Mandatory,
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
			clientDefault: record.AcrLevel2Optional,
			want:          record.AcrLevel2Optional,
		},
		{
			name:          "unrecognized value skipped, then the survivor is raised",
			acrValues:     "urn:example:unknown urn:goiabada:level1",
			clientDefault: record.AcrLevel2Optional,
			want:          record.AcrLevel2Optional,
		},
		{
			name:          "duplicate entries collapse, then the survivor is raised",
			acrValues:     "urn:goiabada:level1 urn:goiabada:level1",
			clientDefault: record.AcrLevel2Optional,
			want:          record.AcrLevel2Optional,
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

			assert.Equal(t, record.AcrLevel2Mandatory, ac.GetTargetAcrLevel(record.AcrLevel2Mandatory))
			assert.Equal(t, record.AcrLevel1, ac.GetTargetAcrLevel(record.AcrLevel1))
		})
	}
}

// The target is snapshotted when the authorization request is accepted, so a client row edited
// while the ceremony is in flight cannot change what that ceremony was required to do (#240).
func TestGetTargetAcrLevel_SnapshotWinsOverTheLiveClientDefault(t *testing.T) {
	t.Run("a client default raised mid-ceremony does not raise the target", func(t *testing.T) {
		ac := &AuthContext{}
		ac.SetTargetAcrLevel(record.AcrLevel1)

		// The administrator raises the row after the ceremony started. Reading it here is what
		// would stamp an acr naming a second factor the user never performed.
		assert.Equal(t, record.AcrLevel1, ac.GetTargetAcrLevel(record.AcrLevel2Mandatory))
	})

	t.Run("a client default lowered mid-ceremony does not lower the target", func(t *testing.T) {
		ac := &AuthContext{}
		ac.SetTargetAcrLevel(record.AcrLevel2Mandatory)

		// Reading the lowered row here is what takes /auth/level2's switch to its default branch
		// and answers 500.
		assert.Equal(t, record.AcrLevel2Mandatory, ac.GetTargetAcrLevel(record.AcrLevel1))
	})

	t.Run("the snapshot carries the floor, not the raw request", func(t *testing.T) {
		ac := &AuthContext{AcrValuesFromAuthorizeRequest: "urn:goiabada:level1"}
		ac.SetTargetAcrLevel(record.AcrLevel2Mandatory)

		assert.Equal(t, record.AcrLevel2Mandatory.String(), ac.TargetAcrLevel)
		assert.Equal(t, record.AcrLevel2Mandatory, ac.GetTargetAcrLevel(record.AcrLevel1))
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
			assert.Equal(t, record.AcrLevel2Optional, ac.GetTargetAcrLevel(record.AcrLevel2Optional))
		})
	}
}

// SetTargetAcrLevel and GetTargetAcrLevel are pinned to each other rather than each only to
// itself: whatever the writer stores, the reader must give back unchanged for every level.
func TestSetTargetAcrLevel_RoundTripsEveryLevel(t *testing.T) {
	for _, clientDefault := range []record.AcrLevel{record.AcrLevel1, record.AcrLevel2Optional, record.AcrLevel2Mandatory} {
		t.Run(clientDefault.String(), func(t *testing.T) {
			ac := &AuthContext{}
			ac.SetTargetAcrLevel(clientDefault)

			assert.Equal(t, clientDefault.String(), ac.TargetAcrLevel)
			// Read back against a client default that differs from the snapshot wherever it can,
			// so a reader ignoring the snapshot answers something else.
			other := record.AcrLevel1
			if clientDefault == record.AcrLevel1 {
				other = record.AcrLevel2Mandatory
			}
			assert.Equal(t, clientDefault, ac.GetTargetAcrLevel(other))
		})
	}
}

// / acr_values is read with the grammar the space-delimited parameters share (#244): one space between
// each two levels and none at either end. A value that breaks it is read as no acr_values at all,
// never refused, since OIDC Core makes acr_values a request the server may decline; the client's
// level is the floor either way, so declining can never lower the target. Only a space separates,
// and nothing is trimmed: a tab, a newline, a no-break space, U+0085 or a vertical tab joins two
// levels into one value that names none. Until #244 a tab or a newline separated and a padded level
// was trimmed and recognized.
func TestSetTargetAcrLevel_SplitsAcrValuesAsTheSharedSplitterDoes(t *testing.T) {
	testCases := []struct {
		name          string
		acrValues     string
		clientDefault record.AcrLevel
		want          record.AcrLevel
	}{
		{
			name:          "one space separates values, the first recognized wins",
			acrValues:     "urn:example:unknown urn:goiabada:level2_optional urn:goiabada:level1",
			clientDefault: record.AcrLevel1,
			want:          record.AcrLevel2Optional,
		},
		{
			name:          "a tab and a newline do not separate values",
			acrValues:     "urn:example:unknown\turn:goiabada:level2_optional\nurn:goiabada:level1",
			clientDefault: record.AcrLevel1,
			want:          record.AcrLevel1,
		},
		{
			name:          "a value padded with spaces is malformed and read as no acr_values",
			acrValues:     " urn:goiabada:level2_mandatory ",
			clientDefault: record.AcrLevel1,
			want:          record.AcrLevel1,
		},
		{
			name:          "a run of spaces is malformed and read as no acr_values",
			acrValues:     "urn:goiabada:level2_mandatory  urn:goiabada:level1",
			clientDefault: record.AcrLevel1,
			want:          record.AcrLevel1,
		},
		{
			name:          "a malformed value still leaves the client's level in place",
			acrValues:     " urn:goiabada:level1 ",
			clientDefault: record.AcrLevel2Mandatory,
			want:          record.AcrLevel2Mandatory,
		},
		{
			name:          "a value padded with a no-break space names no level",
			acrValues:     "urn:goiabada:level2_mandatory\u00a0",
			clientDefault: record.AcrLevel1,
			want:          record.AcrLevel1,
		},
		{
			// Spelled as escapes so that no editor can turn them into plain spaces: each joins the
			// two levels into one value.
			name:          "a no-break space between two values does not separate them",
			acrValues:     "urn:goiabada:level2_mandatory\u00a0urn:goiabada:level1",
			clientDefault: record.AcrLevel1,
			want:          record.AcrLevel1,
		},
		{
			name:          "a next-line character between two values does not separate them",
			acrValues:     "urn:goiabada:level2_mandatory\u0085urn:goiabada:level1",
			clientDefault: record.AcrLevel1,
			want:          record.AcrLevel1,
		},
		{
			name:          "a vertical tab between two values does not separate them",
			acrValues:     "urn:goiabada:level2_mandatory\vurn:goiabada:level1",
			clientDefault: record.AcrLevel1,
			want:          record.AcrLevel1,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ac := &AuthContext{AcrValuesFromAuthorizeRequest: tc.acrValues}
			ac.SetTargetAcrLevel(tc.clientDefault)

			assert.Equal(t, tc.want.String(), ac.TargetAcrLevel)
			assert.Equal(t, tc.want, ac.GetTargetAcrLevel(tc.clientDefault))
		})
	}
}

func TestParseAcrValuesFromAuthorizeRequest(t *testing.T) {
	t.Run("one space between two levels", func(t *testing.T) {
		ac := &AuthContext{
			AcrValuesFromAuthorizeRequest: "urn:goiabada:level1 urn:goiabada:level2_mandatory",
		}

		result := ac.parseAcrValuesFromAuthorizeRequest()

		assert.Equal(t, []record.AcrLevel{record.AcrLevel1, record.AcrLevel2Mandatory}, result)
	})

	// The grammar allows one space, and a value that breaks it is read as none (#244). Repeated
	// whitespace used to be collapsed.
	for _, malformed := range []string{
		"urn:goiabada:level1     urn:goiabada:level2_mandatory",
		" urn:goiabada:level1",
		"urn:goiabada:level1 ",
		" ",
	} {
		t.Run("a malformed value yields an empty slice: "+malformed, func(t *testing.T) {
			ac := &AuthContext{AcrValuesFromAuthorizeRequest: malformed}

			assert.Empty(t, ac.parseAcrValuesFromAuthorizeRequest())
		})
	}

	t.Run("deduplicates repeated values preserving first position", func(t *testing.T) {
		ac := &AuthContext{
			AcrValuesFromAuthorizeRequest: "urn:goiabada:level2_optional urn:goiabada:level1 urn:goiabada:level2_optional",
		}

		result := ac.parseAcrValuesFromAuthorizeRequest()

		assert.Equal(t, []record.AcrLevel{record.AcrLevel2Optional, record.AcrLevel1}, result)
	})

	t.Run("drops unrecognized values", func(t *testing.T) {
		ac := &AuthContext{
			AcrValuesFromAuthorizeRequest: "nonsense urn:goiabada:level1 more-nonsense",
		}

		result := ac.parseAcrValuesFromAuthorizeRequest()

		assert.Equal(t, []record.AcrLevel{record.AcrLevel1}, result)
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
	for _, target := range []record.AcrLevel{record.AcrLevel1, record.AcrLevel2Optional, record.AcrLevel2Mandatory} {
		t.Run(target.String(), func(t *testing.T) {
			ac := &AuthContext{}

			err := ac.SetAcrLevel(target, nil)

			require.NoError(t, err)
			assert.Equal(t, target, ac.AcrLevel)
		})
	}
}

func TestSetAcrLevel_UsesHigherOfTargetAndSession(t *testing.T) {
	testCases := []struct {
		name        string
		target      record.AcrLevel
		sessionAcr  record.AcrLevel
		wantAcr     record.AcrLevel
		description string
	}{
		{
			name:        "session higher than target is kept",
			target:      record.AcrLevel1,
			sessionAcr:  record.AcrLevel2Mandatory,
			wantAcr:     record.AcrLevel2Mandatory,
			description: "a level2 session must not be downgraded by a level1 request",
		},
		{
			name:        "target higher than session wins",
			target:      record.AcrLevel2Mandatory,
			sessionAcr:  record.AcrLevel1,
			wantAcr:     record.AcrLevel2Mandatory,
			description: "a step-up request must raise the ACR",
		},
		{
			name:        "equal levels",
			target:      record.AcrLevel2Optional,
			sessionAcr:  record.AcrLevel2Optional,
			wantAcr:     record.AcrLevel2Optional,
			description: "matching levels stay put",
		},
		{
			name:        "optional session with mandatory target",
			target:      record.AcrLevel2Mandatory,
			sessionAcr:  record.AcrLevel2Optional,
			wantAcr:     record.AcrLevel2Mandatory,
			description: "mandatory outranks optional",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ac := &AuthContext{}
			session := &record.UserSession{AcrLevel: tc.sessionAcr}

			err := ac.SetAcrLevel(tc.target, session)

			require.NoError(t, err)
			assert.Equal(t, tc.wantAcr, ac.AcrLevel, tc.description)
		})
	}
}

// A session row carrying an unrecognized ACR string must surface an error rather
// than silently defaulting to some level.
func TestSetAcrLevel_InvalidSessionAcrReturnsError(t *testing.T) {
	ac := &AuthContext{}
	session := &record.UserSession{AcrLevel: "urn:goiabada:bogus"}

	err := ac.SetAcrLevel(record.AcrLevel1, session)

	require.Error(t, err)
	assert.Empty(t, ac.AcrLevel, "the ACR must not be set when the session level cannot be parsed")
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
		session       *record.UserSession
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
			session:       &record.UserSession{UserId: 0},
			want:          false,
			description:   "two zeros are not a match: an unidentified ceremony must not match an unsaved session",
		},
		{
			name:          "no user with a real session",
			contextUserId: 0,
			session:       &record.UserSession{UserId: 1},
			want:          false,
			description:   "a ceremony that has not authenticated anyone owns nothing",
		},
		{
			name:          "same user",
			contextUserId: 1,
			session:       &record.UserSession{UserId: 1},
			want:          true,
			description:   "the ordinary SSO path, the only true row",
		},
		{
			name:          "different user",
			contextUserId: 2,
			session:       &record.UserSession{UserId: 1},
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
// Tests for RequestedMaxAge
//
// max_age is carried on the context as the raw parameter and read by every hop after
// /auth/authorize through RequestedMaxAge. The parse itself is oidc.ParseMaxAge's table; these
// cases pin what this reader adds: nil for absent, and 0 for a value that does not parse, which
// forces re-authentication rather than ignoring the constraint (#243).
// =============================================================================

func TestRequestedMaxAge(t *testing.T) {
	accepted := []struct {
		name   string
		maxAge string
		want   int64
	}{
		{"typical value", "3600", 3600},
		{"zero means reauthenticate now", "0", 0},
		{"beyond int64 is held as the largest", "99999999999999999999", math.MaxInt64},
	}
	for _, tc := range accepted {
		t.Run(tc.name, func(t *testing.T) {
			got := (&AuthContext{MaxAge: tc.maxAge}).RequestedMaxAge()
			require.NotNil(t, got)
			assert.Equal(t, tc.want, *got)
		})
	}

	t.Run("absent is nil", func(t *testing.T) {
		assert.Nil(t, (&AuthContext{MaxAge: ""}).RequestedMaxAge())
	})

	for _, unparseable := range []string{"abc", "10s", "3600.5", " 3600 ", "-1", "+5"} {
		t.Run("unparseable "+unparseable+" is read as 0", func(t *testing.T) {
			got := (&AuthContext{MaxAge: unparseable}).RequestedMaxAge()
			require.NotNil(t, got, "an unparseable value must not read as absent, which would ignore it")
			assert.Equal(t, int64(0), *got)
		})
	}
}

// =============================================================================
// Tests for AddAuthMethod
//
// AuthMethods becomes the "amr" claim. It must stay free of duplicates, since
// clients read it to decide whether a second factor was used. It takes an AuthMethod, so the only
// inputs are the two constants and a value outside their range (#436).
// =============================================================================

func TestAddAuthMethod(t *testing.T) {
	testCases := []struct {
		name     string
		existing string
		add      []oidc.AuthMethod
		want     string
	}{
		{"password on an empty list", "", []oidc.AuthMethod{oidc.AuthMethodPassword}, "pwd"},
		{"otp on an empty list", "", []oidc.AuthMethod{oidc.AuthMethodOTP}, "otp"},
		{"otp appended after password", "", []oidc.AuthMethod{oidc.AuthMethodPassword, oidc.AuthMethodOTP}, "pwd otp"},
		{"a duplicate of the only method", "pwd", []oidc.AuthMethod{oidc.AuthMethodPassword}, "pwd"},
		{"a duplicate of the first of two", "pwd otp", []oidc.AuthMethod{oidc.AuthMethodPassword}, "pwd otp"},
		{"a duplicate of the second of two", "pwd otp", []oidc.AuthMethod{oidc.AuthMethodOTP}, "pwd otp"},
		{"a method listed inside another's name is not a duplicate", "xotp", []oidc.AuthMethod{oidc.AuthMethodOTP}, "xotp otp"},
		{"repeated calls stay idempotent", "", []oidc.AuthMethod{oidc.AuthMethodPassword, oidc.AuthMethodOTP,
			oidc.AuthMethodPassword, oidc.AuthMethodOTP, oidc.AuthMethodOTP}, "pwd otp"},
		{"an out-of-range value adds nothing to an empty list", "", []oidc.AuthMethod{oidc.AuthMethodOTP + 1}, ""},
		{"an out-of-range value adds nothing to a list", "pwd", []oidc.AuthMethod{oidc.AuthMethod(-1)}, "pwd"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ac := &AuthContext{AuthMethods: tc.existing}

			for _, method := range tc.add {
				ac.AddAuthMethod(method)
			}

			assert.Equal(t, tc.want, ac.AuthMethods)
		})
	}
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
		// SetScope stores a scope the validator found well formed. It splits on the space alone
		// (#244), so a tab or a newline is part of a value, not a separator, and is kept as it is.
		{"tabs and newlines are not separators", "openid\tprofile\nemail", "openid\tprofile\nemail"},
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

// The whole table for the gate's predicate. Every gated route asks it, so the handler cases each
// need only one refused state and requireAuthState's own table needs no second copy of this one
// (#436 seam 1).
func TestInState(t *testing.T) {
	testCases := []struct {
		name     string
		actual   AuthState
		accepted []AuthState
		want     bool
	}{
		{
			name:     "the one accepted state",
			actual:   AuthStateRequiresLevel1,
			accepted: []AuthState{AuthStateRequiresLevel1},
			want:     true,
		},
		{
			name:     "a refused state",
			actual:   AuthStateReadyToIssueCode,
			accepted: []AuthState{AuthStateRequiresLevel1},
			want:     false,
		},
		{
			name:     "the first of several accepted states",
			actual:   AuthStateLevel1PasswordCompleted,
			accepted: []AuthState{AuthStateLevel1PasswordCompleted, AuthStateLevel1ExistingSession},
			want:     true,
		},
		{
			name:     "the last of several accepted states",
			actual:   AuthStateLevel1ExistingSession,
			accepted: []AuthState{AuthStateLevel1PasswordCompleted, AuthStateLevel1ExistingSession},
			want:     true,
		},
		{
			name:     "a state refused by several accepted states",
			actual:   AuthStateLevel1Password,
			accepted: []AuthState{AuthStateLevel1PasswordCompleted, AuthStateLevel1ExistingSession},
			want:     false,
		},
		{
			// What a context that never had a state carries: it is on no step, so no gate may
			// take it for one.
			name:     "the zero state",
			actual:   "",
			accepted: []AuthState{AuthStateRequiresLevel1},
			want:     false,
		},
		{
			name:     "no accepted state accepts nothing",
			actual:   AuthStateRequiresLevel1,
			accepted: nil,
			want:     false,
		},
		{
			name:     "no accepted state accepts nothing, the zero state included",
			actual:   "",
			accepted: nil,
			want:     false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ac := &AuthContext{AuthState: tc.actual}

			assert.Equal(t, tc.want, ac.InState(tc.accepted...))
		})
	}
}

// =============================================================================
// Tests for ParkDeferredError
//
// The whole table for parking. HandleAuthorizeGet's handler cases each park one error and read it
// back; what the parked description may hold is decided here (#213, #437 seam 1).
// =============================================================================

func TestParkDeferredError(t *testing.T) {
	testCases := []struct {
		name            string
		code            string
		description     string
		wantDescription string
	}{
		{
			name:            "a conforming description is kept byte for byte",
			code:            "invalid_request",
			description:     "Invalid response_type parameter value.",
			wantDescription: "Invalid response_type parameter value.",
		},
		{
			// The double quote, the backslash and every non-ASCII rune are outside RFC 6749
			// Appendix A.8's NQSCHAR, and each becomes one '?'.
			name:            "forbidden characters are replaced before they are stored",
			code:            "invalid_scope",
			description:     "bad \"x\\y\" é",
			wantDescription: "bad ?x?y? ?",
		},
		{
			// A description interpolates request text, so the parked copy is bounded rather than
			// carried at whatever length the request chose.
			name:            "a long description is bounded before it is stored",
			code:            "invalid_scope",
			description:     strings.Repeat("a", 600),
			wantDescription: strings.Repeat("a", 509) + "...",
		},
		{
			name:            "an empty description stays empty",
			code:            "invalid_request",
			description:     "",
			wantDescription: "",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ac := &AuthContext{
				AuthState: AuthStateLevel1Password,
				ClientId:  "client-1",
				Scope:     "openid",
				UserId:    7,
			}

			ac.ParkDeferredError(tc.code, tc.description)

			assert.Equal(t, tc.code, ac.DeferredErrorCode)
			assert.Equal(t, tc.wantDescription, ac.DeferredErrorDescription)
			assert.Equal(t, AuthStateRequiresLevel1, ac.AuthState,
				"a parked error is delivered after level 1, so the ceremony goes there")
			assert.Equal(t, "client-1", ac.ClientId, "parking writes nothing else")
			assert.Equal(t, "openid", ac.Scope, "parking writes nothing else")
			assert.Equal(t, int64(7), ac.UserId, "parking writes nothing else")
		})
	}
}

// =============================================================================
// Tests for RecordPasswordVerified and RecordOTPVerified
//
// The whole table for what a verified credential writes. The password and OTP handler cases each
// check one verified submission reaches its save; which field it writes is decided here (#437 seam 1).
// =============================================================================

func TestRecordPasswordVerified(t *testing.T) {
	// A zone other than UTC, so the test sees the conversion rather than a value already in UTC.
	now := time.Date(2026, 9, 29, 12, 30, 0, 0, time.FixedZone("UTC-3", -3*60*60))

	testCases := []struct {
		name            string
		existingMethods string
		wantMethods     string
	}{
		{"a first password", "", "pwd"},
		{"a password verified again is listed once", "pwd", "pwd"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			user := &record.User{Id: 42, AuthStateGeneration: 3, OtpConfigGeneration: 5}
			ac := &AuthContext{
				AuthState:   AuthStateLevel1Password,
				AuthMethods: tc.existingMethods,
				OTPKeyURL:   "otpauth://totp/kept",
				Scope:       "openid",
			}

			ac.RecordPasswordVerified(user, now)

			assert.Equal(t, int64(42), ac.UserId)
			assert.Equal(t, int64(3), ac.AuthStateGeneration, "captured from the user the password was checked against (#106)")
			require.NotNil(t, ac.OtpConfigGeneration)
			assert.Equal(t, int64(5), *ac.OtpConfigGeneration, "captured for the create arm at /auth/completed (#242)")
			assert.Equal(t, tc.wantMethods, ac.AuthMethods)
			require.NotNil(t, ac.AuthenticatedAt)
			assert.True(t, now.Equal(*ac.AuthenticatedAt), "the instant verified")
			assert.Equal(t, time.UTC, ac.AuthenticatedAt.Location(), "stored in UTC")
			assert.True(t, ac.Level1AuthCompleted, "level 1 was performed in this ceremony (#129)")
			assert.Equal(t, AuthStateLevel1PasswordCompleted, ac.AuthState)
			assert.Equal(t, "otpauth://totp/kept", ac.OTPKeyURL, "a password writes no OTP field")
			assert.Equal(t, "openid", ac.Scope, "a password writes no request field")

			// The capture is a copy: a later change to the user row read here does not reach the
			// ceremony's snapshot.
			user.OtpConfigGeneration = 6
			assert.Equal(t, int64(5), *ac.OtpConfigGeneration)
		})
	}
}

// What reusing a session writes, for /auth/authorize's SSO path and prompt=none alike; each
// handler's cases check only that its path adopts the session it read (#437 seam 1).
func TestAdoptSession(t *testing.T) {
	userSession := &record.UserSession{
		UserId:              42,
		AcrLevel:            record.AcrLevel2Optional,
		AuthMethods:         "pwd otp",
		AuthStateGeneration: 3,
		User:                record.User{Id: 42, AuthStateGeneration: 9},
	}
	ac := &AuthContext{
		AuthState:           AuthStateRequiresLevel1,
		Scope:               "openid",
		OtpConfigGeneration: func() *int64 { g := int64(7); return &g }(),
	}

	ac.AdoptSession(userSession)

	assert.Equal(t, int64(42), ac.UserId)
	assert.Equal(t, record.AcrLevel2Optional, ac.AcrLevel)
	assert.Equal(t, "pwd otp", ac.AuthMethods)
	assert.Equal(t, int64(3), ac.AuthStateGeneration,
		"the session's generation and never the user's, or an old session is laundered into a newer one (#106)")
	assert.Nil(t, ac.AuthenticatedAt, "adopting records no authentication performed here")
	assert.False(t, ac.Level1AuthCompleted, "level 1 was not performed in this ceremony (#129)")
	assert.Equal(t, AuthStateRequiresLevel1, ac.AuthState, "the caller decides the next state")
	assert.Equal(t, "openid", ac.Scope, "adopting writes no request field")
	require.NotNil(t, ac.OtpConfigGeneration)
	assert.Equal(t, int64(7), *ac.OtpConfigGeneration, "the OTP snapshot is not the session's to write")
}

func TestRecordOTPVerified(t *testing.T) {
	now := time.Date(2026, 9, 29, 12, 30, 0, 0, time.FixedZone("UTC+2", 2*60*60))
	captured := int64(4)

	testCases := []struct {
		name                string
		existingMethods     string
		existingGeneration  *int64
		level1Completed     bool
		enrolledGeneration  *int64
		wantMethods         string
		wantOtpConfigGenNil bool
		wantOtpConfigGen    int64
	}{
		{
			name:               "an enrolled user after a password keeps what level 2 captured",
			existingMethods:    "pwd",
			existingGeneration: &captured,
			level1Completed:    true,
			wantMethods:        "pwd otp",
			wantOtpConfigGen:   4,
		},
		{
			// The ceremony moved the counter by enrolling, so it promotes the value the increment
			// returned rather than the one it asked the question against (#242).
			name:               "an enrolment overwrites what level 2 captured",
			existingMethods:    "pwd",
			existingGeneration: &captured,
			level1Completed:    true,
			enrolledGeneration: func() *int64 { g := int64(5); return &g }(),
			wantMethods:        "pwd otp",
			wantOtpConfigGen:   5,
		},
		{
			name:               "an enrolment on a context with no capture sets it",
			existingMethods:    "pwd",
			enrolledGeneration: func() *int64 { g := int64(1); return &g }(),
			wantMethods:        "pwd otp",
			wantOtpConfigGen:   1,
		},
		{
			name:                "no enrolment and no capture leaves nothing to promote",
			existingMethods:     "pwd",
			wantMethods:         "pwd otp",
			wantOtpConfigGenNil: true,
		},
		{
			// A session reused at level 1 and stepping up: the session's methods came across, and
			// OTP must not stand in for a level 1 this ceremony never performed (#129).
			name:               "a step-up on a reused session leaves level 1 not completed",
			existingMethods:    "pwd",
			existingGeneration: &captured,
			level1Completed:    false,
			wantMethods:        "pwd otp",
			wantOtpConfigGen:   4,
		},
		{
			name:               "an otp verified again is listed once",
			existingMethods:    "pwd otp",
			existingGeneration: &captured,
			level1Completed:    true,
			wantMethods:        "pwd otp",
			wantOtpConfigGen:   4,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ac := &AuthContext{
				AuthState:           AuthStateLevel2OTP,
				AuthMethods:         tc.existingMethods,
				OtpConfigGeneration: tc.existingGeneration,
				Level1AuthCompleted: tc.level1Completed,
				OTPKeyURL:           "otpauth://totp/spent",
				UserId:              42,
				Scope:               "openid",
			}

			ac.RecordOTPVerified(now, tc.enrolledGeneration)

			assert.Equal(t, tc.wantMethods, ac.AuthMethods)
			if tc.wantOtpConfigGenNil {
				assert.Nil(t, ac.OtpConfigGeneration)
			} else {
				require.NotNil(t, ac.OtpConfigGeneration)
				assert.Equal(t, tc.wantOtpConfigGen, *ac.OtpConfigGeneration)
			}
			require.NotNil(t, ac.AuthenticatedAt)
			assert.True(t, now.Equal(*ac.AuthenticatedAt), "the instant verified")
			assert.Equal(t, time.UTC, ac.AuthenticatedAt.Location(), "stored in UTC")
			assert.Equal(t, tc.level1Completed, ac.Level1AuthCompleted, "OTP never writes level 1 (#129)")
			assert.Equal(t, AuthStateAuthenticationCompleted, ac.AuthState)
			assert.Empty(t, ac.OTPKeyURL, "the spent enrolment key is cleared (#247)")
			assert.Equal(t, int64(42), ac.UserId, "OTP writes no user")
			assert.Equal(t, "openid", ac.Scope, "OTP writes no request field")

			if tc.enrolledGeneration != nil {
				// A copy: the caller's variable is not aliased by the ceremony.
				*tc.enrolledGeneration += 100
				assert.Equal(t, tc.wantOtpConfigGen, *ac.OtpConfigGeneration)
			}
		})
	}
}
