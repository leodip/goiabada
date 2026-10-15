package authflow

import (
	"testing"

	"github.com/leodip/goiabada/authserver/internal/ceremony"
	"github.com/leodip/goiabada/authserver/internal/oidc"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/core/errs"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// silentWorld is what SilentAuthentication would load for a prompt=none request, answered from the
// row, so a DecideSilentAuthentication case needs no HTTP harness and no mocks.
type silentWorld struct {
	noSession          bool
	valid              bool
	maxAgeRequested    bool
	validWithoutMaxAge bool
	disabled           bool
	subject            string
	hint               string
	target             record.AcrLevel
	sessionAcr         record.AcrLevel
	sessionOtpGen      int64
	userOtpGen         int64
	otpEnabled         bool
	effectiveScope     string
	consentRequired    bool
	clientIdentifier   string
	consentScope       *string // nil for no consent row
}

// driveSilentAuthentication runs DecideSilentAuthentication as SilentAuthentication.Run does,
// loading each fact it asks for from the world, and answers the answer and the facts in the order
// asked for.
func driveSilentAuthentication(t *testing.T, world silentWorld) (SilentAuthenticationAnswer, []SilentFact) {
	t.Helper()

	facts := SilentAuthenticationFacts{
		MaxAgeRequested:  world.maxAgeRequested,
		HintSubject:      world.hint,
		Target:           world.target,
		ConsentRequired:  world.consentRequired,
		ClientIdentifier: world.clientIdentifier,
	}
	var asked []SilentFact
	for {
		answer, need := DecideSilentAuthentication(facts)
		if need == SilentFactNone {
			return answer, asked
		}
		require.NotContains(t, asked, need, "each fact is loaded once")
		asked = append(asked, need)

		switch need {
		case SilentFactSession:
			facts.SessionLoaded = true
			if !world.noSession {
				facts.Session = &record.UserSession{
					UserId:              7,
					AcrLevel:            world.sessionAcr,
					OtpConfigGeneration: world.sessionOtpGen,
					User: record.User{
						Id:                  7,
						Subject:             world.subject,
						Enabled:             !world.disabled,
						OTPEnabled:          world.otpEnabled,
						OtpConfigGeneration: world.userOtpGen,
					},
				}
			}
		case SilentFactValidity:
			valid := world.valid
			facts.SessionValid = &valid
		case SilentFactValidityWithoutMaxAge:
			valid := world.validWithoutMaxAge
			facts.SessionValidWithoutMaxAge = &valid
		case SilentFactEffectiveScope:
			scope := world.effectiveScope
			facts.EffectiveScope = &scope
		case SilentFactConsent:
			facts.ConsentLoaded = true
			if world.consentScope != nil {
				facts.Consent = &record.UserConsent{UserId: 7, Scope: *world.consentScope}
			}
		default:
			require.FailNow(t, "an unknown fact", "%v", need)
		}
	}
}

// Every answer prompt=none can get, in the order the checks are asked, with the reads each makes:
// a refusal reads nothing past the check that refused. The handler cases of prompt=none show each
// kind of answer reaching the client; which answer, and its exact text, is decided here (#437
// seam 1).
func TestDecideSilentAuthentication(t *testing.T) {
	const (
		session       = SilentFactSession
		validity      = SilentFactValidity
		withoutMaxAge = SilentFactValidityWithoutMaxAge
		scope         = SilentFactEffectiveScope
		consent       = SilentFactConsent
	)
	scopes := func(s string) *string { return &s }

	// A session that passes every check before the scope, at level 1 for a level 1 target.
	passing := silentWorld{
		valid:          true,
		subject:        "sub-1",
		target:         record.AcrLevel1,
		sessionAcr:     record.AcrLevel1,
		effectiveScope: "openid profile",
	}
	with := func(edit func(*silentWorld)) silentWorld {
		world := passing
		edit(&world)
		return world
	}

	testCases := []struct {
		name             string
		world            silentWorld
		wantCode         string
		wantDescription  string
		wantUserDisabled bool
		wantReads        []SilentFact
	}{
		{
			name:            "no session",
			world:           with(func(w *silentWorld) { w.noSession = true }),
			wantCode:        oidc.ErrorLoginRequired,
			wantDescription: "User authentication is required",
			wantReads:       []SilentFact{session},
		},
		{
			name:            "an expired session with no max_age is not asked about max_age",
			world:           with(func(w *silentWorld) { w.valid = false; w.validWithoutMaxAge = true }),
			wantCode:        oidc.ErrorLoginRequired,
			wantDescription: "User session has expired",
			wantReads:       []SilentFact{session, validity},
		},
		{
			name: "a session valid but for max_age says so",
			world: with(func(w *silentWorld) {
				w.valid = false
				w.maxAgeRequested = true
				w.validWithoutMaxAge = true
			}),
			wantCode:        oidc.ErrorLoginRequired,
			wantDescription: "Session age exceeds max_age",
			wantReads:       []SilentFact{session, validity, withoutMaxAge},
		},
		{
			name: "a session expired with max_age as well is expired",
			world: with(func(w *silentWorld) {
				w.valid = false
				w.maxAgeRequested = true
				w.validWithoutMaxAge = false
			}),
			wantCode:        oidc.ErrorLoginRequired,
			wantDescription: "User session has expired",
			wantReads:       []SilentFact{session, validity, withoutMaxAge},
		},
		{
			name: "a valid session with max_age asks nothing more about it",
			world: with(func(w *silentWorld) {
				w.maxAgeRequested = true
			}),
			wantReads: []SilentFact{session, validity, scope},
		},
		{
			name:             "a disabled user, audited",
			world:            with(func(w *silentWorld) { w.disabled = true }),
			wantCode:         "access_denied",
			wantDescription:  "The user account is disabled",
			wantUserDisabled: true,
			wantReads:        []SilentFact{session, validity},
		},
		{
			name:             "a disabled user is asked before the hint",
			world:            with(func(w *silentWorld) { w.disabled = true; w.hint = "sub-2" }),
			wantCode:         "access_denied",
			wantDescription:  "The user account is disabled",
			wantUserDisabled: true,
			wantReads:        []SilentFact{session, validity},
		},
		{
			name:            "a hint naming another user",
			world:           with(func(w *silentWorld) { w.hint = "sub-2" }),
			wantCode:        oidc.ErrorLoginRequired,
			wantDescription: "The current session user does not match the id_token_hint",
			wantReads:       []SilentFact{session, validity},
		},
		{
			name:      "a hint naming the session's user passes",
			world:     with(func(w *silentWorld) { w.hint = "sub-1" }),
			wantReads: []SilentFact{session, validity, scope},
		},
		{
			name:            "a hint mismatch is asked before the step-up rule",
			world:           with(func(w *silentWorld) { w.hint = "sub-2"; w.target = record.AcrLevel2Mandatory }),
			wantCode:        oidc.ErrorLoginRequired,
			wantDescription: "The current session user does not match the id_token_hint",
			wantReads:       []SilentFact{session, validity},
		},
		{
			name:            "a target above the session's level",
			world:           with(func(w *silentWorld) { w.target = record.AcrLevel2Optional; w.otpEnabled = true }),
			wantCode:        oidc.ErrorInteractionRequired,
			wantDescription: "Higher authentication level required",
			wantReads:       []SilentFact{session, validity},
		},
		{
			name:            "an unknown session level is insufficient",
			world:           with(func(w *silentWorld) { w.sessionAcr = "urn:goiabada:pwd" }),
			wantCode:        oidc.ErrorInteractionRequired,
			wantDescription: "Higher authentication level required",
			wantReads:       []SilentFact{session, validity},
		},
		{
			name: "a mandatory target with no authenticator, before the changed configuration",
			world: with(func(w *silentWorld) {
				w.target = record.AcrLevel2Mandatory
				w.sessionAcr = record.AcrLevel2Mandatory
				w.sessionOtpGen, w.userOtpGen = 2, 3
			}),
			wantCode:        oidc.ErrorInteractionRequired,
			wantDescription: "Additional authentication setup required",
			wantReads:       []SilentFact{session, validity},
		},
		{
			name: "the authenticator changed since the session answered level 2",
			world: with(func(w *silentWorld) {
				w.target = record.AcrLevel2Optional
				w.sessionAcr = record.AcrLevel2Optional
				w.otpEnabled = true
				w.sessionOtpGen, w.userOtpGen = 2, 3
			}),
			wantCode:        oidc.ErrorInteractionRequired,
			wantDescription: "Authentication configuration has changed",
			wantReads:       []SilentFact{session, validity},
		},
		{
			// The level 2 question is not asked of a level 1 target.
			name: "a changed authenticator does not refuse a level 1 target",
			world: with(func(w *silentWorld) {
				w.sessionAcr = record.AcrLevel2Optional
				w.sessionOtpGen, w.userOtpGen = 2, 3
			}),
			wantReads: []SilentFact{session, validity, scope},
		},
		{
			name: "a mandatory target satisfied by an enrolled session passes",
			world: with(func(w *silentWorld) {
				w.target = record.AcrLevel2Mandatory
				w.sessionAcr = record.AcrLevel2Mandatory
				w.otpEnabled = true
			}),
			wantReads: []SilentFact{session, validity, scope},
		},
		{
			name:            "no requested scope the user holds",
			world:           with(func(w *silentWorld) { w.effectiveScope = "  " }),
			wantCode:        "access_denied",
			wantDescription: "The user is not authorized to access any of the requested scopes",
			wantReads:       []SilentFact{session, validity, scope},
		},
		{
			name:      "no consent asked for when the client does not require it and offline_access is absent",
			world:     passing,
			wantReads: []SilentFact{session, validity, scope},
		},
		{
			name:            "a client requiring consent with none given",
			world:           with(func(w *silentWorld) { w.consentRequired = true }),
			wantCode:        oidc.ErrorConsentRequired,
			wantDescription: "User consent is required",
			wantReads:       []SilentFact{session, validity, scope, consent},
		},
		{
			name: "a consent missing one scope",
			world: with(func(w *silentWorld) {
				w.consentRequired = true
				w.consentScope = scopes("openid")
			}),
			wantCode:        oidc.ErrorConsentRequired,
			wantDescription: "Additional consent is required",
			wantReads:       []SilentFact{session, validity, scope, consent},
		},
		{
			name: "a consent covering every scope passes",
			world: with(func(w *silentWorld) {
				w.consentRequired = true
				w.consentScope = scopes("openid profile email")
			}),
			wantReads: []SilentFact{session, validity, scope, consent},
		},
		{
			name: "offline_access asks for consent on a client that does not require it",
			world: with(func(w *silentWorld) {
				w.effectiveScope = "openid offline_access"
				w.consentScope = scopes("openid")
			}),
			wantCode:        oidc.ErrorConsentRequired,
			wantDescription: "Additional consent is required",
			wantReads:       []SilentFact{session, validity, scope, consent},
		},
		{
			name: "offline_access covered by the consent passes",
			world: with(func(w *silentWorld) {
				w.effectiveScope = "openid offline_access"
				w.consentScope = scopes("openid offline_access")
			}),
			wantReads: []SilentFact{session, validity, scope, consent},
		},
		{
			// The scope is read through oidc.SplitScope like every other reader of one (#244): a
			// no-break space is no separator, so this is one value, and the consent that names it
			// covers it. Read with strings.Fields it was two, neither of which the consent holds.
			name: "a value holding a no-break space is one scope, covered by the consent that names it",
			world: with(func(w *silentWorld) {
				w.consentRequired = true
				w.effectiveScope = "openid res:read all"
				w.consentScope = scopes("openid res:read all")
			}),
			wantReads: []SilentFact{session, validity, scope, consent},
		},
		// authserver:manage-account needs a stored consent covering it from every client but the
		// admin console's, whatever its Consent required says, with today's sentences (#509
		// decisions 1 to 3).
		{
			name: "manage-account from a consent-off client with no stored consent",
			world: with(func(w *silentWorld) {
				w.clientIdentifier = "crafted-link-client"
				w.effectiveScope = "openid authserver:manage-account"
			}),
			wantCode:        oidc.ErrorConsentRequired,
			wantDescription: "User consent is required",
			wantReads:       []SilentFact{session, validity, scope, consent},
		},
		{
			name: "manage-account from a consent-off client with a stored consent leaving it out",
			world: with(func(w *silentWorld) {
				w.clientIdentifier = "crafted-link-client"
				w.effectiveScope = "openid authserver:manage-account"
				w.consentScope = scopes("openid profile")
			}),
			wantCode:        oidc.ErrorConsentRequired,
			wantDescription: "Additional consent is required",
			wantReads:       []SilentFact{session, validity, scope, consent},
		},
		{
			// A consent-off client is asked about manage-account and nothing else.
			name: "manage-account covered by the stored consent passes, profile left out",
			world: with(func(w *silentWorld) {
				w.clientIdentifier = "crafted-link-client"
				w.effectiveScope = "openid profile authserver:manage-account"
				w.consentScope = scopes("openid authserver:manage-account")
			}),
			wantReads: []SilentFact{session, validity, scope, consent},
		},
		{
			name: "manage-account from the admin console's client passes with no consent read",
			world: with(func(w *silentWorld) {
				w.clientIdentifier = "admin-console-client"
				w.effectiveScope = "authserver:manage authserver:manage-account email openid profile"
			}),
			wantReads: []SilentFact{session, validity, scope},
		},
		{
			name: "manage-account filtered out of the effective scope is owed nothing",
			world: with(func(w *silentWorld) {
				w.clientIdentifier = "crafted-link-client"
				w.effectiveScope = "openid"
			}),
			wantReads: []SilentFact{session, validity, scope},
		},
		{
			// A client requiring consent still needs every scope covered, manage-account included.
			name: "a client requiring consent with manage-account covered and profile not",
			world: with(func(w *silentWorld) {
				w.clientIdentifier = "crafted-link-client"
				w.consentRequired = true
				w.effectiveScope = "openid profile authserver:manage-account"
				w.consentScope = scopes("openid authserver:manage-account")
			}),
			wantCode:        oidc.ErrorConsentRequired,
			wantDescription: "Additional consent is required",
			wantReads:       []SilentFact{session, validity, scope, consent},
		},
		{
			name: "a tab still separates two scopes of an effective scope",
			world: with(func(w *silentWorld) {
				w.consentRequired = true
				w.effectiveScope = "openid\tprofile"
				w.consentScope = scopes("openid")
			}),
			wantCode:        oidc.ErrorConsentRequired,
			wantDescription: "Additional consent is required",
			wantReads:       []SilentFact{session, validity, scope, consent},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			answer, reads := driveSilentAuthentication(t, tc.world)

			assert.Equal(t, tc.wantCode, answer.ErrorCode)
			assert.Equal(t, tc.wantDescription, answer.ErrorDescription)
			assert.Equal(t, tc.wantUserDisabled, answer.UserDisabled)
			assert.Equal(t, tc.wantReads, reads)
		})
	}
}

// The silent flow answers every step-up a session owes with interaction_required, and anything
// StepUp does not name, as a reason added to it later would be, is refused as well: prompt=none fails
// closed rather than issuing a code its target was not met for (#542). StepUpOwed's error is
// refused the same way.
func TestSilentStepUpRefusal_FailsClosed(t *testing.T) {
	testCases := []struct {
		name            string
		stepUp          ceremony.StepUp
		err             error
		wantRefused     bool
		wantDescription string
	}{
		{"no step-up", ceremony.StepUpNone, nil, false, ""},
		{"a higher level", ceremony.StepUpLevel, nil, true, "Higher authentication level required"},
		{"no authenticator", ceremony.StepUpAuthenticatorMissing, nil, true, "Additional authentication setup required"},
		{"a changed authenticator", ceremony.StepUpOtpConfigChanged, nil, true, "Authentication configuration has changed"},
		{"a value StepUp does not name", ceremony.StepUp(99), nil, true, "Higher authentication level required"},
		{"StepUpOwed's error", ceremony.StepUpNone, errs.New("unknown target level"), true, "Higher authentication level required"},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			code, description, refused := silentStepUpRefusal(tc.stepUp, tc.err)

			assert.Equal(t, tc.wantRefused, refused)
			assert.Equal(t, tc.wantDescription, description)
			if tc.wantRefused {
				assert.Equal(t, oidc.ErrorInteractionRequired, code)
			} else {
				assert.Empty(t, code)
			}
		})
	}
}
