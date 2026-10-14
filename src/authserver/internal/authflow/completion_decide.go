package authflow

import (
	"github.com/leodip/goiabada/authserver/internal/ceremony"
	"github.com/leodip/goiabada/authserver/internal/oidc"
	"github.com/leodip/goiabada/authserver/internal/otpcredential"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/authserver/internal/userconsent"
)

// completionFacts is what decideCompletion decides from, every one of them read before the
// decision.
type completionFacts struct {
	// sessionPresent, sessionValid and sessionOwned are about the session the browser arrived with.
	sessionPresent bool
	sessionValid   bool
	sessionOwned   bool
	// level1Completed is the ceremony's Level1AuthCompleted.
	level1Completed bool
	// credentialEntered says a credential was accepted in this ceremony: AuthenticatedAt is set.
	credentialEntered bool
	// raisesPrivilege is usersession.WillRaisePrivilege for the arrived-with session.
	raisesPrivilege bool
	// otpConfigGenerationCaptured says the ceremony captured the user's OTP config generation.
	otpConfigGenerationCaptured bool
	target                      record.AcrLevel
}

// completionPlan is decideCompletion's answer, one of three modes: reuseSessionPlan,
// createSessionPlan or restartPlan. Each carries only what its own arm does beyond its core write, and
// each is built by its constructor alone (reuseSession, createSession, restartAtLevel1), which
// completion_plan_lint_test.go holds, so every attribute Completion acts on is one a decision chose.
type completionPlan interface {
	// completionPlan seals the set to the three modes.
	completionPlan()
}

// reuseSessionPlan binds the session the browser arrived with, valid and this user's, raising it to
// this ceremony's authentication or, when the ceremony authenticated afresh, replacing it (#537).
// Its four attributes are independent of each other.
type reuseSessionPlan struct {
	// rotateIdentifier rotates the browser session's identifier before the bind (#266).
	rotateIdentifier bool
	// refreshAuthTime writes the credential's instant onto the bound session.
	refreshAuthTime bool
	// replaceAuthentication writes this ceremony's level, methods and password instant onto the bound
	// session, as the create arm would stamp them on a new one (#537).
	replaceAuthentication bool
	// promoteOtpConfigGeneration records the generation the session answered level 2 against (#242).
	promoteOtpConfigGeneration bool
}

func (reuseSessionPlan) completionPlan() {}

// reuseSession is the reuse mode with the attributes given.
func reuseSession(rotateIdentifier, refreshAuthTime, replaceAuthentication,
	promoteOtpConfigGeneration bool) reuseSessionPlan {

	return reuseSessionPlan{
		rotateIdentifier:           rotateIdentifier,
		refreshAuthTime:            refreshAuthTime,
		replaceAuthentication:      replaceAuthentication,
		promoteOtpConfigGeneration: promoteOtpConfigGeneration,
	}
}

// arrivedWithSession is the session the browser arrived with, as the create arm meets it: none,
// another user's, or this user's and not reusable. The three exclude each other, so a session is
// never both terminated and replaced.
type arrivedWithSession int

const (
	// arrivedWithNoSession: the browser carried no session, and the new one replaces nothing.
	arrivedWithNoSession arrivedWithSession = iota + 1
	// arrivedWithForeignSession: another user's, valid or not, which is terminated before the new one
	// is started (#133).
	arrivedWithForeignSession
	// arrivedWithOwnSession: this user's, expired, idle or older than max_age, which the new one
	// replaces without revoking what it authorized (#133, #243).
	arrivedWithOwnSession
)

// createSessionPlan starts a new session, after ending the arrived-with session when it is another
// user's.
type createSessionPlan struct {
	arrivedWith arrivedWithSession
}

func (createSessionPlan) completionPlan() {}

// createSession is the create mode, for the session the browser arrived with.
func createSession(arrivedWith arrivedWithSession) createSessionPlan {
	return createSessionPlan{arrivedWith: arrivedWith}
}

// terminatesForeignSession reports whether the arrived-with session is another user's, which the
// create arm terminates with its codes and refresh tokens.
func (p createSessionPlan) terminatesForeignSession() bool {
	return p.arrivedWith == arrivedWithForeignSession
}

// replacesOwnSession reports whether the arrived-with session is this user's, which the new session
// replaces.
func (p createSessionPlan) replacesOwnSession() bool {
	return p.arrivedWith == arrivedWithOwnSession
}

// restartPlan sends the ceremony back to level 1 (restart route 1), binding nothing.
type restartPlan struct{}

func (restartPlan) completionPlan() {}

// restartAtLevel1 is the restart mode.
func restartAtLevel1() restartPlan {
	return restartPlan{}
}

// decideCompletion decides how the end of an authentication ceremony binds it to a session.
//
// Reuse needs the arrived-with session both valid and owned. The browser can carry user A's cookie
// while user B authenticates (prompt=login and an id_token_hint naming someone else both reach the
// password form without clearing it, and an invalid session row keeps its cookie), and reusing A's
// session for B's ceremony would bind B's code to a session B does not own and rewrite A's session
// (#133). On that arm, reuseSession:
//
//   - the identifier rotates when the bind will raise a privilege, OWASP's "regenerate on any
//     privilege level change", since this server's ACR levels are privilege levels (#266 decision 6).
//     It is no fixation defence: fixation is closed on the create arm, inside StartNewUserSession;
//   - AuthTime is refreshed when a credential was entered in this ceremony (prompt=login, a step-up),
//     since the bind otherwise keeps the session's, which is right for SSO reuse only;
//   - the level and methods are replaced with this ceremony's when it completed level 1 itself
//     (prompt=login, an id_token_hint naming someone else, a restart). That makes it a new
//     authentication, and /auth/level1completed has already asked it for every factor its target
//     needs (#537), so the session ends up as the create arm would stamp a new one: the target level,
//     this ceremony's methods and its credential's instant, the one authentication OIDC Core 1.0
//     section 2 has acr, amr and auth_time describe. That can lower the session: prompt=login at a
//     level 1 client over a level 3 session leaves it at level 1 with amr "pwd". Do not undo this:
//     keeping level 3 beside "pwd" contradicts itself (#239 finding F4), and merging the methods back
//     to "pwd otp" beside a fresh AuthTime claims a code never entered then (PR #238 decision 9). The
//     session row is kept, so other clients' session-bound refresh tokens keep working;
//   - the OTP config generation is promoted when the ceremony captured one and the target is above
//     level 1, the level test ceremony.StepUpOwed applies, so the two agree. The password step
//     captures too, and without the level test a prompt=login ceremony at a level 1 client would
//     discharge a level 2 obligation it never addressed (#242 decision 3).
//
// With no session this ceremony may reuse, only level 1 performed in this ceremony
// (level1Completed) creates one; otherwise the ceremony restarts at level 1 (restartAtLevel1), so a
// ceremony whose session ended mid-flight never mints a session from its UserId with no proof anyone
// authenticated (#129 decision 6). It reads level1Completed, not credentialEntered, because AuthenticatedAt is also
// set by a code entered over a reused session, with no password (#129 decision 15). The second pass
// sets level1Completed at the password step, so the restart does not loop, and a session deleted
// before the user signs in afresh still succeeds (#46).
//
// On the create arm, createSession, an arrived-with session that is another user's is terminated,
// valid or not: the browser carries its cookie either way, and its offline grants would keep working
// on a row nobody can resume (#133). One that is this user's is not reusable (expired, idle, or older than
// the max_age asked for), so the new session replaces it (#133, #243).
func decideCompletion(f completionFacts) completionPlan {
	if f.sessionValid && f.sessionOwned {
		return reuseSession(
			f.raisesPrivilege,   // rotateIdentifier
			f.credentialEntered, // refreshAuthTime
			f.level1Completed,   // replaceAuthentication
			f.otpConfigGenerationCaptured && ceremony.TargetRequiresSecondFactor(f.target), // promoteOtpConfigGeneration
		)
	}
	if !f.level1Completed {
		return restartAtLevel1()
	}
	switch {
	case !f.sessionPresent:
		return createSession(arrivedWithNoSession)
	case f.sessionOwned:
		return createSession(arrivedWithOwnSession)
	default:
		return createSession(arrivedWithForeignSession)
	}
}

// beforeBindingAnswer is what Completion does with the ceremony's user before an arm binds a
// session.
type beforeBindingAnswer int

const (
	// beforeBindingBind lets the arm bind.
	beforeBindingBind beforeBindingAnswer = iota + 1
	// beforeBindingUserMissing answers 500: the ceremony's user no longer exists.
	beforeBindingUserMissing
	// beforeBindingUserDisabled answers access_denied: the ceremony's user has been disabled.
	beforeBindingUserDisabled
	// beforeBindingGenerationMoved restarts the ceremony at level 1 (restart route 1).
	beforeBindingGenerationMoved
	// beforeBindingAuthenticatorRemoved restarts the ceremony at level 1 (restart route 1): it names
	// a one-time code from an authenticator the user no longer has.
	beforeBindingAuthenticatorRemoved
)

// decideBeforeBinding decides on the ceremony's user before either arm binds a session, so a refused
// or restarted ceremony leaves no session row behind that /auth/issue would refuse to use (#522
// decision 6). ceremonyGeneration is the authentication generation the ceremony holds, captured at
// its password step or inherited from the session it reused. In order of precedence:
//
//   - a missing user is refused;
//   - a disabled user is refused, as /auth/issue refuses one. It is asked before the generation,
//     which a disable moves on too: the client is owed access_denied, not a password form the
//     disabled account cannot get past;
//   - a generation other than the ceremony's restarts at level 1, the restart /auth/issue would make
//     one step later, compared as the token endpoint compares it at redemption. The user's current
//     value is never read into the ceremony, which would launder a sign-in that began before a
//     credential change into the generation that change established (#106 decision 11);
//   - a ceremony whose methods name a one-time code restarts at level 1 unless the user still has the
//     authenticator that code came from (otpcredential.OTPClaim). A removal lowers the user's
//     sessions, but a ceremony in flight adopted the session's methods before that, and binding it
//     would merge otp back into the lowered session. An authenticator set up since makes no
//     difference: the code came from the one removed. The write asks again under the user's row
//     lock, for a removal landing after this (#542 decision 1).
func decideBeforeBinding(user *record.User, ceremonyGeneration int64, otpClaim otpcredential.OTPClaim) beforeBindingAnswer {
	if user == nil {
		return beforeBindingUserMissing
	}
	if !user.Enabled {
		return beforeBindingUserDisabled
	}
	if user.AuthStateGeneration != ceremonyGeneration {
		return beforeBindingGenerationMoved
	}
	if !otpClaim.StandsFor(user) {
		return beforeBindingAuthenticatorRemoved
	}
	return beforeBindingBind
}

// AfterBindingFact is a fact DecideAfterBinding needs and has not been given. Completion loads it
// and asks again.
type AfterBindingFact int

const (
	// AfterBindingFactNone means the answer is decided.
	AfterBindingFactNone AfterBindingFact = iota
	// AfterBindingFactEffectiveScope is the ceremony's scope narrowed to what the user holds, as
	// AuthContext.SetScope stores it.
	AfterBindingFactEffectiveScope
	// AfterBindingFactConsent is the user's stored consent to the client, or none.
	AfterBindingFactConsent
)

// AfterBindingAnswer is where a ceremony bound to a session goes next.
type AfterBindingAnswer int

const (
	// AfterBindingUndecided is returned beside a fact still to load.
	AfterBindingUndecided AfterBindingAnswer = iota
	// AfterBindingNoScope answers access_denied for a user holding none of the requested scopes.
	AfterBindingNoScope
	// AfterBindingConsent goes on to the consent screen.
	AfterBindingConsent
	// AfterBindingIssue goes on to issuance.
	AfterBindingIssue
)

// AfterBindingFacts is what DecideAfterBinding decides from. EffectiveScope is nil until it has been
// loaded.
type AfterBindingFacts struct {
	// PromptConsent is the prompt's consent token.
	PromptConsent bool
	// ConsentRequired is the client's ConsentRequired.
	ConsentRequired bool
	// ClientIdentifier is the client's ClientIdentifier.
	ClientIdentifier string
	EffectiveScope   *string
	// ConsentLoaded is set once the consent has been looked up; Consent is nil when there is none.
	ConsentLoaded bool
	Consent       *record.UserConsent
}

// DecideAfterBinding decides where a ceremony goes once it is bound to a session, or names the next
// fact it needs to decide that. The user is enabled by now, since decideBeforeBinding refused a
// disabled one, so the scope is filtered only for a user who may be issued something. In order of
// precedence:
//
//   - a user holding none of the requested scopes is answered access_denied;
//   - prompt=consent, the client's ConsentRequired or offline_access goes to the consent screen,
//     which then skips itself for a scope already consented unless offline_access or prompt=consent
//     is there;
//   - a scope owed a consent whatever the client says (userconsent.AlwaysOwed) goes to the consent
//     screen unless the user's stored consent covers it, the one case the stored consent is read
//     here (#509 decision 1);
//   - otherwise the ceremony goes on to issuance.
//
// The consent table on the Clients concept page is held to this, with the consent step's own rule,
// by the handlers package's consent docs test.
func DecideAfterBinding(f AfterBindingFacts) (AfterBindingAnswer, AfterBindingFact) {
	if f.EffectiveScope == nil {
		return AfterBindingUndecided, AfterBindingFactEffectiveScope
	}
	if len(*f.EffectiveScope) == 0 {
		return AfterBindingNoScope, AfterBindingFactNone
	}
	if f.PromptConsent || f.ConsentRequired || oidc.HasOfflineAccessScope(*f.EffectiveScope) {
		return AfterBindingConsent, AfterBindingFactNone
	}
	if owed := userconsent.AlwaysOwed(f.ClientIdentifier, *f.EffectiveScope); len(owed) > 0 {
		if !f.ConsentLoaded {
			return AfterBindingUndecided, AfterBindingFactConsent
		}
		if !userconsent.Covers(f.Consent, owed) {
			return AfterBindingConsent, AfterBindingFactNone
		}
	}
	return AfterBindingIssue, AfterBindingFactNone
}
