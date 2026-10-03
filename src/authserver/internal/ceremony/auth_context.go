package ceremony

import (
	"slices"
	"strings"
	"time"

	"github.com/leodip/goiabada/authserver/internal/oidc"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/core/oauth"
)

// AuthState is one state of the authorization ceremony's machine: the value AuthContext.AuthState
// holds between hops, and what each route's gate compares against. The roster in CLAUDE.md's
// "Auth States (State Machine)" section is held to these constants by AssertAgentDocs in
// core/guard, which reads them from this file's const block, so each is written as a typed
// string literal rather than a conversion (#436).
type AuthState string

const (
	AuthStateRequiresLevel1          AuthState = "requires_level_1"
	AuthStateRequiresLevel2          AuthState = "requires_level_2"
	AuthStateLevel1Password          AuthState = "level1_password"
	AuthStateLevel1PasswordCompleted AuthState = "level1_password_completed"
	AuthStateLevel1ExistingSession   AuthState = "level1_existing_session"
	AuthStateLevel2OTP               AuthState = "level2_otp"
	AuthStateAuthenticationCompleted AuthState = "authentication_completed"
	AuthStateRequiresConsent         AuthState = "requires_consent"
	AuthStateReadyToIssueCode        AuthState = "ready_to_issue_code"
)

type AuthContext struct {
	ClientId                      string
	RedirectURI                   string
	ResponseType                  string
	CodeChallengeMethod           string
	CodeChallenge                 string
	ResponseMode                  string
	Scope                         string
	ConsentedScope                string
	MaxAge                        string
	AcrValuesFromAuthorizeRequest string
	State                         string
	Nonce                         string
	UserAgent                     string
	IpAddress                     string
	AcrLevel                      record.AcrLevel
	AuthMethods                   string
	UserId                        int64
	AuthState                     AuthState
	Prompt                        string     // Normalized prompt values (space-delimited, deduplicated)
	AuthenticatedAt               *time.Time // Optional: override for auth_time in code issuance (used by prompt=none)
	IdTokenHintSub                string     // sub claim from id_token_hint (empty if no hint provided)
	// Level1AuthCompleted records that level 1 authentication happened in THIS ceremony,
	// as opposed to being inherited from a session the ceremony reused. It is written only
	// where level 1 is performed, today only handler_auth_pwd, and read by
	// handler_auth_completed to decide whether a ceremony with no valid session may create
	// one (#129 decision 15).
	//
	// AuthenticatedAt cannot answer that question, which is why this field exists: the OTP
	// handler sets it too, so a ceremony that stepped up to level 2 by reusing a session
	// and never saw the password form satisfies it on OTP alone. Any future level 1 method
	// must set this, or a ceremony using it is sent back to /auth/level1 when its session
	// is gone. Absent from an older cookie it unmarshals as false, which is the safe
	// direction.
	Level1AuthCompleted bool
	// AuthStateGeneration is the user's authentication generation as it stood when this
	// ceremony authenticated. Captured from the user at password verification, or
	// inherited from the reused session on the SSO path, and NEVER read from the current
	// user mid-ceremony: doing that would launder a ceremony that began before a
	// credential change into the generation that change established (#106 decision 11).
	AuthStateGeneration int64
	// OtpConfigGeneration is the user's otp_config_generation as this ceremony observed it
	// when it answered the level 2 question, and it is what /auth/completed promotes onto
	// the session this ceremony binds to. Captured at password verification and again on
	// every arm of /auth/level2, and overwritten with the value the increment returned
	// when the ceremony itself enrolls an authenticator (#242).
	//
	// **Living on the auth context is what makes an abandoned ceremony free.** The value
	// dies with the context, so a visitor who closes the browser at the OTP prompt has
	// discharged nothing and is asked again; the boolean this replaced was cleared by the
	// handler that decided to ask, so abandoning spent the re-prompt.
	//
	// Captured, never read live at /auth/completed: an authenticator change landing after
	// /auth/level2 must not be discharged by a ceremony that never saw it, which is #106
	// decision 11's rule applied to the same shape of counter.
	//
	// A pointer, so a context written by an older binary unmarshals as nil, which reads as
	// "this ceremony observed nothing, promote nothing" and leaves the session owing its
	// re-prompt. That is the fail-closed direction, exactly as Level1AuthCompleted,
	// CeremonyId and DeferredErrorCode each document for their own fields.
	OtpConfigGeneration *int64
	// OTPKeyURL holds the otpauth:// URL of the TOTP key this ceremony's user is enrolling:
	// written by the /auth/otp render that generated it, read by HandleAuthOtpPost to verify
	// the code the user types.
	//
	// One field rather than the seed and its rendered QR code, because the URL is the
	// library's own record of the whole key and both are derived from it, otp.SecretFromKeyURL
	// for the verifier and otp.RenderQRCodeImage for the page. Two fields could disagree; one
	// cannot. It is also what keeps an enrolment small: the URL is about 150 bytes where the
	// base64 image was roughly 2.4 KB. That used to be an entire extra cookie chunk on every
	// request; since the session became a database row it is 2.4 KB written, read and, on the
	// admin console, carried over an internal hop instead, for the duration of the enrolment
	// (#247, #266).
	//
	// It lives on the ceremony rather than in a slot on the browser session, and that is what
	// fixes the enrolment reload. The session had ONE pair of slots for the whole browser,
	// written on every GET of /auth/otp, so reloading the page replaced the seed behind a QR
	// code the user had already scanned and every code from it was then refused. Generating
	// only when this field carries no usable key makes that GET idempotent (#242 part 3).
	//
	// The binding to the ceremony is structural rather than compared, which is the second
	// half of it: a second /auth/authorize mints a new auth context and takes the old key
	// with it, so there is no shared slot for one ceremony's seed to be read out of by
	// another and no ceremony id to check it against. ClearAuthContext at /auth/issue removes
	// it, and HandleAuthOtpPost blanks it once the enrolment has succeeded, so a spent
	// credential neither travels through the rest of the ceremony nor sits in the cookie of
	// one abandoned after enrolling (#247).
	//
	// Absent from a context written by an older binary it unmarshals as "", which reads as
	// "this ceremony has generated nothing" and makes the next render generate. So does a
	// value that will not parse, for the same reason. A user mid enrolment across a deploy is
	// shown a new QR code and scans it again, which is the safe direction: no code from the
	// seed they can no longer prove they were shown is accepted.
	OTPKeyURL string
	// CeremonyId names this authorization ceremony, so a form this ceremony rendered, or a step
	// it redirected to, can say which ceremony it belongs to and be refused once the browser's
	// single auth context slot holds another one.
	//
	// A browser holds ONE auth context, so a second /auth/authorize replaces it while every
	// form already on screen still posts to the same URL. No rule about WRITING the context
	// can bind a page that is already rendered, which is why the page has to carry the id and
	// the POST has to check it: without that, a consent screen naming client A resolves its
	// checkbox indices against client B's scope list, and a password submitted at A's screen
	// finishes B's authorization outright (#79, the shape #112 records for emailed links). A
	// page load is bound the same way: every redirect between steps carries the id in the URL
	// (QueryParameter) and loadAuthContext compares it before anything else, so a tab of a
	// replaced sign-in that reaches its next step gets the "no longer active" page instead of
	// acting on the newer one (#246, #437).
	//
	// Generated only in HandleAuthorizeGet, through NewId, the sole creation site, so no other
	// path can mint one. Absent from a context written by an older binary it unmarshals as "", which
	// ceremonyMatches refuses rather than matching against an empty submission: a user mid-flow
	// across a deploy is refused once and restarts the authorization, bounded by the session
	// cookie's life. That is the fail-closed direction.
	CeremonyId string
	// UILocales carries the OIDC ui_locales hint as captured on /auth/authorize,
	// preserving the RP's stated preference across the multi-step auth flow.
	// Sanitized before storage (BCP 47 shape filter, capped at 10 tags / 256 bytes).
	UILocales []string
	// DeferredErrorCode and DeferredErrorDescription park an authorization error that the
	// server refused to deliver until somebody had authenticated. RFC 9700 4.11.2 requires
	// that the user be authenticated before the server redirects them, so a validation
	// failure reaching a logged-out browser is carried across the login ceremony and
	// delivered to the client afterwards, instead of redirecting an anonymous visitor to a
	// host the client chose (#213).
	//
	// DeferredErrorCode != "" is the sentinel, and it is sound rather than merely convenient:
	// the five deferrable validations have 23 error returns between them and not one carries
	// an empty code, while the empty-code constructor oauth.NewErrorDetail("", ...) is
	// used only by ValidateClientAndRedirectURI, which answers a rendered page and never a
	// redirect. An edit that introduces an empty-coded error on a deferrable path silently
	// turns a parked error into no error at all, so it must mint a code instead.
	//
	// Absent from a context written by an older binary they unmarshal as "", which reads as
	// "no parked error" and is the safe direction, exactly as Level1AuthCompleted and
	// CeremonyId document for their own fields.
	DeferredErrorCode        string
	DeferredErrorDescription string
	// TargetAcrLevel is the authentication level this ceremony must reach, snapshotted at
	// /auth/authorize when the request was accepted and never recomputed afterwards.
	//
	// Without it the target is a live read of the client's default_acr_level at three later
	// handlers, so an administrator changing that row mid-ceremony retroactively redefines what
	// the ceremony was required to do. A raise landing after /auth/level1completed has already
	// decided no step-up is needed makes /auth/completed stamp acr: urn:goiabada:level2_mandatory
	// on a ceremony that only ever saw a password, and OIDC Core section 2 defines acr as the
	// class "the authentication performed satisfied", so the claim is false in the direction a
	// relying party trusts. A lowering landing before /auth/level2 takes its target outside that
	// handler's switch and answers 500 instead.
	//
	// Absent from a context written by an older binary it unmarshals as "", and an unparsable
	// value could only mean a later release dropped an ACR level. Both fall back to computing the
	// target from the client's current row, which is what every handler did before this field
	// existed and is never below what the request asked for, so a ceremony in flight across a
	// deploy finishes at that answer rather than at a 500 and the window closes as the session
	// cookies age out (#240).
	TargetAcrLevel string
	// RequestedScope is the scope as SetScope normalized it when /auth/authorize accepted the
	// request, and it is never narrowed. Scope is the working copy: /auth/completed and /auth/issue
	// narrow it in place to what the authenticated user holds, so after a restart it describes the
	// abandoned attempt's user rather than the request. Restart puts Scope back from this field, so
	// whoever completes the second pass is filtered against what the client asked for (#436).
	//
	// Absent from a context written by an older binary it unmarshals as "", and a restart of such a
	// context ends with an empty scope, which /auth/completed answers access_denied. There is no
	// fallback to the narrowed Scope: keeping it is the defect this field exists to remove, and the
	// window is one ceremony per browser across the deploy.
	RequestedScope string
}

func (ac *AuthContext) SetScope(scope string) {
	ac.Scope = oidc.NormalizeScope(scope)
}

// ParkDeferredError carries an authorization error across the login ceremony instead of
// redirecting an anonymous visitor to a host the client chose, and sends the ceremony to
// requires_level_1; /auth/level1completed delivers it once level 1 credentials are verified (RFC
// 9700 4.11.2, #213).
//
// The description is conformed HERE and not only at the emitter. RFC 6749 Appendix A.8's character
// set is enforced when the redirect is written as well, and that filter is idempotent so the two
// paths stay byte-identical, but a bound applied at emission does nothing for a string already
// parked in the session: descriptions interpolate request text, so an unbounded one would be carried
// by every request of the ceremony that parked it (#213 decision 10, #266).
//
// Both fields are request fields, so this is a setter the request-field guard holds to
// HandleAuthorizeGet like a direct write (#437).
func (ac *AuthContext) ParkDeferredError(code, description string) {
	ac.DeferredErrorCode = code
	ac.DeferredErrorDescription = oauth.ConformErrorDescription(description)
	ac.AuthState = AuthStateRequiresLevel1
}

// RecordPasswordVerified records that this ceremony verified user's password at now, which is
// level 1 performed here rather than inherited from a session.
//
//   - AuthStateGeneration is captured from the user the credentials were verified against. If a
//     credential change lands while the rest of this ceremony completes, the code it eventually
//     issues carries this older value and is rejected at redemption, which is the intended
//     direction (#106 decision 11 rule 1).
//   - OtpConfigGeneration is captured too. It is the value the create arm at /auth/completed stamps
//     onto a brand new session, always present there because that arm refuses to mint a session
//     without Level1AuthCompleted. /auth/level2 overwrites it on every arm with a value read no
//     earlier, so a ceremony that answers the level 2 question promotes what that answer was given
//     against (#242 decision 3).
//   - AuthenticatedAt marks that real authentication occurred, which /auth/completed reads to decide
//     whether to refresh the session's auth time.
//   - Level1AuthCompleted is written here and nowhere else, deliberately: RecordOTPVerified sets
//     AuthenticatedAt as well, and level 2 alone must not stand in for level 1 at /auth/completed's
//     create gate (#129 decisions 6 and 15).
func (ac *AuthContext) RecordPasswordVerified(user *record.User, now time.Time) {
	ac.UserId = user.Id
	ac.AuthStateGeneration = user.AuthStateGeneration
	otpConfigGeneration := user.OtpConfigGeneration
	ac.OtpConfigGeneration = &otpConfigGeneration
	ac.AddAuthMethod(oidc.AuthMethodPassword)
	authenticatedAt := now.UTC()
	ac.AuthenticatedAt = &authenticatedAt
	ac.Level1AuthCompleted = true
	ac.AuthState = AuthStateLevel1PasswordCompleted
}

// RecordOTPVerified records that this ceremony verified a one-time code at now. enrolledGeneration
// is the otp_config_generation an enrolment in this ceremony established, nil when the user was
// already enrolled.
//
//   - An enrolment overwrites what /auth/level2 captured with the value the increment returned. The
//     ceremony asked the level 2 question against generation N and answered it by MOVING the counter
//     to N+1, so promoting N at /auth/completed would leave the session it binds owing another
//     second-factor prompt at once. The caller passes the read-back rather than N+1, so a concurrent
//     change cannot be laundered into it (#242).
//   - Level1AuthCompleted is deliberately left alone. OTP is level 2, and a ceremony can arrive here
//     having reused a session rather than entered a password, so verifying OTP is no proof of level
//     1 and must not let a ceremony recreate a session that was ended mid-flight (#129 decision 15).
//   - OTPKeyURL is cleared: the enrolment key has done its work, and leaving it set carries a spent
//     credential through the rest of the ceremony and leaves it in the session of one abandoned
//     after enrolling (#82, #247).
func (ac *AuthContext) RecordOTPVerified(now time.Time, enrolledGeneration *int64) {
	if enrolledGeneration != nil {
		generation := *enrolledGeneration
		ac.OtpConfigGeneration = &generation
	}
	ac.AddAuthMethod(oidc.AuthMethodOTP)
	authenticatedAt := now.UTC()
	ac.AuthenticatedAt = &authenticatedAt
	ac.AuthState = AuthStateAuthenticationCompleted
	ac.OTPKeyURL = ""
}

// AdoptSession records that this ceremony reuses userSession rather than authenticating: the user,
// the level and methods the session reached, and its authentication generation. /auth/authorize's
// SSO path and prompt=none both reuse one this way.
//
// The generation is inherited from the SESSION, never read from the user. Neither path reaches the
// password handler, and reading the user's current generation here would launder an old session
// into a newer one (#106 decision 11(d)).
func (ac *AuthContext) AdoptSession(userSession *record.UserSession) {
	ac.UserId = userSession.UserId
	ac.AcrLevel = userSession.AcrLevel
	ac.AuthMethods = userSession.AuthMethods
	ac.AuthStateGeneration = userSession.AuthStateGeneration
}

// Restart sends the ceremony back to requires_level_1 keeping the request and discarding the
// attempt. The request is what /auth/authorize accepted and is left untouched; everything an
// authentication wrote is set to its zero value, and Scope is put back to RequestedScope. The
// caller saves the context and redirects to /auth/level1.
//
// Discarding rather than relying on each field being overwritten before its next read is what
// keeps an abandoned attempt out of the second pass. AuthMethods is the field that proved it:
// AddAuthMethod appends and nothing recomputes it, so an otp from the attempt reached the session
// the second pass created and the amr of its tokens, although OIDC Core 1.0 section 2 has amr, like
// auth_time, describe the authentication that was performed (#140). Scope and ConsentedScope carried
// the first user's narrowing and consent to whoever signed in next.
//
// Which fields are request and which attempt is held by the classification test beside this file,
// which fails on a field in neither list, so a new field cannot pass the unit tier until it is
// placed in one (#436).
func (ac *AuthContext) Restart() {
	ac.AuthState = AuthStateRequiresLevel1
	ac.Scope = ac.RequestedScope
	ac.ConsentedScope = ""
	ac.UserId = 0
	ac.AcrLevel = ""
	ac.AuthMethods = ""
	ac.AuthenticatedAt = nil
	ac.Level1AuthCompleted = false
	ac.AuthStateGeneration = 0
	ac.OtpConfigGeneration = nil
	ac.OTPKeyURL = ""
}

// AddAuthMethod records a completed factor on AuthMethods, the space-separated list that becomes
// the amr claim, once: a method already listed is not added again. It takes an AuthMethod rather
// than a string, so every value it can store is one String() spells; an out-of-range value, whose
// String() is "", adds nothing (#436).
func (ac *AuthContext) AddAuthMethod(method oidc.AuthMethod) {
	value := method.String()
	if value == "" {
		return
	}

	if ac.AuthMethods == "" {
		ac.AuthMethods = value
		return
	}

	if slices.Contains(strings.Fields(ac.AuthMethods), value) {
		return
	}

	ac.AuthMethods = ac.AuthMethods + " " + value
}

// RequestedMaxAge is the client's max_age as every hop after /auth/authorize reads it: nil when
// the request carried none, otherwise the value oidc.ParseMaxAge reads from the raw parameter.
//
// MaxAge stays the raw string on the context, so the wire shape every ceremony in flight at a
// deploy carries does not change. /auth/authorize refuses a malformed value before any session
// check, so the only context carrying one is a refusal #213 parked for /auth/level1completed,
// which answers it before asking about a session. Anything else reading one is read as 0, which
// forces re-authentication: the fail-closed direction, where ignoring it would let a value nobody
// validated relax a constraint the client asked for (#243).
func (ac *AuthContext) RequestedMaxAge() *int64 {
	requestedMaxAge, err := oidc.ParseMaxAge(ac.MaxAge)
	if err != nil {
		forceReauthentication := int64(0)
		return &forceReauthentication
	}
	return requestedMaxAge
}

// SetAcrLevel sets the AuthContext's ACR level, taking into account the user's
// existing session. The effective ACR is the maximum of the target and session ACR,
// ensuring we never downgrade the authentication level within a session.
//
// Uses record.AcrMax() as the single source of truth for ACR comparison.
func (ac *AuthContext) SetAcrLevel(targetAcrLevel record.AcrLevel, userSession *record.UserSession) error {
	if userSession == nil {
		ac.AcrLevel = targetAcrLevel
		return nil
	}

	userSessionAcrLevel, err := record.AcrLevelFromString(userSession.AcrLevel.String())
	if err != nil {
		return err
	}

	// Use the higher of the two ACR levels (never downgrade)
	ac.AcrLevel = record.AcrMax(targetAcrLevel, userSessionAcrLevel)
	return nil
}

// OwnsSession reports whether the browser's ambient session belongs to the user this ceremony
// authenticated. A ceremony may read, mutate or bind to that session only when it does: the
// browser can still be carrying user A's session cookie while user B authenticates (prompt=login,
// or an id_token_hint naming someone else), and reusing A's session for B's ceremony skips B's
// second factor, mints a code stamped with A's session identifier and overwrites A's session row.
//
// Both zero cases return false, which is the safe direction: a ceremony with no session and a
// ceremony with no authenticated user each have nothing to reuse. The UserId != 0 check in
// particular stops a future auth state reaching a call site before the user is known and matching
// an unsaved session by accident, since two zeros are not a match (#133).
func (ac *AuthContext) OwnsSession(userSession *record.UserSession) bool {
	return userSession != nil && ac.UserId != 0 && userSession.UserId == ac.UserId
}

// parseAcrValuesFromAuthorizeRequest reads acr_values, which OIDC Core 1.0 section 3.1.2.1 defines
// as a space-separated string, through oauth.SplitSpaceDelimited, the one splitter for the
// space-delimited parameters, keeping each recognised level once in request order.
//
// A value that is not well formed (oauth.IsWellFormedSpaceDelimited: one space between each two
// levels, none at either end) is read as no acr_values at all, and is not refused: OIDC Core makes
// acr_values a request the server may decline to honour (sections 3.1.2.1 and 5.5.1.1), and declining
// can only leave the target at the client's default, the floor computeTargetAcrLevel sets. A level
// padded with a tab or a no-break space is not recognised either, where a trim used to admit it
// (#244, #436).
func (ac *AuthContext) parseAcrValuesFromAuthorizeRequest() []record.AcrLevel {
	arr := []record.AcrLevel{}
	if !oauth.IsWellFormedSpaceDelimited(ac.AcrValuesFromAuthorizeRequest) {
		return arr
	}
	for _, v := range oauth.SplitSpaceDelimited(ac.AcrValuesFromAuthorizeRequest) {
		acr, err := record.AcrLevelFromString(v)
		if err == nil && !slices.Contains(arr, acr) {
			arr = append(arr, acr)
		}
	}
	return arr
}

// SetTargetAcrLevel snapshots the level this ceremony must reach. Called once, at the point the
// authorization request is accepted, because a target recomputed later is a target an
// administrator can move underneath a ceremony that is already in progress. See TargetAcrLevel
// for what that costs (#240).
func (ac *AuthContext) SetTargetAcrLevel(defaultAcrLevelFromClient record.AcrLevel) {
	ac.TargetAcrLevel = ac.computeTargetAcrLevel(defaultAcrLevelFromClient).String()
}

// GetTargetAcrLevel returns the authentication level this ceremony must reach: the snapshot taken
// when the request was accepted, or, when there is none to read, the level computed from the
// client's current default. It stays the only way a caller obtains a target, so no handler can
// compute one another way and be missed. See TargetAcrLevel for why the fallback is the safe
// direction.
func (ac *AuthContext) GetTargetAcrLevel(defaultAcrLevelFromClient record.AcrLevel) record.AcrLevel {
	if ac.TargetAcrLevel != "" {
		acr, err := record.AcrLevelFromString(ac.TargetAcrLevel)
		if err == nil {
			return acr
		}
	}
	return ac.computeTargetAcrLevel(defaultAcrLevelFromClient)
}

// computeTargetAcrLevel raises the level the request asked for to the client's configured level
// and never lowers it, so the client's configuration is a floor.
//
// acr_values arrives on the front channel with no client authentication, so undo this and whoever
// composes the URL chooses the authentication policy: appending &acr_values=urn:goiabada:level1
// then turns off the second factor of a client configured to demand one, for anybody who can get
// the end user to follow a link. A request asking for MORE than the client's level still gets it,
// which is what makes this a floor rather than the client default always winning, and dropping
// that half would leave step-up broken while every clamp case still passed.
//
// record.AcrMax is the codebase's existing comparison, already used by SetAcrLevel one layer up for
// the same never-downgrade rule against a session's ACR (#240).
func (ac *AuthContext) computeTargetAcrLevel(defaultAcrLevelFromClient record.AcrLevel) record.AcrLevel {
	acrValuesFromAuthorizeRequest := ac.parseAcrValuesFromAuthorizeRequest()
	if len(acrValuesFromAuthorizeRequest) > 0 {
		return record.AcrMax(acrValuesFromAuthorizeRequest[0], defaultAcrLevelFromClient)
	}
	return defaultAcrLevelFromClient
}

// InState reports whether the ceremony is on one of the accepted states, the question every gated
// route asks before it reads anything else from the context. No accepted state accepts nothing
// (#436).
func (ac *AuthContext) InState(accepted ...AuthState) bool {
	return slices.Contains(accepted, ac.AuthState)
}

// HasPromptValue checks if a specific prompt value was requested.
// The Prompt field contains normalized, space-delimited prompt values.
func (ac *AuthContext) HasPromptValue(value string) bool {
	return slices.Contains(oauth.SplitSpaceDelimited(ac.Prompt), value)
}
