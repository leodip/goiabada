package oauth

import (
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/leodip/goiabada/core/enums"
	"github.com/leodip/goiabada/core/models"
)

var (
	AuthStateInitial                 = "initial"
	AuthStateRequiresLevel1          = "requires_level_1"
	AuthStateRequiresLevel2          = "requires_level_2"
	AuthStateLevel1Password          = "level1_password"
	AuthStateLevel1PasswordCompleted = "level1_password_completed"
	AuthStateLevel1ExistingSession   = "level1_existing_session"
	AuthStateLevel2OTP               = "level2_otp"
	AuthStateLevel2OTPCompleted      = "level2_otp_completed"
	AuthStateAuthenticationCompleted = "authentication_completed"
	AuthStateRequiresConsent         = "requires_consent"
	AuthStateReadyToIssueCode        = "ready_to_issue_code"
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
	AcrLevel                      string
	AuthMethods                   string
	UserId                        int64
	AuthState                     string
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
	// CeremonyId names this authorization ceremony, so a form this ceremony rendered can say
	// which ceremony rendered it and be refused once the browser's single auth context slot
	// holds another one.
	//
	// A browser holds ONE auth context, so a second /auth/authorize replaces it while every
	// form already on screen still posts to the same URL. No rule about WRITING the context
	// can bind a page that is already rendered, which is why the page has to carry the id and
	// the POST has to check it: without that, a consent screen naming client A resolves its
	// checkbox indices against client B's scope list, and a password submitted at A's screen
	// finishes B's authorization outright (#79, the shape #112 records for emailed links).
	//
	// Generated only in HandleAuthorizeGet, the sole creation site, so no other path can mint
	// one. Absent from a context written by an older binary it unmarshals as "", which
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
	// an empty code, while the empty-code constructor customerrors.NewErrorDetail("", ...) is
	// used only by ValidateClientAndRedirectURI, which answers a rendered page and never a
	// redirect. An edit that introduces an empty-coded error on a deferrable path silently
	// turns a parked error into no error at all, so it must mint a code instead.
	//
	// Absent from a context written by an older binary they unmarshal as "", which reads as
	// "no parked error" and is the safe direction, exactly as Level1AuthCompleted and
	// CeremonyId document for their own fields.
	DeferredErrorCode        string
	DeferredErrorDescription string
}

func (ac *AuthContext) SetScope(scope string) {
	scopeArr := []string{}

	// remove duplicated spaces
	space := regexp.MustCompile(`\s+`)
	scopeSanitized := space.ReplaceAllString(scope, " ")

	// remove duplicated scopes
	scopeElements := strings.Split(scopeSanitized, " ")
	for _, s := range scopeElements {
		if !slices.Contains(scopeArr, strings.TrimSpace(s)) {
			scopeArr = append(scopeArr, strings.TrimSpace(s))
		}
	}
	ac.Scope = strings.TrimSpace(strings.Join(scopeArr, " "))
}

func (ac *AuthContext) HasScope(scope string) bool {
	if len(ac.Scope) == 0 {
		return false
	}
	return slices.Contains(strings.Split(ac.Scope, " "), scope)
}

func (ac *AuthContext) AddAuthMethod(method string) {
	method = strings.ToLower(strings.TrimSpace(method))

	if method == "" {
		return
	}

	if ac.AuthMethods == "" {
		ac.AuthMethods = method
		return
	}

	lowerMethods := strings.ToLower(ac.AuthMethods)
	methods := strings.Fields(lowerMethods)

	for _, existingMethod := range methods {
		if existingMethod == method {
			return
		}
	}

	ac.AuthMethods = ac.AuthMethods + " " + method
}

func (ac *AuthContext) ParseRequestedMaxAge() *int {
	var requestedMaxAge *int
	if len(ac.MaxAge) > 0 {
		i, err := strconv.Atoi(ac.MaxAge)
		if err == nil {
			requestedMaxAge = &i
		}
	}
	return requestedMaxAge
}

// SetAcrLevel sets the AuthContext's ACR level, taking into account the user's
// existing session. The effective ACR is the maximum of the target and session ACR,
// ensuring we never downgrade the authentication level within a session.
//
// Uses enums.AcrMax() as the single source of truth for ACR comparison.
func (ac *AuthContext) SetAcrLevel(targetAcrLevel enums.AcrLevel, userSession *models.UserSession) error {
	if userSession == nil {
		ac.AcrLevel = targetAcrLevel.String()
		return nil
	}

	userSessionAcrLevel, err := enums.AcrLevelFromString(userSession.AcrLevel)
	if err != nil {
		return err
	}

	// Use the higher of the two ACR levels (never downgrade)
	ac.AcrLevel = enums.AcrMax(targetAcrLevel, userSessionAcrLevel).String()
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
func (ac *AuthContext) OwnsSession(userSession *models.UserSession) bool {
	return userSession != nil && ac.UserId != 0 && userSession.UserId == ac.UserId
}

func (ac *AuthContext) parseAcrValuesFromAuthorizeRequest() []enums.AcrLevel {
	arr := []enums.AcrLevel{}
	acrValues := ac.AcrValuesFromAuthorizeRequest
	if len(strings.TrimSpace(acrValues)) > 0 {
		space := regexp.MustCompile(`\s+`)
		acrValues = space.ReplaceAllString(acrValues, " ")
		parts := strings.Split(acrValues, " ")
		for _, v := range parts {
			acr, err := enums.AcrLevelFromString(v)
			if err == nil && !slices.Contains(arr, acr) {
				arr = append(arr, acr)
			}
		}
	}
	return arr
}

func (ac *AuthContext) GetTargetAcrLevel(defaultAcrLevelFromClient enums.AcrLevel) enums.AcrLevel {
	acrValuesFromAuthorizeRequest := ac.parseAcrValuesFromAuthorizeRequest()
	if len(acrValuesFromAuthorizeRequest) > 0 {
		return acrValuesFromAuthorizeRequest[0]
	}
	return defaultAcrLevelFromClient
}

// HasPromptValue checks if a specific prompt value was requested.
// The Prompt field contains normalized, space-delimited prompt values.
func (ac *AuthContext) HasPromptValue(value string) bool {
	if ac.Prompt == "" {
		return false
	}
	for _, v := range strings.Fields(ac.Prompt) {
		if v == value {
			return true
		}
	}
	return false
}
