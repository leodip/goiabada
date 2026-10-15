package authflow

import (
	"strings"

	"github.com/leodip/goiabada/authserver/internal/ceremony"
	"github.com/leodip/goiabada/authserver/internal/oidc"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/authserver/internal/userconsent"
)

// SilentFact is a fact DecideSilentAuthentication needs and has not been given. SilentAuthentication
// loads it and asks again.
type SilentFact int

const (
	// SilentFactNone means the answer is decided.
	SilentFactNone SilentFact = iota
	// SilentFactSession is the browser's session with its user, or none.
	SilentFactSession
	// SilentFactValidity is whether the session is valid with the request's max_age applied.
	SilentFactValidity
	// SilentFactValidityWithoutMaxAge is whether it would be valid without max_age.
	SilentFactValidityWithoutMaxAge
	// SilentFactEffectiveScope is the requested scope narrowed to what the user holds.
	SilentFactEffectiveScope
	// SilentFactConsent is the user's consent to this client, or none.
	SilentFactConsent
)

// SilentAuthenticationFacts is what DecideSilentAuthentication decides from. The first five are
// known from the ceremony and its client; every other fact is unknown until SilentAuthentication
// has loaded it, a nil pointer or a false loaded flag.
type SilentAuthenticationFacts struct {
	MaxAgeRequested bool
	HintSubject     string
	Target          record.AcrLevel
	// ConsentRequired is the client's ConsentRequired.
	ConsentRequired bool
	// ClientIdentifier is the client's ClientIdentifier.
	ClientIdentifier string

	// SessionLoaded is set once the session has been looked up; Session is nil when there is none,
	// and otherwise carries its User.
	SessionLoaded             bool
	Session                   *record.UserSession
	SessionValid              *bool
	SessionValidWithoutMaxAge *bool
	EffectiveScope            *string
	// ConsentLoaded is set once the consent has been looked up; Consent is nil when there is none.
	ConsentLoaded bool
	Consent       *record.UserConsent
}

// SilentAuthenticationAnswer is DecideSilentAuthentication's answer: an error for the client, or an
// empty ErrorCode to proceed.
type SilentAuthenticationAnswer struct {
	ErrorCode        string
	ErrorDescription string
	// UserDisabled says the refusal is for a disabled account, which is audited.
	UserDisabled bool
}

// DecideSilentAuthentication decides whether a prompt=none request can be answered silently, or
// names the next fact it needs to decide that. The checks run in a fixed order and the first that
// fails is the answer, so each fact is asked for only once every check before it has passed:
//
//  1. a session exists;
//  2. it is valid, and when it is not only because of max_age, the answer says so;
//  3. its user is enabled;
//  4. an id_token_hint names that user (OIDC Core 1.0 section 3.1.2.1: "MUST NOT reply with an ID
//     Token for a different user");
//  5. the step-up rule asks for no higher level (an unknown session ACR is insufficient);
//  6. level2_mandatory has an authenticator to satisfy it;
//  7. the user's authenticator has not changed since the session last answered the level 2
//     question, when the target asks it. A reader only: it refuses and promotes nothing, because no
//     interaction happened, which is what makes an identical second prompt=none request get the
//     identical answer (#242 decision 1). Steps 5 to 7 are the step-up rule's three answers, in
//     the order it gives them;
//  8. the user holds at least one requested scope;
//  9. when the client requires consent or offline_access is asked for, a consent covers every
//     scope, and otherwise it covers authserver:manage-account when the scope holds it and the
//     client is not the admin console's (userconsent.AlwaysOwed, #509 decision 3).
//
// The refusals, their order and their descriptions are the silent checks table on the docs' prompt
// page, which handlers' concept_docs_test.go holds to this function.
func DecideSilentAuthentication(f SilentAuthenticationFacts) (SilentAuthenticationAnswer, SilentFact) {
	refuse := func(code, description string) (SilentAuthenticationAnswer, SilentFact) {
		return SilentAuthenticationAnswer{ErrorCode: code, ErrorDescription: description}, SilentFactNone
	}

	if !f.SessionLoaded {
		return SilentAuthenticationAnswer{}, SilentFactSession
	}
	if f.Session == nil {
		return refuse(oidc.ErrorLoginRequired, "User authentication is required")
	}

	if f.SessionValid == nil {
		return SilentAuthenticationAnswer{}, SilentFactValidity
	}
	if !*f.SessionValid {
		if f.MaxAgeRequested {
			if f.SessionValidWithoutMaxAge == nil {
				return SilentAuthenticationAnswer{}, SilentFactValidityWithoutMaxAge
			}
			if *f.SessionValidWithoutMaxAge {
				return refuse(oidc.ErrorLoginRequired, "Session age exceeds max_age")
			}
		}
		return refuse(oidc.ErrorLoginRequired, "User session has expired")
	}

	user := &f.Session.User
	if !user.Enabled {
		return SilentAuthenticationAnswer{
			ErrorCode:        "access_denied",
			ErrorDescription: "The user account is disabled",
			UserDisabled:     true,
		}, SilentFactNone
	}

	if f.HintSubject != "" && user.Subject != f.HintSubject {
		return refuse(oidc.ErrorLoginRequired, "The current session user does not match the id_token_hint")
	}

	if code, description, refused := silentStepUpRefusal(ceremony.StepUpOwed(f.Target, f.Session)); refused {
		return refuse(code, description)
	}

	if f.EffectiveScope == nil {
		return SilentAuthenticationAnswer{}, SilentFactEffectiveScope
	}
	if len(strings.TrimSpace(*f.EffectiveScope)) == 0 {
		return refuse("access_denied", "The user is not authorized to access any of the requested scopes")
	}

	// The scopes a stored consent must cover: every one when the client requires consent or
	// offline_access is asked for, and otherwise those owed a consent whatever the client says
	// (#509 decision 3).
	mustCover := userconsent.AlwaysOwed(f.ClientIdentifier, *f.EffectiveScope)
	if f.ConsentRequired || oidc.HasOfflineAccessScope(*f.EffectiveScope) {
		mustCover = oidc.SplitScope(*f.EffectiveScope)
	}
	if len(mustCover) > 0 {
		if !f.ConsentLoaded {
			return SilentAuthenticationAnswer{}, SilentFactConsent
		}
		if f.Consent == nil {
			return refuse(oidc.ErrorConsentRequired, "User consent is required")
		}
		if !userconsent.Covers(f.Consent, mustCover) {
			return refuse(oidc.ErrorConsentRequired, "Additional consent is required")
		}
	}

	return SilentAuthenticationAnswer{}, SilentFactNone
}

// silentStepUpRefusal is DecideSilentAuthentication's answer to the step-up a session still owes a
// prompt=none request: none passes, each reason ceremony.StepUp names is refused with its own
// description, and a value it does not name is refused too, so a reason added to StepUp later fails
// closed here, rather than letting the silent flow issue a code its target was not met for, until
// this switch names it (#542).
func silentStepUpRefusal(stepUp ceremony.StepUp, err error) (code, description string, refused bool) {
	if err != nil {
		return oidc.ErrorInteractionRequired, "Higher authentication level required", true
	}
	switch stepUp {
	case ceremony.StepUpNone:
		return "", "", false
	case ceremony.StepUpAuthenticatorMissing:
		return oidc.ErrorInteractionRequired, "Additional authentication setup required", true
	case ceremony.StepUpOtpConfigChanged:
		return oidc.ErrorInteractionRequired, "Authentication configuration has changed", true
	default:
		// ceremony.StepUpLevel, and any value this switch does not name.
		return oidc.ErrorInteractionRequired, "Higher authentication level required", true
	}
}
