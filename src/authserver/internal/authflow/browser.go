package authflow

import "github.com/leodip/goiabada/authserver/internal/ceremony"

// stepSaver is the browser-session write a step makes to move its ceremony on: the auth context
// saved with its next state. The save lands only while the browser session still holds the step's
// ceremony, and otherwise answers ceremony.ErrCeremonyReplaced and writes nothing (#579). The
// handler's per-request adapter satisfies it, over ceremony.Store.
type stepSaver interface {
	SaveAuthContext(authContext *ceremony.AuthContext) error
}

// recoveryCodesTaker is the browser-session write that takes the set of recovery codes off a
// ceremony: read afresh and cleared in one conditional write, answering the set the write took, none
// when the ceremony as stored holds none, and ceremony.ErrCeremonyReplaced, with nothing written,
// when the browser session no longer holds it (#257 decision 14). The handler's per-request adapter
// satisfies it, over ceremony.Store.
type recoveryCodesTaker interface {
	TakeRecoveryCodes(ceremonyId string) ([]string, error)
}

// ceremonyClearer is the browser-session write that ends a ceremony: its auth context cleared, only
// while the browser session still holds it, and otherwise ceremony.ErrCeremonyReplaced with nothing
// written (#579). The handler's per-request adapter satisfies it, over ceremony.Store.
type ceremonyClearer interface {
	ClearAuthContext(ceremonyId string) error
}

// sessionRotator is the browser-session write that replaces the session's identifier at a privilege
// change, keeping its contents: the instant a password or a code is accepted, and on
// /auth/completed's reuse arm when the bind raises the session, so an identifier planted before the
// sign-in names nothing the sign-in produced (#266). It lands only while the browser session still
// holds the ceremony, and otherwise answers ceremony.ErrCeremonyReplaced and writes nothing (#579).
// It keeps no ceremony held for a user other than userId, the user the ceremony has authenticated
// (#246). The handler's per-request adapter satisfies it, over ceremony.Store.
type sessionRotator interface {
	RegenerateSession(ceremonyId string, userId int64) error
}

// credentialFailureRecorder charges a refused credential to the rate limiter, against the
// reservation the limiter placed on this request before the handler ran, so the operation names no
// bucket and no key (#219). The handler's per-request adapter satisfies it, over the rate limiter.
type credentialFailureRecorder interface {
	RecordCredentialFailure()
}
