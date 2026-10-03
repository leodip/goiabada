package ceremony

import "github.com/leodip/goiabada/authserver/internal/record"

// StepUp is what a ceremony still owes before a session satisfies its target level, and why.
type StepUp int

const (
	// StepUpNone means the session satisfies the target: no second factor is asked.
	StepUpNone StepUp = iota
	// StepUpLevel means the target is above the level the session reached, or there is no session
	// to reuse and the target is above level 1.
	StepUpLevel
	// StepUpOtpConfigChanged means the session reached the target's level, but the user's
	// authenticator has changed since the session last answered the level 2 question, and the
	// target asks that question.
	StepUpOtpConfigChanged
)

// TargetRequiresSecondFactor reports whether a ceremony aiming at target has to answer the level 2
// question, which is every level above level 1. A level outside the three answers false, as
// IsHigherThan ranks it below level 1.
func TargetRequiresSecondFactor(target record.AcrLevel) bool {
	return target.IsHigherThan(record.AcrLevel1)
}

// StepUpOwed is the one "does this session satisfy the target level" rule, read by
// /auth/level1completed to decide whether to go to /auth/level2 and by prompt=none to decide
// whether to answer interaction_required. Both used to write it out, and /auth/completed's promotion
// gate a third copy of its level test (#437).
//
// session is the session the ceremony may reuse, with its User loaded by UserSessionLoadUser, or nil
// when there is none: no session at all, one that is not valid, or one that belongs to another user.
// A session belonging to anyone else must be passed as nil, or this would decide one user's step-up
// from another's ACR (#133).
//
// The OTP configuration check compares the session's snapshot with its user's counter, and != rather
// than <, so a snapshot somehow ahead of the counter asks again too: the fail-closed answer, and
// what makes migration 000031's -1 seed work with no special case. It writes nothing. The obligation
// stands until /auth/completed records that a ceremony answered it, so an abandoned ceremony spends
// no re-prompt (#242 decision 1).
//
// A session ACR that does not parse is returned as an error; each caller decides what that answers.
func StepUpOwed(target record.AcrLevel, session *record.UserSession) (StepUp, error) {
	if session == nil {
		if TargetRequiresSecondFactor(target) {
			return StepUpLevel, nil
		}
		return StepUpNone, nil
	}

	sessionAcrLevel, err := record.AcrLevelFromString(session.AcrLevel.String())
	if err != nil {
		return StepUpNone, err
	}
	if target.IsHigherThan(sessionAcrLevel) {
		return StepUpLevel, nil
	}
	if session.OtpConfigGeneration != session.User.OtpConfigGeneration && TargetRequiresSecondFactor(target) {
		return StepUpOtpConfigChanged, nil
	}
	return StepUpNone, nil
}
