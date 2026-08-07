package otp

import (
	"time"

	pquernaotp "github.com/pquerna/otp"
	"github.com/pquerna/otp/hotp"
)

// StepSeconds is the TOTP time step in seconds. It is the library default that
// GenerateOTPSecret relies on, restated here because the step is what identifies a
// consumed code.
const StepSeconds = 30

const (
	// skewSteps is how far either side of the current step a code is accepted, the
	// library default totp.Validate applies. Narrowing it is #142, deliberately not
	// part of this change (#111 decision 6).
	skewSteps = 1

	// lookbackSteps is how far below a step MatchStep looks for an earlier one
	// producing the same passcode. Derived from the window rather than written as a
	// literal, so narrowing the skew narrows this with it.
	//
	// Step A is acceptable while the current step is A-skew through A+skew, so two
	// steps producing one passcode are acceptable over an unbroken run of current
	// steps only when they are at most 2*skew+1 apart. A wider pair has a gap in
	// which the passcode is refused, and by the time it is accepted again the
	// authenticator is legitimately displaying those same digits for a new step,
	// which no marker recording a step can tell apart (#111 decision 11).
	lookbackSteps = 2*skewSteps + 1

	// maxLookbackScans bounds how far the walk in matchStepWith repeats, so resolving
	// a chain of colliding steps costs at most maxLookbackScans*lookbackSteps HMAC
	// computations. Reaching it refuses the passcode rather than answering with a step
	// that may not be the bottom of its chain, which fails in the same direction as
	// the error branches below: a refusal costs the user one code and their next one
	// works, while claiming a step above the bottom is a replay.
	//
	// The cap is not what makes the walk terminate. Each scan searches strictly below
	// the step it last found, so the loop is already a total function; what the cap
	// bounds is work per request, turning a bound of the whole step axis into a small
	// constant.
	//
	// 5 is read off an executed sweep of the step axis rather than rounded to a
	// comfortable number. Every scan that finds something
	// needs one more step producing the same six digits within lookbackSteps below the
	// last, and the sweep measured that link rate instead of assuming it: 55 links in
	// 20,000,000 steps over 4 secrets, 2.75e-06 per step against the 3.0e-06 an
	// independent-uniform model predicts. Links are independent, so a chain of n steps
	// is (3e-06)^(n-1) per presentation. That sweep, 19 years of one authenticator,
	// could not reach a chain of 3 at all. The criterion for the cap is that it must
	// first refuse at a chain whose expected count stays under one in a billion across
	// 1e18 presentations, an absurdly generous bound on every authentication every
	// deployment of this server will ever perform. 5 scans is the first value that
	// clears it, refusing at a chain of 6 steps, 2.4e-28 per presentation; the probe
	// prints the whole ladder so the number is checkable rather than asserted.
	maxLookbackScans = 5
)

// producesPasscode reports whether the given time step produces the passcode being
// verified. MatchStep supplies the library's HMAC over the user's secret. A test
// supplies an explicit set of steps instead, which is the only way to reach a chain of
// colliding steps at all, since no secret anyone can enrol exhibits one (#111
// decision 12, which amends the seams for exactly this reason).
type producesPasscode func(step int64) (bool, error)

// MatchStep reports which time step produced passcode, within the accepted skew
// window, so the caller can record that step as consumed. now is a parameter rather
// than read here so the window can be tested at a pinned instant.
//
// A passcode does not name a step. Several steps can produce the same six digits, so
// the step reported is the lowest one in the chain of such steps, found by walking
// lookbackSteps down at a time from the match. That answer is the same at every current
// step in one unbroken run of accepting steps, which is what makes the first claim of it
// refuse every later presentation in that run. Steps spread wider than lookbackSteps
// apart have a refused gap between their runs and so a different answer either side,
// which is the residual lookbackSteps records as inherent. Reporting the step that
// matched inside the window instead would let one passcode be consumed once against each
// colliding step as the window slides (#111 decision 11), and applying the lookback once
// rather than walking it would do the same for three or more colliding steps (#111
// decision 12). What is accepted does not change either way: only a match inside the
// window accepts, and the walk moves nothing but the answer.
//
// An empty secret matches nothing (#111 decision 9). The library happily derives a
// code from the empty key, and that code depends only on the time step, so it is the
// same everywhere and anyone can compute it. Refusing here covers every call site at
// once, including a stored secret that decrypts to empty.
func MatchStep(passcode string, secret string, now time.Time) (int64, bool) {
	if secret == "" {
		return 0, false
	}

	produces := func(step int64) (bool, error) {
		return hotp.ValidateCustom(passcode, uint64(step), secret, hotp.ValidateOpts{
			Digits:    pquernaotp.DigitsSix,
			Algorithm: pquernaotp.AlgorithmSHA1,
		})
	}

	step, matched, err := matchStepWith(produces, now.Unix()/StepSeconds)
	if err != nil {
		// Errors collapse to "no match" rather than propagating, which is what
		// totp.Validate does today (rv, _ := ValidateCustom(...)). A wrong-length
		// passcode or an unparseable secret stays a generic incorrect-OTP response
		// instead of becoming a 500.
		return 0, false
	}
	if !matched {
		return 0, false
	}
	return step, true
}

// matchStepWith is MatchStep's step arithmetic over a step predicate rather than over
// the HMAC directly, so the walk below can be pinned against a chain of colliding steps
// that no real secret produces.
func matchStepWith(produces producesPasscode, current int64) (int64, bool, error) {
	lowest, matched, err := lowestMatch(produces, current-skewSteps, current+skewSteps)
	if err != nil || !matched {
		return 0, false, err
	}

	// Walk down from the matched step rather than searching one fixed interval below
	// the window. Three steps producing one passcode chain their acceptance ranges into
	// one unbroken run of current steps when each adjacent gap is at most lookbackSteps,
	// and one fixed interval then stops reaching the bottom of that chain while the run
	// is still live: the answer advances as the window slides, and the passcode is
	// consumed a second time with no refusal in between (#111 decision 12).
	//
	// Each scan takes the lowest step it finds. That is enough to reach the bottom of
	// the chain in one pass down: a higher step in the same scan is within lookbackSteps
	// of the step being searched below, so anything it could reach is itself within
	// lookbackSteps of the lowest one, and the next scan sees it.
	for scans := 1; ; scans++ {
		earlier, found, err := lowestMatch(produces, lowest-lookbackSteps, lowest-1)
		if err != nil {
			// Unreachable through MatchStep once the window has matched: the library's
			// two errors are an unparseable secret and a wrong-length passcode, and
			// neither depends on the step. Refused anyway rather than answered with a
			// step whose chain has not been walked to the bottom.
			return 0, false, err
		}
		if !found {
			return lowest, true, nil
		}
		if scans == maxLookbackScans {
			// A chain longer than anything reachable, so this is a fault rather than a
			// user. Refuse, for the reason maxLookbackScans records.
			return 0, false, nil
		}
		lowest = earlier
	}
}

// lowestMatch reports the lowest step in [lo, hi] that produces the passcode.
func lowestMatch(produces producesPasscode, lo int64, hi int64) (int64, bool, error) {
	for step := lo; step <= hi; step++ {
		ok, err := produces(step)
		if err != nil {
			return 0, false, err
		}
		if ok {
			return step, true, nil
		}
	}
	return 0, false, nil
}
