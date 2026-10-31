package otp

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/leodip/goiabada/authserver/internal/otp/otptest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The table below runs at a pinned instant rather than time.Now(). A table built on the
// real clock straddles a period boundary a few times a day and then fails for a reason
// that has nothing to do with the code under test.
//
// 1700000000 is 20 seconds into step 56666666, so nothing here sits on a boundary.
const (
	pinnedUnix = int64(1700000000)
	pinnedStep = pinnedUnix / StepSeconds

	// 16 characters of valid base32. The length matters: a secret is padded to a
	// multiple of 8 with "=" before it is decoded, and 16 already is one, so the
	// interior-space row below fails the decode for that reason alone.
	validSecret = "JBSWY3DPEHPK3PXP"
)

func pinnedNow() time.Time {
	return time.Unix(pinnedUnix, 0).UTC()
}

// stepMidpoint is an instant 15 seconds into a time step, so neither an instant
// under test nor one a code is derived at ever sits on a period boundary.
func stepMidpoint(step int64) time.Time {
	return time.Unix(step*StepSeconds+15, 0).UTC()
}

// codeAtStep derives the code for a time step through otptest, asking for it mid-step
// so the timestamp cannot land on a boundary either.
//
// otptest is a second RFC 6238 implementation sharing nothing with this package's, both
// pinned by the RFC vectors, so this table checks the verifier against an independent
// answer: the HMAC, the truncation and the step arithmetic MatchStep derives from now are
// all under test, where they agree with an authenticator only if each is right.
func codeAtStep(t *testing.T, secret string, step int64) string {
	t.Helper()
	return otptest.Code(t, secret, stepMidpoint(step))
}

func TestMatchStep(t *testing.T) {
	now := pinnedNow()
	codeAtPinnedStep := codeAtStep(t, validSecret, pinnedStep)

	tests := []struct {
		name          string
		passcode      string
		secret        string
		expectedStep  int64
		expectedMatch Match
	}{
		{
			// Outside the window: MatchStep accepts the previous and the current step only.
			name:     "Code from two steps back is refused",
			passcode: codeAtStep(t, validSecret, pinnedStep-2),
			secret:   validSecret,
		},
		{
			name:          "Code from the previous step is accepted, naming that step",
			passcode:      codeAtStep(t, validSecret, pinnedStep-1),
			secret:        validSecret,
			expectedStep:  pinnedStep - 1,
			expectedMatch: Matched,
		},
		{
			name:          "Code from the current step is accepted, naming that step",
			passcode:      codeAtPinnedStep,
			secret:        validSecret,
			expectedStep:  pinnedStep,
			expectedMatch: Matched,
		},
		{
			// Only an authenticator whose clock runs ahead of the server's shows it, so it is
			// told apart from a wrong code, and names no step: nothing is claimed (#142).
			name:          "Code from the next step is refused as a clock running ahead, naming no step",
			passcode:      codeAtStep(t, validSecret, pinnedStep+1),
			secret:        validSecret,
			expectedMatch: ClockAhead,
		},
		{
			// Outside the window and past the next step, so an ordinary wrong code.
			name:     "Code from two steps ahead is refused",
			passcode: codeAtStep(t, validSecret, pinnedStep+2),
			secret:   validSecret,
		},
		{
			// Wrong passcode length: refused before any step is computed, and MatchStep
			// collapses that to no match.
			name:     "Empty passcode is refused",
			passcode: "",
			secret:   validSecret,
		},
		{
			// Wrong passcode length, as above.
			name:     "Five-digit passcode is refused",
			passcode: codeAtPinnedStep[:len(codeAtPinnedStep)-1],
			secret:   validSecret,
		},
		{
			// Wrong passcode length, as above.
			name:     "Seven-digit passcode is refused",
			passcode: codeAtPinnedStep + "0",
			secret:   validSecret,
		},
		{
			// Right length, so every step in the window is computed and none of the
			// constant-time comparisons match.
			name:     "Non-numeric passcode is refused",
			passcode: "abcdef",
			secret:   validSecret,
		},
		{
			name:          "Passcode padded with whitespace is accepted, since it is trimmed",
			passcode:      " " + codeAtPinnedStep + " ",
			secret:        validSecret,
			expectedStep:  pinnedStep,
			expectedMatch: Matched,
		},
		{
			// Keep this. It asserts acceptance, which reads like a laxity to tighten.
			// A secret is upper-cased before it is decoded, as pquerna/otp did, so Google's
			// lower-case base32 works and refusing it here would be a silent behaviour change.
			name:          "Lower-case secret is accepted, since it is upper-cased",
			passcode:      codeAtPinnedStep,
			secret:        strings.ToLower(validSecret),
			expectedStep:  pinnedStep,
			expectedMatch: Matched,
		},
		{
			// Keep this, together with the row below. The two look contradictory: the
			// outside of a secret is trimmed and then it is base32-decoded, so interior
			// spaces fail the decode and surrounding ones do not. Both directions are
			// stated so a later reader does not "fix" one of them.
			//
			// Unparseable base32 secret: refused before any step is computed, collapsed
			// to no match.
			name:     "Secret with interior spaces is refused",
			passcode: codeAtPinnedStep,
			secret:   "JBSW Y3DP EHPK 3PXP",
		},
		{
			// Keep this, together with the row above.
			name:          "Secret with surrounding spaces is accepted, since it is trimmed",
			passcode:      codeAtPinnedStep,
			secret:        " " + validSecret + " ",
			expectedStep:  pinnedStep,
			expectedMatch: Matched,
		},
		{
			// Unparseable base32 secret, as above.
			name:     "Invalid base32 secret is refused",
			passcode: codeAtPinnedStep,
			secret:   "INVALID!SECRET!!",
		},
		{
			// Keep this. HOTP derives a real six-digit code from the empty key, and that
			// code depends only on the time step, so anyone can compute it for any
			// deployment (#111 decision 9). pquerna/otp's totp.Validate accepted it.
			//
			// The passcode has to be the code RFC 6238 actually derives from the empty
			// secret at the pinned step, never arbitrary digits, or the row still passes
			// with the refusal in decodeSecret deleted.
			name:     "Empty secret is refused, even with the code derived from it",
			passcode: codeAtStep(t, "", pinnedStep),
			secret:   "",
		},
		{
			// Keep this, together with the row below. A secret's surrounding whitespace is
			// trimmed before it is decoded, so whitespace alone decodes to the empty key and
			// derives the same code anyone can compute, as the row above. The refusal is of
			// the key, not the string as stored.
			name:     "Secret of spaces alone is refused, even with the empty key's code",
			passcode: codeAtStep(t, "", pinnedStep),
			secret:   "   ",
		},
		{
			// Keep this, together with the row above.
			name:     "Secret of mixed whitespace alone is refused, even with the empty key's code",
			passcode: codeAtStep(t, "", pinnedStep),
			secret:   " \t\n ",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			step, match := MatchStep(tt.passcode, tt.secret, now)

			assert.Equal(t, tt.expectedMatch, match)
			// The accepted rows assert the step, not just the boolean, or the table
			// would pass with the step arithmetic wrong.
			assert.Equal(t, tt.expectedStep, step)
		})
	}
}

// Keep all of this. Two time steps can produce the same six digits, so a passcode
// does not name a step (#111 decision 11). MatchStep answers with the lowest step in
// the chain of steps that produce it, and what these subtests assert is that the
// answer is the *same* at every current step from which that passcode is accepted
// in one unbroken run. That constancy is the whole mechanism: the first claim of that
// step is what refuses every later presentation of the same passcode.
//
// The table above cannot pin any of this. Nothing collides within eight steps of the
// instant it pins, so every rule decision 11 rejected passes all of its rows,
// including the shipped one that returned the step matched inside the window.
// Colliding pairs are rare, roughly 8 authentications in a million meet one, so no
// other test in the suite will ever reach this path by accident.
//
// The pairs are transcribed from an executed sweep of 600,000 consecutive steps of this
// secret, which also confirmed that no third step within eight either side produces these
// passcodes. That is what makes the answer constant rather than merely lower than it was.
// The sweep ran over pquerna/otp's HMAC, so the check below that both steps still produce
// one passcode also shows this package's HOTP and otptest's agreeing with the library at
// six steps no RFC vector names.
//
// Every expectation is a literal for the window of the previous and current step (#142):
// a step is accepted while the current step is that step or the one after it, and the
// current step before it is the clock-ahead refusal. Two steps up to two apart are
// therefore accepted over one unbroken run and answered with the lower step throughout.
// Three apart, the pair the wider window still covered, now has a refused step between
// its two runs, so the upper step is answered for itself: the residual lookbackSteps
// records as inherent, which no step marker can refuse.
func TestMatchStepWithCollidingSteps(t *testing.T) {
	type answer struct {
		current int64
		match   Match
		step    int64
	}

	pairs := []struct {
		name    string
		lower   int64
		upper   int64
		answers []answer
	}{
		{"Two steps one apart", 56245959, 56245960, []answer{
			{56245957, NoMatch, 0},
			{56245958, ClockAhead, 0},
			{56245959, Matched, 56245959},
			{56245960, Matched, 56245959},
			{56245961, Matched, 56245959},
			{56245962, NoMatch, 0},
		}},
		// Two apart, the widest pair that is acceptable over an unbroken run of current
		// steps and so the widest one a step marker can refuse at all.
		{"Two steps two apart", 818665, 818667, []answer{
			{818663, NoMatch, 0},
			{818664, ClockAhead, 0},
			{818665, Matched, 818665},
			{818666, Matched, 818665},
			{818667, Matched, 818665},
			{818668, Matched, 818665},
			{818669, NoMatch, 0},
		}},
		{"Two steps three apart, with a refused step between their runs", 56077475, 56077478, []answer{
			{56077473, NoMatch, 0},
			{56077474, ClockAhead, 0},
			{56077475, Matched, 56077475},
			{56077476, Matched, 56077475},
			// The previous step, 56077476, does not produce it, and the next one does.
			{56077477, ClockAhead, 0},
			{56077478, Matched, 56077478},
			{56077479, Matched, 56077478},
			{56077480, NoMatch, 0},
		}},
	}

	for _, p := range pairs {
		t.Run(p.name, func(t *testing.T) {
			passcode := codeAtStep(t, validSecret, p.lower)
			require.Equal(t, passcode, codeAtStep(t, validSecret, p.upper),
				"the two steps must still produce one passcode, or this proves nothing")

			for _, a := range p.answers {
				step, match := MatchStep(passcode, validSecret, stepMidpoint(a.current))

				assert.Equal(t, a.match, match, "current step %d", a.current)
				assert.Equal(t, a.step, step, "current step %d", a.current)
			}
		})
	}
}

// Keep all of this too, and read section 5's amendment before changing its shape. Three
// or more steps producing one passcode chain their acceptance ranges into one unbroken
// run of current steps, and a lookback applied once below the window stops reaching the
// bottom of that chain while the run is still live, so the same passcode is consumed
// twice with no refusal in between (#111 decision 12). MatchStep walks the lookback down
// instead, and this is what pins the walk.
//
// It calls matchStepWith rather than MatchStep, one boundary below the seam the interview
// sealed, because a chain cannot be exhibited with a real secret: an executed sweep found
// 0 chains of three in 20,000,000 steps over 4 secrets, against 1.8e-04 expected.
// Driving MatchStep with a real secret
// therefore passes with the walk deleted. The steps below are a synthetic match set
// standing in for the HMAC. Under the window of the previous and current step (#142) the
// shapes acceptable over an unbroken run of current steps are the pairs up to spread 2
// and every chain of three whose adjacent gaps are at most 2; each is here, beside the
// pairs and chains one and two gaps wider, which have a refused step between their runs
// and are the inherent case.
//
// Each shape is checked by replaying decision 2's high-water claim over every
// presentation, rather than by transcribing an expected step per current step: claim the
// step reported at one current step, then look for a later current step that reports a
// higher one, since the claim accepts only a step strictly above the stored marker. A
// shape is safe when no presentation leaves a later one acceptable.
func TestMatchStepWithChainsOfCollidingSteps(t *testing.T) {
	// The absolute step cannot matter, since the predicate replaces the HMAC and what is
	// left is arithmetic on step numbers.
	const lowestStep = int64(100)

	shapes := []struct {
		name string
		// Offsets from lowestStep, ascending, starting at 0.
		steps []int64
		// Whether a second acceptance is expected to remain possible. True only for the
		// shapes with a gap wider than the lookback, which decisions 11 and 12 accepted as
		// inherent.
		inherent bool
	}{
		{name: "Two steps one apart", steps: []int64{0, 1}},
		{name: "Two steps two apart", steps: []int64{0, 2}},
		{name: "Two steps three apart, inherent", steps: []int64{0, 3}, inherent: true},
		{name: "Two steps four apart, inherent", steps: []int64{0, 4}, inherent: true},
		{name: "Three steps, gaps of one and one", steps: []int64{0, 1, 2}},
		{name: "Three steps, gaps of one and two", steps: []int64{0, 1, 3}},
		{name: "Three steps, gaps of two and one", steps: []int64{0, 2, 3}},
		{name: "Three steps, gaps of two and two", steps: []int64{0, 2, 4}},
		{name: "Three steps, gaps of one and three, inherent", steps: []int64{0, 1, 4}, inherent: true},
		{name: "Three steps, gaps of three and one, inherent", steps: []int64{0, 3, 4}, inherent: true},
		{name: "Three steps, gaps of two and three, inherent", steps: []int64{0, 2, 5}, inherent: true},
	}

	for _, shape := range shapes {
		t.Run(shape.name, func(t *testing.T) {
			matches := map[int64]bool{}
			for _, offset := range shape.steps {
				matches[lowestStep+offset] = true
			}
			highestStep := lowestStep + shape.steps[len(shape.steps)-1]
			produces := func(step int64) (bool, error) { return matches[step], nil }

			// One current step either side of everything acceptable, so a refusal at the
			// edges is part of what is swept, the clock-ahead step below the lowest included.
			first, last := lowestStep-2, highestStep+2

			var replays []string
			for claimAt := first; claimAt <= last; claimAt++ {
				claimed, match, err := matchStepWith(produces, claimAt)
				require.NoError(t, err)
				if match != Matched {
					continue
				}

				for replayAt := claimAt + 1; replayAt <= last; replayAt++ {
					reported, match, err := matchStepWith(produces, replayAt)
					require.NoError(t, err)
					if match == Matched && reported > claimed {
						replays = append(replays, fmt.Sprintf(
							"claimed step %d at current %d, then step %d at current %d",
							claimed, claimAt, reported, replayAt))
						break
					}
				}
			}

			if shape.inherent {
				// Keep this. It asserts that a replay is still possible, which reads like
				// a test of a bug, and it is one: a gap wider than lookbackSteps leaves a
				// current step at which the passcode is refused, so by the time it is
				// accepted again the authenticator is legitimately displaying those
				// digits for a new step. No marker recording a step can refuse that, and
				// refusing it means storing the code itself, which is stronger than the
				// consumed-codes table #111 decision 1 rejected.
				//
				// If a later change closes this class, this row is what tells you, and
				// updating it then is the right answer. Asserting safety here instead
				// would assert something the design does not provide.
				assert.NotEmpty(t, replays,
					"this spread is the inherent case: if it is now safe, #111 decisions 11 and 12 need revisiting")
				return
			}

			assert.Empty(t, replays,
				"one passcode was accepted twice under the high-water claim, which is the defect #111 exists to close")
		})
	}
}

// The walk's cap. maxLookbackScans is there so one request cannot spend unbounded work
// following a chain, and what this pins is the direction it fails in: a chain the walk
// cannot reach the bottom of is refused, never answered with a step that might not be the
// bottom. Both cases are written in terms of the constants, so changing the cap or the
// lookback moves them together rather than leaving a stale literal behind.
//
// Over the predicate for the reason in section 5's amendment: reaching the cap needs a
// chain of maxLookbackScans+1 colliding steps, which the sweep puts at 2.4e-28 per
// presentation.
func TestMatchStepWithAChainLongerThanTheWalk(t *testing.T) {
	// Spaced lookbackSteps apart, the widest spacing the walk still follows, so every
	// scan advances it by exactly one step and the number of scans is the number of steps
	// in the chain.
	chain := func(steps int) (produces producesPasscode, lowest int64, highest int64) {
		matches := map[int64]bool{}
		lowest, highest = 100, 100
		for i := 0; i < steps; i++ {
			highest = lowest + int64(i)*lookbackSteps
			matches[highest] = true
		}
		return func(step int64) (bool, error) { return matches[step], nil }, lowest, highest
	}

	t.Run("A chain the walk can follow to the bottom reports that bottom", func(t *testing.T) {
		produces, lowest, highest := chain(maxLookbackScans)

		step, match, err := matchStepWith(produces, highest)

		require.NoError(t, err)
		assert.Equal(t, Matched, match)
		assert.Equal(t, lowest, step)
	})

	t.Run("One step further and the passcode is refused instead", func(t *testing.T) {
		produces, _, highest := chain(maxLookbackScans + 1)

		step, match, err := matchStepWith(produces, highest)

		require.NoError(t, err)
		assert.Equal(t, NoMatch, match, "a chain the walk cannot reach the bottom of must be refused")
		assert.Equal(t, int64(0), step)
	})
}

// The error branches, both of which refuse. Through MatchStep the predicate's two errors
// are an unparseable secret and a wrong-length passcode, neither of which depends on the
// step, so the table above reaches the window's branch and nothing can reach the walk's.
// Over the predicate both are reachable, and the walk's is the one worth pinning: an error
// below the window means the steps under the match were not all checked, so answering
// with the match would answer with a step that might not be the bottom of its chain.
func TestMatchStepWithAFailingStepPredicate(t *testing.T) {
	predicateFailed := errors.New("the step predicate failed")
	const current = int64(100)

	t.Run("An error inside the window is refused", func(t *testing.T) {
		produces := func(step int64) (bool, error) { return false, predicateFailed }

		step, match, err := matchStepWith(produces, current)

		require.ErrorIs(t, err, predicateFailed)
		assert.Equal(t, NoMatch, match)
		assert.Equal(t, int64(0), step)
	})

	t.Run("An error below the window is refused, not answered with the match", func(t *testing.T) {
		produces := func(step int64) (bool, error) {
			if step < current-pastSteps {
				return false, predicateFailed
			}
			return step == current, nil
		}

		step, match, err := matchStepWith(produces, current)

		require.ErrorIs(t, err, predicateFailed)
		assert.Equal(t, NoMatch, match)
		assert.Equal(t, int64(0), step,
			"the matched step must not leak out of a walk that could not finish")
	})
}
