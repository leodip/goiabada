// Probe behind decision 11: one six-digit passcode can be produced by more than
// one time step, so a marker that records the consumed *step* does not always
// record the consumed *code*.
//
// It sweeps a long run of steps for pairs that produce the same passcode, then
// replays each pair against candidate rules for the step MatchStep should return,
// under the high-water claim of decision 2 (accept iff guard > stored, then store
// the claim). A rule is safe for a pair when no first presentation of that
// passcode leaves a later presentation acceptable.
//
// Run it from src/core, where the pquerna/otp dependency lives:
//
//	cp -r ../../docs/issue-111-otp-replay/probe/step-collisions ./probe-tmp
//	go run ./probe-tmp && rm -rf ./probe-tmp
//
// It has no dependency on goiabada code, so it stays valid as the tree moves.
// output.txt beside this file is what it printed on 2026-08-06, and the last
// section of that output is what TestMatchStepWithCollidingSteps asserts.
package main

import (
	"fmt"

	pquernaotp "github.com/pquerna/otp"
	"github.com/pquerna/otp/hotp"
)

// The secret src/core/otp/verifier_test.go pins its table on.
const secret = "JBSWY3DPEHPK3PXP"

var memo = map[int64]string{}

func codeAt(step int64) string {
	if c, ok := memo[step]; ok {
		return c
	}
	c, err := hotp.GenerateCodeCustom(secret, uint64(step), hotp.ValidateOpts{
		Digits:    pquernaotp.DigitsSix,
		Algorithm: pquernaotp.AlgorithmSHA1,
	})
	if err != nil {
		panic(err)
	}
	memo[step] = c
	return c
}

// A rule reports, for passcode p presented while the server's current step is c:
// whether it is accepted at all, the value the claim predicate compares against
// (guard) and the value it stores (claim). Every rule accepts exactly the codes
// totp.Validate accepts, the steps c-1, c and c+1; they differ only in what they
// record as consumed.
type rule func(p string, c int64) (claim int64, guard int64, ok bool)

func matchesIn(p string, lo, hi int64) []int64 {
	var out []int64
	for s := lo; s <= hi; s++ {
		if codeAt(s) == p {
			out = append(out, s)
		}
	}
	return out
}

// shipped is stage 1 as it stands: the first match in delta order 0, -1, +1.
func shipped(p string, c int64) (int64, int64, bool) {
	for _, d := range []int64{0, -1, 1} {
		if codeAt(c+d) == p {
			return c + d, c + d, true
		}
	}
	return 0, 0, false
}

// ruleA is the reviewer's forced answer: the greatest match in the acceptance
// window.
func ruleA(p string, c int64) (int64, int64, bool) {
	m := matchesIn(p, c-1, c+1)
	if len(m) == 0 {
		return 0, 0, false
	}
	top := m[len(m)-1]
	return top, top, true
}

// ruleB guards on the lowest step within L below the window that produces the
// passcode, while still claiming the greatest match inside the window. Two
// values, so both MatchStep and the claim predicate widen.
func ruleB(L int64) rule {
	return func(p string, c int64) (int64, int64, bool) {
		win := matchesIn(p, c-1, c+1)
		if len(win) == 0 {
			return 0, 0, false
		}
		back := matchesIn(p, c-1-L, c+1)
		return win[len(win)-1], back[0], true
	}
}

// ruleBprime returns that same lowest step and claims it, so one value carries
// both roles and no signature moves.
func ruleBprime(L int64) rule {
	return func(p string, c int64) (int64, int64, bool) {
		if len(matchesIn(p, c-1, c+1)) == 0 {
			return 0, 0, false
		}
		back := matchesIn(p, c-1-L, c+1)
		return back[0], back[0], true
	}
}

// ruleD claims the greatest match within L above the window. Same coverage of
// the contiguous cases, but it moves the guard upward too, which is what makes
// it leak sooner than ruleB on a wide pair.
func ruleD(L int64) rule {
	return func(p string, c int64) (int64, int64, bool) {
		if len(matchesIn(p, c-1, c+1)) == 0 {
			return 0, 0, false
		}
		fwd := matchesIn(p, c-1, c+1+L)
		top := fwd[len(fwd)-1]
		return top, top, true
	}
}

// doubleAccept lists every first-presentation current c1 from which the same
// passcode is accepted a second time later, with the earliest such c2.
func doubleAccept(r rule, p string, lo, hi int64) [][2]int64 {
	var out [][2]int64
	for c1 := lo; c1 <= hi; c1++ {
		claim1, _, ok := r(p, c1)
		if !ok {
			continue
		}
		stored := claim1
		for c2 := c1 + 1; c2 <= hi; c2++ {
			_, guard2, ok := r(p, c2)
			if ok && guard2 > stored {
				out = append(out, [2]int64{c1, c2})
				break
			}
		}
	}
	return out
}

type pair struct{ a, b int64 }

func main() {
	const lo, hi = int64(56000000), int64(56600000)

	var pairs []pair
	window := map[int64]string{}
	for s := lo; s < hi; s++ {
		window[s] = codeAt(s)
		for d := int64(1); d <= 5; d++ {
			if prev, ok := window[s-d]; ok && prev == window[s] {
				pairs = append(pairs, pair{s - d, s})
			}
		}
		delete(window, s-6)
	}
	spans := map[int64]int{}
	for _, p := range pairs {
		spans[p.b-p.a]++
	}
	fmt.Printf("scanned %d steps, %.0f days of one secret\n", hi-lo, float64(hi-lo)*30/86400)
	fmt.Printf("same-passcode pairs within span 5, by span: %v, total %d\n", spans, len(pairs))
	fmt.Printf("so an authentication meets one about %.1e of the time, against %.1e expected\n",
		float64(len(pairs))/float64(hi-lo), 5e-6)

	// Two matching steps are *continuously* acceptable only when their spread is
	// at most 3: step A is live while the current step is A-1, A or A+1, so a
	// pair spread 4 or more apart has a gap in which the passcode is refused.
	fmt.Println("\ncontinuously live pairs are those of span 1 to 3")

	// The reviewer's own example, outside the scanned range.
	pairs = append(pairs, pair{818665, 818667})

	rules := []struct {
		name string
		r    rule
	}{
		{"shipped: first match, deltas 0, -1, +1", shipped},
		{"A: greatest in the window", ruleA},
		{"B: greatest in the window, guard on lookback 3", ruleB(3)},
		{"B': lowest within lookback 3, claimed", ruleBprime(3)},
		{"D: greatest with lookahead 3", ruleD(3)},
	}

	fmt.Println("\n== can one passcode be accepted twice under a high-water claim? ==")
	fmt.Println("A is the lower colliding step; a trace reads first accepted at c1, accepted again at c2")
	for _, rl := range rules {
		fmt.Printf("\n--- %s ---\n", rl.name)
		for _, p := range pairs {
			traces := doubleAccept(rl.r, codeAt(p.a), p.a-2, p.b+2)
			if len(traces) == 0 {
				fmt.Printf("  steps %d/%d span %d: safe from every presentation\n", p.a, p.b, p.b-p.a)
				continue
			}
			var parts []string
			for _, t := range traces {
				parts = append(parts, fmt.Sprintf("A%+d->A%+d", t[0]-p.a, t[1]-p.a))
			}
			fmt.Printf("  steps %d/%d span %d passcode %s: replayable from %d presentations %v\n",
				p.a, p.b, p.b-p.a, codeAt(p.a), len(traces), parts)
		}
	}

	// Whichever rule wins, the 15 rows already in verifier_test.go are unaffected:
	// nothing collides near the instant they pin.
	const pinned = int64(1700000000) / 30
	for _, s := range []string{secret, ""} {
		seen, dup := map[string][]int64{}, 0
		for step := pinned - 8; step <= pinned+8; step++ {
			c, err := hotp.GenerateCodeCustom(s, uint64(step), hotp.ValidateOpts{
				Digits: pquernaotp.DigitsSix, Algorithm: pquernaotp.AlgorithmSHA1,
			})
			if err != nil {
				panic(err)
			}
			seen[c] = append(seen[c], step)
		}
		for _, steps := range seen {
			if len(steps) > 1 {
				dup++
			}
		}
		fmt.Printf("\nsecret %q: %d duplicate codes in steps [%d, %d], the pinned table's neighbourhood\n",
			s, dup, pinned-8, pinned+8)
	}

	fmt.Println("\ninstants that would pin a collision row:")
	for _, p := range []pair{{56245959, 56245960}, {818665, 818667}, {56077475, 56077478}} {
		fmt.Printf("  steps %d/%d span %d code %s: the lower step starts at Unix %d\n",
			p.a, p.b, p.b-p.a, codeAt(p.a), p.a*30)
	}

	// Decision 11 answered B, the rule ruleBprime models. The rows verifier_test.go
	// asserts are transcribed from the sweep below rather than reasoned out: for each
	// located pair, every current step from which the passcode is accepted must report
	// the *same* step, and the two steps either side of that range must refuse.
	fmt.Println("\n== decision 11 answer B: the sweep the test table is transcribed from ==")
	const L = int64(3)
	for _, p := range []pair{{56245959, 56245960}, {818665, 818667}, {56077475, 56077478}} {
		code := codeAt(p.a)
		fmt.Printf("\n  pair %d/%d span %d, passcode %s, lower step starts at Unix %d\n",
			p.a, p.b, p.b-p.a, code, p.a*30)

		// A third colliding step near the pair would make the lowest match move as the
		// window slides, so the sweep is only transcribable if there is not one.
		var others []int64
		for s := p.a - 8; s <= p.b+8; s++ {
			if codeAt(s) == code && s != p.a && s != p.b {
				others = append(others, s)
			}
		}
		fmt.Printf("    other steps producing it within 8 either side: %v\n", others)

		for c := p.a - 2; c <= p.b+2; c++ {
			claim, guard, ok := ruleBprime(L)(code, c)
			if !ok {
				fmt.Printf("    current %d (A%+d): refused\n", c, c-p.a)
				continue
			}
			fmt.Printf("    current %d (A%+d): accepted, reports step %d (A%+d), guard %d\n",
				c, c-p.a, claim, claim-p.a, guard)
		}
	}
}
