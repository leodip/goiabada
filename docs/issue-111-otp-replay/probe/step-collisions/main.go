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
// The final two sections were added for decision 12, stage 1 round 3: three or
// more steps can chain, and a fixed lookback closes pairs without closing chains.
// They measure how often a chain occurs and replay both rules against every chain
// shape, using an explicit match set because no reachable secret exhibits one.
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

// codeAtSecret is codeAt for a secret other than the pinned one, unmemoised so a
// long sweep does not retain every step it visits.
func codeAtSecret(s string, step int64) string {
	c, err := hotp.GenerateCodeCustom(s, uint64(step), hotp.ValidateOpts{
		Digits:    pquernaotp.DigitsSix,
		Algorithm: pquernaotp.AlgorithmSHA1,
	})
	if err != nil {
		panic(err)
	}
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

	chainFrequency()
	chainShapes()

	// Does the closure rule change any row TestMatchStepWithCollidingSteps already
	// asserts? If it did, decision 12 would cost a test rewrite as well as a code
	// change, so this is executed rather than argued.
	fmt.Println("\n== the three located pairs under the closure rule, for comparison ==")
	for _, p := range []pair{{56245959, 56245960}, {818665, 818667}, {56077475, 56077478}} {
		code := codeAt(p.a)
		same := true
		for c := p.a - 2; c <= p.b+2; c++ {
			builtClaim, _, builtOK := ruleBprime(3)(code, c)
			closureClaim, _, closureOK := closureCode(3)(code, c)
			if builtOK != closureOK || builtClaim != closureClaim {
				same = false
				fmt.Printf("  pair %d/%d span %d, current %d: as built (%d, %t), closure (%d, %t)\n",
					p.a, p.b, p.b-p.a, c, builtClaim, builtOK, closureClaim, closureOK)
			}
		}
		if same {
			fmt.Printf("  pair %d/%d span %d: identical at every current step %d to %d, so the\n"+
				"    transcribed rows are unaffected\n", p.a, p.b, p.b-p.a, p.a-2, p.b+2)
		}
	}
}

// closureCode is the closure rule over real HMAC output rather than a match set,
// so it can be compared against ruleBprime on the located pairs.
func closureCode(L int64) rule {
	return func(p string, c int64) (int64, int64, bool) {
		win := matchesIn(p, c-1, c+1)
		if len(win) == 0 {
			return 0, 0, false
		}
		lowest := win[0]
		for {
			back := matchesIn(p, lowest-L, lowest-1)
			if len(back) == 0 {
				return lowest, lowest, true
			}
			lowest = back[0]
		}
	}
}

// == decision 12: three steps can chain, and a fixed lookback does not close it ==
//
// Two steps producing one passcode are continuously acceptable when they are at
// most 3 apart. So are three, when each adjacent gap is at most 3, and then their
// acceptance ranges overlap into one unbroken run with no refused current step in
// it. The lookback of 3 keeps the answer constant across a pair because both steps
// stay inside the searched interval; across a chain the lowest one falls out of
// that interval while the run is still live, and the reported step advances.
//
// chainFrequency measures how often a chain occurs, over more secrets and more
// steps than the pair sweep above, because that number is what decision 12 turns
// on. It counts an "edge" wherever two steps at most 3 apart produce one passcode,
// and a "chain" wherever a step closes a run of three such steps.
func chainFrequency() {
	secrets := []string{
		"JBSWY3DPEHPK3PXP",
		"KRSXG5CTMVRXEZLU",
		"MFRGGZDFMZTWQ2LK",
		"NB2W45DFOIZA4CQK",
	}
	const perSecret = int64(5000000)

	edges, chains, steps := 0, 0, int64(0)
	edgesBySpan := map[int64]int{}
	for _, s := range secrets {
		// chainLen[step] is the length of the longest run of colliding steps
		// ending at step. Only the last 3 are ever consulted.
		recent := map[int64]string{}
		chainLen := map[int64]int{}
		for step := int64(0); step < perSecret; step++ {
			c := codeAtSecret(s, step)
			recent[step] = c
			chainLen[step] = 1
			for d := int64(1); d <= 3; d++ {
				if prev, ok := recent[step-d]; ok && prev == c {
					edges++
					edgesBySpan[d]++
					if chainLen[step-d]+1 > chainLen[step] {
						chainLen[step] = chainLen[step-d] + 1
					}
				}
			}
			if chainLen[step] >= 3 {
				chains++
				fmt.Printf("  CHAIN found: secret %q ending at step %d, code %s\n", s, step, c)
			}
			delete(recent, step-4)
			delete(chainLen, step-4)
			steps++
		}
	}

	fmt.Printf("\n== how often do steps collide, and how often do three of them chain? ==\n")
	fmt.Printf("  swept %d steps over %d secrets, %.0f years of one authenticator\n",
		steps, len(secrets), float64(steps)*30/86400/365)
	fmt.Printf("  colliding pairs at most 3 apart, by span: %v, total %d\n", edgesBySpan, edges)
	fmt.Printf("  measured %.2e per step, against 3.0e-06 expected (3 spans, 1e-6 each)\n",
		float64(edges)/float64(steps))
	fmt.Printf("  chains of three: %d, against %.1e expected (9 shapes, 1e-12 each)\n",
		chains, float64(steps)*9e-12)
	fmt.Printf("  so a presented code sits in a chain about 2.7e-11 of the time, roughly\n")
	fmt.Printf("  3 in 100 billion authentications, five orders of magnitude below the\n")
	fmt.Printf("  8.3e-06 pair rate decision 11 was answered against\n")
}

// setRule is a rule over an explicit set of matching steps rather than over HMAC
// output. No reachable secret produces a chain of three, so the shapes below
// cannot be exhibited with a real secret; the control flow under test is the step
// arithmetic, and swapping the predicate is what makes it reachable at all.
type setRule func(matches map[int64]bool, c int64) (claim int64, guard int64, ok bool)

func lowestIn(matches map[int64]bool, lo, hi int64) (int64, bool) {
	for s := lo; s <= hi; s++ {
		if matches[s] {
			return s, true
		}
	}
	return 0, false
}

// asBuilt is verifier.go as decision 11 answer B was applied: the lowest match in
// the interval [c-1-L, c+1], searched as two scans.
func asBuilt(L int64) setRule {
	return func(matches map[int64]bool, c int64) (int64, int64, bool) {
		inWindow, matched := lowestIn(matches, c-1, c+1)
		if !matched {
			return 0, 0, false
		}
		if earlier, found := lowestIn(matches, c-1-L, c-2); found {
			return earlier, earlier, true
		}
		return inWindow, inWindow, true
	}
}

// closure walks the lookback down transitively instead of applying it once, so the
// answer is the bottom of the whole backward-connected chain rather than the bottom
// of one interval.
func closure(L int64) setRule {
	return func(matches map[int64]bool, c int64) (int64, int64, bool) {
		lowest, matched := lowestIn(matches, c-1, c+1)
		if !matched {
			return 0, 0, false
		}
		for {
			earlier, found := lowestIn(matches, lowest-L, lowest-1)
			if !found {
				return lowest, lowest, true
			}
			lowest = earlier
		}
	}
}

// chainOf builds a chain of n steps spaced gap apart, starting at a.
func chainOf(a, gap int64, n int) map[int64]bool {
	m := map[int64]bool{}
	for i := 0; i < n; i++ {
		m[a+int64(i)*gap] = true
	}
	return m
}

// replaySet is doubleAccept over an explicit match set: every first presentation
// from which the same passcode is accepted a second time later.
func replaySet(r setRule, matches map[int64]bool, a, top int64) []string {
	var traces []string
	for c1 := a - 3; c1 <= top+3; c1++ {
		claim1, _, ok := r(matches, c1)
		if !ok {
			continue
		}
		for c2 := c1 + 1; c2 <= top+3; c2++ {
			if _, guard2, ok := r(matches, c2); ok && guard2 > claim1 {
				traces = append(traces, fmt.Sprintf("A%+d->A%+d", c1-a, c2-a))
				break
			}
		}
	}
	return traces
}

// chainShapes replays both rules against every chain of three whose adjacent gaps
// are at most 3, which is every chain that is continuously acceptable, and against
// the pairs for comparison. A rule is safe for a shape when no first presentation
// leaves a later one acceptable.
func chainShapes() {
	fmt.Printf("\n== every continuously live shape, both rules ==\n")
	fmt.Printf("A is the lowest step; a trace reads first accepted at c1, accepted again at c2\n")
	fmt.Printf("pairs at span 4 and 5 are the inherent case decision 11 accepted: they have a\n")
	fmt.Printf("refused gap, so the authenticator is legitimately redisplaying those digits\n")

	const a = int64(100)
	type shape struct {
		name    string
		matches map[int64]bool
		top     int64
	}
	var shapes []shape
	for d := int64(1); d <= 5; d++ {
		shapes = append(shapes, shape{
			name:    fmt.Sprintf("pair  {A, A+%d}", d),
			matches: map[int64]bool{a: true, a + d: true},
			top:     a + d,
		})
	}
	for d1 := int64(1); d1 <= 3; d1++ {
		for d2 := int64(1); d2 <= 3; d2++ {
			shapes = append(shapes, shape{
				name:    fmt.Sprintf("chain {A, A+%d, A+%d}", d1, d1+d2),
				matches: map[int64]bool{a: true, a + d1: true, a + d1 + d2: true},
				top:     a + d1 + d2,
			})
		}
	}

	rules := []struct {
		name string
		r    setRule
	}{
		{"as built: lowest within lookback 3 below the window", asBuilt(3)},
		{"closure: lookback 3 walked down from the matched step", closure(3)},
	}
	for _, rl := range rules {
		fmt.Printf("\n--- %s ---\n", rl.name)
		for _, sh := range shapes {
			traces := replaySet(rl.r, sh.matches, a, sh.top)
			if len(traces) == 0 {
				fmt.Printf("  %s: safe from every presentation\n", sh.name)
				continue
			}
			fmt.Printf("  %s: replayable from %d presentations %v\n",
				sh.name, len(traces), traces)
		}
	}

	// The cost of walking the lookback down rather than applying it once, counted
	// as scans of 3 steps rather than estimated, at the worst current step for each
	// shape rather than at a convenient one. The failure path is untouched: it
	// computes the window and stops without any lookback at all.
	fmt.Printf("\n  cost of the closure walk, worst accepting current step per shape,\n")
	fmt.Printf("  in lookback scans of 3 steps each (as built always takes exactly 1):\n")
	for _, tc := range []struct {
		name    string
		matches map[int64]bool
		top     int64
	}{
		{"no collision, what every real authentication takes", map[int64]bool{100: true}, 100},
		{"a colliding pair {A, A+3}", map[int64]bool{100: true, 103: true}, 103},
		{"a chain of three {A, A+3, A+6}", map[int64]bool{100: true, 103: true, 106: true}, 106},
		{"a chain of ten, three apart, unreachable", chainOf(100, 3, 10), 127},
	} {
		worst := 0
		for c := a - 1; c <= tc.top+1; c++ {
			lowest, matched := lowestIn(tc.matches, c-1, c+1)
			if !matched {
				continue
			}
			scans := 0
			for {
				scans++
				earlier, found := lowestIn(tc.matches, lowest-3, lowest-1)
				if !found {
					break
				}
				lowest = earlier
			}
			if scans > worst {
				worst = scans
			}
		}
		fmt.Printf("    %-52s %d scan(s)\n", tc.name, worst)
	}
}
