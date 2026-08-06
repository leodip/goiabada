# Stage 1: the step matcher

## As built

Two new files in `src/core/otp/`, nothing else in the tree touched. Nothing calls `MatchStep` yet, by
design: stage 3 and stage 4 are the callers, and stage 2 owns the storage they claim against.

`verifier.go` holds `const StepSeconds = 30` and
`MatchStep(passcode string, secret string, now time.Time) (int64, bool)`, exactly the shape §4
sketches: the decision 9 empty-secret guard first, then the deltas `0, -1, 1` over
`hotp.ValidateCustom` with `Digits: DigitsSix` and `Algorithm: AlgorithmSHA1`, returning the matched
step. §4's doc comment is carried verbatim. The root package is imported aliased as `pquernaotp` for
the two enum values, per the step, so `otp.DigitsSix` inside `package otp` does not read as a
self-reference.

`verifier_test.go` holds seam 1's table, `TestMatchStep`, 15 rows at the pinned instant
`time.Unix(1700000000, 0).UTC()`, plus the `codeAtStep` helper and the two pinned constants. Codes
come from `totp.GenerateCode` at `step*StepSeconds+15`, mid-step, so neither the instant under test
nor the instant a code is derived at sits on a period boundary. Every accepted row asserts the
returned step, not just the boolean.

**Two constants are worth naming**, because a later reader will want to change them. `pinnedUnix` is
20 seconds into step `56666666`, which is what keeps deltas -2 through +2 inside distinct steps;
`validSecret` is `JBSWY3DPEHPK3PXP`, 16 characters and so already a multiple of 8, which matters
because the library pads a secret to a multiple of 8 with `=` before decoding it and a secret that
needed padding would make the interior-space row fail for a second reason.

## Tiers

`where.sh test --type core`, foreground, whole core module. Green:

```
ok  github.com/leodip/goiabada/core/otp  0.023s
All tests completed successfully.
```

No `FAIL` anywhere in `/tmp/goiabada-tests-20260805-235113-1172177`. `go vet ./otp/...` clean.
`check-anchors.sh`: 24 of 24 rows resolve. Stage 1 added files rather than moving cited code, so
section 0 needed no re-sweep, and the green result is the confirmation of that rather than an
independent claim.

## The table earns its rows: three mutations, run and reverted

A 15 row table that passes proves nothing about what it would catch, and two of these rows exist
specifically because they look wrong. So each load-bearing property was broken on purpose and the
failure set recorded. The tree is back to the committed state; `git status` was checked after each.

1. **Delete the `if secret == ""` guard.** Exactly one row fails, `Empty secret is refused, even with
   the code the library derives from it`. This is the row the plan flagged as the one that could
   silently pass with the guard gone, and it does not.
2. **Return `current` instead of the matched `step`.** Exactly two rows fail, the previous-step and
   next-step rows. Nothing else moves, which is the point of asserting the step rather than the
   boolean: the delta-0 row cannot distinguish the two.
3. **Widen the deltas to `{0, -1, 1, 2}`.** Exactly one row fails, `Code from two steps ahead is
   refused`. The window boundary is pinned in the direction that matters, since widening the window is
   the change a later reader would make casually.

**Independent cross-check of the pinned instant.** The empty secret derives `501315` at
`time.Unix(1700000000, 0)`, and the same `501315` at the mid-step timestamp the helper actually uses.
The plan review's own probe, run in the container from a different program, reported `501315` for that
instant. Two independent derivations agreeing means the pinned constants are what both documents think
they are.

## Deviations from the plan, all additive

None changes behaviour, and none needed a decision.

1. **`StepSeconds` gained a one-line doc comment** §4 did not sketch. It is exported, and the reason it
   is restated here rather than taken from the library is that the step is what identifies a consumed
   code.
2. **The error-collapse rationale moved into the loop as a comment.** §4 states it in prose under the
   code block. At the call site is where a later reader meets `return 0, false` on an error and wonders
   whether it is an oversight, which the plan explicitly says it is not.
3. **`now.Unix() / StepSeconds`, §4's spelling, rather than the library's
   `math.Floor(float64(t.Unix()) / 30)`.** Checked rather than assumed equal: Go integer division
   truncates toward zero, and truncation equals floor for non-negative operands, so the two agree for
   every Unix time from the epoch onward and differ only before 1970. §4's spelling kept, since it is
   what was agreed and it is the clearer of the two.
4. **The empty-secret row derives its passcode through `codeAtStep(t, "", pinnedStep)`** rather than
   literally `totp.GenerateCode("", pinned)`. Same step, same code, verified above as `501315` both
   ways. Keeping one derivation path through the table is worth more than matching the plan's prose
   letter for letter.
5. **The 15 rows are a table-driven loop over `t.Run`** rather than 15 hand-written `t.Run` blocks.
   `generator_test.go`'s convention is `t.Run` subtests, which this keeps, and the plan presents seam 1
   as a table, which a slice of structs reads as.

## Not done, and one blocking decision

Nothing in stage 1 was skipped. The implementation above is complete against the plan as written, and
the review then found that the plan as written is wrong about one thing, which is decision 11. No
follow-up discovered, so `closing.md` is unchanged.

## Review

**Round 1** at this gate was the plan review, traced in `log/plan.md`. It produced decision 10.

**Round 2**, code review, `gpt-5.6-sol` at effort `xhigh`, Codex session resumed, per
`.review/reviewer.env`. Request `111-20260805T235329Z`, one finding, `blocking`, `needs_human: true`
with a populated `forced_answer`. All three axes `reviewed`. It ran the core tier, `go vet ./otp/...`,
`check-anchors.sh`, `gofmt -d` on both files, and its own container probe. It did not re-run the three
mutations recorded above and said so, and it declared the data, integration and module tiers not run
because stage 1 has no interface, query, schema, caller or endpoint. That is the correct scope for
this stage, so the review is clean rather than partial in the sense of `reviewer.md` section 4.

Everything the round found sound is listed in its response and is not repeated here. What it found is:

### Finding 1, returning the first matching step can let one passcode be consumed twice

**Disposition: confirmed, and its `forced_answer` refuted. Escalated as decision 11.**

The mechanism is real and reproduces. A six-digit passcode does not name a time step: steps 3710568
and 3710569 both yield `874294` for `validSecret`, and steps 818665 and 818667 both yield `475244`.
The matcher returns the lower of two matching steps, decision 2's marker records it, and the higher
one is still claimable when the window slides, so the same passcode is accepted twice.

**The `forced_answer` was "return the greatest matching step". Applying it verbatim does not restore
the invariant**, which is why this did not become an in-stage repair under `decisions.md` section 1.
`probe/step-collisions`, written for this and kept, sweeps 600,000 steps for same-passcode pairs and
replays each against candidate rules under decision 2's high-water claim:

- Greatest-in-window leaves the spread 1 pair replayable when the code is presented a step early,
  which is exactly what the `+1` window exists to allow: `874294` is accepted at current step 3710567
  and again at 3710568.
- It does not touch spread 2 or spread 3 pairs at all, which are replayable from an ordinary
  presentation because the colliding step is not yet in the window when the claim is made. `475244` is
  accepted at 818665 and again at 818666.

Three rules do close every continuously live case, and they differ in what they cost and in how they
fail. The comparison, the frequencies, the options and the recommendation are decision 11; the numbers
behind them are reproducible from `probe/step-collisions`, which prints its own working and which was
run from `src/core` exactly as its header documents.

**Why this blocked rather than resolving in-stage.** `decisions.md` section 1 never auto-resolves
authentication or cryptography, and the one exception, a finding that mechanically restores an
invariant the agreement already decided, needs the `forced_answer` to actually restore it. This one
does not, so a choice remains: three viable rules with different residuals, different failure
directions and, for one of them, different signatures in stage 2. `reviewer.md` section 5 puts a
security finding in the same place.

**What the review did not reach, and does not need to.** The frequency of the collision, the
continuous-liveness boundary, and the behaviour of any rule other than its own suggestion. The probe
covers all three and is the evidence decision 11 rests on.

## Bookkeeping, fixed in passing rather than spending a round

The review flagged two overbroad explanations, neither affecting behaviour. Both are corrected here
rather than in the files, since the files are the subject of an open decision:

1. **Deviation 3 above** says integer division agrees with the library's `math.Floor(float64(...))`
   for every non-negative Unix time. It does so until `float64` loses integer precision, first at Unix
   9007199254741019. True for every production-era timestamp, which is the claim that matters.
2. **`verifier_test.go`'s comment** calls the 16-character fixture "the shape `GenerateOTPSecret`
   produces". The default 20-byte TOTP secret encodes to 32 base32 characters. The property the
   fixture actually needs is being a multiple of 8, so it needs no padding, and that is what the
   comment should say when the file is next touched.

## Decision 11 answered: B, applied 2026-08-06

The user replied "B" on PR #143. Decision 11 is `Decided` and carries the reasoning; what follows is
what the answer did to the code.

**`MatchStep`.** Acceptance is untouched and still decided by the window alone. The reported step is
now the lowest within `lookbackSteps` below the window that produces the same passcode, which is one
constant answer at every current step from which a continuously acceptable passcode is accepted, and
that constancy is what makes the first claim of it refuse the rest. Two unexported constants,
`skewSteps = 1` and `lookbackSteps = 2*skewSteps + 1`, the second derived from the first per the
answer, so #142 narrowing the window narrows the lookback with it. A `lowestMatch` helper carries
both scans, which is what keeps the window scan reading as exactly the acceptance rule it was before.

Cost, counted rather than estimated: the failure path computes the window and stops, 3 HMACs as
before. A successful match adds at most 3 more, the steps `current-4` through `current-2`. The
escalation's "up to four" was a bound, not a count.

**The lookback cannot error once the window has matched**, since the library's two errors are an
unparseable secret and a wrong-length passcode and neither depends on the step. Collapsed to
`(0, false)` anyway, so the file has one error rule and the unreachable branch fails closed.

**`TestMatchStepWithCollidingSteps`**, three pairs at spreads 1, 2 and 3, sweeping 21 current steps in
total, each asserting the reported step where the passcode is accepted and `(0, false)` either side.
The pairs and every expectation are transcribed from `probe/step-collisions`, extended for this with a
sweep section and its output committed as `probe/step-collisions/output.txt`. The probe also reports
no third step within eight either side producing those passcodes, which is what makes the answer
constant rather than merely lower. Spreads are written as literals, not as `2*skewSteps + 1`, because
they are claims about a skew of 1: #142 should fail here rather than quietly adjust.

**Three mutations, run in the container and reverted**, since a new table that passes proves nothing
about what it catches. `git diff` confirmed the file back to its pre-mutation bytes each time.

1. **Drop the lookback, report the step matched inside the window.** All three collision subtests
   fail. The 15-row table passes, which is the point: it cannot see this defect, and every rule
   decision 11 rejected passes all 15 of its rows.
2. **`lookbackSteps = 2*skewSteps`, one too narrow.** Only the spread 3 subtest fails, so the pair at
   the continuous-liveness boundary is what pins the derivation rather than decoration around it.
3. **`skewSteps = 2`, a wider acceptance window.** The two window-boundary rows fail, as they did
   under the old shape, and all three collision subtests fail with them.

**Tiers.** `where.sh test --type core`, foreground, whole core module. Green:
`ok github.com/leodip/goiabada/core/otp`, `All tests completed successfully`, no `FAIL` in the run.
`gofmt -l ./otp/` empty and `go vet ./otp/...` clean in the container. `check-anchors.sh`: 24 of 24
rows resolve.

**Bookkeeping item 2 above is now done.** `validSecret`'s comment no longer claims to be the shape
`GenerateOTPSecret` produces; it says the length is a multiple of 8 and why that matters to the
interior-space row. Item 1 stands as corrected in this entry. `stepMidpoint` was extracted while
touching the file, so the mid-step instant has one definition shared by the code generator and the
collision sweep.

## Where this stops

Stage 1 is `In progress`. Both files are written and green and stay **uncommitted** until the gate
closes, per §4.5. Committed on this branch: the agreement carrying decision 11 as `Decided`, the
amended plan steps, this entry, and the probe with its output. Round 3 is requested at this gate,
scoped to the matcher's new rule and the cases that pin it.
