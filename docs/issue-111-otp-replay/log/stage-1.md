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

## Where this stops

Stage 1 is `In progress` and stays there. `verifier.go` and `verifier_test.go` are written, their
tiers are green, and they are **not committed**, because the step `MatchStep` returns is precisely
what decision 11 asks about and `decisions.md` forbids committing work resting on an open decision.
Committed on this branch: the agreement carrying decision 11, this entry, and the probe. Decision 11
is posted on PR #143. The next session applies the answer, amends plan steps 1 and 2 and seam 1's
table to match, re-runs the core tier, and opens round 3 at this gate.
