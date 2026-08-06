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

### Round 3, 2026-08-06

Code review, `gpt-5.6-sol` at effort `xhigh`, Codex session resumed, per `.review/reviewer.env`.
Request `111-20260806T004343Z`. All three axes `reviewed`. One finding, `security`, `blocking`,
confidence medium, `needs_human: true` with an **empty** `forced_answer`. It ran the core tier, its
own control-flow model, `go vet ./otp/...` and `gofmt -d` on both files and the model. It declared
data, integration and cross-module tiers not run because stage 1 has no interface, query, schema,
caller or endpoint, and it did not re-run round 2's three mutations. That is the correct scope for
this stage, so the review is clean rather than partial in the sense of `reviewer.md` §4.

Everything it found sound is in its response and is not repeated here.

### Finding 1, a third colliding step advances the reported step with no refusal gap

**Disposition: confirmed, widened by execution, and escalated as decision 12. Status: **Open**.**

Decision 11's answer reports the lowest match in `current-4 .. current+1`. The review's claim is that
this is constant only for an isolated pair, not for a chain. Verified by running its model
(`.review/scratch/issue111_decision11_model.go`, an exact copy of `MatchStep`'s two scans with the
HMAC predicate replaced by the set `{100, 103, 106}`): accepted continuously from current 99 through
107, reporting 100 through current 104 and **103 from current 105**. A marker holding 100 admits 103,
so the passcode is consumed twice with no refused step between the two presentations. The production
code forces that result: at current 105 its whole search interval is 101 through 106, and 100 has
fallen out of it.

**Not refuted, and it is worse than reported.** `probe/step-collisions` gained two sections for this
and its output is committed. Replaying both rules against every continuously live shape:

- **6 of the 9 chains of three are replayable as built**, every one whose total span exceeds the
  lookback of 3. `{A, A+1, A+2}`, `{A, A+1, A+3}` and `{A, A+2, A+3}` are safe.
- The span 4 pair leaks from 5 presentations rather than 3, which the earlier single-rule sweep did
  not surface.
- The transitive walk closes all 9 chain shapes and all 3 continuously live pairs.

**How often, since that is what the decision turns on.** 20,000,000 steps over 4 secrets, 19 years of
one authenticator: 55 colliding pairs at most 3 apart, 2.75e-06 per step against 3.0e-06 expected,
which is what validates the 1e-06 per-pair model the rest of this rests on. Chains of three: 0,
against 1.8e-04 expected. A presented code sits in a chain about 2.7e-11 of the time, roughly 3 in
100 billion authentications, five orders of magnitude below the 8.3e-06 pair rate decision 11 was
answered against.

**Two costs of the walk, both executed rather than estimated.** It costs exactly what the current code
costs whenever nothing collides, one lookback scan of 3 steps, because the walk stops the moment a
scan finds nothing; 2 scans on a pair, 3 on a chain of three, 10 on an unreachable chain of ten. And
the three located pairs report identically under both rules at every current step, so
`TestMatchStepWithCollidingSteps` and the 15-row table are unaffected whichever way this goes.

**Why this blocked rather than resolving in-stage.** `decisions.md` §1 never auto-resolves
authentication, and its one exception requires a populated `forced_answer`; this one is empty and the
reviewer named three resolutions, one of which is accepting the residual. `reviewer.md` §5 puts a
security finding in the same place. The run declining to judge 3 in 100 billion on the user's behalf
is the same call decision 11 recorded at 3 in a million.

**The escalation budget is now 4**, which `decisions.md` §5 says is evidence the agreement was sealed
too early. Recording the judgement, since it belongs to the next `/leo-spec` rather than to this run:
decisions 10, 11 and 12 all came out of stage 1 and all three are about the same thing, the exact
contract of a step-based replay marker. §4 sketched `MatchStep` as an eight-line function and §5 sealed
one seam over it, and neither asked what a step means when a passcode does not name one. One grounding
question, whether a passcode identifies a step, would have caught 11 and 12 together at interview time.
Decision 10 is unrelated and was a genuine plan-review find.

**No follow-up discovered**, so `closing.md` is unchanged.

### Where this stops, after round 3

Stage 1 is `In progress` and **blocked on decision 12**. Stage 1's two files are unchanged since round
2's fix and stay **uncommitted**, since committing them would be committing work that rests on an open
decision. Committed on this branch by this session: decision 12 in the agreement, the header, this
entry, and the probe's two new sections with the regenerated output. The pre-existing sections of
`probe/step-collisions/output.txt` are byte-identical, checked with `diff`, so the rows
`TestMatchStepWithCollidingSteps` transcribes still have their source.

`.review/request.md` set to `status: ingested`. No further review request is written at this gate
until the answer arrives.

## Decision 12 answered: A, applied 2026-08-06

The user answered on PR #143: "A. Walk the lookback down transitively." Recorded in the agreement as
`Decided`, with the three amendments the answer attached folded in. Stage 1's two files are rewritten
and green, still uncommitted until the gate closes.

**What moved.** `MatchStep` keeps `(int64, bool)` and accepts exactly what it accepted before, so
stages 2 to 4 are untouched again. The reported step is now the bottom of the whole backward-connected
chain rather than the bottom of one fixed interval: from the matched step, scan the `lookbackSteps`
below it, and repeat from whatever that finds until a scan finds nothing. Each scan takes the lowest
step it finds, which is enough to reach the bottom in one pass down, and the doc comment says why: a
higher step in the same scan is within `lookbackSteps` of the step being searched below, so anything
that step could reach is itself within `lookbackSteps` of the lowest one and the next scan sees it.

Cost, counted rather than estimated: unchanged in the case every real authentication takes, one scan
of 3 steps, because the walk stops the moment a scan finds nothing. The probe's cost table puts it at
2 scans on a pair and 3 on a chain of three.

**Amendment 1, the seam, recorded in §5 and not inside a plan step.** The walk cannot be exercised
through `MatchStep`: no secret anyone can enrol exhibits a chain, so a test driving real HMAC output
passes with the walk deleted. The walk therefore sits behind an unexported step predicate,
`producesPasscode`, reached through `matchStepWith(produces, current)`, and is pinned with a synthetic
match set. §5's seam 1 now carries that as a named amendment: what the boundary is, why it exists, the
three things it owns, what it does not move, and why two of its rows assert a replay rather than
safety.

**Amendment 2, the cap, with its derivation where it is written.** `maxLookbackScans = 5`, and the
constant's comment carries four things: what it bounds (`maxLookbackScans * lookbackSteps` HMAC
computations), that reaching it refuses rather than answers and why that is the safe direction, that
the walk terminates without it so the cap bounds work rather than correctness, and where 5 comes from.

That last part is read off measured output rather than rounded. Every scan that finds something needs
one more step producing the same six digits within `lookbackSteps` below the last, and the sweep
measured that link rate instead of assuming it: 2.75e-06 per step against 3.0e-06 modelled. Links are
independent, so a chain of n steps is `(3e-06)^(n-1)` per presentation. The criterion is stated: the
cap must first refuse at a chain whose expected count stays under one in a billion across 1e18
presentations, a deliberately absurd bound on every authentication every deployment will ever perform.
`capLadder` in the probe prints the ladder and names the first value that clears it, independently of
the constant in the code, and it prints 5. The sweep's own longest run was 2 steps, which the probe
now reports rather than leaving implicit.

**Amendment 3, the class.** The answer settles colliding steps as a class, so a fourth shape gets the
same rule and a line here rather than a fifth escalation. Nothing in this application needed that.

**The accepted residual, restated because the answer restates it.** Pairs spread 4 or more apart stay
replayable at roughly a millionth per presentation, about a hundred thousand times more likely than
the chain case closed here, and closing them needs the consumed-codes table decision 1 rejected. The
walk re-accepts the span 4 pair at `A+3` rather than `A+5`, 60 seconds sooner, from 3 presentations
rather than 5. Two test rows assert that this class is still replayable, with a note saying that
asserting safety there would assert something the design does not provide.

## Tiers, after decision 12

`where.sh test --type core`, foreground, whole core module, tree `ba3b1f75278d`. Green:
`All tests completed successfully`, no `FAIL` anywhere in the run. `go test ./otp/ -v`:
`ok github.com/leodip/goiabada/core/otp 0.023s`, 54 `PASS` lines over 7 test functions, 0 `FAIL`.
`go vet ./otp/...` clean and `gofmt -l ./otp/` empty, both in the container. `check-anchors.sh`: 24 of
24 rows resolve. Data, integration and cross-module tiers are still not applicable: stage 1 has no
interface, query, schema, caller or endpoint.

The probe was re-run from `src/core` and `output.txt` regenerated. Its first 150 lines are
byte-identical, checked with `diff`, so every row `TestMatchStepWithCollidingSteps` transcribes still
has its source; the ladder is appended after them.

## The new cases earn their rows: three more mutations, run and reverted

Each was applied to `verifier.go`, the package run, and the file restored from a copy taken first,
with `diff` confirming it back to its pre-mutation bytes.

1. **Apply the lookback once instead of walking it**, which is decision 11's rule exactly. **6 of the
   9 chain subtests fail** and the other 3 pass, `{A, A+1, A+2}`, `{A, A+1, A+3}` and `{A, A+2, A+3}`,
   which is the same 6 and the same 3 the probe reported from a separate model. That agreement between
   the production code under test and the probe's model is the strongest evidence in this round. The
   cap's two subtests fail with them, since without the walk a chain never reaches its bottom. All 15
   rows of the pinned table pass, and so do the three located pairs: neither can see this defect.
2. **Reach the cap and answer with the lowest step found so far** rather than refusing. Only
   "One step further and the passcode is refused instead" fails, which is precisely the direction that
   subtest exists to pin.
3. **On an error below the window, answer with the match** rather than refusing. Only "An error below
   the window is refused, not answered with the match" fails. That branch is unreachable through
   `MatchStep`, so before this round nothing could have caught it.

## Where this stops, after decision 12

Stage 1 is `In progress` and no longer blocked: all twelve decisions are `Decided`. Both files are
written and green and stay **uncommitted** until the gate closes, per §4.5. Committed on this branch by
this session: decision 12 as `Decided`, §5's named amendment, the header, the amended plan steps, this
entry, and the probe's cap ladder with the regenerated output.

Round 4 is requested at this gate, scoped to the walk, the cap and the boundary the amendment opened.
The three escalations from this stage are all settled and the judgement about the agreement having been
sealed too early stands as recorded after round 3: it belongs to the next `/leo-spec`, not to this run.

### Round 4, 2026-08-06: clean

Code review, `gpt-5.6-sol` at effort `xhigh`, Codex session resumed, per `.review/reviewer.env`.
Request `111-20260806T112000Z`. All three axes `reviewed`. **Verdict `clean`, zero findings**, so
nothing was refuted, resolved or deferred and no code moved in response to it.

It ran: `tree-hash.sh`; a reconstruction of the recorded hash against the parent agreement;
`where.sh test --type core --run 'TestMatchStepWith(ChainsOfCollidingSteps|AChainLongerThanTheWalk|AFailingStepPredicate)$'`;
its own exhaustive model, `.review/scratch/issue111_decision12_exhaustive.go`, in the container; and
`gofmt -d` on both files and the model.

**What the round actually contributed**, since a clean verdict is otherwise unfalsifiable. The run
pinned 14 hand-enumerated shapes. The review pinned the class: it enumerated **every one of the 32,767
nonempty match sets over a 15-step domain**, which includes mixed-gap chains of four and five and
disconnected components the run never wrote down, and checked each against an independent
connected-component oracle. The walk had **0 failures**; substituting round 3's fixed lookback produced
**50,816**. That is a stronger statement than anything in this entry, arrived at from a different
direction, and it is what makes decision 12's amendment 3, settling colliding steps as a class rather
than shape by shape, hold in the code rather than only in the agreement.

It also redid the cap arithmetic independently rather than reading it off the comment: five successful
links need six local occurrences at `(3e-6)^5 = 2.4e-28`, about `7.3e-28` allowing the three skew
positions, so `7.3e-10` expected over the deliberately extreme `1e18` presentations, under the stated
`1e-9` criterion. It reached the same conclusion the probe's ladder prints. It further observed that
`current` is `Unix()/30` in production, so subtracting at most 15 cannot approach `int64` underflow and
the inclusive scan cannot wrap, and that the two library errors are counter-independent so both
internal error positions still return no match.

**Coverage, and what it declared not checked.** Conformance: signature and acceptance window unchanged,
the walk begins only after a window match, and the only new refusal of an otherwise matching passcode
is the cap, which is the behaviour decision 12 chose. Quality: cap accounting, termination, cost on the
ordinary paths, and the synthetic predicate staying inside the named seam 1 amendment with the 15 rows
and the three real HMAC pairs still reaching `MatchStep`. Security: comparison stays inside
`hotp.ValidateCustom`, nothing logs or exposes the passcode or secret, and predicate errors and cap
exhaustion both fail closed. Not checked: the 20,000,000-step sweep was not re-run, round 2 and round
3's actual-source mutations were not repeated (the exhaustive scratch mutation was run instead, after
confirming the reviewed source byte-identical to the pre-mutation backup), and the data, integration
and cross-module tiers are not applicable because stage 1 has no interface, query, schema, caller or
endpoint. That is the correct scope for this stage, so the review is clean rather than partial in the
sense of `reviewer.md` §4.

### The one bookkeeping item, and why it is not a follow-up here

The review reported that `tree-hash.sh` prints `d60a482eeab0` and not the `ba3b1f75278d` the tier claim
above records. Confirmed, and the cause is in the helper rather than in this tree: it excludes the
agreement directory from `git add` but then pins it with `git reset -q HEAD -- "$SPEC"`, so the hash
carries **HEAD's** copy of the agreement rather than a constant, and committing the agreement moves the
hash even though the script's header says that directory is excluded.

The claim it was protecting still holds, checked independently at this gate rather than taken from the
review: `git diff --name-only HEAD~1 HEAD` returns only paths under `docs/issue-111-otp-replay/`, so
the source the reviewer read is byte-identical to the source the recorded tier ran against. The
reviewer's own reconstruction reached `ba3b1f75278d` exactly.

**Not drafted into `closing.md`.** `tree-hash.sh` lives in `~/.claude/skills/leo-spec/scripts/`, outside
this repository, so it is neither a goiabada defect nor something `gh issue create` could file against
this tracker. Reported to the user in the run's account instead. `closing.md` is unchanged by this
round: still two follow-ups, neither from stage 1.

## Tiers at the gate, re-run after the review

Re-run here rather than cited from the entry above, because that claim's hash no longer reproduces for
the reason just given. Tree `d60a482eeab0` at HEAD `e6c626a`, with the two files still uncommitted at
the time of the run.

- `where.sh test --type core`, foreground, whole core module. Exit 0,
  `All tests completed successfully`, 29 packages `ok`, no `FAIL` anywhere. 3 seconds warm; the first
  run of this tree at 11:28 was cold and slower.
- `go test ./otp/ -count=1 -v` in the container, cache defeated so the green is this tree's and not a
  replay: `ok github.com/leodip/goiabada/core/otp 0.027s`, **54 `PASS` lines over 7 test functions, 0
  `FAIL`**.
- `check-anchors.sh`: **24 of 24** rows resolve. Stage 1 added files rather than moving cited code, so
  section 0 needed no re-sweep.
- Data, integration and cross-module tiers: not applicable, for the reason repeated throughout this
  entry. Stage 2 is the first stage that has a schema to run them against.

## Where this stage closed

Stage 1 is **`Done`**. Both files are committed on `issue-111-otp-replay`: `src/core/otp/verifier.go`
and `src/core/otp/verifier_test.go`, and nothing else in the tree. Nothing calls `MatchStep` yet, which
is the plan's shape and not an omission: stage 2 owns the storage the callers claim against and stages
3 and 4 are the callers.

Four rounds at this gate, one of them the plan review, and three escalations, decisions 10, 11 and 12,
all `Decided` and all applied. Nine mutations were run against the two files across the stage and
reverted, and the review's exhaustive model is the tenth check of the same property from outside. The
judgement recorded after round 3, that decisions 11 and 12 both came from one grounding question the
interview never asked, stands as written and belongs to the next `/leo-spec` rather than to this run.
