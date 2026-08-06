# Issue 111: closing pass, 2026-08-06

**The full suite, every tier**, against tree `a260b415eee3` (`tree-hash.sh`), which is the tree at
commits `f14696f` (code) and `dcc0564` (agreement).

One `where.sh test --type all`, 7m14s, `All tests completed successfully`, **9122 PASS, 0 FAIL,
4 SKIP**.

| Tier | Engines | Result |
|---|---|---|
| Unit | n/a, all three modules | 2770 PASS, 0 FAIL, 0 SKIP |
| Data | sqlite, mysql, postgres, mssql | 1564 PASS, 0 FAIL, 4 SKIP (12.0s / 2.1s / 6.1s / 2.5s) |
| Integration | mysql, postgres, mssql, sqlite | 4788 PASS, 0 FAIL, 0 SKIP (77.3s / 112.7s / 155.3s / 44.4s) |

The 4 data skips are the pre-existing engine-capability skips, unchanged all run: three on sqlite
(`TestTransaction_UncommittedWriteIsNotVisibleOutside`,
`TestTryClaimCleanupRun_ConcurrentCallersProduceOneWinner`,
`TestTryConsumeUserOTPStep_ConcurrentCallersProduceOneWinner`, all single-connection contention) and
one on mssql (`TestTransaction_UncommittedWriteIsNotVisibleOutside`, `READ COMMITTED`). The unit
packages report `(cached)`: they ran on this exact tree earlier in the same session, 2770 PASS 0 FAIL,
and the three counts sum to the 9122 above.

`check-anchors.sh`: 25 of 25. `go vet ./...` clean in all three modules. `gofmt -l` clean in every
package this issue touched; the two `src/core/i18n` files it lists are byte-identical to `main` and
unrelated to #111, recorded in `log/stage-4.md`.

## What the run cost

Four stages, five blocking escalations, all five answered by the user on PR #143 and applied.
`decisions.md` §5 calls four evidence the agreement was sealed too early, and the note for the next
`/leo-spec` is written into decision 13 itself: two of the five (11 and 12, colliding steps) and two
more (10 and 13, unbound authenticator identity) were each one family asked twice, and each family was
answerable at its first escalation.

Review rounds: stage 1 four, stage 2 one, stage 3 two, stage 4 two. Every gate's reviewer was
`gpt-5.6-sol` at effort `xhigh`. The reviewer skipped re-running the recorded tiers at every gate on a
matching tree hash and spent the budget on programs of its own instead; it never found a failure the
run had missed, and it found a real defect at four of the five gates that way.

## Deferred decisions

**None.** Section 8 of `closing.md` is empty, and that is a result rather than an omission: every
question the run met was either resolved with a demonstration recorded in its stage's log entry, or
blocked and escalated. Nothing was carried on a stated assumption, so there is nothing here for the
user to settle after the fact.

## Follow-ups

Three, in `closing.md` §9. Follow-up 1 is already filed as
[#142](https://github.com/leodip/goiabada/issues/142). Follow-ups 2 and 3 are drafted and posted on
the PR for the user to file; their duplicate searches were re-run at the closing pass, 2026-08-06,
and returned nothing.
