# Issue 111: closing

## 8. Deferred decisions

None yet.

## 9. Follow-ups

1. **Narrow the TOTP skew window so future-period codes are not accepted.**
   `enhancement`, `security`, `go`. Found during grounding. Status: **Filed** as
   [#142](https://github.com/leodip/goiabada/issues/142) on 2026-08-05.

   Raised as recommendation 3 of #111 and deliberately left out of that change (decision 6): it is
   independent of replay, and it changes behaviour for users whose device clock runs fast, which should
   not ride along inside a security fix. Drafted here so closing #111 does not lose it.

   Verified: `src/core/otp/generator.go` passes no `Period`, `Digits` or `Algorithm` to
   `totp.Generate`, so every parameter is a library default, and the default skew of 1 accepts the
   previous, current and next period. Confirmed by reading `totp.Validate` in `pquerna/otp v1.5.0`,
   which builds its candidate set as `counter`, then `counter+i` and `counter-i` for each skew step.

   Searched `gh issue list --state open --search "skew"` and `--state all --search "totp skew window"`:
   only #111 itself.

   **Body:** Goiabada accepts a TOTP code from the previous, current and next 30 second period, so the
   acceptance window is roughly 90 seconds. The future period is there for users whose device clock
   runs slow. Accepting only the previous and current period would halve the window at some cost to
   users whose clock runs fast, who would start seeing codes rejected.

   After #111 each code can only be used once, so the remaining exposure is narrower than it was: a
   code obtained by an attacker is useful only until the legitimate user spends it or it expires.
   Decide whether the window should shrink, and whether the skew should become configurable rather than
   fixed, before changing it. If it changes, `otp.MatchStep` in `src/core/otp/verifier.go` is the single
   place that defines the window.

2. **A re-enrolment landing mid-request can still let a consumed code assert `otp`.**
   `security`, `go`. Found while applying decision 10. Status: **Drafted**, not filed.

   Decision 10 closed the disable case by binding the claim to `otp_enabled`, and its option A said
   plainly that a disable immediately followed by a re-enrolment is not closed, because `otp_enabled` is
   true again by the time the stale claim lands. Recorded here so the residual is not lost with #111.

   Narrower than option A's text says, worked out while applying it. The re-enrolment claims a step of
   its own, so the stale request survives only if the re-enrolment's step is strictly below the replayed
   one: the replayed code must come from the +1 window and the re-enrolment from the current window or
   earlier. It also needs the disable, the re-enrolment and the stale request to overlap inside one
   30 second period, and the attacker to already hold both the level 1 credential and a code from the
   removed authenticator.

   Adjacent to #140, which is the same class of defect (a token asserting `amr: ["pwd","otp"]` for
   authentication that no longer holds) by a different mechanism, so whoever picks one up should read
   the other. Searched `gh issue list --state open --search "otp"`, `--search "otp enrolment
   generation"` and `--state all --search "otp replay in-flight"` on 2026-08-05: #140 is the only
   neighbour and it is not this.

   **Body:** After #111, `TryConsumeUserOTPStep` refuses a verification claim unless `otp_enabled` is
   still true, so removing an authenticator invalidates a claim from a request that loaded it. A
   re-enrolment restores `otp_enabled`, so a verification request holding the *old* secret can still
   claim a code it already spent, provided the new enrolment claimed a lower time step. The resulting
   token asserts `otp` for an authenticator that no longer exists, without the `AuditEnabledOTP` trail
   that enrolling would leave. No access is gained that the disable did not already grant (see #111
   decision 10), so this is a false factor assertion rather than an authentication bypass.

   Closing it properly needs the claim bound to the authenticator rather than to the enrolment flag: an
   enrolment generation column on `users`, incremented on every enable and disable, carried on the
   request and compared in the claim predicate. That is a migration plus a second column, which #111
   deliberately did not take on. Decide whether the window is worth that before building it.
