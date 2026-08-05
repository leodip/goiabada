# Issue 111: closing

## 8. Deferred decisions

None yet.

## 9. Follow-ups

1. **Narrow the TOTP skew window so future-period codes are not accepted.**
   `enhancement`, `security`, `go`. Found during grounding. Status: **Drafted**

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
