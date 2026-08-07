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

2. **A re-enrolment landing mid-request can still let a consumed code assert `otp`, and a stale
   enrolment can replace a fresh authenticator.**
   `security`, `go`. Found while applying decision 10, widened at stage 3's review.
   Status: **Filed** as [#144](https://github.com/leodip/goiabada/issues/144) on 2026-08-06, titled
   "Security: the OTP claim binds to otp_enabled, not to the authenticator". Duplicate search re-run
   before filing: `gh issue list --state all` across otp, enrol, enroll, amr and authenticator returned
   only #140, #111, #142, #113, #98 and #82, none of them this. Kept separate from #140 rather than
   folded in: same class and same harm, but a different mechanism and a different fix, so one issue
   would carry two unrelated changes. #144's body links #140 and GitHub carries the backlink.

   Decision 10 closed the disable case by binding the claim to `otp_enabled`, and its option A said
   plainly that a disable immediately followed by a re-enrolment is not closed, because `otp_enabled` is
   true again by the time the stale claim lands. Recorded here so the residual is not lost with #111.

   Narrower than option A's text says, worked out while applying it. The re-enrolment claims a step of
   its own, so the stale request survives only if the re-enrolment's step is strictly below the replayed
   one: the replayed code must come from the +1 window and the re-enrolment from the current window or
   earlier. It also needs the disable, the re-enrolment and the stale request to overlap inside one
   30 second period, and the attacker to already hold both the level 1 credential and a code from the
   removed authenticator.

   **The second shape, raised by stage 3's review and verified against the code.** It needs no disable
   at all. At `otp/verify-enrolling` the claim passes `requireOTPEnabled` false, so it binds nothing
   about *which* authenticator is being established, and the enable is a whole-user `UpdateUser` writing
   the secret this request holds in its own session. Two password-authenticated enrolment ceremonies
   that both loaded `otp_enabled` false therefore both succeed: the first claims step N and stores
   secret A, the second claims N+1 and replaces A with secret B. One-time use of a code is not violated,
   since each ceremony spends a different code, which is why this was not a stage 3 finding; it is the
   same unbound-authenticator class, and the enrolment generation below closes both shapes.

   Adjacent to #140, which is the same class of defect (a token asserting `amr: ["pwd","otp"]` for
   authentication that no longer holds) by a different mechanism, so whoever picks one up should read
   the other. Searched `gh issue list --state open --search "otp"`, `--search "otp enrolment
   generation"` and `--state all --search "otp replay in-flight"` on 2026-08-05: #140 is the only
   neighbour and it is not this. Re-searched for the second shape on 2026-08-06,
   `--state open --search "concurrent enrollment otp secret"` and
   `--state all --search "otp enrolment race"`: nothing.

   **Body:** After #111, `TryConsumeUserOTPStep` refuses a verification claim unless `otp_enabled` is
   still true, so removing an authenticator invalidates a claim from a request that loaded it. A
   re-enrolment restores `otp_enabled`, so a verification request holding the *old* secret can still
   claim a code it already spent, provided the new enrolment claimed a lower time step. The resulting
   token asserts `otp` for an authenticator that no longer exists, without the `AuditEnabledOTP` trail
   that enrolling would leave. No access is gained that the disable did not already grant (see #111
   decision 10), so this is a false factor assertion rather than an authentication bypass.

   The enrolment claim has the mirror image of the same gap, which predates #111: it passes
   `requireOTPEnabled` false and so binds nothing about which authenticator it establishes, while the
   enable is a whole-user write. Two overlapping enrolment ceremonies both succeed and the later one's
   write replaces the earlier one's secret.

   Closing both properly needs the claim bound to the authenticator rather than to the enrolment flag:
   an enrolment generation column on `users`, incremented on every enable and disable, carried on the
   request and compared in the claim predicate. That is a migration plus a second column, which #111
   deliberately did not take on. Decide whether the window is worth that before building it.

3. **Redact credentials and OTP material from API debug request logging.**
   Status: **Filed** as [#145](https://github.com/leodip/goiabada/issues/145) on 2026-08-06. Duplicate
   search re-run before filing: `redact`, `debug`, `logging` and `secret` across all states returned
   nothing on this path, and no logging-hardening issue exists to fold it into.

   Raised by stage 4's code review as a follow-up, not a finding, and verified against the code before
   drafting. Belongs to a logging-hardening change rather than to #111: §2 asks for nothing about debug
   logging, so this is genuinely out of scope rather than a missing requirement wearing that label.

   **Title:** Redact passwords, client secrets and OTP material from API debug logging

   **Labels:** security, enhancement

   **Anchor:** `src/authserver/internal/middleware/api_debug_middleware.go`, `debugLog`, locate by
   `slog.Info(fmt.Sprintf("[DEBUG API]   Request Body:\n%s", prettyReq.String()))`

   **Duplicate search**, 2026-08-06: `gh issue list --state open --search "debug request logging redact
   password"` and `--search "DEBUG_API_REQUESTS"` both return nothing.

   **Body:** When `GOIABADA_AUTHSERVER_DEBUG_API_REQUESTS` is enabled, `debugLog` pretty-prints the
   entire JSON request and response body to the log. The function already redacts the `Authorization`
   header to `Bearer ***`, so the intent to keep credentials out of logs is there, but the bodies are
   written verbatim. `PUT /api/v1/account/otp` alone carries `password`, `otpCode` and `secretKey`,
   which is the account password, a live TOTP code and the authenticator seed; other account and admin
   endpoints carry passwords and client secrets on the same path.

   Redact by key before formatting, so the shape of the body is still readable for debugging while the
   values are not. Worth covering with tests over at least `password`, `currentPassword`,
   `newPassword`, `clientSecret`, `otpCode` and `secretKey`, and worth applying to the response body
   too, since enrollment responses return `secretKey`.

   This is a debug-only path and off by default, which is why it is a follow-up rather than a blocker.
   The cost of leaving it is that anyone who turns the flag on to diagnose an unrelated problem writes
   reusable credentials and authenticator seeds into their console and log aggregator.
