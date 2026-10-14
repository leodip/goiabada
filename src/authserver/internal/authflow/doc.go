// Package authflow holds the steps of the authorization ceremony, one operation per step: what a
// step loads, the decision it applies, and the writes it makes to the database and to the browser
// session, in that order, ending in a result the step's handler answers from.
//
// The operations and the routes they serve:
//
//   - SelectLevel1Method, GET /auth/level1: chooses the level 1 method, today always the password.
//   - Level1Completion, GET /auth/level1completed: delivers an authorization error parked by
//     /auth/authorize, or decides whether level 2 is owed (ceremony.StepUpOwed).
//   - Level2Selection, GET /auth/level2: chooses the level 2 method (DecideLevel2Arm) and captures
//     the user's OTP configuration generation.
//   - Completion, GET /auth/completed: decides on the user (decideBeforeBinding), binds the ceremony
//     to a user session by reusing the browser's or creating one, or restarts it at level 1
//     (decideCompletion), then sends it to consent or to issuance (DecideAfterBinding).
//   - Issuance, GET /auth/issue: checks again what may have changed since /auth/authorize
//     (decideIssuance), restarts a ceremony whose session can no longer carry a grant, and issues an
//     authorization code or the implicit grant's tokens. The handler delivers them: the encoders of
//     the authorization response are response writers and stay in internal/handlers.
//
// The other steps are still written in internal/handlers.
//
// Rules every operation keeps:
//
//   - No HTTP. Nothing here imports net/http, chi, internal/handlers, internal/middleware or
//     internal/reqctx (import_lint_test.go). What the request carries, its settings, its session
//     identifier and the browser's address, reaches an operation as a plain value the handler read.
//   - Every browser-session write goes through the port an operation declares for it, which the
//     handler satisfies with an adapter built for that one request (handlers.browserSession), holding
//     the request and the response writer the handler holds. An operation never stores one.
//   - The handler writes the response, after the operation has returned. An operation's result says
//     what to answer and how its last browser-session write went, ceremony.ErrCeremonyReplaced
//     included, and the handler maps that to the next step's redirect, the error response to the
//     client, the "no longer active" page or a 500. So a step's clear lands before the response that
//     depends on it is written (#141), and no step answers before its save.
//   - A load or a decision that fails is returned as an error, and the handler answers 500.
//
// The orderings the steps here keep:
//
//   - A parked error reads the client's provenance before the ceremony is cleared, and the clear
//     comes before the answer (Level1Completion); so does every access_denied Completion owes.
//   - A step saves its next state before the handler redirects to it.
//   - Completion decides on the user before either arm binds, so a refusal or a restart writes no
//     session (#522).
//   - Completion's reuse arm asks whether its bind is stale before it rotates the browser session's
//     identifier, and rotates before the bind commits the raised level (#538, #266).
//   - Completion's create arm confirms the browser session still holds the ceremony before it ends a
//     foreign session or creates one, and the session start commits before its rotation (#579).
//   - Audit records of a session write follow its commit.
//   - Issuance clears the ceremony only after the code or the tokens are committed and audited, and
//     a failed clear withholds them (#248). An issuer's refusal, a session or an authenticator gone
//     by the time of the write, is answered after the issuer has rolled back (#139, #542).
package authflow
