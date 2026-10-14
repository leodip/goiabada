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
//
// The other steps are still written in internal/handlers.
//
// Rules every operation keeps:
//
//   - No HTTP. Nothing here imports net/http, chi, internal/handlers, internal/middleware or
//     internal/reqctx (import_lint_test.go). What the request carries, its settings and its session
//     identifier, reaches an operation as a plain value the handler read.
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
// The orderings the steps here keep: a parked error reads the client's provenance before the
// ceremony is cleared, and the clear comes before the answer (Level1Completion); a step saves its
// next state before the handler redirects to it.
package authflow
