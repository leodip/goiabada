// Package authflow holds the steps of the authorization ceremony, one operation per step: what a
// step loads, the decision it applies, and the writes it makes to the database and to the browser
// session, in that order, ending in a result the step's handler answers from.
//
// The operations and the routes they serve:
//
//   - Authorization, GET /auth/authorize: swaps in a request a POST parked (ResolveParked), then
//     creates the ceremony, the one place an AuthContext is created and a request field written,
//     refuses on the page a request no answer can be addressed to, validates the rest, fixes the
//     target ACR, and routes the ceremony (decideAuthorizeRoute): the error answered to the client
//     now or parked behind a login (#213), /auth/level1, the session's SSO shortcut to
//     /auth/level1completed, or SilentAuthentication.
//   - AuthorizationParking, POST /auth/authorize: refuses what the GET would refuse on the page, and
//     parks the rest under a one-time handle for the GET the handler redirects to (#246).
//   - SelectLevel1Method, GET /auth/level1: chooses the level 1 method, today always the password.
//   - PasswordPrompt, GET /auth/pwd and a POST /auth/pwd that is refused: the client block of the
//     password form, which the handler renders, on the POST only beside a refusal, and loaded only
//     then.
//   - PasswordSubmission, POST /auth/pwd: checks the password the handler read from the form, and
//     records level 1 on the ceremony when it is right and the account enabled.
//   - Level1Completion, GET /auth/level1completed: delivers an authorization error parked by
//     /auth/authorize, or decides whether level 2 is owed (ceremony.StepUpOwed).
//   - Level2Selection, GET /auth/level2: chooses the level 2 method (decideLevel2Arm) and captures
//     the user's OTP configuration generation.
//   - OTPPrompt, GET /auth/otp: chooses the code form or the enrolment form, and keeps, or mints,
//     the ceremony's enrolment key; the handler renders the form.
//   - OTPSubmission, POST /auth/otp: checks the code the handler read from the form, stores the
//     enrolment key as the user's authenticator when the user is enrolling, and records level 2 on
//     the ceremony, or ends a sign-in whose enrolment can no longer be stored.
//   - Completion, GET /auth/completed: decides on the user (decideBeforeBinding), binds the ceremony
//     to a user session by reusing the browser's or creating one, or restarts it at level 1
//     (decideCompletion), then sends it to the acceptance step when the user owes a legal document,
//     or to consent or to issuance (decideAfterBinding).
//   - LegalAcceptance, GET and POST /auth/legal-acceptance (#622): lists the must-accept legal
//     documents the user owes for the client (Prompt), and records the versions shown or ends the
//     sign-in with access_denied (Submit). Once nothing is owed it decides consent or issuance as
//     Completion does (routeBoundCeremony).
//   - ConsentPrompt, GET /auth/consent: shows the consent screen (consentScreenOwed), handing its
//     data to the handler to render, or moves a ceremony whose scope is already consented on to
//     issuance.
//   - ConsentSubmission, POST /auth/consent: reads the user's answer from the submitted body, weighs
//     the ticked scopes against the permissions the user holds now (decideConsentSubmission), and
//     records the consent (userconsent.Record) or refuses with access_denied.
//   - SilentAuthentication, GET /auth/authorize with prompt=none, once Authorization has accepted
//     it: decides whether the browser's session answers it without showing anything
//     (decideSilentAuthentication), and either refuses it for the client or adopts the session,
//     bumps it and sends the ceremony straight to /auth/issue.
//   - Issuance, GET /auth/issue: checks again what may have changed since /auth/authorize
//     (decideIssuance), restarts a ceremony whose session can no longer carry a grant, and issues an
//     authorization code or the implicit grant's tokens. The handler delivers them: the encoders of
//     the authorization response are response writers and stay in internal/handlers.
//
// getClientDisplayInfo is the client block every sign-in screen shows, and loadClientDisplay reads it
// for the ceremony's client when a password or OTP form is about to be rendered. The consent screen
// names the client by record.Client's NameForUsers instead.
//
// Rules every operation keeps:
//
//   - No HTTP. Nothing here imports net/http, core/routing, core/httpmw, core/requestid,
//     internal/handlers, internal/middleware or internal/reqctx (import_lint_test.go). What the
//     request carries, its settings, its session identifier, its request id, the browser's address
//     and a form's submitted body, reaches an operation as a plain value the handler read.
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
//   - Authorization creates the ceremony before it judges the request and saves it only once a
//     route has given it a state, so a request refused on the page writes nothing (#436). It
//     loads the client before every answer that can redirect (#108), asks the responder's emission
//     gate before the session and the session before the validations, and reads the session only
//     when the route turns on it: never for prompt=login, and a failed read is an error, never "no
//     session" (#213). A refusal answered now writes nothing, so the sign-in the browser holds
//     carries on (#246).
//   - A parked error reads the client's provenance before the ceremony is cleared, and the clear
//     comes before the answer (Level1Completion); so does every access_denied Completion owes.
//   - A step saves its next state before the handler redirects to it.
//   - PasswordSubmission rotates the browser session's identifier before it saves the
//     password-completed ceremony, and saves nothing when the rotation fails (#266). It charges a
//     refused guess to the rate limiter, through the adapter, before the audit record, and never a
//     right password (#219).
//   - OTPPrompt draws an enrolment key's QR code before it saves the ceremony, so a key that cannot
//     be drawn is not saved.
//   - OTPSubmission ends a lost enrolment before it looks at the code, and clears the ceremony
//     before the handler answers (#471, #141). Like PasswordSubmission it charges a refused or
//     replayed code before the audit records, and rotates before it saves the ceremony in
//     authentication_completed, saving nothing when the rotation fails (#219, #266).
//   - Completion decides on the user before either arm binds, so a refusal or a restart writes no
//     session (#522).
//   - Completion's reuse arm asks whether its bind is stale before it rotates the browser session's
//     identifier, and rotates before the bind commits the raised level (#538, #266).
//   - Completion's create arm confirms the browser session still holds the ceremony before it ends a
//     foreign session or creates one (#579), and the session start commits before the rotation that
//     binds the new session to the browser session (#266). A failed rotation deletes the new session
//     (#198), and the device cookie is written only once the rotation succeeded.
//   - Audit records of a session write, of a recorded consent, and of recorded acceptances, follow
//     its commit. The acceptance step records nothing for a submission it shows again.
//   - ConsentSubmission narrows the ticked scopes to what the user holds before it reads or writes a
//     consent, so a selection the narrowing empties writes nothing (#241). Its refusals read the
//     client's provenance before the clear, and the clear comes before the answer (#141).
//   - SilentAuthentication reads nothing past the check that refused, and its refusal writes nothing
//     but the discard of the ceremony, which comes before the answer (#141). It refuses a session
//     with no auth time before it bumps the session or saves the ceremony, and records
//     bumped_user_session after the bump.
//   - Issuance clears the ceremony only after the code or the tokens are committed and audited, and
//     a failed clear withholds them (#248). An issuer's refusal, a session or an authenticator gone
//     by the time of the write, is answered after the issuer has rolled back (#139, #542).
package authflow
