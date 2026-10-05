// Package audit records the auth server's security events. Logger writes each one to the
// console, the audit_logs table or both, as the settings' two switches say, and never fails the
// request that raised it. This file declares every event name and the catalog of them the admin
// console's filter dropdown is built from.
//
// The names live in the auth server because it is the only process that emits one: every call to
// Logger.Log in this tree is made from this module, and the admin console names no event
// at all. It reaches the catalog over GET /api/v1/admin/audit-logs/event-types instead of
// compiling it in, so an event added here reaches the dropdown without that binary being
// rebuilt (#351).
//
// The value is what is persisted in the audit_logs table's audit_event column and what the
// admin API's auditEvent filter matches, so a string here is stored data and changing one
// orphans every row already carrying it. Each name carries the Event prefix, the standard
// library's shape for a family of named values (http.MethodGet, http.StatusOK): it keeps the
// events together in godoc and is what the catalog check tells an event from any other
// constant by. A name can change without its value; a value cannot change at all.
//
// Adding an event means two edits in this file, the declaration and the catalog entry, and
// TestAuditCatalog_MatchesTheDeclarations in events_catalog_lint_test.go fails the auth
// server's unit tier until both are made. That check is the whole of #209: before it, an
// Audit* constant added to the declarations alone passed the suite and was then missing from
// the operator's filter dropdown, with nothing going red.
package audit

import "slices"

const (
	EventAuthFailedPwd                        = "auth_failed_pwd" //nolint:gosec // G101: an audit event name, not a credential
	EventAuthFailedOtp                        = "auth_failed_otp"
	EventAuthSuccessPwd                       = "auth_success_pwd" //nolint:gosec // G101: an audit event name, not a credential
	EventAuthSuccessOtp                       = "auth_success_otp"
	EventUserDisabled                         = "user_disabled"
	EventStartedNewUserSession                = "started_new_user_session"
	EventBumpedUserSession                    = "bumped_user_session"
	EventCreatedAuthCode                      = "created_auth_code"
	EventSavedConsent                         = "saved_consent"
	EventTokenIssuedAuthorizationCodeResponse = "token_issued_authorization_code_response"
	EventTokenIssuedClientCredentialsResponse = "token_issued_client_credentials_response"
	EventTokenIssuedRefreshTokenResponse      = "token_issued_refresh_token_response" //nolint:gosec // G101: an audit event name, not a credential
	// EventTokenIssuedImplicitResponse is logged when tokens are issued via implicit flow.
	// SECURITY NOTE: Implicit flow is deprecated in OAuth 2.1.
	EventTokenIssuedImplicitResponse = "token_issued_implicit_response"
	// EventTokenIssuedROPCResponse is logged when tokens are issued via ROPC flow.
	// RFC 6749 Section 4.3
	// SECURITY NOTE: ROPC is deprecated in OAuth 2.1 due to credential exposure risks.
	EventTokenIssuedROPCResponse = "token_issued_ropc_response" //nolint:gosec // G101: an audit event name, not a credential
	// EventTokenScopeDenied is logged when a token request fails scope validation, on any grant
	// type. Emitted from a single call site in HandleTokenPost, after ValidateTokenRequest has
	// failed with an invalid_scope error, so every row follows a successful authentication of
	// whichever principal that grant authenticates.
	//
	// Not every row is an authorization denial. The predicate covers every authenticated
	// invalid_scope failure, of which only "not granted to the client", "the user does not have
	// permission" and a refresh asking for a scope its grant does not hold are authorization
	// decisions; malformed format and unknown resource or permission usually mean a misconfigured
	// client. See the call site for the full accounting, including the two branches outside it.
	//
	// The name is deliberately grant-agnostic and sorts immediately after the five
	// token_issued_* events, so a token_* filter groups token issuance with scope denials. That
	// is NOT the whole token endpoint: it also emits user_disabled, bumped_user_session and
	// auth_code_reuse_detected, none of which carry the prefix.
	//
	// The payload carries clientIdentifier, the string from the request, rather than the numeric
	// clientId the issuance events use: the validator returns (nil, err) on failure and discards
	// the client model it resolved. What that string attests to varies by grant. Client
	// credentials authenticates the client itself, so the row does attest to the named client.
	// ROPC authenticates the USER, and the client only when it is confidential, so for a public
	// ROPC client the identifier is caller-supplied request context rather than proof that the
	// named client made the request. The row is still worth having, because the user behind it
	// did authenticate. A refresh authenticates a confidential client, and for a public one the
	// row follows the presentation of a refresh token issued to the named client, because the
	// refresh arm checks the token's owner before it compares scopes.
	EventTokenScopeDenied = "token_scope_denied"
	// EventROPCAuthFailed is logged when ROPC authentication fails.
	// This includes invalid credentials, disabled users, and 2FA-blocked users.
	EventROPCAuthFailed = "ropc_auth_failed"
	// EventAuthCodeReuseDetected is logged when an authorization code is replayed
	// at the token endpoint by an authenticated requester (correct client_id,
	// redirect_uri, client_secret/PKCE). Per RFC 6749 Section 4.1.2 the server
	// then revokes refresh tokens issued from that code and terminates the
	// associated user session.
	EventAuthCodeReuseDetected = "auth_code_reuse_detected"
	// EventRefreshTokenReplayDetected records an authenticated presentation of an
	// already-revoked refresh token that caused at least one live member of the
	// same rotation family to be revoked. Per RFC 9700 Section 4.14.2, rotation
	// responds to an invalidated refresh token by revoking the active one, since
	// the server cannot tell which presenter is legitimate.
	//
	// It does NOT assert malicious intent. Under the strict rotation policy this
	// event can legitimately describe a concurrent duplicate whose lookup landed
	// after the winner's claim (#128).
	//
	// A presentation that revokes nothing emits no event, so an idempotent no-op
	// (a family already fully revoked, or a repeated replay) cannot amplify the
	// audit log.
	EventRefreshTokenReplayDetected = "refresh_token_replay_detected"
	// EventOTPCodeReplayDetected records a TOTP code that validated against the user's
	// secret but whose time step could not be claimed, which per RFC 6238 Section 5.2
	// means the code had already been used. Emitted alongside EventAuthFailedOtp rather
	// than instead of it: a replayed code is a far stronger signal than a mistyped one,
	// usually a real-time phishing proxy, and it deserves to be alertable on its own
	// (#111 decision 5).
	//
	// It does NOT assert malicious intent, and it is not proof of replay. The claim is a
	// compare-and-set, so a false return only says no row transitioned, which is either
	// an already-consumed step, a user row that vanished, or an authenticator disabled
	// under this very request. The caller loaded the user moments earlier, so replay is
	// overwhelmingly the cause. See TryConsumeUserOTPStep for the full accounting.
	//
	// Payload: userId and the matched time step, so an operator can see which code was
	// replayed. Never the code itself. The caller learns nothing either way: a replay
	// renders the same generic incorrect-code response as a wrong code.
	EventOTPCodeReplayDetected = "otp_code_replay_detected"
	// EventRateLimitExceeded records that a rate limiter refused a request. It exists
	// because a rejected request never reaches the handler, so a sustained guessing run
	// shows N audited credential failures and then silence, and nothing in the log
	// distinguishes "they stopped" from "we are throttling them". RFC 6749 Section 4.3.2
	// names "generating alerts" as the alternative to rate limiting, so recording the
	// intervention is the compensating control that MUST contemplates (#219).
	//
	// Deliberately NOT emitted on every rejection. Every audit write is a settings read
	// plus a table insert on an unauthenticated path, so an event per 429 would turn the
	// rate limiter into the write amplifier it exists to stop (#212). Each limiter pairs
	// with a gate of one event per key per window, which bounds the writes by construction
	// rather than by convention. The gate shares its limiter's window and phase, so the
	// guarantee is exactly one event per key per window (#276).
	//
	// Payload: the limiter name, plus the identifier that limiter's neighbours already
	// carry, which is the email for account tiers, the user id for the OTP tier and the
	// client block for IP tiers.
	EventRateLimitExceeded = "rate_limit_exceeded"

	EventCreatedUser              = "created_user"
	EventActivatedAccount         = "activated_account"
	EventDeletedUserSessionClient = "deleted_user_session_client"
	EventLogout                   = "logout"

	EventRotatedKeys                  = "rotated_keys"
	EventRevokedKey                   = "revoked_key"
	EventDeletedUserSession           = "deleted_user_session"
	EventUpdatedRedirectURIs          = "updated_redirect_uris"
	EventUpdatedClientPermissions     = "updated_client_permissions"
	EventDeletedClient                = "deleted_client"
	EventCreatedClient                = "created_client"
	EventDynamicClientRegistration    = "dynamic_client_registration"
	EventUpdatedResourcePermissions   = "updated_resource_permissions"
	EventDeletedResource              = "deleted_resource"
	EventUpdatedResource              = "updated_resource"
	EventCreatedResource              = "created_resource"
	EventUserAddedToGroup             = "user_added_to_group"
	EventUserRemovedFromGroup         = "user_removed_from_group"
	EventCreatedGroup                 = "created_group"
	EventUpdatedGroup                 = "updated_group"
	EventDeletedGroup                 = "deleted_group"
	EventDeleteGroupAttribute         = "deleted_group_attribute"
	EventAddedGroupAttribute          = "added_group_attribute"
	EventUpdatedGroupAttribute        = "updated_group_attribute"
	EventAddedGroupPermission         = "added_group_permission"
	EventDeletedGroupPermission       = "deleted_group_permission"
	EventAddedUserPermission          = "added_user_permission"
	EventDeletedUserPermission        = "deleted_user_permission"
	EventDeleteUserAttribute          = "deleted_user_attribute"
	EventAddedUserAttribute           = "added_user_attribute"
	EventUpdatedUserAttribute         = "updated_user_attribute"
	EventDeletedUser                  = "deleted_user"
	EventUpdatedSMTPSettings          = "updated_smtp_settings"
	EventUpdatedGeneralSettings       = "updated_general_settings"
	EventUpdatedSessionsSettings      = "updated_sessions_settings"
	EventUpdatedTokensSettings        = "updated_tokens_settings"
	EventUpdatedUIThemeSettings       = "updated_ui_theme_settings"
	EventUpdatedAuditLogsSettings     = "updated_audit_logs_settings"
	EventUpdatedWebOrigins            = "updated_web_origins"
	EventUpdatedClientSettings        = "updated_client_settings"
	EventUpdatedClientTokens          = "updated_client_tokens"
	EventUpdatedClientAuthentication  = "updated_client_authentication"
	EventUpdatedClientOAuth2Flows     = "updated_client_oauth2_flows"
	EventUpdatedUserDetails           = "updated_user_details"
	EventUpdatedUserProfile           = "updated_user_profile"
	EventUpdatedOwnProfile            = "updated_own_profile"
	EventUpdatedOwnEmail              = "updated_own_email"
	EventUpdatedOwnPhone              = "updated_own_phone"
	EventUpdatedOwnAddress            = "updated_own_address"
	EventUpdatedUserEmail             = "updated_user_email"
	EventUpdatedUserPhone             = "updated_user_phone"
	EventUpdatedUserAddress           = "updated_user_address"
	EventUpdatedUserAuthentication    = "updated_user_authentication"
	EventDeletedUserConsent           = "deleted_user_consent"
	EventDeletedOwnUserConsent        = "deleted_own_user_consent"
	EventVerifiedEmail                = "verified_email"
	EventSentEmailVerificationMessage = "sent_email_verification_message"
	EventFailedEmailVerificationCode  = "failed_email_verification_code"
	EventFailedResetPasswordCode      = "failed_reset_password_code"
	// EventFailedAccountActivationCode records a refused self-registration activation link, the
	// twin of EventFailedResetPasswordCode: both emailed-link flows answer every refusal with one
	// page, so this entry is the only place the cause is visible, and a burst of them is what
	// probing activation links looks like. It replaced a Warn record in #435.
	//
	// Payload: reason (the reset flow's names for the same states), the client IP, and
	// preRegistrationId only when the lookup resolved a pre-registration the link's code matched.
	EventFailedAccountActivationCode = "failed_account_activation_code"
	// EventRequestedPasswordReset records one forgot-password request, written exactly once for
	// every POST that reaches the handler, a malformed address included. Every well-formed
	// request is answered with the same "link sent" page whatever became of it, so this entry is
	// the only place an administrator can see why a user was sent nothing (#404 decision 6). A
	// request the rate limiter refuses never reaches the handler and is EventRateLimitExceeded's.
	//
	// Written once the outcome is decided and before any mail is sent, so code_issued says a code
	// was stored, not that the mail went out: a send failure is an Error log line carrying the
	// same request id, never a second entry.
	//
	// Payload: ip, the client IP truncated as the reset refusals record it; emailDigest, the
	// SHA-256 hex of the submitted address normalized as the lookup normalizes it, never the
	// address itself, so the table does not collect every address typed into an unauthenticated
	// form; userId, present only when an account matched; and outcome, one of code_issued,
	// unknown_address, unverified_address, account_disabled, account_changed, invalid_address
	// or server_error, the last a request the server failed before deciding it (the lookup, or
	// the code's encryption or store), whose cause is the Error log line on the same request id.
	// The digest is a pseudonym, not a secret: anyone holding a candidate address can test it.
	EventRequestedPasswordReset = "requested_password_reset"
	// EventRequestedRegistration records one self-registration request made while registration
	// requires email verification, the twin of EventRequestedPasswordReset: written exactly once
	// for every POST in that mode that reaches the handler, a malformed address included. Every
	// well-formed request is answered with the same "check your email" page whatever became of
	// it, so this entry is the only place an administrator can see what it led to (#207
	// decision 8). A request the rate limiter refuses never reaches the handler and is
	// EventRateLimitExceeded's. Registration without verification writes created_user instead.
	//
	// Written once the outcome is decided and before any mail is sent, so link_issued and
	// notice_issued say what was issued, not that the mail went out: a send failure is an Error
	// log line carrying the same request id, never a second entry.
	//
	// Payload: ip, the client IP truncated as the emailed-link records truncate it; emailDigest,
	// the SHA-256 hex of the submitted address normalized as the lookups normalize it, never the
	// address itself; userId, present only when an account matched; preRegistrationId, present
	// only when a pending registration was written or found; and outcome, one of link_issued (a
	// new pending registration, or a dead one given a fresh code, and its link), link_pending (a
	// pending registration that can still complete; nothing sent), notice_issued (a verified,
	// enabled account, sent a notice that it already exists), unverified_address (an enabled
	// account whose address is not verified; nothing sent), account_disabled (a disabled account,
	// verified or not; nothing sent), replacement_lost (a dead pending registration whose
	// conditional replacement was declined, because another request replaced it first; nothing
	// sent), invalid_address (the form was redrawn with its error) or server_error (the server failed
	// before deciding; the cause is the Error log line on the same request id).
	//
	// It replaced created_pre_registration, which recorded the address in plain text and only
	// for a new one. Rows already written under that name keep it; nothing writes it any more.
	EventRequestedRegistration = "requested_registration"
	EventChangedPassword       = "changed_password"
	// EventRevokedUserAuthState records that a credential change invalidated a user's live
	// authentication state: their generation advanced, their sessions were terminated and their
	// refresh tokens revoked. Emitted by the four sites that perform that action AFTER their
	// transaction commits, on success only, and emitted even when nothing was found to revoke,
	// so the event attests that the action happened rather than that something was there to
	// sweep (#106 decision 7). Its `reason` field distinguishes the sites: password_reset,
	// password_change, admin_password_set or account_disabled. A fifth, email_collision_backfill,
	// existed until #351 replaced the startup pass that emitted it with migration 000047 and a
	// pre-flight that refuses to migrate rather than disabling an account nobody asked about.
	//
	// Deliberately NOT EventUserDisabled, which already means "a disabled user was rejected"
	// and is emitted from six auth paths; overloading it would make that event ambiguous.
	EventRevokedUserAuthState = "revoked_user_auth_state"
	// EventTerminatedUserSession records that an explicit "end this session" action durably cut
	// off the grants that session authorized: the authorization codes issued through it are
	// marked revoked, its refresh tokens including offline ones are revoked, and the session row
	// is deleted. Emitted by the two session-termination endpoints AFTER their transaction
	// commits, on success only, and emitted even when nothing was found to revoke, so the event
	// attests that the action happened (#129 decision 9).
	//
	// It accompanies EventDeletedUserSession rather than replacing it. The two carry different
	// meanings, one a session-lifecycle fact and one a security action, and leaving the older
	// event's payload untouched keeps any external consumer parsing it strictly working. The
	// consequence is that both are emitted per action, so THIS is the event to count for
	// terminations and deleted_user_session is the lifecycle record beside it.
	//
	// Its payload carries userId, userSessionId, sessionIdentifier, revokedRefreshTokenJtis and
	// revokedCodeCount, plus loggedInUser. Codes get a count rather than a list of ids because no
	// event here lists code ids, and a count answers the only question an auditor has, whether
	// anything was revoked.
	EventTerminatedUserSession = "terminated_user_session"
	// EventRevokedClientGrants records that a client-scoped security action cut off every grant
	// one client holds: its not-yet-revoked authorization codes are marked revoked and its
	// refresh tokens, through both linkage shapes, are revoked. Emitted by the
	// confidential-to-public flip AFTER its transaction commits, on success only, and emitted
	// even when nothing was found to revoke, so the event attests that the action happened
	// rather than that something was there to sweep (#245 decision 4). Its `reason` field
	// distinguishes future sites; today the only value is client_became_public.
	//
	// Deliberately NOT EventRevokedUserAuthState, whose payload asserts a generation bracket and
	// a list of terminated sessions. This action advances no generation and ends no session: it
	// is scoped to one client, so the users of that client stay signed in everywhere else and
	// their access tokens keep working until they expire.
	//
	// Its payload carries clientId, reason, revokedCodeCount and revokedRefreshTokenJtis, plus
	// loggedInUser. Codes get a count rather than a list of ids, following
	// terminated_user_session, because no event here lists code ids and a count answers the only
	// question an auditor has, whether anything was revoked.
	EventRevokedClientGrants = "revoked_client_grants"
	// EventCrossUserSessionReplaced records that a different user signed in on a browser that was
	// still carrying someone else's session cookie, so that session was ended. The browser reaches
	// that state through prompt=login, through an id_token_hint naming another user, or simply by
	// arriving with a session row that has stopped being valid; in each case the cookie survives
	// the redirect to the login page (#133).
	//
	// It answers WHY, beside the deleted_user_session and terminated_user_session pair for the
	// session that was ended and what its grants authorized, and started_new_user_session for what
	// replaced it. Emitted only after revocation.TerminateUserSessionTx commits, so it never attests to a
	// termination that rolled back.
	//
	// It attests the handover and the ending, and deliberately NOT that a replacement exists: it is
	// written before the new session is created, which can still fail and return a 500.
	// started_new_user_session is the event that attests the replacement, and its absence after
	// this one is how an operator sees a handover that did not complete. Writing this one after the
	// creation instead would leave that failure recorded as a termination with no actor and no
	// reason.
	//
	// Its payload carries userId (the user who just authenticated), previousUserId and
	// previousSessionIdentifier (the session that was ended) and clientId. previousUserId is the
	// field that makes this event what it is: without it an operator reading the two older events
	// cannot tell a browser changing hands from an administrator ending a session, which is why
	// reusing that pair was rejected. Nothing links them, and they are emitted in that same order
	// by ordinary session housekeeping.
	EventCrossUserSessionReplaced = "cross_user_session_replaced"

	EventEnabledOTP                     = "enabled_otp"
	EventDisabledOTP                    = "disabled_otp"
	EventSentTestEmail                  = "sent_test_email"
	EventUpdatedUserProfilePicture      = "updated_user_profile_picture"
	EventDeletedUserProfilePicture      = "deleted_user_profile_picture"
	EventUpdatedOwnProfilePicture       = "updated_own_profile_picture"
	EventDeletedOwnProfilePicture       = "deleted_own_profile_picture"
	EventUpdatedClientLogo              = "updated_client_logo"
	EventDeletedClientLogo              = "deleted_client_logo"
	EventGeneratedEmailVerificationCode = "generated_email_verification_code"
	// EventAuthCeremonyMismatch records a form in the authorization flow submitted with a
	// ceremony id the browser's auth context no longer holds, which means a second
	// /auth/authorize replaced the ceremony the page was rendered for. The submission is
	// refused with a 400 and the current ceremony is left alone (#79).
	//
	// Ordinary in a browser the user runs two authorizations in, so a row on its own is not an
	// attack. A run of them against one client is worth looking at: this is the event that
	// fires when a page tries to act on an authorization request its user never saw.
	EventAuthCeremonyMismatch = "auth_ceremony_mismatch"

	// The three refusals at /auth/issue, one per fact the last step re-establishes before it
	// mints anything. Each is the proof that an administrator's action reached a ceremony
	// already in flight: the consent screen has no time bound, so a session can time out, a
	// permission can be revoked and a callback can be deregistered while it is on screen, and
	// without these the operator has no way to ask whether the removal stopped anything (#241).

	// EventIssuanceRefusedSessionInvalid records a ceremony refused at /auth/issue because the
	// session it authenticated under is no longer within its idle timeout or its maximum
	// lifetime. It attests that check alone: a session that resolves to another user, or that
	// is gone from the database entirely, is refused by the older ownership and liveness tests
	// beside it and writes no audit row.
	EventIssuanceRefusedSessionInvalid = "issuance_refused_session_invalid"

	// EventIssuanceRefusedScopeDenied records a ceremony refused at /auth/issue because
	// re-filtering the scope against the user's live permissions left nothing to grant. A
	// filter that merely narrows the set issues the narrowed grant and writes no row: the
	// client is told what it got through the response's scope parameter.
	EventIssuanceRefusedScopeDenied = "issuance_refused_scope_denied"

	// EventIssuanceRefusedRedirectURI records a ceremony refused at /auth/issue because the
	// redirect URI it would answer at is no longer registered on the client. It is the one of
	// the three whose refusal reaches the client with nothing at all, not even an error: the
	// destination is exactly what this server may no longer navigate a browser to.
	EventIssuanceRefusedRedirectURI = "issuance_refused_redirect_uri"

	// EventRedemptionRefusedRedirectURI records an authorization code exchange refused at the
	// token endpoint because the redirect URI recorded on the code is no longer registered on
	// the client. It is the same fact as EventIssuanceRefusedRedirectURI arriving one step
	// later, and it exists because a code minted a second before the deregistration would
	// otherwise stay redeemable for the rest of its 60 second life (#241 decision 5).
	//
	// It attests that check alone. A request whose submitted redirect_uri merely differs from
	// the one on the code is a different refusal, answered generically much earlier in the
	// arm, and writes no row: this event means the registration was withdrawn, not that the
	// caller sent the wrong value.
	//
	// A row here is worth looking at. The check sits below client authentication and PKCE, so
	// whoever produced it had proved possession, which makes it either an administrator
	// rotating a callback inside the window or a grant being redeemed after its destination
	// was deliberately pulled.
	EventRedemptionRefusedRedirectURI = "redemption_refused_redirect_uri"

	// EventAdministratorChangeRefused records an admin API request the administrative policy
	// refused: a token without authserver:manage reaching for what only manage may do, which
	// is creating an administrator, changing one, or changing what reaches one. One row per
	// refused request, written before the 403 MANAGE_SCOPE_REQUIRED is answered, so an
	// integration retrying writes one per attempt, which is right for an attempted administrative
	// act. The route gate's own INSUFFICIENT_SCOPE refusals write none (#402 decision 5).
	//
	// Payload: loggedInUser, the token's sub; method and route, the route pattern rather than the
	// path; ceiling, the one that refused it (grant is granting or revoking an administrative
	// permission); targetKind and targetId, where the request has a target; and, for a grant
	// refusal, permissionIds, the administrative permissions whose change caused it.
	EventAdministratorChangeRefused = "administrator_change_refused"

	// EventAdministrativePermissionChanged records a committed change to who is an administrator:
	// an administrative permission granted to or revoked from a user, a group or a client, or a
	// user joining or leaving a group that holds one. It is written after the write's own records
	// (added_user_permission and its siblings, updated_client_permissions, user_added_to_group and
	// user_removed_from_group), never instead of them, so one filter or one alert rule sees every
	// such change and a filter on those still sees every grant. Deleting an administrator or an
	// administrative group keeps its own deletion record and writes none of these (#402 decision
	// 6).
	//
	// Payload: change, granted or revoked; targetKind and targetId, the user, group or client
	// whose permissions changed, the user for a membership change; permissionIdentifiers, the
	// administrative permissions granted or revoked, as resource:permission; groupId, for a
	// membership change, the group joined or left; and loggedInUser. A permission save writes at
	// most one per direction, a membership change one per administrative group.
	EventAdministrativePermissionChanged = "administrative_permission_changed"

	// EventViewedClientSecret records a read of a client's secret through GET
	// /api/v1/admin/clients/{id}/secret, the one route that answers one, decrypted. Only a read
	// that disclosed a secret writes it: a client holding none is answered an empty one and
	// records nothing (#402 decision 8, #403).
	//
	// Payload: clientId and clientIdentifier, the client whose secret was read, and loggedInUser.
	EventViewedClientSecret = "viewed_client_secret"
)

// EventTypes returns the canonical list of audit event names, which the admin console's
// filter dropdown is built from. It returns a copy, so a caller changing the slice it got changes
// no later answer (#433).
func EventTypes() []string {
	return slices.Clone(auditEventTypes)
}

// auditEventTypes is the catalog EventTypes copies.
var auditEventTypes = []string{
	EventActivatedAccount,
	EventAddedGroupAttribute,
	EventAddedGroupPermission,
	EventAddedUserAttribute,
	EventAddedUserPermission,
	EventAdministrativePermissionChanged,
	EventAdministratorChangeRefused,
	EventAuthCeremonyMismatch,
	EventAuthCodeReuseDetected,
	EventAuthFailedOtp,
	EventAuthFailedPwd,
	EventAuthSuccessOtp,
	EventAuthSuccessPwd,
	EventBumpedUserSession,
	EventChangedPassword,
	EventCreatedAuthCode,
	EventCreatedClient,
	EventCreatedGroup,
	EventCreatedResource,
	EventCreatedUser,
	EventCrossUserSessionReplaced,
	EventDeletedClient,
	EventDeletedClientLogo,
	EventDeletedGroup,
	EventDeleteGroupAttribute,
	EventDeletedGroupPermission,
	EventDeletedOwnProfilePicture,
	EventDeletedOwnUserConsent,
	EventDeletedResource,
	EventDeletedUser,
	EventDeleteUserAttribute,
	EventDeletedUserConsent,
	EventDeletedUserPermission,
	EventDeletedUserProfilePicture,
	EventDeletedUserSession,
	EventDeletedUserSessionClient,
	EventDisabledOTP,
	EventDynamicClientRegistration,
	EventEnabledOTP,
	EventFailedAccountActivationCode,
	EventFailedEmailVerificationCode,
	EventFailedResetPasswordCode,
	EventGeneratedEmailVerificationCode,
	EventIssuanceRefusedRedirectURI,
	EventIssuanceRefusedScopeDenied,
	EventIssuanceRefusedSessionInvalid,
	EventLogout,
	EventOTPCodeReplayDetected,
	EventRateLimitExceeded,
	EventRedemptionRefusedRedirectURI,
	EventRefreshTokenReplayDetected,
	EventRequestedPasswordReset,
	EventRequestedRegistration,
	EventRevokedClientGrants,
	EventRevokedKey,
	EventRevokedUserAuthState,
	EventROPCAuthFailed,
	EventRotatedKeys,
	EventSavedConsent,
	EventSentEmailVerificationMessage,
	EventSentTestEmail,
	EventStartedNewUserSession,
	EventTerminatedUserSession,
	EventTokenIssuedAuthorizationCodeResponse,
	EventTokenIssuedClientCredentialsResponse,
	EventTokenIssuedImplicitResponse,
	EventTokenIssuedRefreshTokenResponse,
	EventTokenIssuedROPCResponse,
	EventTokenScopeDenied,
	EventUpdatedAuditLogsSettings,
	EventUpdatedClientAuthentication,
	EventUpdatedClientLogo,
	EventUpdatedClientOAuth2Flows,
	EventUpdatedClientPermissions,
	EventUpdatedClientSettings,
	EventUpdatedClientTokens,
	EventUpdatedGeneralSettings,
	EventUpdatedGroup,
	EventUpdatedGroupAttribute,
	EventUpdatedOwnAddress,
	EventUpdatedOwnEmail,
	EventUpdatedOwnPhone,
	EventUpdatedOwnProfile,
	EventUpdatedOwnProfilePicture,
	EventUpdatedRedirectURIs,
	EventUpdatedResource,
	EventUpdatedResourcePermissions,
	EventUpdatedSessionsSettings,
	EventUpdatedSMTPSettings,
	EventUpdatedTokensSettings,
	EventUpdatedUIThemeSettings,
	EventUpdatedUserAddress,
	EventUpdatedUserAttribute,
	EventUpdatedUserAuthentication,
	EventUpdatedUserDetails,
	EventUpdatedUserEmail,
	EventUpdatedUserPhone,
	EventUpdatedUserProfile,
	EventUpdatedUserProfilePicture,
	EventUpdatedWebOrigins,
	EventUserAddedToGroup,
	EventUserDisabled,
	EventUserRemovedFromGroup,
	EventVerifiedEmail,
	EventViewedClientSecret,
}
