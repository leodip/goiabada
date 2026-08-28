package constants

const (
	AdminConsoleClientIdentifier = "admin-console-client"

	AuthServerResourceIdentifier = "authserver"

	UserinfoPermissionIdentifier      = "userinfo"
	ManageAccountPermissionIdentifier = "manage-account"
	ManagePermissionIdentifier        = "manage"

	// Granular admin API scopes
	AdminReadPermissionIdentifier      = "admin-read"
	ManageUsersPermissionIdentifier    = "manage-users"
	ManageClientsPermissionIdentifier  = "manage-clients"
	ManageSettingsPermissionIdentifier = "manage-settings"

	// BrowserSessionsPermissionIdentifier is what the admin console's bearer token
	// carries when it reaches its own browser sessions through the auth server. It is
	// deliberately not one of the manage-* scopes above: it permits reading and writing
	// admin console browser sessions and nothing else, so holding the admin console's
	// client secret does not drive the whole admin API (#266).
	BrowserSessionsPermissionIdentifier = "browser-sessions"
)

// BuiltInAuthServerPermissionIdentifiers lists the permission identifiers on the
// "authserver" resource that are required by Goiabada's runtime scope checks.
// These cannot be renamed or deleted.
var BuiltInAuthServerPermissionIdentifiers = []string{
	UserinfoPermissionIdentifier,
	ManageAccountPermissionIdentifier,
	ManagePermissionIdentifier,
	AdminReadPermissionIdentifier,
	ManageUsersPermissionIdentifier,
	ManageClientsPermissionIdentifier,
	ManageSettingsPermissionIdentifier,
	BrowserSessionsPermissionIdentifier,
}

const (
	// OIDC Authorization Error Codes (per OpenID Connect Core 1.0, Section 3.1.2.6)
	ErrorLoginRequired       = "login_required"
	ErrorConsentRequired     = "consent_required"
	ErrorInteractionRequired = "interaction_required"

	AuditAuthFailedPwd                        = "auth_failed_pwd"
	AuditAuthFailedOtp                        = "auth_failed_otp"
	AuditAuthSuccessPwd                       = "auth_success_pwd"
	AuditAuthSuccessOtp                       = "auth_success_otp"
	AuditUserDisabled                         = "user_disabled"
	AuditStartedNewUserSesson                 = "started_new_user_session"
	AuditBumpedUserSession                    = "bumped_user_session"
	AuditCreatedAuthCode                      = "created_auth_code"
	AuditSavedConsent                         = "saved_consent"
	AuditTokenIssuedAuthorizationCodeResponse = "token_issued_authorization_code_response"
	AuditTokenIssuedClientCredentialsResponse = "token_issued_client_credentials_response"
	AuditTokenIssuedRefreshTokenResponse      = "token_issued_refresh_token_response"
	// AuditTokenIssuedImplicitResponse is logged when tokens are issued via implicit flow.
	// SECURITY NOTE: Implicit flow is deprecated in OAuth 2.1.
	AuditTokenIssuedImplicitResponse = "token_issued_implicit_response"
	// AuditTokenIssuedROPCResponse is logged when tokens are issued via ROPC flow.
	// RFC 6749 Section 4.3
	// SECURITY NOTE: ROPC is deprecated in OAuth 2.1 due to credential exposure risks.
	AuditTokenIssuedROPCResponse = "token_issued_ropc_response"
	// AuditTokenScopeDenied is logged when a token request fails scope validation, on any grant
	// type. Emitted from a single call site in HandleTokenPost, after ValidateTokenRequest has
	// failed with an invalid_scope error, so every row follows a successful authentication of
	// whichever principal that grant authenticates.
	//
	// Not every row is an authorization denial. The predicate covers every authenticated
	// invalid_scope failure, of which only "not granted to the client" and "the user does not
	// have permission" are authorization decisions; malformed format and unknown resource or
	// permission usually mean a misconfigured client. See the call site for the full accounting,
	// including the one genuine authorization denial this event misses.
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
	// did authenticate.
	AuditTokenScopeDenied = "token_scope_denied"
	// AuditROPCAuthFailed is logged when ROPC authentication fails.
	// This includes invalid credentials, disabled users, and 2FA-blocked users.
	AuditROPCAuthFailed = "ropc_auth_failed"
	// AuditAuthCodeReuseDetected is logged when an authorization code is replayed
	// at the token endpoint by an authenticated requester (correct client_id,
	// redirect_uri, client_secret/PKCE). Per RFC 6749 Section 4.1.2 the server
	// then revokes refresh tokens issued from that code and terminates the
	// associated user session.
	AuditAuthCodeReuseDetected = "auth_code_reuse_detected"
	// AuditRefreshTokenReplayDetected records an authenticated presentation of an
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
	AuditRefreshTokenReplayDetected = "refresh_token_replay_detected"
	// AuditOTPCodeReplayDetected records a TOTP code that validated against the user's
	// secret but whose time step could not be claimed, which per RFC 6238 Section 5.2
	// means the code had already been used. Emitted alongside AuditAuthFailedOtp rather
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
	AuditOTPCodeReplayDetected = "otp_code_replay_detected"
	// AuditRateLimitExceeded records that a rate limiter refused a request. It exists
	// because a rejected request never reaches the handler, so a sustained guessing run
	// shows N audited credential failures and then silence, and nothing in the log
	// distinguishes "they stopped" from "we are throttling them". RFC 6749 Section 4.3.2
	// names "generating alerts" as the alternative to rate limiting, so recording the
	// intervention is the compensating control that MUST contemplates (#219).
	//
	// Deliberately NOT emitted on every rejection. Every audit write is a settings read
	// plus a table insert on an unauthenticated path, so an event per 429 would turn the
	// rate limiter into the write amplifier it exists to stop (#212). Each limiter pairs
	// with a gate of one event per key per its own window, which bounds the writes by
	// construction rather than by convention. The gate's window cannot be phase-aligned
	// with the limiter's through httprate's public API, so the guarantee is at most one
	// event per key per window and at most two per window length in the worst phase.
	//
	// Payload: the limiter name, plus the identifier that limiter's neighbours already
	// carry, which is the email for account tiers, the user id for the OTP tier and the
	// client block for IP tiers.
	AuditRateLimitExceeded = "rate_limit_exceeded"

	AuditCreatedUser              = "created_user"
	AuditActivatedAccount         = "activated_account"
	AuditCreatedPreRegistration   = "created_pre_registration"
	AuditDeletedUserSessionClient = "deleted_user_session_client"
	AuditLogout                   = "logout"

	AuditRotatedKeys                  = "rotated_keys"
	AuditRevokedKey                   = "revoked_key"
	AuditDeletedUserSession           = "deleted_user_session"
	AuditUpdatedRedirectURIs          = "updated_redirect_uris"
	AuditUpdatedClientPermissions     = "updated_client_permissions"
	AuditDeletedClient                = "deleted_client"
	AuditCreatedClient                = "created_client"
	AuditDynamicClientRegistration    = "dynamic_client_registration"
	AuditUpdatedResourcePermissions   = "updated_resource_permissions"
	AuditDeletedResource              = "deleted_resource"
	AuditUpdatedResource              = "updated_resource"
	AuditCreatedResource              = "created_resource"
	AuditUserAddedToGroup             = "user_added_to_group"
	AuditUserRemovedFromGroup         = "user_removed_from_group"
	AuditCreatedGroup                 = "created_group"
	AuditUpdatedGroup                 = "updated_group"
	AuditDeletedGroup                 = "deleted_group"
	AuditDeleteGroupAttribute         = "deleted_group_attribute"
	AuditAddedGroupAttribute          = "added_group_attribute"
	AuditUpdatedGroupAttribute        = "updated_group_attribute"
	AuditAddedGroupPermission         = "added_group_permission"
	AuditDeletedGroupPermission       = "deleted_group_permission"
	AuditAddedUserPermission          = "added_user_permission"
	AuditDeletedUserPermission        = "deleted_user_permission"
	AuditDeleteUserAttribute          = "deleted_user_attribute"
	AuditAddedUserAttribute           = "added_user_attribute"
	AuditUpdatedUserAttribute         = "updated_user_attribute"
	AuditDeletedUser                  = "deleted_user"
	AuditUpdatedSMTPSettings          = "updated_smtp_settings"
	AuditUpdatedGeneralSettings       = "updated_general_settings"
	AuditUpdatedSessionsSettings      = "updated_sessions_settings"
	AuditUpdatedSMSSettings           = "updated_sms_settings"
	AuditUpdatedTokensSettings        = "updated_tokens_settings"
	AuditUpdatedUIThemeSettings       = "updated_ui_theme_settings"
	AuditUpdatedAuditLogsSettings     = "updated_audit_logs_settings"
	AuditUpdatedWebOrigins            = "updated_web_origins"
	AuditUpdatedClientSettings        = "updated_client_settings"
	AuditUpdatedClientTokens          = "updated_client_tokens"
	AuditUpdatedClientAuthentication  = "updated_client_authentication"
	AuditUpdatedClientOAuth2Flows     = "updated_client_oauth2_flows"
	AuditUpdatedUserDetails           = "updated_user_details"
	AuditUpdatedUserProfile           = "updated_user_profile"
	AuditUpdatedOwnProfile            = "updated_own_profile"
	AuditUpdatedOwnEmail              = "updated_own_email"
	AuditUpdatedOwnPhone              = "updated_own_phone"
	AuditUpdatedOwnAddress            = "updated_own_address"
	AuditUpdatedUserEmail             = "updated_user_email"
	AuditUpdatedUserPhone             = "updated_user_phone"
	AuditUpdatedUserAddress           = "updated_user_address"
	AuditUpdatedUserAuthentication    = "updated_user_authentication"
	AuditDeletedUserConsent           = "deleted_user_consent"
	AuditDeletedOwnUserConsent        = "deleted_own_user_consent"
	AuditVerifiedEmail                = "verified_email"
	AuditSentEmailVerificationMessage = "sent_email_verification_message"
	AuditFailedEmailVerificationCode  = "failed_email_verification_code"
	AuditFailedResetPasswordCode      = "failed_reset_password_code"
	AuditVerifiedPhone                = "verified_phone"
	AuditSentPhoneVerificationMessage = "sent_phone_verification_message"
	AuditChangedPassword              = "changed_password"
	// AuditRevokedUserAuthState records that a credential change invalidated a user's live
	// authentication state: their generation advanced, their sessions were terminated and their
	// refresh tokens revoked. Emitted by the five sites that perform that action AFTER their
	// transaction commits, on success only, and emitted even when nothing was found to revoke,
	// so the event attests that the action happened rather than that something was there to
	// sweep (#106 decision 7). Its `reason` field distinguishes the sites: password_reset,
	// password_change, admin_password_set, account_disabled or email_collision_backfill.
	//
	// Deliberately NOT AuditUserDisabled, which already means "a disabled user was rejected"
	// and is emitted from six auth paths; overloading it would make that event ambiguous.
	AuditRevokedUserAuthState = "revoked_user_auth_state"
	// AuditTerminatedUserSession records that an explicit "end this session" action durably cut
	// off the grants that session authorized: the authorization codes issued through it are
	// marked revoked, its refresh tokens including offline ones are revoked, and the session row
	// is deleted. Emitted by the two session-termination endpoints AFTER their transaction
	// commits, on success only, and emitted even when nothing was found to revoke, so the event
	// attests that the action happened (#129 decision 9).
	//
	// It accompanies AuditDeletedUserSession rather than replacing it. The two carry different
	// meanings, one a session-lifecycle fact and one a security action, and leaving the older
	// event's payload untouched keeps any external consumer parsing it strictly working. The
	// consequence is that both are emitted per action, so THIS is the event to count for
	// terminations and deleted_user_session is the lifecycle record beside it.
	//
	// Its payload carries userId, userSessionId, sessionIdentifier, revokedRefreshTokenJtis and
	// revokedCodeCount, plus loggedInUser. Codes get a count rather than a list of ids because no
	// event here lists code ids, and a count answers the only question an auditor has, whether
	// anything was revoked.
	AuditTerminatedUserSession = "terminated_user_session"
	// AuditRevokedClientGrants records that a client-scoped security action cut off every grant
	// one client holds: its not-yet-revoked authorization codes are marked revoked and its
	// refresh tokens, through both linkage shapes, are revoked. Emitted by the
	// confidential-to-public flip AFTER its transaction commits, on success only, and emitted
	// even when nothing was found to revoke, so the event attests that the action happened
	// rather than that something was there to sweep (#245 decision 4). Its `reason` field
	// distinguishes future sites; today the only value is client_became_public.
	//
	// Deliberately NOT AuditRevokedUserAuthState, whose payload asserts a generation bracket and
	// a list of terminated sessions. This action advances no generation and ends no session: it
	// is scoped to one client, so the users of that client stay signed in everywhere else and
	// their access tokens keep working until they expire.
	//
	// Its payload carries clientId, reason, revokedCodeCount and revokedRefreshTokenJtis, plus
	// loggedInUser. Codes get a count rather than a list of ids, following
	// terminated_user_session, because no event here lists code ids and a count answers the only
	// question an auditor has, whether anything was revoked.
	AuditRevokedClientGrants = "revoked_client_grants"
	// AuditCrossUserSessionReplaced records that a different user signed in on a browser that was
	// still carrying someone else's session cookie, so that session was ended. The browser reaches
	// that state through prompt=login, through an id_token_hint naming another user, or simply by
	// arriving with a session row that has stopped being valid; in each case the cookie survives
	// the redirect to the login page (#133).
	//
	// It answers WHY, beside the deleted_user_session and terminated_user_session pair for the
	// session that was ended and what its grants authorized, and started_new_user_session for what
	// replaced it. Emitted only after TerminateUserSessionTx commits, so it never attests to a
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
	AuditCrossUserSessionReplaced = "cross_user_session_replaced"

	AuditEnabledOTP                     = "enabled_otp"
	AuditDisabledOTP                    = "disabled_otp"
	AuditAutoRefreshedToken             = "auto_refreshed_token"
	AuditSentTestEmail                  = "sent_test_email"
	AuditUpdatedUserProfilePicture      = "updated_user_profile_picture"
	AuditDeletedUserProfilePicture      = "deleted_user_profile_picture"
	AuditUpdatedOwnProfilePicture       = "updated_own_profile_picture"
	AuditDeletedOwnProfilePicture       = "deleted_own_profile_picture"
	AuditUpdatedClientLogo              = "updated_client_logo"
	AuditDeletedClientLogo              = "deleted_client_logo"
	AuditGeneratedEmailVerificationCode = "generated_email_verification_code"
	// AuditAuthCeremonyMismatch records a form in the authorization flow submitted with a
	// ceremony id the browser's auth context no longer holds, which means a second
	// /auth/authorize replaced the ceremony the page was rendered for. The submission is
	// refused with a 400 and the current ceremony is left alone (#79).
	//
	// Ordinary in a browser the user runs two authorizations in, so a row on its own is not an
	// attack. A run of them against one client is worth looking at: this is the event that
	// fires when a page tries to act on an authorization request its user never saw.
	AuditAuthCeremonyMismatch = "auth_ceremony_mismatch"

	// The three refusals at /auth/issue, one per fact the last step re-establishes before it
	// mints anything. Each is the proof that an administrator's action reached a ceremony
	// already in flight: the consent screen has no time bound, so a session can time out, a
	// permission can be revoked and a callback can be deregistered while it is on screen, and
	// without these the operator has no way to ask whether the removal stopped anything (#241).

	// AuditIssuanceRefusedSessionInvalid records a ceremony refused at /auth/issue because the
	// session it authenticated under is no longer within its idle timeout or its maximum
	// lifetime. It attests that check alone: a session that resolves to another user, or that
	// is gone from the database entirely, is refused by the older ownership and liveness tests
	// beside it and writes no audit row.
	AuditIssuanceRefusedSessionInvalid = "issuance_refused_session_invalid"

	// AuditIssuanceRefusedScopeDenied records a ceremony refused at /auth/issue because
	// re-filtering the scope against the user's live permissions left nothing to grant. A
	// filter that merely narrows the set issues the narrowed grant and writes no row: the
	// client is told what it got through the response's scope parameter.
	AuditIssuanceRefusedScopeDenied = "issuance_refused_scope_denied"

	// AuditIssuanceRefusedRedirectURI records a ceremony refused at /auth/issue because the
	// redirect URI it would answer at is no longer registered on the client. It is the one of
	// the three whose refusal reaches the client with nothing at all, not even an error: the
	// destination is exactly what this server may no longer navigate a browser to.
	AuditIssuanceRefusedRedirectURI = "issuance_refused_redirect_uri"

	// AuditRedemptionRefusedRedirectURI records an authorization code exchange refused at the
	// token endpoint because the redirect URI recorded on the code is no longer registered on
	// the client. It is the same fact as AuditIssuanceRefusedRedirectURI arriving one step
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
	AuditRedemptionRefusedRedirectURI = "redemption_refused_redirect_uri"
)

// RevocationReasonEmailCollisionBackfill is the `reason` for AuditRevokedUserAuthState at the
// one revoking site that is not a credential endpoint: the startup pass that lowercases stored
// email addresses disables the losers of a case-variant collision, and a disable revokes what
// the account authenticated under (#283).
//
// It lives HERE and not beside its four siblings in the authserver handlers package, which is
// where RevocationReasonPasswordReset and the rest are declared, because the site emitting it
// is in core and core cannot import that package. The four are unchanged rather than moved:
// relocating them would touch four handlers and their tests for a tidiness this change does
// not otherwise need. What keeps the two homes in step is the doc comment on
// AuditRevokedUserAuthState above, which enumerates all five reasons in one place.
const RevocationReasonEmailCollisionBackfill = "email_collision_backfill"

// AuditEventTypes is the canonical list of all audit event type strings.
// Used by the admin UI filter dropdown.
var AuditEventTypes = []string{
	AuditActivatedAccount,
	AuditAddedGroupAttribute,
	AuditAddedGroupPermission,
	AuditAddedUserAttribute,
	AuditAddedUserPermission,
	AuditAuthCeremonyMismatch,
	AuditAuthCodeReuseDetected,
	AuditAuthFailedOtp,
	AuditAuthFailedPwd,
	AuditAuthSuccessOtp,
	AuditAuthSuccessPwd,
	AuditAutoRefreshedToken,
	AuditBumpedUserSession,
	AuditChangedPassword,
	AuditCreatedAuthCode,
	AuditCreatedClient,
	AuditCreatedGroup,
	AuditCreatedPreRegistration,
	AuditCreatedResource,
	AuditCreatedUser,
	AuditCrossUserSessionReplaced,
	AuditDeletedClient,
	AuditDeletedClientLogo,
	AuditDeletedGroup,
	AuditDeleteGroupAttribute,
	AuditDeletedGroupPermission,
	AuditDeletedOwnProfilePicture,
	AuditDeletedOwnUserConsent,
	AuditDeletedResource,
	AuditDeletedUser,
	AuditDeleteUserAttribute,
	AuditDeletedUserConsent,
	AuditDeletedUserPermission,
	AuditDeletedUserProfilePicture,
	AuditDeletedUserSession,
	AuditDeletedUserSessionClient,
	AuditDisabledOTP,
	AuditDynamicClientRegistration,
	AuditEnabledOTP,
	AuditFailedEmailVerificationCode,
	AuditFailedResetPasswordCode,
	AuditGeneratedEmailVerificationCode,
	AuditIssuanceRefusedRedirectURI,
	AuditIssuanceRefusedScopeDenied,
	AuditIssuanceRefusedSessionInvalid,
	AuditLogout,
	AuditOTPCodeReplayDetected,
	AuditRateLimitExceeded,
	AuditRedemptionRefusedRedirectURI,
	AuditRefreshTokenReplayDetected,
	AuditRevokedClientGrants,
	AuditRevokedKey,
	AuditRevokedUserAuthState,
	AuditROPCAuthFailed,
	AuditRotatedKeys,
	AuditSavedConsent,
	AuditSentEmailVerificationMessage,
	AuditSentPhoneVerificationMessage,
	AuditSentTestEmail,
	AuditStartedNewUserSesson,
	AuditTerminatedUserSession,
	AuditTokenIssuedAuthorizationCodeResponse,
	AuditTokenIssuedClientCredentialsResponse,
	AuditTokenIssuedImplicitResponse,
	AuditTokenIssuedRefreshTokenResponse,
	AuditTokenIssuedROPCResponse,
	AuditTokenScopeDenied,
	AuditUpdatedAuditLogsSettings,
	AuditUpdatedClientAuthentication,
	AuditUpdatedClientLogo,
	AuditUpdatedClientOAuth2Flows,
	AuditUpdatedClientPermissions,
	AuditUpdatedClientSettings,
	AuditUpdatedClientTokens,
	AuditUpdatedGeneralSettings,
	AuditUpdatedGroup,
	AuditUpdatedGroupAttribute,
	AuditUpdatedOwnAddress,
	AuditUpdatedOwnEmail,
	AuditUpdatedOwnPhone,
	AuditUpdatedOwnProfile,
	AuditUpdatedOwnProfilePicture,
	AuditUpdatedRedirectURIs,
	AuditUpdatedResource,
	AuditUpdatedResourcePermissions,
	AuditUpdatedSessionsSettings,
	AuditUpdatedSMSSettings,
	AuditUpdatedSMTPSettings,
	AuditUpdatedTokensSettings,
	AuditUpdatedUIThemeSettings,
	AuditUpdatedUserAddress,
	AuditUpdatedUserAttribute,
	AuditUpdatedUserAuthentication,
	AuditUpdatedUserDetails,
	AuditUpdatedUserEmail,
	AuditUpdatedUserPhone,
	AuditUpdatedUserProfile,
	AuditUpdatedUserProfilePicture,
	AuditUpdatedWebOrigins,
	AuditUserAddedToGroup,
	AuditUserDisabled,
	AuditUserRemovedFromGroup,
	AuditVerifiedEmail,
	AuditVerifiedPhone,
}
