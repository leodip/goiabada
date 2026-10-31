package server

import (
	"github.com/leodip/goiabada/authserver/internal/accountvalidation"
	"github.com/leodip/goiabada/authserver/internal/audit"
	"github.com/leodip/goiabada/authserver/internal/authflow"
	"github.com/leodip/goiabada/authserver/internal/ceremony"
	"github.com/leodip/goiabada/authserver/internal/emaildelivery"
	"github.com/leodip/goiabada/authserver/internal/emaillinks"
	"github.com/leodip/goiabada/authserver/internal/handlers"
	"github.com/leodip/goiabada/authserver/internal/handlers/accounthandlers"
	"github.com/leodip/goiabada/authserver/internal/handlers/apihandlers"
	"github.com/leodip/goiabada/authserver/internal/issuance"
	"github.com/leodip/goiabada/authserver/internal/legaldocuments"
	"github.com/leodip/goiabada/authserver/internal/middleware"
	"github.com/leodip/goiabada/authserver/internal/otp"
	"github.com/leodip/goiabada/authserver/internal/permissions"
	"github.com/leodip/goiabada/authserver/internal/protocolvalidation"
	"github.com/leodip/goiabada/authserver/internal/sessionkeys"
	"github.com/leodip/goiabada/authserver/internal/signingkeys"
	"github.com/leodip/goiabada/authserver/internal/usercreation"
	"github.com/leodip/goiabada/authserver/internal/usersession"
	"github.com/leodip/goiabada/core/builtin"
	"github.com/leodip/goiabada/core/inputvalidation"
	"github.com/leodip/goiabada/core/routing"
)

// initRoutes registers the application's routes on the branches initMiddleware returns
// rather than on s.router itself: the settings read, the session load and the locale
// resolution belong to these routes and not to the static file server registered beside them
// (#266). Each route goes on the branch of the format its handler answers a fault in, so the
// protocol endpoints and the APIs answer a settings or session failure, or a panic, as JSON
// (see appBranches, #435).
func (s *Server) initRoutes(branches appBranches) {
	pages, files, protocol, api, token, revoke, introspect := branches.pages, branches.files, branches.protocol, branches.api,
		branches.token, branches.revoke, branches.introspect

	auditLogger := audit.NewLogger(s.database, middleware.NewAuditSwitches(s.database))
	authorizeValidator := protocolvalidation.NewAuthorizeValidator(s.database)
	tokenParser := signingkeys.NewTokenParser(s.database)
	permissionChecker := permissions.NewChecker(s.database)
	tokenValidator := protocolvalidation.NewTokenValidator(s.database, tokenParser, permissionChecker, s.dataCipher)
	emailValidator := accountvalidation.NewEmailValidator(s.database)
	passwordValidator := accountvalidation.NewPasswordValidator()
	profileValidator := accountvalidation.NewProfileValidator(s.database)
	addressValidator := accountvalidation.NewAddressValidator()
	phoneValidator := accountvalidation.NewPhoneValidator()
	identifierValidator := inputvalidation.NewIdentifierValidator()

	codeIssuer := issuance.NewCodeIssuer(s.database)
	userSessionManager := usersession.NewManager(s.database)
	otpSecretGenerator := otp.NewKeyGenerator()
	tokenIssuer := issuance.NewTokenIssuer(s.database, s.cfg.AuthServer.BaseURL, s.cfg.AdminConsole.BaseURL, s.dataCipher, userSessionManager)
	// The tokens the token endpoint and /auth/issue answer with, and the token requests refused,
	// counted on the metrics listener (#400 decision 5).
	tokenMetrics := s.tokenMetrics
	userCreator := usercreation.New(s.database)
	emailSender := emaildelivery.NewSender(s.dataCipher)

	// One renderer, handed to each handler as the one role it answers in: handlers.PageRenderer
	// or handlers.JSONWriter (#435).
	httpHelper := s.newRenderer()
	ceremonyStore := ceremony.NewStore(s.sessionStore, sessionkeys.AuthServerSessionName)
	legalDocuments := legaldocuments.NewReader(s.database)

	// Two bearer guard sets, one per surface, because the two surfaces promise different refusal
	// bodies: the admin and account APIs their {error_code, error_description} envelope, /userinfo
	// the RFC 6749 {error, error_description} shape its handler answers in. The routes choose the
	// set; nothing reads the request path to decide (#435).
	apiBearer := middleware.NewBearerTokenForAPI(tokenParser)
	userinfoBearer := middleware.NewBearerTokenForUserInfo(tokenParser, httpHelper)

	authServerConfig := &s.cfg.AuthServer
	baseURL := authServerConfig.BaseURL
	adminConsoleBaseURL := s.cfg.AdminConsole.BaseURL
	maxUploadBytes := authServerConfig.ProfilePictureMaxSizeBytes
	rateLimiter := middleware.NewRateLimiter(
		ceremonyStore,
		httpHelper,
		// The token endpoint's error writer, through which LimitROPC answers a body that does not
		// parse and a credential count it could not read: a token request refused before the
		// handler, and counted as one.
		tokenMetrics.Refusals(httpHelper),
		auditLogger,
		authServerConfig.RateLimiterEnabled,
		sharedCredentialCounts(s.cfg.Database.Type, s.database),
		s.metrics,
	)
	emitRateLimiterConfigWarnings(
		authServerConfig.RateLimiterEnabled,
		authServerConfig.TrustProxyHeaders,
		authServerConfig.TrustedProxies,
	)

	pages.NotFound(handlers.HandleNotFoundGet(httpHelper))
	pages.Get("/", handlers.HandleIndexGet(adminConsoleBaseURL))
	// A legal document's public pages, which need no sign-in: its current version, and each
	// version by number (#622 decision 5).
	legalDocumentPage := handlers.HandleLegalDocumentGet(httpHelper, s.database)
	pages.Get("/legal/{shortName}", legalDocumentPage)
	pages.Get("/legal/{shortName}/versions/{version}", legalDocumentPage)
	// The email check runs ahead of the limiter, so a request refused for email being off spends
	// no budget and is never answered 429 (#542).
	pages.With(accounthandlers.ForgotPasswordRequiresEmail(httpHelper)).Get(emaillinks.ForgotPasswordPath, accounthandlers.HandleForgotPasswordGet(httpHelper))
	// The Turnstile challenge after the email check and ahead of the limiter, while it is on: a
	// submission without a verified token is refused before any tier counts it (#642 decision 5).
	pages.With(accounthandlers.ForgotPasswordRequiresEmail(httpHelper), accounthandlers.RequireForgotPasswordChallenge(httpHelper, s.challengeVerifier), rateLimiter.LimitForgotPwd).Post(emaillinks.ForgotPasswordPath, accounthandlers.HandleForgotPasswordPost(httpHelper, s.database, emailSender, auditLogger, s.jobs, s.dataCipher, baseURL))
	// The two endpoints an emailed link points at register from the constants the links are
	// built from, so a link and the endpoint it names cannot drift apart (#112, #434).
	pages.With(rateLimiter.LimitResetPwd).Get(emaillinks.ResetPasswordPath, accounthandlers.HandleResetPasswordGet(httpHelper, s.sessionStore, s.database, auditLogger, s.dataCipher))
	pages.With(rateLimiter.LimitResetPwd).Post(emaillinks.ResetPasswordPath, accounthandlers.HandleResetPasswordPost(httpHelper, s.sessionStore, s.database, passwordValidator, auditLogger, adminConsoleBaseURL))
	// One discovery document at both well-known addresses, OIDC Discovery 1.0's and RFC 8414's, so
	// the two cannot disagree: RFC 8414 section 3 allows more than one address and section 3.2 fields
	// beyond its own. RFC 8414 section 3.1's path-suffixed form has no route; a reverse proxy serving
	// an issuer with a path routes it here, as it strips the path for every other endpoint (#576).
	discovery := handlers.HandleWellKnownOIDCConfigGet(httpHelper, baseURL)
	getAndHead(protocol, "/.well-known/openid-configuration", discovery)
	getAndHead(protocol, "/.well-known/oauth-authorization-server", discovery)
	getAndHead(protocol, "/certs", handlers.HandleCertsGet(httpHelper, s.database))
	// /userinfo takes a user's access token whose scope carries openid, which is what OIDC Core 1.0
	// section 5.3 says the endpoint exists for (#449). The scope check comes first, as on every
	// user-token route (#104): a client credentials token can never carry openid, since that grant
	// refuses every OpenID Connect scope, so it stops there with 403 insufficient_scope, and
	// RequireUserBoundToken behind it is what would stop a client's token that ever carried it.
	// Refresh and ID tokens never get this far: the parse guard admits only an access token
	// for authserver (#401). GET and POST are separate registrations: a guard added to only one of
	// them leaves the other reachable.
	protocol.With(userinfoBearer.JwtAuthorizationHeaderToContext(), userinfoBearer.RequireBearerTokenScope("openid"), userinfoBearer.RequireUserBoundToken(), userinfoBearer.RequireValidSession(s.database)).Get("/userinfo", handlers.HandleUserInfoGetPost(httpHelper, s.database, auditLogger, baseURL, adminConsoleBaseURL))
	protocol.With(userinfoBearer.JwtAuthorizationHeaderToContext(), userinfoBearer.RequireBearerTokenScope("openid"), userinfoBearer.RequireUserBoundToken(), userinfoBearer.RequireValidSession(s.database)).Post("/userinfo", handlers.HandleUserInfoGetPost(httpHelper, s.database, auditLogger, baseURL, adminConsoleBaseURL))
	files.Get("/openapi.yaml", handlers.HandleOpenAPIGet())
	getAndHead(files, "/userinfo/picture/{subject}", handlers.HandleProfilePictureGet(httpHelper, s.database))
	getAndHead(files, "/client/logo/{clientIdentifier}", handlers.HandleClientLogoGet(httpHelper, s.database))

	// Dynamic Client Registration endpoint (RFC 7591)
	// Note: Already CSRF-exempt via middleware (server-to-server API)
	protocol.With(rateLimiter.LimitDCR).Post("/connect/register",
		handlers.HandleDynamicClientRegistrationPost(s.database, auditLogger, s.dataCipher))

	// Public API endpoints (no authentication required)
	publicSettingsHandler := handlers.NewPublicSettings(s.database, legalDocuments, baseURL)
	api.Get("/api/public/settings", publicSettingsHandler.ServeHTTP)

	// One route boundary and one client-error responder, shared by every ceremony route: the
	// ceremony load, its id check, the state gate, the step redirects and the error responses to a
	// client are each written once.
	ceremonyBoundary := handlers.NewCeremonyBoundary(httpHelper, ceremonyStore, auditLogger, baseURL, adminConsoleBaseURL)
	clientErrorResponder := handlers.NewClientErrorResponder(s.database, httpHelper)

	pages.Route("/auth", func(r *routing.Router) {
		// The admission tier ahead of both methods, one budget for the two: the GET writes a
		// browser-session row and the POST a parked-request row, on every request that passes its
		// first validation (#504).
		// A POST is parked and answered with a 303 to a GET, which runs the ceremony from it: the
		// POST arrives cross-site without the Lax session cookie and must not touch the browser's
		// own session (#246).
		r.With(rateLimiter.LimitAuthorize).Get("/authorize", handlers.HandleAuthorizeGet(ceremonyBoundary, clientErrorResponder, httpHelper, ceremonyStore, authflow.NewAuthorization(s.database, userSessionManager, authorizeValidator, tokenParser, clientErrorResponder, auditLogger, authflow.NewSilentAuthentication(s.database, userSessionManager, permissionChecker, auditLogger, legalDocuments))))
		r.With(rateLimiter.LimitAuthorize).Post("/authorize", handlers.HandleAuthorizePost(httpHelper, authflow.NewAuthorizationParking(authorizeValidator, s.database), baseURL))
		r.Get("/level1", handlers.HandleAuthLevel1Get(ceremonyBoundary, ceremonyStore))
		r.Get("/level1completed", handlers.HandleAuthLevel1CompletedGet(ceremonyBoundary, clientErrorResponder, httpHelper, ceremonyStore, authflow.NewLevel1Completion(s.database, userSessionManager)))
		r.Get("/level2", handlers.HandleAuthLevel2Get(ceremonyBoundary, httpHelper, ceremonyStore, authflow.NewLevel2Selection(s.database)))
		r.Get("/completed", handlers.HandleAuthCompletedGet(ceremonyBoundary, clientErrorResponder, httpHelper, ceremonyStore, handlers.NewDeviceCookie(s.cfg.AuthServer.IsCookieSecure()), authflow.NewCompletion(s.database, userSessionManager, auditLogger, permissionChecker, legalDocuments)))
		r.Get("/issue", handlers.HandleIssueGet(ceremonyBoundary, clientErrorResponder, httpHelper, ceremonyStore, authflow.NewIssuance(s.database, codeIssuer, tokenIssuer, userSessionManager, permissionChecker, auditLogger, tokenMetrics)))
		passwordPrompt := authflow.NewPasswordPrompt(s.database)
		r.Get("/pwd", handlers.HandleAuthPwdGet(ceremonyBoundary, httpHelper, passwordPrompt))
		// The Turnstile challenge ahead of the limiter, while it is on: a submission without a
		// verified token is refused before any tier counts it and before any password is compared
		// (#642 decision 5).
		r.With(handlers.RequirePasswordChallenge(ceremonyBoundary, httpHelper, passwordPrompt, s.challengeVerifier), rateLimiter.LimitPwd).Post("/pwd", handlers.HandleAuthPwdPost(ceremonyBoundary, httpHelper, ceremonyStore, rateLimiter, passwordPrompt, authflow.NewPasswordSubmission(s.database, auditLogger)))
		r.Get("/otp", handlers.HandleAuthOtpGet(ceremonyBoundary, httpHelper, ceremonyStore, authflow.NewOTPPrompt(s.database, otpSecretGenerator)))
		r.With(rateLimiter.LimitOtp).Post("/otp", handlers.HandleAuthOtpPost(ceremonyBoundary, httpHelper, ceremonyStore, rateLimiter, authflow.NewOTPSubmission(s.database, auditLogger, s.dataCipher)))
		// The set of recovery codes an authenticator set up during this sign-in came with, shown once
		// after the accepted setup code, and the Continue that goes on to /auth/completed (#257
		// decision 14). It checks no credential, so neither method is behind a limiter.
		r.Get("/recovery-codes", handlers.HandleAuthRecoveryCodesGet(ceremonyBoundary, httpHelper, ceremonyStore, authflow.NewRecoveryCodesPrompt(s.database)))
		r.Post("/recovery-codes", handlers.HandleAuthRecoveryCodesPost(ceremonyBoundary, ceremonyStore))
		legalAcceptance := authflow.NewLegalAcceptance(s.database, permissionChecker, auditLogger, legalDocuments)
		r.Get("/legal-acceptance", handlers.HandleLegalAcceptanceGet(ceremonyBoundary, clientErrorResponder, httpHelper, ceremonyStore, legalAcceptance))
		r.Post("/legal-acceptance", handlers.HandleLegalAcceptancePost(ceremonyBoundary, clientErrorResponder, httpHelper, ceremonyStore, legalAcceptance))
		r.Get("/consent", handlers.HandleConsentGet(ceremonyBoundary, httpHelper, ceremonyStore, authflow.NewConsentPrompt(s.database)))
		r.Post("/consent", handlers.HandleConsentPost(ceremonyBoundary, clientErrorResponder, httpHelper, ceremonyStore, authflow.NewConsentSubmission(s.database, permissionChecker, auditLogger)))
		r.Get("/logout", handlers.HandleLogoutGet(httpHelper, s.sessionStore, s.database, tokenParser, auditLogger, s.dataCipher))
		r.Get("/logout/declined", handlers.HandleLogoutDeclinedGet(httpHelper))
		r.Post("/logout", handlers.HandleLogoutPost(httpHelper, s.sessionStore, s.database, tokenParser, auditLogger, s.dataCipher))
	})
	// Token endpoint with ROPC rate limiting (RFC 6749 §4.3.2 MUST protect against brute force).
	// Outside the /auth group, which is mounted on the page branch whole, because it answers on the
	// token branch, the protocol branch counting its faults as refusals. The router answers POST
	// /auth/token from this route, behind the token branch alone; any other method falls to the
	// group its path is under, whose chain runs before the 405, as it did when the route was its
	// own (#435).
	token.With(rateLimiter.LimitROPC).Post("/auth/token", handlers.HandleTokenPost(httpHelper, s.database, tokenIssuer, tokenValidator, auditLogger, rateLimiter, tokenMetrics))
	// Token revocation (RFC 7009, #676), outside the /auth group for the reason the token endpoint
	// is, on a branch of its own that answers a fault 503. No rate limit: the client authenticates
	// before anything else, as at the token endpoint's grants that have none (decision 10).
	revoke.Post("/auth/revoke", handlers.HandleRevokePost(httpHelper, s.database, tokenParser, s.dataCipher, auditLogger, s.revocationMetrics))
	// Token introspection (RFC 7662, #676), outside the /auth group for the same reason, on a branch
	// of its own that counts the faults it answers. POST alone: every other method is a 405 the
	// endpoint answers itself rather than the /auth group's, so no token reaches a URL and the
	// refusal is not stored either (decision 13). No rate limit, as for revocation (decision 10).
	introspect.Post("/auth/introspect", handlers.HandleIntrospectPost(httpHelper, s.database, tokenParser, s.dataCipher, s.introspectionMetrics))
	introspect.Handle("/auth/introspect", handlers.HandleIntrospectOtherMethods())

	pages.Route("/account", func(r *routing.Router) {
		// While registration is unavailable both routes are a 404 ahead of the limiter, so a refused
		// submission spends no budget (#526 decision 2). The POST alone is limited: the GET renders
		// a static form, while the POST probes whether an address already has an account, sends
		// mail to it and writes a row.
		r.With(accounthandlers.RefuseUnavailableRegistration(httpHelper)).Get("/register", accounthandlers.HandleRegisterGet(httpHelper, ceremonyStore, legalDocuments))
		// The Turnstile challenge sits between the two, while it is on, as on forgot-password (#642).
		r.With(accounthandlers.RefuseUnavailableRegistration(httpHelper), accounthandlers.RequireRegistrationChallenge(httpHelper, ceremonyStore, legalDocuments, s.challengeVerifier), rateLimiter.LimitRegister).Post("/register", accounthandlers.HandleRegisterPost(httpHelper, ceremonyStore, legalDocuments, s.database, userCreator, emailValidator, passwordValidator, emailSender, auditLogger, s.jobs, s.dataCipher, baseURL, adminConsoleBaseURL))
	})
	// From emaillinks.AccountActivatePath, as the reset endpoints above are.
	pages.With(rateLimiter.LimitActivate).Get(emaillinks.AccountActivatePath, accounthandlers.HandleActivateGet(httpHelper, s.sessionStore, ceremonyStore, s.database, auditLogger, s.dataCipher))
	pages.With(rateLimiter.LimitActivate).Post(emaillinks.AccountActivatePath, accounthandlers.HandleActivatePost(httpHelper, s.sessionStore, ceremonyStore, s.database, userCreator, passwordValidator, auditLogger, baseURL, adminConsoleBaseURL))

	// Admin API routes
	api.Route("/api/v1/admin", func(r *routing.Router) {
		// FIRST in the group, ahead of the debug middleware and every guard. GET
		// /api/v1/admin/clients/{id}/secret returns a decrypted client secret, so RFC 6749
		// section 5.1's MUST reaches this group, and the 401 and 403 refusals below
		// commit their status themselves: anything mounted behind the guards would
		// never write the pair on a refusal (#247).
		r.Use(middleware.NoStore())
		r.Use(middleware.APIDebug(authServerConfig.DebugAPIRequests))
		r.Use(apiBearer.JwtAuthorizationHeaderToContext())
		r.Use(apiBearer.RequireValidSession(s.database))

		// Scope helper function
		scope := func(perm string) string {
			return builtin.AuthServerResourceIdentifier + ":" + perm
		}

		// Scope sets for granular authorization
		// Users domain: manage-users OR manage
		scopesUsers := []string{
			scope(builtin.ManageUsersPermissionIdentifier),
			scope(builtin.ManagePermissionIdentifier),
		}
		// Users read: admin-read OR manage-users OR manage
		scopesUsersRead := []string{
			scope(builtin.AdminReadPermissionIdentifier),
			scope(builtin.ManageUsersPermissionIdentifier),
			scope(builtin.ManagePermissionIdentifier),
		}
		// Clients domain: manage-clients OR manage
		scopesClients := []string{
			scope(builtin.ManageClientsPermissionIdentifier),
			scope(builtin.ManagePermissionIdentifier),
		}
		// Clients read: admin-read OR manage-clients OR manage
		scopesClientsRead := []string{
			scope(builtin.AdminReadPermissionIdentifier),
			scope(builtin.ManageClientsPermissionIdentifier),
			scope(builtin.ManagePermissionIdentifier),
		}
		// Settings domain: manage-settings OR manage
		scopesSettings := []string{
			scope(builtin.ManageSettingsPermissionIdentifier),
			scope(builtin.ManagePermissionIdentifier),
		}
		// Settings read: admin-read OR manage-settings OR manage
		scopesSettingsRead := []string{
			scope(builtin.AdminReadPermissionIdentifier),
			scope(builtin.ManageSettingsPermissionIdentifier),
			scope(builtin.ManagePermissionIdentifier),
		}
		// Any administrative scope: admin-read, any of the three domains, or manage
		scopesAnyAdmin := []string{
			scope(builtin.AdminReadPermissionIdentifier),
			scope(builtin.ManageUsersPermissionIdentifier),
			scope(builtin.ManageClientsPermissionIdentifier),
			scope(builtin.ManageSettingsPermissionIdentifier),
			scope(builtin.ManagePermissionIdentifier),
		}

		// User management routes
		r.With(apiBearer.RequireBearerTokenScopeAnyOf(scopesUsersRead)).Get("/users/search", apihandlers.HandleUsersSearchGet(s.database))
		r.With(apiBearer.RequireBearerTokenScopeAnyOf(scopesUsersRead)).Get("/users/{id}", apihandlers.HandleUserGet(s.database))
		r.With(apiBearer.RequireBearerTokenScopeAnyOf(scopesUsers)).Put("/users/{id}/enabled", apihandlers.HandleUserEnabledPut(s.database, auditLogger))
		r.With(apiBearer.RequireBearerTokenScopeAnyOf(scopesUsers)).Put("/users/{id}/profile", apihandlers.HandleUserProfilePut(s.database, profileValidator, auditLogger))
		r.With(apiBearer.RequireBearerTokenScopeAnyOf(scopesUsers)).Put("/users/{id}/address", apihandlers.HandleUserAddressPut(s.database, addressValidator, auditLogger))
		r.With(apiBearer.RequireBearerTokenScopeAnyOf(scopesUsers)).Put("/users/{id}/email", apihandlers.HandleUserEmailPut(s.database, emailValidator, auditLogger))
		r.With(apiBearer.RequireBearerTokenScopeAnyOf(scopesUsers)).Post("/users/{id}/email/verification-code", apihandlers.HandleUserEmailVerificationCodePost(s.database, auditLogger, s.dataCipher))
		r.With(apiBearer.RequireBearerTokenScopeAnyOf(scopesUsers)).Put("/users/{id}/phone", apihandlers.HandleUserPhonePut(s.database, phoneValidator, auditLogger))
		r.With(apiBearer.RequireBearerTokenScopeAnyOf(scopesUsers)).Put("/users/{id}/password", apihandlers.HandleUserPasswordPut(s.database, passwordValidator, auditLogger))
		r.With(apiBearer.RequireBearerTokenScopeAnyOf(scopesUsers)).Put("/users/{id}/otp", apihandlers.HandleUserOTPPut(s.database, auditLogger))
		r.With(apiBearer.RequireBearerTokenScopeAnyOf(scopesUsersRead)).Get("/users/{id}/profile-picture", apihandlers.HandleUserProfilePictureGet(s.database, baseURL))
		r.With(apiBearer.RequireBearerTokenScopeAnyOf(scopesUsers)).Post("/users/{id}/profile-picture", apihandlers.HandleUserProfilePicturePost(s.database, auditLogger, baseURL, maxUploadBytes))
		r.With(apiBearer.RequireBearerTokenScopeAnyOf(scopesUsers)).Delete("/users/{id}/profile-picture", apihandlers.HandleUserProfilePictureDelete(s.database, auditLogger))
		r.With(apiBearer.RequireBearerTokenScopeAnyOf(scopesUsers)).Post("/users/create", apihandlers.HandleUserCreatePost(httpHelper, s.database, userCreator, emailValidator, profileValidator, passwordValidator, auditLogger, emailSender, s.dataCipher, baseURL))
		r.With(apiBearer.RequireBearerTokenScopeAnyOf(scopesUsers)).Delete("/users/{id}", apihandlers.HandleUserDelete(s.database, auditLogger))

		// User attributes routes
		r.With(apiBearer.RequireBearerTokenScopeAnyOf(scopesUsersRead)).Get("/users/{id}/attributes", apihandlers.HandleUserAttributesGet(s.database))
		r.With(apiBearer.RequireBearerTokenScopeAnyOf(scopesUsersRead)).Get("/user-attributes/{id}", apihandlers.HandleUserAttributeGet(s.database))
		r.With(apiBearer.RequireBearerTokenScopeAnyOf(scopesUsers)).Post("/user-attributes", apihandlers.HandleUserAttributeCreatePost(s.database, identifierValidator, auditLogger))
		r.With(apiBearer.RequireBearerTokenScopeAnyOf(scopesUsers)).Put("/user-attributes/{id}", apihandlers.HandleUserAttributeUpdatePut(s.database, identifierValidator, auditLogger))
		r.With(apiBearer.RequireBearerTokenScopeAnyOf(scopesUsers)).Delete("/user-attributes/{id}", apihandlers.HandleUserAttributeDelete(s.database, auditLogger))

		// User session routes
		r.With(apiBearer.RequireBearerTokenScopeAnyOf(scopesUsersRead)).Get("/users/{id}/sessions", apihandlers.HandleUserSessionsGet(s.database))
		r.With(apiBearer.RequireBearerTokenScopeAnyOf(scopesUsersRead)).Get("/user-sessions/{id}", apihandlers.HandleUserSessionGet(s.database))
		r.With(apiBearer.RequireBearerTokenScopeAnyOf(scopesUsers)).Delete("/user-sessions/{id}", apihandlers.HandleUserSessionDelete(s.database, auditLogger))

		// User consent routes
		r.With(apiBearer.RequireBearerTokenScopeAnyOf(scopesUsersRead)).Get("/users/{id}/consents", apihandlers.HandleUserConsentsGet(s.database))
		r.With(apiBearer.RequireBearerTokenScopeAnyOf(scopesUsers)).Delete("/user-consents/{id}", apihandlers.HandleUserConsentDelete(s.database, auditLogger))

		// The legal document versions the user accepted, read as part of the user (#622 decision 6).
		r.With(apiBearer.RequireBearerTokenScopeAnyOf(scopesUsersRead)).Get("/users/{id}/legal-document-acceptances", apihandlers.HandleUserLegalDocumentAcceptancesGet(s.database, baseURL))

		// Group management routes
		r.With(apiBearer.RequireBearerTokenScopeAnyOf(scopesUsersRead)).Get("/groups", apihandlers.HandleGroupsGet(s.database))
		r.With(apiBearer.RequireBearerTokenScopeAnyOf(scopesUsers)).Post("/groups", apihandlers.HandleGroupCreatePost(s.database, identifierValidator, auditLogger))
		r.With(apiBearer.RequireBearerTokenScopeAnyOf(scopesUsersRead)).Get("/groups/{id}", apihandlers.HandleGroupGet(s.database))
		r.With(apiBearer.RequireBearerTokenScopeAnyOf(scopesUsers)).Put("/groups/{id}", apihandlers.HandleGroupUpdatePut(s.database, identifierValidator, auditLogger))
		r.With(apiBearer.RequireBearerTokenScopeAnyOf(scopesUsers)).Delete("/groups/{id}", apihandlers.HandleGroupDelete(s.database, auditLogger))
		r.With(apiBearer.RequireBearerTokenScopeAnyOf(scopesUsersRead)).Get("/groups/{id}/members", apihandlers.HandleGroupMembersGet(s.database))
		r.With(apiBearer.RequireBearerTokenScopeAnyOf(scopesUsers)).Post("/groups/{id}/members", apihandlers.HandleGroupMemberAddPost(s.database, auditLogger))
		r.With(apiBearer.RequireBearerTokenScopeAnyOf(scopesUsers)).Delete("/groups/{id}/members/{userId}", apihandlers.HandleGroupMemberDelete(s.database, auditLogger))
		r.With(apiBearer.RequireBearerTokenScopeAnyOf(scopesUsersRead)).Get("/users/{id}/groups", apihandlers.HandleUserGroupsGet(s.database))
		r.With(apiBearer.RequireBearerTokenScopeAnyOf(scopesUsers)).Put("/users/{id}/groups", apihandlers.HandleUserGroupsPut(s.database, auditLogger))

		// Group search
		r.With(apiBearer.RequireBearerTokenScopeAnyOf(scopesUsersRead)).Get("/groups/search", apihandlers.HandleGroupsSearchGet(s.database))

		// Group attributes routes
		r.With(apiBearer.RequireBearerTokenScopeAnyOf(scopesUsersRead)).Get("/groups/{id}/attributes", apihandlers.HandleGroupAttributesGet(s.database))
		r.With(apiBearer.RequireBearerTokenScopeAnyOf(scopesUsers)).Post("/group-attributes", apihandlers.HandleGroupAttributeCreatePost(s.database, identifierValidator, auditLogger))
		r.With(apiBearer.RequireBearerTokenScopeAnyOf(scopesUsersRead)).Get("/group-attributes/{id}", apihandlers.HandleGroupAttributeGet(s.database))
		r.With(apiBearer.RequireBearerTokenScopeAnyOf(scopesUsers)).Put("/group-attributes/{id}", apihandlers.HandleGroupAttributeUpdatePut(s.database, identifierValidator, auditLogger))
		r.With(apiBearer.RequireBearerTokenScopeAnyOf(scopesUsers)).Delete("/group-attributes/{id}", apihandlers.HandleGroupAttributeDelete(s.database, auditLogger))

		// User permissions routes
		r.With(apiBearer.RequireBearerTokenScopeAnyOf(scopesUsersRead)).Get("/users/{id}/permissions", apihandlers.HandleUserPermissionsGet(s.database))
		r.With(apiBearer.RequireBearerTokenScopeAnyOf(scopesUsers)).Put("/users/{id}/permissions", apihandlers.HandleUserPermissionsPut(s.database, auditLogger))

		// Group permissions routes
		r.With(apiBearer.RequireBearerTokenScopeAnyOf(scopesUsersRead)).Get("/groups/{id}/permissions", apihandlers.HandleGroupPermissionsGet(s.database))
		r.With(apiBearer.RequireBearerTokenScopeAnyOf(scopesUsers)).Put("/groups/{id}/permissions", apihandlers.HandleGroupPermissionsPut(s.database, auditLogger))

		// Users with a permission
		r.With(apiBearer.RequireBearerTokenScopeAnyOf(scopesUsersRead)).Get("/permissions/{permissionId}/users", apihandlers.HandlePermissionUsersGet(s.database))

		// Resources routes (part of settings domain - defines permissions structure)
		r.With(apiBearer.RequireBearerTokenScopeAnyOf(scopesSettingsRead)).Get("/resources", apihandlers.HandleResourcesGet(s.database))
		r.With(apiBearer.RequireBearerTokenScopeAnyOf(scopesSettings)).Post("/resources", apihandlers.HandleResourceCreatePost(s.database, identifierValidator, auditLogger))
		r.With(apiBearer.RequireBearerTokenScopeAnyOf(scopesSettingsRead)).Get("/resources/{id}", apihandlers.HandleResourceGet(s.database))
		r.With(apiBearer.RequireBearerTokenScopeAnyOf(scopesSettings)).Put("/resources/{id}", apihandlers.HandleResourceUpdatePut(s.database, identifierValidator, auditLogger))
		r.With(apiBearer.RequireBearerTokenScopeAnyOf(scopesSettings)).Delete("/resources/{id}", apihandlers.HandleResourceDelete(s.database, auditLogger))
		r.With(apiBearer.RequireBearerTokenScopeAnyOf(scopesSettingsRead)).Get("/resources/{resourceId}/permissions", apihandlers.HandlePermissionsByResourceGet(s.database))
		r.With(apiBearer.RequireBearerTokenScopeAnyOf(scopesSettings)).Put("/resources/{resourceId}/permissions", apihandlers.HandleResourcePermissionsPut(s.database, identifierValidator, auditLogger))

		// Legal documents (settings domain: a document sets rules for the whole instance, #622
		// decision 6). Reading also accepts admin-read; every change, the preview included, needs
		// manage-settings or manage.
		r.With(apiBearer.RequireBearerTokenScopeAnyOf(scopesSettingsRead)).Get("/legal-documents", apihandlers.HandleLegalDocumentsGet(s.database))
		r.With(apiBearer.RequireBearerTokenScopeAnyOf(scopesSettings)).Post("/legal-documents", apihandlers.HandleLegalDocumentCreatePost(s.database, auditLogger))
		r.With(apiBearer.RequireBearerTokenScopeAnyOf(scopesSettings)).Post("/legal-documents/preview", apihandlers.HandleLegalDocumentPreviewPost())
		r.With(apiBearer.RequireBearerTokenScopeAnyOf(scopesSettingsRead)).Get("/legal-documents/{id}", apihandlers.HandleLegalDocumentGet(s.database))
		r.With(apiBearer.RequireBearerTokenScopeAnyOf(scopesSettings)).Delete("/legal-documents/{id}", apihandlers.HandleLegalDocumentDelete(s.database, auditLogger))
		r.With(apiBearer.RequireBearerTokenScopeAnyOf(scopesSettings)).Put("/legal-documents/{id}/draft", apihandlers.HandleLegalDocumentDraftPut(s.database, auditLogger))
		r.With(apiBearer.RequireBearerTokenScopeAnyOf(scopesSettings)).Post("/legal-documents/{id}/publish", apihandlers.HandleLegalDocumentPublishPost(s.database, auditLogger))
		r.With(apiBearer.RequireBearerTokenScopeAnyOf(scopesSettings)).Post("/legal-documents/{id}/retire", apihandlers.HandleLegalDocumentRetirePost(s.database, auditLogger))
		r.With(apiBearer.RequireBearerTokenScopeAnyOf(scopesSettings)).Post("/legal-documents/{id}/restore", apihandlers.HandleLegalDocumentRestorePost(s.database, auditLogger))
		r.With(apiBearer.RequireBearerTokenScopeAnyOf(scopesSettings)).Put("/legal-documents/{id}/apps", apihandlers.HandleLegalDocumentAppsPut(s.database, auditLogger))
		r.With(apiBearer.RequireBearerTokenScopeAnyOf(scopesSettingsRead)).Get("/legal-documents/{id}/versions/{version}", apihandlers.HandleLegalDocumentVersionGet(s.database))

		// Client management routes
		r.With(apiBearer.RequireBearerTokenScopeAnyOf(scopesClientsRead)).Get("/clients", apihandlers.HandleClientsGet(s.database))
		r.With(apiBearer.RequireBearerTokenScopeAnyOf(scopesClientsRead)).Get("/clients/{id}", apihandlers.HandleClientGet(s.database))
		// The secret is a credential, so admin-read does not reach it (#403).
		r.With(apiBearer.RequireBearerTokenScopeAnyOf(scopesClients)).Get("/clients/{id}/secret", apihandlers.HandleClientSecretGet(s.database, auditLogger, s.dataCipher))
		r.With(apiBearer.RequireBearerTokenScopeAnyOf(scopesClientsRead)).Get("/clients/{id}/sessions", apihandlers.HandleClientSessionsGet(s.database))
		r.With(apiBearer.RequireBearerTokenScopeAnyOf(scopesClients)).Post("/clients", apihandlers.HandleClientCreatePost(s.database, identifierValidator, auditLogger, s.dataCipher))
		r.With(apiBearer.RequireBearerTokenScopeAnyOf(scopesClients)).Put("/clients/{id}", apihandlers.HandleClientUpdatePut(s.database, identifierValidator, auditLogger))
		r.With(apiBearer.RequireBearerTokenScopeAnyOf(scopesClients)).Put("/clients/{id}/authentication", apihandlers.HandleClientAuthenticationPut(s.database, auditLogger, s.dataCipher))
		r.With(apiBearer.RequireBearerTokenScopeAnyOf(scopesClients)).Put("/clients/{id}/oauth2-flows", apihandlers.HandleClientOAuth2FlowsPut(s.database, auditLogger))
		r.With(apiBearer.RequireBearerTokenScopeAnyOf(scopesClients)).Put("/clients/{id}/redirect-uris", apihandlers.HandleClientRedirectURIsPut(s.database, auditLogger))
		r.With(apiBearer.RequireBearerTokenScopeAnyOf(scopesClients)).Put("/clients/{id}/post-logout-redirect-uris", apihandlers.HandleClientPostLogoutRedirectURIsPut(s.database, auditLogger))
		r.With(apiBearer.RequireBearerTokenScopeAnyOf(scopesClients)).Put("/clients/{id}/web-origins", apihandlers.HandleClientWebOriginsPut(s.database, auditLogger))
		r.With(apiBearer.RequireBearerTokenScopeAnyOf(scopesClients)).Put("/clients/{id}/tokens", apihandlers.HandleClientTokensPut(s.database, auditLogger))
		r.With(apiBearer.RequireBearerTokenScopeAnyOf(scopesClientsRead)).Get("/clients/{id}/permissions", apihandlers.HandleClientPermissionsGet(s.database))
		r.With(apiBearer.RequireBearerTokenScopeAnyOf(scopesClients)).Put("/clients/{id}/permissions", apihandlers.HandleClientPermissionsPut(s.database, auditLogger))
		r.With(apiBearer.RequireBearerTokenScopeAnyOf(scopesClientsRead)).Get("/clients/{id}/introspection-resources", apihandlers.HandleClientIntrospectionResourcesGet(s.database))
		r.With(apiBearer.RequireBearerTokenScopeAnyOf(scopesClients)).Put("/clients/{id}/introspection-resources", apihandlers.HandleClientIntrospectionResourcesPut(s.database, auditLogger))
		// The legal documents that apply to the client, read as part of the client (#622 decision 6).
		r.With(apiBearer.RequireBearerTokenScopeAnyOf(scopesClientsRead)).Get("/clients/{id}/legal-documents", apihandlers.HandleClientLegalDocumentsGet(s.database))
		r.With(apiBearer.RequireBearerTokenScopeAnyOf(scopesClients)).Put("/clients/{id}/administrative-scopes", apihandlers.HandleClientAdministrativeScopesPut(s.database, auditLogger))
		r.With(apiBearer.RequireBearerTokenScopeAnyOf(scopesClients)).Delete("/clients/{id}", apihandlers.HandleClientDelete(s.database, auditLogger))
		r.With(apiBearer.RequireBearerTokenScopeAnyOf(scopesClientsRead)).Get("/clients/{id}/logo", apihandlers.HandleClientLogoGet(s.database, baseURL))
		r.With(apiBearer.RequireBearerTokenScopeAnyOf(scopesClients)).Post("/clients/{id}/logo", apihandlers.HandleClientLogoPost(s.database, auditLogger, baseURL, maxUploadBytes))
		r.With(apiBearer.RequireBearerTokenScopeAnyOf(scopesClients)).Delete("/clients/{id}/logo", apihandlers.HandleClientLogoDelete(s.database, auditLogger))

		// Settings - General
		r.With(apiBearer.RequireBearerTokenScopeAnyOf(scopesSettingsRead)).Get("/settings/general", apihandlers.HandleSettingsGeneralGet())
		r.With(apiBearer.RequireBearerTokenScopeAnyOf(scopesSettings)).Put("/settings/general", apihandlers.HandleSettingsGeneralPut(s.database, auditLogger, s.cfg.AuthServer.BaseURL))

		// Settings - Email
		r.With(apiBearer.RequireBearerTokenScopeAnyOf(scopesSettingsRead)).Get("/settings/email", apihandlers.HandleSettingsEmailGet())
		r.With(apiBearer.RequireBearerTokenScopeAnyOf(scopesSettings)).Put("/settings/email", apihandlers.HandleSettingsEmailPut(s.database, emailValidator, auditLogger, s.dataCipher))
		r.With(apiBearer.RequireBearerTokenScopeAnyOf(scopesSettings)).Post("/settings/email/send-test", apihandlers.HandleSettingsEmailSendTestPost(emailValidator, emailSender, auditLogger))

		// Settings - Turnstile
		r.With(apiBearer.RequireBearerTokenScopeAnyOf(scopesSettingsRead)).Get("/settings/turnstile", apihandlers.HandleSettingsTurnstileGet())
		r.With(apiBearer.RequireBearerTokenScopeAnyOf(scopesSettings)).Put("/settings/turnstile", apihandlers.HandleSettingsTurnstilePut(s.database, auditLogger, s.dataCipher))

		// Settings - Sessions
		r.With(apiBearer.RequireBearerTokenScopeAnyOf(scopesSettingsRead)).Get("/settings/sessions", apihandlers.HandleSettingsSessionsGet())
		r.With(apiBearer.RequireBearerTokenScopeAnyOf(scopesSettings)).Put("/settings/sessions", apihandlers.HandleSettingsSessionsPut(s.database, auditLogger))

		// Settings - UI Theme
		r.With(apiBearer.RequireBearerTokenScopeAnyOf(scopesSettingsRead)).Get("/settings/ui-theme", apihandlers.HandleSettingsUIThemeGet())
		r.With(apiBearer.RequireBearerTokenScopeAnyOf(scopesSettings)).Put("/settings/ui-theme", apihandlers.HandleSettingsUIThemePut(s.database, auditLogger))

		// Settings - Tokens
		r.With(apiBearer.RequireBearerTokenScopeAnyOf(scopesSettingsRead)).Get("/settings/tokens", apihandlers.HandleSettingsTokensGet())
		r.With(apiBearer.RequireBearerTokenScopeAnyOf(scopesSettings)).Put("/settings/tokens", apihandlers.HandleSettingsTokensPut(s.database, auditLogger))

		// Settings - Keys
		r.With(apiBearer.RequireBearerTokenScopeAnyOf(scopesSettingsRead)).Get("/settings/keys", apihandlers.HandleSettingsKeysGet(s.database))
		r.With(apiBearer.RequireBearerTokenScopeAnyOf(scopesSettings)).Post("/settings/keys/rotate", apihandlers.HandleSettingsKeysRotatePost(s.database, auditLogger, s.dataCipher))
		r.With(apiBearer.RequireBearerTokenScopeAnyOf(scopesSettings)).Delete("/settings/keys/{id}", apihandlers.HandleSettingsKeyDelete(s.database, auditLogger))

		// Settings - Audit Logs
		r.With(apiBearer.RequireBearerTokenScopeAnyOf(scopesSettingsRead)).Get("/settings/audit-logs", apihandlers.HandleSettingsAuditLogsGet())
		r.With(apiBearer.RequireBearerTokenScopeAnyOf(scopesSettings)).Put("/settings/audit-logs", apihandlers.HandleSettingsAuditLogsPut(s.database, auditLogger))

		// Audit Logs Viewer
		r.With(apiBearer.RequireBearerTokenScopeAnyOf(scopesSettingsRead)).Get("/audit-logs", apihandlers.HandleAuditLogsGet(s.database))
		// The catalog the auditEvent filter above accepts. Same read scope, because it describes
		// that endpoint and tells a caller nothing the endpoint itself does not (#351).
		r.With(apiBearer.RequireBearerTokenScopeAnyOf(scopesSettingsRead)).Get("/audit-logs/event-types", apihandlers.HandleAuditEventTypesGet())

		// Reference data routes (read-only, accessible by any admin scope). Static, so it reveals
		// nothing about any user, and a manage-users caller needs its ids to set a phone (#563).
		r.With(apiBearer.RequireBearerTokenScopeAnyOf(scopesAnyAdmin)).Get("/phone-countries", apihandlers.HandlePhoneCountriesGet())
	})

	// Account API routes (self-service)
	api.Route("/api/v1/account", func(r *routing.Router) {
		// FIRST in the group, for the same reason as the admin group above. GET
		// /api/v1/account/otp/enrollment serves a TOTP enrolment seed (#247).
		r.Use(middleware.NoStore())
		r.Use(middleware.APIDebug(authServerConfig.DebugAPIRequests))
		r.Use(apiBearer.JwtAuthorizationHeaderToContext())
		r.Use(apiBearer.RequireBearerTokenScope(builtin.AuthServerResourceIdentifier + ":" + builtin.ManageAccountPermissionIdentifier))
		// After the scope check, so an insufficient-scope caller still receives the 403 it
		// receives today. These handlers resolve the acting user from `sub`, which is the
		// client identifier on a client_credentials token, so the token type must be gated.
		r.Use(apiBearer.RequireUserBoundToken())
		r.Use(apiBearer.RequireValidSession(s.database))

		r.Get("/profile", apihandlers.HandleAccountProfileGet(s.database))
		r.Put("/profile", apihandlers.HandleAccountProfilePut(s.database, profileValidator, auditLogger))
		// The email change verifies the account password too, so it spends the same bucket as
		// the password and OTP changes below (#404). Past the password it says whether the address
		// is taken, so every change counts on the account first, and a request that tier refuses
		// never reaches the password check.
		r.With(rateLimiter.LimitAccountEmailChange, rateLimiter.LimitAccountPassword).Put("/email",
			apihandlers.HandleAccountEmailPut(httpHelper, s.database, emailValidator, emailSender, auditLogger, rateLimiter, s.jobs))
		// The send counts every request on the account, beside its own five minute resend cooldown:
		// the account chooses the address it mails, so each send is a mail to any address (#404).
		r.With(rateLimiter.LimitEmailVerificationSend).Post("/email/verification/send",
			apihandlers.HandleAccountEmailVerificationSendPost(httpHelper, s.database, emailSender, auditLogger, s.dataCipher, adminConsoleBaseURL))
		// The verification check counts failures only, in a bucket of its own.
		r.With(rateLimiter.LimitEmailVerification).Post("/email/verification",
			apihandlers.HandleAccountEmailVerificationPost(s.database, auditLogger, rateLimiter, s.dataCipher))
		r.Put("/phone", apihandlers.HandleAccountPhonePut(s.database, phoneValidator, auditLogger))
		r.Put("/address", apihandlers.HandleAccountAddressPut(s.database, addressValidator, auditLogger))
		// One limiter over these PUTs and the email change above, which is what makes the
		// failure budget shared: they verify the same password, so separate buckets would hand
		// an attacker more guesses by alternating. The enrollment GET between them checks no
		// credential.
		r.With(rateLimiter.LimitAccountPassword).Put("/password",
			apihandlers.HandleAccountPasswordPut(s.database, passwordValidator, auditLogger, rateLimiter))
		r.Get("/otp/enrollment", apihandlers.HandleAccountOTPEnrollmentGet(s.database, otpSecretGenerator, s.dataCipher))
		r.With(rateLimiter.LimitAccountPassword).Put("/otp",
			apihandlers.HandleAccountOTPPut(s.database, auditLogger, rateLimiter, s.dataCipher))
		// The count of unused recovery codes checks no credential; a new set takes the password,
		// so it spends the same bucket as the changes above (#257 decision 8).
		r.Get("/otp/recovery-codes", apihandlers.HandleAccountRecoveryCodesGet(s.database))
		r.With(rateLimiter.LimitAccountPassword).Post("/otp/recovery-codes",
			apihandlers.HandleAccountRecoveryCodesPost(s.database, auditLogger, rateLimiter))
		r.Get("/consents", apihandlers.HandleAccountConsentsGet(s.database))
		r.Delete("/consents/{id}", apihandlers.HandleAccountConsentDelete(s.database, auditLogger))
		// The legal document versions the caller accepted (#622 decision 10).
		r.Get("/legal-document-acceptances", apihandlers.HandleAccountLegalDocumentAcceptancesGet(s.database, baseURL))

		// Sessions (self-service)
		r.Get("/sessions", apihandlers.HandleAccountSessionsGet(s.database))
		r.Delete("/sessions/{id}", apihandlers.HandleAccountSessionDelete(s.database, auditLogger))

		// Logout request (self-service)
		r.Post("/logout-request", apihandlers.HandleAccountLogoutRequestPost(s.database, s.dataCipher, baseURL))

		// Profile picture (self-service)
		r.Get("/profile-picture", apihandlers.HandleAccountProfilePictureGet(s.database, baseURL))
		r.Post("/profile-picture", apihandlers.HandleAccountProfilePicturePost(s.database, auditLogger, baseURL, maxUploadBytes))
		r.Delete("/profile-picture", apihandlers.HandleAccountProfilePictureDelete(s.database, auditLogger))
	})

	// Browser session store, for the admin console (#266).
	//
	// The admin console keeps no database connection, so its browser sessions live in a
	// row here and it reaches them through these five operations. What it sends is
	// ciphertext encrypted with its own session keys, so nothing crossing this boundary
	// is readable on this side.
	//
	// POST throughout, with the session identifier in the body and never in the request
	// line: a handle in a path lands in this server's access log and in every proxy in
	// front of it.
	api.Route("/api/v1/sessions", func(r *routing.Router) {
		// FIRST in the group, for the same reason as the two groups above: every 200
		// here carries session ciphertext, and RFC 6749 section 5.1's MUST covers "any
		// response containing tokens, credentials, or other sensitive information".
		r.Use(middleware.NoStore())
		// No middleware.APIDebug here, and it is the only /api/v1 group without it. That
		// middleware logs whole request and response bodies, redacting by field name, and
		// this group's fields are called "id" and "data": neither matches its key set nor
		// its password/secret/otp/token substring net, so turning the debug flag on would
		// write every live admin console session handle into this server's log in the
		// clear, beside the session ciphertext. The identifier is in the body rather than
		// the request line precisely so that it never reaches a log, and a debug switch an
		// operator is offered must not be the thing that undoes it. Widening the redaction
		// set is not the alternative: "id" is a field name the rest of the admin and
		// account API uses everywhere, and redacting it would blind the surface this
		// middleware exists to make debuggable. What is lost is recoverable from the SQL
		// log, which records the digest rather than the handle (#266).
		r.Use(apiBearer.JwtAuthorizationHeaderToContext())
		// The same token lifecycle as the admin API: a token with the pre-#676 header, from
		// another issuer, of a disabled or deleted client, or revoked by its jti at
		// /auth/revoke is refused here too, rather than holding the console's sessions
		// until it expires. The console fetches a fresh token on a 401, so only a client
		// that can no longer get one stays out.
		r.Use(apiBearer.RequireValidSession(s.database))
		// One narrow permission of its own, deliberately not one of the manage-* admin
		// API scopes: holding the admin console's client secret must not be a way to
		// drive the whole admin API with no user present.
		r.Use(apiBearer.RequireBearerTokenScope(builtin.AuthServerResourceIdentifier + ":" + builtin.BrowserSessionsPermissionIdentifier))

		// No RequireUserBoundToken here, and the absence is deliberate. This endpoint is
		// reached only by a client_credentials token, which has no user behind it, so
		// RequireUserBoundToken would refuse every call.
		//
		// The handlers take a database and name the owner themselves. There is no owner
		// parameter anywhere in this group's contract, which is what makes reaching an
		// auth server session impossible to ask for rather than merely refused.
		r.Post("/load", apihandlers.HandleSessionLoadPost(s.database))
		r.Post("/create", apihandlers.HandleSessionCreatePost(s.database))
		r.Post("/update", apihandlers.HandleSessionUpdatePost(s.database))
		r.Post("/touch", apihandlers.HandleSessionTouchPost(s.database))
		r.Post("/delete", apihandlers.HandleSessionDeletePost(s.database))
	})
}
