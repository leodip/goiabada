package handlers

import (
	"io/fs"
	"net/http"

	datamocks "github.com/leodip/goiabada/authserver/internal/data/mocks"
	"github.com/leodip/goiabada/authserver/internal/tokenmetrics"
)

// The builders below are the one place a test constructs a ceremony route's handler. Each takes
// the doubles a test already holds, by name, and builds the handler from them, so a change to a
// handler's constructor changes its builder and no test. A field left out is nil, as the nil a
// test passed before. The two base URLs are always testBaseURL and testAdminConsoleBaseURL, and the
// data cipher always testDataCipher.

type authorizeGetDeps struct {
	pageRenderer       PageRenderer
	ceremonyStore      CeremonyStore
	userSessionManager UserSessionManager
	database           *datamocks.Database
	templateFS         fs.FS
	authorizeValidator AuthorizeValidator
	auditLogger        AuditLogger
	permissionChecker  PermissionChecker
	tokenParser        TokenParser
}

func buildAuthorizeGet(d authorizeGetDeps) http.HandlerFunc {
	return HandleAuthorizeGet(d.pageRenderer, d.ceremonyStore, d.userSessionManager, d.database, d.templateFS,
		d.authorizeValidator, d.auditLogger, d.permissionChecker, d.tokenParser, testBaseURL)
}

type authorizePostDeps struct {
	pageRenderer       PageRenderer
	authorizeValidator AuthorizeValidator
	database           *datamocks.Database
}

func buildAuthorizePost(d authorizePostDeps) http.HandlerFunc {
	return HandleAuthorizePost(d.pageRenderer, d.authorizeValidator, d.database, testBaseURL)
}

type authLevel1GetDeps struct {
	pageRenderer  PageRenderer
	ceremonyStore CeremonyStore
	auditLogger   AuditLogger
}

func buildAuthLevel1Get(d authLevel1GetDeps) http.HandlerFunc {
	return HandleAuthLevel1Get(d.pageRenderer, d.ceremonyStore, d.auditLogger, testBaseURL, testAdminConsoleBaseURL)
}

type authLevel1CompletedGetDeps struct {
	pageRenderer       PageRenderer
	ceremonyStore      CeremonyStore
	userSessionManager UserSessionManager
	database           *datamocks.Database
	templateFS         fs.FS
	auditLogger        AuditLogger
}

func buildAuthLevel1CompletedGet(d authLevel1CompletedGetDeps) http.HandlerFunc {
	return HandleAuthLevel1CompletedGet(d.pageRenderer, d.ceremonyStore, d.userSessionManager, d.database,
		d.templateFS, d.auditLogger, testBaseURL, testAdminConsoleBaseURL)
}

type authPwdGetDeps struct {
	pageRenderer  PageRenderer
	ceremonyStore CeremonyStore
	database      *datamocks.Database
	auditLogger   AuditLogger
}

func buildAuthPwdGet(d authPwdGetDeps) http.HandlerFunc {
	return HandleAuthPwdGet(d.pageRenderer, d.ceremonyStore, d.database, d.auditLogger, testAdminConsoleBaseURL)
}

// authPwdPostDeps.credentialFailures left out records nothing (noCredentialFailures).
type authPwdPostDeps struct {
	pageRenderer       PageRenderer
	ceremonyStore      CeremonyStore
	database           *datamocks.Database
	auditLogger        AuditLogger
	credentialFailures CredentialFailureRecorder
}

func buildAuthPwdPost(d authPwdPostDeps) http.HandlerFunc {
	return HandleAuthPwdPost(d.pageRenderer, d.ceremonyStore, d.database, d.auditLogger,
		credentialFailuresOrNone(d.credentialFailures), testBaseURL, testAdminConsoleBaseURL)
}

type authLevel2GetDeps struct {
	pageRenderer  PageRenderer
	ceremonyStore CeremonyStore
	database      *datamocks.Database
	auditLogger   AuditLogger
}

func buildAuthLevel2Get(d authLevel2GetDeps) http.HandlerFunc {
	return HandleAuthLevel2Get(d.pageRenderer, d.ceremonyStore, d.database, d.auditLogger,
		testBaseURL, testAdminConsoleBaseURL)
}

type authOtpGetDeps struct {
	pageRenderer       PageRenderer
	ceremonyStore      CeremonyStore
	database           *datamocks.Database
	otpSecretGenerator OtpSecretGenerator
	auditLogger        AuditLogger
}

func buildAuthOtpGet(d authOtpGetDeps) http.HandlerFunc {
	return HandleAuthOtpGet(d.pageRenderer, d.ceremonyStore, d.database, d.otpSecretGenerator, d.auditLogger,
		testAdminConsoleBaseURL)
}

// authOtpPostDeps.credentialFailures left out records nothing (noCredentialFailures).
type authOtpPostDeps struct {
	pageRenderer       PageRenderer
	ceremonyStore      CeremonyStore
	database           *datamocks.Database
	auditLogger        AuditLogger
	credentialFailures CredentialFailureRecorder
}

func buildAuthOtpPost(d authOtpPostDeps) http.HandlerFunc {
	return HandleAuthOtpPost(d.pageRenderer, d.ceremonyStore, d.database, d.auditLogger,
		credentialFailuresOrNone(d.credentialFailures), testDataCipher, testBaseURL, testAdminConsoleBaseURL)
}

type authCompletedGetDeps struct {
	pageRenderer       PageRenderer
	ceremonyStore      CeremonyStore
	userSessionManager UserSessionManager
	database           *datamocks.Database
	templateFS         fs.FS
	auditLogger        AuditLogger
	permissionChecker  PermissionChecker
}

func buildAuthCompletedGet(d authCompletedGetDeps) http.HandlerFunc {
	return HandleAuthCompletedGet(d.pageRenderer, d.ceremonyStore, d.userSessionManager, d.database,
		d.templateFS, d.auditLogger, d.permissionChecker, testBaseURL, testAdminConsoleBaseURL)
}

type consentGetDeps struct {
	pageRenderer  PageRenderer
	ceremonyStore CeremonyStore
	database      *datamocks.Database
	auditLogger   AuditLogger
}

func buildConsentGet(d consentGetDeps) http.HandlerFunc {
	return HandleConsentGet(d.pageRenderer, d.ceremonyStore, d.database, d.auditLogger,
		testBaseURL, testAdminConsoleBaseURL)
}

type consentPostDeps struct {
	pageRenderer      PageRenderer
	ceremonyStore     CeremonyStore
	database          *datamocks.Database
	templateFS        fs.FS
	auditLogger       AuditLogger
	permissionChecker PermissionChecker
}

func buildConsentPost(d consentPostDeps) http.HandlerFunc {
	return HandleConsentPost(d.pageRenderer, d.ceremonyStore, d.database, d.templateFS, d.auditLogger,
		d.permissionChecker, testBaseURL, testAdminConsoleBaseURL)
}

// issueGetDeps.tokenMetrics left out is a recorder over a registry of its own (testTokenMetrics).
type issueGetDeps struct {
	pageRenderer        PageRenderer
	ceremonyStore       CeremonyStore
	templateFS          fs.FS
	codeIssuer          CodeIssuer
	implicitTokenIssuer ImplicitTokenIssuer
	database            *datamocks.Database
	auditLogger         AuditLogger
	userSessionManager  UserSessionManager
	permissionChecker   PermissionChecker
	tokenMetrics        *tokenmetrics.Recorder
}

func buildIssueGet(d issueGetDeps) http.HandlerFunc {
	tokenMetrics := d.tokenMetrics
	if tokenMetrics == nil {
		tokenMetrics = testTokenMetrics()
	}
	return HandleIssueGet(d.pageRenderer, d.ceremonyStore, d.templateFS, d.codeIssuer, d.implicitTokenIssuer,
		d.database, d.auditLogger, d.userSessionManager, d.permissionChecker, tokenMetrics,
		testBaseURL, testAdminConsoleBaseURL)
}

func credentialFailuresOrNone(credentialFailures CredentialFailureRecorder) CredentialFailureRecorder {
	if credentialFailures == nil {
		return noCredentialFailures{}
	}
	return credentialFailures
}
