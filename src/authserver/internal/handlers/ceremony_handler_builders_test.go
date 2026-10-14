package handlers

import (
	"io/fs"
	"net/http"

	"github.com/leodip/goiabada/authserver/internal/authflow"
	datamocks "github.com/leodip/goiabada/authserver/internal/data/mocks"
	"github.com/leodip/goiabada/authserver/internal/tokenmetrics"
)

// The builders below are the one place a test constructs a ceremony route's handler. Each takes
// the doubles a test already holds, by name, and builds the handler from them, so a change to a
// handler's constructor changes its builder and no test. A field left out is nil, as the nil a
// test passed before. The two base URLs are always testBaseURL and testAdminConsoleBaseURL, and the
// data cipher always testDataCipher. The route boundary, the client-error responder and the authflow
// operations are built from the same doubles the handler takes, as the route table builds them from
// the same ports.

// testCeremonyBoundary is the route boundary the route table would build from these doubles.
func testCeremonyBoundary(pageRenderer PageRenderer, ceremonyStore CeremonyStore, auditLogger AuditLogger) *CeremonyBoundary {
	return NewCeremonyBoundary(pageRenderer, ceremonyStore, auditLogger, testBaseURL, testAdminConsoleBaseURL)
}

// testClientErrorResponder is the client-error responder the route table would build from these
// doubles.
func testClientErrorResponder(database *datamocks.Database, pageRenderer PageRenderer, templateFS fs.FS) *ClientErrorResponder {
	return NewClientErrorResponder(database, pageRenderer, templateFS)
}

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
	return HandleAuthorizeGet(testCeremonyBoundary(d.pageRenderer, d.ceremonyStore, d.auditLogger),
		testClientErrorResponder(d.database, d.pageRenderer, d.templateFS),
		d.pageRenderer, d.ceremonyStore, d.userSessionManager, d.database,
		d.authorizeValidator, d.auditLogger, d.permissionChecker, d.tokenParser)
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
	return HandleAuthLevel1Get(testCeremonyBoundary(d.pageRenderer, d.ceremonyStore, d.auditLogger), d.ceremonyStore)
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
	return HandleAuthLevel1CompletedGet(testCeremonyBoundary(d.pageRenderer, d.ceremonyStore, d.auditLogger),
		testClientErrorResponder(d.database, d.pageRenderer, d.templateFS),
		d.pageRenderer, d.ceremonyStore, authflow.NewLevel1Completion(d.database, d.userSessionManager))
}

type authPwdGetDeps struct {
	pageRenderer  PageRenderer
	ceremonyStore CeremonyStore
	database      *datamocks.Database
	auditLogger   AuditLogger
}

func buildAuthPwdGet(d authPwdGetDeps) http.HandlerFunc {
	return HandleAuthPwdGet(testCeremonyBoundary(d.pageRenderer, d.ceremonyStore, d.auditLogger),
		d.pageRenderer, d.database)
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
	return HandleAuthPwdPost(testCeremonyBoundary(d.pageRenderer, d.ceremonyStore, d.auditLogger),
		d.pageRenderer, d.ceremonyStore, d.database, d.auditLogger, credentialFailuresOrNone(d.credentialFailures))
}

type authLevel2GetDeps struct {
	pageRenderer  PageRenderer
	ceremonyStore CeremonyStore
	database      *datamocks.Database
	auditLogger   AuditLogger
}

func buildAuthLevel2Get(d authLevel2GetDeps) http.HandlerFunc {
	return HandleAuthLevel2Get(testCeremonyBoundary(d.pageRenderer, d.ceremonyStore, d.auditLogger),
		d.pageRenderer, d.ceremonyStore, authflow.NewLevel2Selection(d.database))
}

type authOtpGetDeps struct {
	pageRenderer       PageRenderer
	ceremonyStore      CeremonyStore
	database           *datamocks.Database
	otpSecretGenerator OtpSecretGenerator
	auditLogger        AuditLogger
}

func buildAuthOtpGet(d authOtpGetDeps) http.HandlerFunc {
	return HandleAuthOtpGet(testCeremonyBoundary(d.pageRenderer, d.ceremonyStore, d.auditLogger),
		d.pageRenderer, d.ceremonyStore, d.database, d.otpSecretGenerator)
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
	return HandleAuthOtpPost(testCeremonyBoundary(d.pageRenderer, d.ceremonyStore, d.auditLogger),
		d.pageRenderer, d.ceremonyStore, d.database, d.auditLogger, credentialFailuresOrNone(d.credentialFailures),
		testDataCipher)
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
	return HandleAuthCompletedGet(testCeremonyBoundary(d.pageRenderer, d.ceremonyStore, d.auditLogger),
		testClientErrorResponder(d.database, d.pageRenderer, d.templateFS),
		d.pageRenderer, d.ceremonyStore, d.userSessionManager, d.database, d.auditLogger, d.permissionChecker)
}

type consentGetDeps struct {
	pageRenderer  PageRenderer
	ceremonyStore CeremonyStore
	database      *datamocks.Database
	auditLogger   AuditLogger
}

func buildConsentGet(d consentGetDeps) http.HandlerFunc {
	return HandleConsentGet(testCeremonyBoundary(d.pageRenderer, d.ceremonyStore, d.auditLogger),
		d.pageRenderer, d.ceremonyStore, d.database)
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
	return HandleConsentPost(testCeremonyBoundary(d.pageRenderer, d.ceremonyStore, d.auditLogger),
		testClientErrorResponder(d.database, d.pageRenderer, d.templateFS),
		d.pageRenderer, d.ceremonyStore, d.database, d.auditLogger, d.permissionChecker)
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
	return HandleIssueGet(testCeremonyBoundary(d.pageRenderer, d.ceremonyStore, d.auditLogger),
		testClientErrorResponder(d.database, d.pageRenderer, d.templateFS),
		d.pageRenderer, d.ceremonyStore, d.codeIssuer, d.implicitTokenIssuer,
		d.database, d.auditLogger, d.userSessionManager, d.permissionChecker, tokenMetrics)
}

func credentialFailuresOrNone(credentialFailures CredentialFailureRecorder) CredentialFailureRecorder {
	if credentialFailures == nil {
		return noCredentialFailures{}
	}
	return credentialFailures
}
