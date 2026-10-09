package handlers

// The registration a guide shows, held to what the auth server answers it (#522).
//
// Let clients register themselves (DCR) shows a tool registering itself: the request it sends to
// /connect/register and the answer it gets back, which is what the tool's author writes their code
// against. The request is sent to the registration handler as written, and the example answer must
// name exactly the fields the handler answers it with: a field the handler never sends fails, and
// so does one it sends that the example leaves out. The values are illustrations and are not
// compared, but the status line is.
//
// It reads files and runs the registration handler over a stub database.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/mock"

	"github.com/leodip/goiabada/authserver/internal/audit"
	"github.com/leodip/goiabada/authserver/internal/ceremony"
	"github.com/leodip/goiabada/authserver/internal/data/mocks"
	"github.com/leodip/goiabada/authserver/internal/handlers/mocks"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/authserver/internal/reqctx"
	"github.com/leodip/goiabada/core/guard"
)

// The guides, relative to the repository root.
const (
	registrationGuide = "site/src/content/docs/guides/let-clients-register-themselves-dcr.mdx"
	twoFactorGuide    = "site/src/content/docs/guides/require-two-factor-authentication.mdx"
)

var (
	registrationExampleSection = conceptSection{registrationGuide, "## Register your app"}
	alreadySignedInSection     = conceptSection{twoFactorGuide, "### Users who are already signed in"}
	requireACodeSection        = conceptSection{twoFactorGuide, "## Require a code for your app"}
)

// registrationExample is the request a section shows and the answer it shows for it.
type registrationExample struct {
	requestBody  string
	answerStatus string
	answerFields []string
}

// registrationAnswer is the status line and the top-level fields the registration handler answers
// body with, over a database that accepts every write.
func registrationAnswer(t *testing.T, body string) (string, []string) {
	t.Helper()
	database := datamocks.NewDatabase(t)
	auditLogger := handlersmocks.NewAuditLogger(t)
	datamocks.ExpectRunInTransaction(database, dcrTx)
	database.On("CreateClient", mock.Anything, dcrTx, mock.Anything).Return(nil).Maybe()
	database.On("CreateRedirectURI", mock.Anything, dcrTx, mock.Anything).Return(nil).Maybe()
	auditLogger.On("Log", mock.Anything, audit.EventDynamicClientRegistration, mock.Anything).Return().Maybe()

	req := httptest.NewRequest(http.MethodPost, "/connect/register", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(reqctx.WithSettings(req.Context(), &record.Settings{Id: 1, DynamicClientRegistrationEnabled: true}))
	rr := httptest.NewRecorder()
	HandleDynamicClientRegistrationPost(database, auditLogger, testDataCipher).ServeHTTP(rr, req)

	var answer map[string]json.RawMessage
	if err := json.Unmarshal(rr.Body.Bytes(), &answer); err != nil {
		t.Fatalf("the handler answered %d with %q, which is not a JSON object", rr.Code, rr.Body.String())
	}
	return fmt.Sprintf("%d %s", rr.Code, http.StatusText(rr.Code)), sortedNames(answer)
}

func sortedNames(object map[string]json.RawMessage) []string {
	names := make([]string, 0, len(object))
	for name := range object {
		names = append(names, name)
	}
	slices.Sort(names)
	return names
}

// Require two-factor authentication says that a session which already reached the client's level is
// reused without asking for a code, which is what StepUpOwed decides for a level 3 sign-in over a
// level 3 session whose two-factor settings are unchanged (#522 decision 13).
func TestGuideDocs_ASessionAtTheLevelIsReusedWithoutACode(t *testing.T) {
	session := &record.UserSession{
		AcrLevel:            record.AcrLevel2Mandatory,
		OtpConfigGeneration: 2,
		User:                record.User{OtpConfigGeneration: 2},
	}
	step, err := ceremony.StepUpOwed(record.AcrLevel2Mandatory, session)
	if err != nil {
		t.Fatalf("%v", err)
	}
	if step != ceremony.StepUpNone {
		t.Fatalf("a level 3 session owes %v at level 3, so the guide's sentence no longer holds", step)
	}
	assertSectionSays(t, filepath.Dir(guard.SourceRoot(t)), alreadySignedInSection, []string{
		"A user whose session already reached the client's level isn't asked for anything: the session is reused",
	})
}

// Require two-factor authentication promises a code at a sign-in that starts a session, and at a
// request with prompt=login, whatever the session already gave, not at every sign-in with a password:
// SSO reuses a session at the level. prompt=login is a new authentication (OIDC Core 1.0 section
// 3.1.2.3), so HandleAuthLevel1CompletedGet decides its step-up as for a sign-in with no session and
// sends a level 3 target to /auth/level2 over the user's own level 3 session (#537). Until #537 the
// session's code counted and the guide said prompt=login "doesn't ask for a code" (#522 decision 13).
func TestGuideDocs_PromptLoginAsksForTheCodeAgain(t *testing.T) {
	ceremonyStore := handlersmocks.NewCeremonyStore(t)
	database := datamocks.NewDatabase(t)
	handler := HandleAuthLevel1CompletedGet(handlersmocks.NewPageRenderer(t), ceremonyStore,
		handlersmocks.NewUserSessionManager(t), database, nil, handlersmocks.NewAuditLogger(t),
		testBaseURL, testAdminConsoleBaseURL)

	req, _ := http.NewRequest("GET", "/auth/level1completed?ceremony="+testCeremonyId, nil)
	req = withSessionSettings(req)
	req = req.WithContext(reqctx.WithSessionIdentifier(req.Context(), "s"))
	rr := httptest.NewRecorder()
	ceremonyStore.On("GetAuthContext", mock.Anything).Return(&ceremony.AuthContext{
		CeremonyId: testCeremonyId, AuthState: ceremony.AuthStateLevel1PasswordCompleted,
		Level1AuthCompleted: true, ClientId: "app", UserId: 1,
	}, nil)
	session := &record.UserSession{Id: 1, UserId: 1, AcrLevel: record.AcrLevel2Mandatory, AuthMethods: "pwd otp",
		OtpConfigGeneration: 2, User: record.User{Id: 1, OTPEnabled: true, OtpConfigGeneration: 2}}
	database.On("GetUserSessionBySessionIdentifier", mock.Anything, mock.Anything, "s").Return(session, nil)
	database.On("UserSessionLoadUser", mock.Anything, mock.Anything, session).Return(nil)
	database.On("GetClientByClientIdentifier", mock.Anything, mock.Anything, "app").
		Return(&record.Client{Id: 1, ClientIdentifier: "app", DefaultAcrLevel: record.AcrLevel2Mandatory}, nil)
	ceremonyStore.On("SaveAuthContext", mock.Anything, mock.Anything, mock.Anything).Return(nil)

	handler.ServeHTTP(rr, req)
	if got := rr.Header().Get("Location"); got != testBaseURL+"/auth/level2?ceremony="+testCeremonyId {
		t.Fatalf("prompt=login over a level 3 session went to %q rather than the code step, so the guide's sentences no longer hold", got)
	}

	root := filepath.Dir(guard.SourceRoot(t))
	assertSectionSays(t, root, requireACodeSection, []string{
		"From then on, a sign-in that starts a new session asks for your password and then a code.",
		"A request that asks for a fresh sign-in, with `prompt=login`, asks for both, whatever the session already gave.",
	})
	assertSectionSays(t, root, alreadySignedInSection, []string{
		"`prompt=login` doesn't reuse the session: the user signs in again with their password and a code, whatever their session already gave",
	})
	page, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(twoFactorGuide)))
	if err != nil {
		t.Fatalf("%v", err)
	}
	for _, promise := range []string{
		"whenever a user signs in with their password",
		"each time you sign in with your password",
		"the code their session already gave still counts",
		"doesn't ask for a code",
	} {
		if strings.Contains(string(page), promise) {
			t.Errorf("%s says %q, which the sign-in no longer does", twoFactorGuide, promise)
		}
	}
}

// The registration on Let clients register themselves (DCR) is answered with the status and exactly
// the fields its example answer shows.
func TestGuideDocs_TheRegistrationExampleIsWhatTheHandlerAnswers(t *testing.T) {
	root := filepath.Dir(guard.SourceRoot(t))
	example, err := guideRegistrationExample(root, registrationExampleSection)
	if err != nil {
		t.Fatalf("%v", err)
	}
	status, fields := registrationAnswer(t, example.requestBody)
	assertRegistrationExample(t, root, registrationExampleSection, status, fields)
}

func TestGuideDocs_ARegistrationExampleDisagreeingWithTheAnswerFails(t *testing.T) {
	root := t.TempDir()
	writeConceptFixture(t, root, "site/dcr.mdx", "## Register your app\n\n"+
		"```http\nPOST /connect/register HTTP/1.1\nContent-Type: application/json\n\n"+
		`{"redirect_uris": ["http://127.0.0.1/callback"], "token_endpoint_auth_method": "none"}`+"\n```\n\n"+
		"```http\nHTTP/1.1 200 OK\nContent-Type: application/json\n\n"+
		`{"client_id": "dcr_x", "client_secret": "s", "redirect_uris": []}`+"\n```\n")

	report := guard.Run(func(r guard.Reporter) {
		assertRegistrationExample(r, root, conceptSection{"site/dcr.mdx", "## Register your app"},
			"201 Created", []string{"client_id", "grant_types", "redirect_uris"})
	})

	want := []string{
		`site/dcr.mdx: ## Register your app's example answer is "200 OK", where the auth server answers "201 Created"`,
		"site/dcr.mdx: ## Register your app's example answer has client_secret, which the auth server does not send for that request",
		"site/dcr.mdx: ## Register your app's example answer has no grant_types, which the auth server sends for that request",
	}
	if report.Stopped || !slices.Equal(report.Errors, want) {
		t.Errorf("failures\n%q\nwant\n%q", report.Errors, want)
	}
}

func TestGuideDocs_ARegistrationExampleAgreeingWithTheAnswerPasses(t *testing.T) {
	root := t.TempDir()
	writeConceptFixture(t, root, "site/dcr.mdx", "## Register your app\n\n"+
		"```http\nPOST /connect/register HTTP/1.1\nContent-Type: application/json\n\n{}\n```\n\n"+
		"```http\nHTTP/1.1 201 Created\nContent-Type: application/json\n\n"+
		"{\n  \"client_id\": \"dcr_x\",\n  \"redirect_uris\": []\n}\n```\n")

	report := guard.Run(func(r guard.Reporter) {
		assertRegistrationExample(r, root, conceptSection{"site/dcr.mdx", "## Register your app"},
			"201 Created", []string{"client_id", "redirect_uris"})
	})

	if report.Stopped || len(report.Errors) > 0 {
		t.Errorf("an example naming exactly the answer's fields was refused: %+v", report)
	}
}

func TestGuideDocs_AMissingRegistrationSectionStops(t *testing.T) {
	root := t.TempDir()
	writeConceptFixture(t, root, "site/dcr.mdx", "## Register something\n\n```http\nPOST /connect/register HTTP/1.1\n\n{}\n```\n")

	report := guard.Run(func(r guard.Reporter) {
		assertRegistrationExample(r, root, conceptSection{"site/dcr.mdx", "## Register your app"}, "201 Created", nil)
	})

	if !report.Stopped || !strings.Contains(report.Fatal, "## Register your app") {
		t.Errorf("a page without the section did not stop the check naming it: %+v", report)
	}
}

func TestGuideDocs_ARegistrationSectionWithNoAnswerStops(t *testing.T) {
	root := t.TempDir()
	writeConceptFixture(t, root, "site/dcr.mdx", "## Register your app\n\n"+
		"```http\nPOST /connect/register HTTP/1.1\n\n{}\n```\n\n## Next\n\n```http\nHTTP/1.1 201 Created\n\n{}\n```\n")

	report := guard.Run(func(r guard.Reporter) {
		assertRegistrationExample(r, root, conceptSection{"site/dcr.mdx", "## Register your app"}, "201 Created", nil)
	})

	if !report.Stopped || !strings.Contains(report.Fatal, "no example answer") {
		t.Errorf("a section with no answer did not stop the check: %+v", report)
	}
}

// assertRegistrationExample is the reporting half of the registration check: one failure for a
// status line other than the one the handler answers, and one per field the example answer names
// that the handler does not send, or that the handler sends and the example leaves out; a stop for
// a section, or an example in it, not found or not read.
func assertRegistrationExample(r guard.Reporter, root string, section conceptSection, status string, fields []string) {
	r.Helper()
	example, err := guideRegistrationExample(root, section)
	if err != nil {
		r.Fatalf("%v", err)
		return
	}
	if example.answerStatus != status {
		r.Errorf("%s: %s's example answer is %q, where the auth server answers %q",
			section.page, section.heading, example.answerStatus, status)
	}
	for _, field := range example.answerFields {
		if !slices.Contains(fields, field) {
			r.Errorf("%s: %s's example answer has %s, which the auth server does not send for that request",
				section.page, section.heading, field)
		}
	}
	for _, field := range fields {
		if !slices.Contains(example.answerFields, field) {
			r.Errorf("%s: %s's example answer has no %s, which the auth server sends for that request",
				section.page, section.heading, field)
		}
	}
}

// guideRegistrationExample reads a section's http blocks: the first one opening with a POST to
// /connect/register is the request, and the first one opening with a status line is the answer. Each
// one's body is what follows its first blank line.
func guideRegistrationExample(root string, section conceptSection) (registrationExample, error) {
	content, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(section.page)))
	if err != nil {
		return registrationExample{}, fmt.Errorf("reading %s: %w", section.page, err)
	}
	level := conceptHeadingLevel(section.heading)
	var blocks [][]string
	var block []string
	inSection, inHTTP, inFence := false, false, false
	for _, line := range strings.Split(string(content), "\n") {
		trimmed := strings.TrimSpace(line)
		fence := strings.HasPrefix(trimmed, "```")
		switch {
		case inHTTP && fence:
			blocks = append(blocks, block)
			inHTTP, block = false, nil
		case inHTTP:
			block = append(block, trimmed)
		case inFence:
			inFence = !fence
		case !inSection:
			inSection = strings.TrimRight(line, " \r") == section.heading
		case fence:
			inHTTP = trimmed == "```http"
			inFence = !inHTTP
		default:
			if headingLevel := conceptHeadingLevel(line); headingLevel > 0 && headingLevel <= level {
				return readRegistrationBlocks(section, blocks)
			}
		}
	}
	if !inSection {
		return registrationExample{}, fmt.Errorf("%s has no section headed %q", section.page, section.heading)
	}
	return readRegistrationBlocks(section, blocks)
}

func readRegistrationBlocks(section conceptSection, blocks [][]string) (registrationExample, error) {
	var example registrationExample
	var haveRequest, haveAnswer bool
	for _, block := range blocks {
		if len(block) == 0 {
			continue
		}
		blank := slices.Index(block, "")
		if blank < 0 {
			blank = len(block)
		}
		body := strings.Join(block[blank:], "\n")
		switch {
		case !haveRequest && strings.HasPrefix(block[0], "POST /connect/register "):
			example.requestBody, haveRequest = strings.TrimSpace(body), true
		case !haveAnswer && strings.HasPrefix(block[0], "HTTP/1.1 "):
			var answer map[string]json.RawMessage
			if err := json.NewDecoder(bytes.NewReader([]byte(body))).Decode(&answer); err != nil {
				return registrationExample{}, fmt.Errorf("%s: %s's example answer does not read as an object: %w",
					section.page, section.heading, err)
			}
			example.answerStatus = strings.TrimPrefix(block[0], "HTTP/1.1 ")
			example.answerFields, haveAnswer = sortedNames(answer), true
		}
	}
	if !haveRequest {
		return registrationExample{}, fmt.Errorf("%s: %s has no example request to POST /connect/register", section.page, section.heading)
	}
	if !haveAnswer {
		return registrationExample{}, fmt.Errorf("%s: %s has no example answer", section.page, section.heading)
	}
	return example, nil
}
