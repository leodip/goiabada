package issuance

// The guides' example tokens, held to the tokens the grants issue (#522).
//
// Add sign-in to a web app shows the ID token a sign-in hands the app, and Protect an API shows the
// access token a service gets from the client credentials grant. Each is what a reader writes their
// checks against, so each example names exactly the claims its grant writes: a claim the grant never
// writes fails, and so does one it writes that the example leaves out. The values are illustrations
// and are not compared.
//
// It reads files and drives the issuer through a mocked database, and nothing else.

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/data/mocks"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/core/guard"
	"github.com/stretchr/testify/mock"
)

// The guides, relative to the repository root.
const (
	webAppGuide       = "site/src/content/docs/guides/add-sign-in-to-a-web-app.mdx"
	protectAnAPIGuide = "site/src/content/docs/guides/protect-an-api.mdx"
)

// guideSection is one section of a guide: the page, and its heading line as written.
type guideSection struct{ page, heading string }

var (
	signedInIDTokenSection = guideSection{webAppGuide, "### What the ID token says"}
	serviceTokenSection    = guideSection{protectAnAPIGuide, "### What a service's token carries"}
)

// signedInIDTokenClaims is the claims of the ID token the authorization code grant issues for the
// web app guide's sign-in: scope openid email, with a nonce, from a session, with the server's
// default of OpenID Connect claims in the ID token.
func signedInIDTokenClaims(t *testing.T) []string {
	t.Helper()
	mockDB := datamocks.NewDatabase(t)
	issuer := NewTokenIssuer(mockDB, "http://localhost:8081", testDataCipher, nil)
	code := armCodeMint(t, mockDB, func(string) {})
	code.Scope = "openid email"
	code.Nonce = "n-0S6_WzA2Mj"
	code.AcrLevel = record.AcrLevel2Optional
	code.User.EmailVerified = true

	settings := codeGrantSettings()
	settings.IncludeOpenIDConnectClaimsInIdToken = true
	response, err := issuer.mintAuthorizationCodeTokens(context.Background(), settings, code)
	if err != nil {
		t.Fatalf("minting the code's tokens: %v", err)
	}
	return claimNames(verifyAndDecodeToken(t, response.IdToken, getTestPublicKey(t)))
}

// serviceAccessTokenClaims is the claims of the access token the client credentials grant issues.
func serviceAccessTokenClaims(t *testing.T) []string {
	t.Helper()
	mockDB := datamocks.NewDatabase(t)
	issuer := NewTokenIssuer(mockDB, "http://localhost:8081", testDataCipher, nil)
	mockDB.On("GetCurrentSigningKey", mock.Anything, mock.Anything).Return(&record.KeyPair{
		KeyIdentifier: "test-key-id",
		PrivateKeyPEM: encryptPEM(t, getTestPrivateKey(t)),
	}, nil)

	settings := &record.Settings{Issuer: "https://auth.example.com", TokenExpirationInSeconds: 300}
	client := &record.Client{Id: 1, ClientIdentifier: "billing-service"}
	response, err := issuer.IssueClientCredentialsGrant(context.Background(), settings, client, "product-api:read")
	if err != nil {
		t.Fatalf("issuing the client credentials grant: %v", err)
	}
	return claimNames(verifyAndDecodeToken(t, response.AccessToken, getTestPublicKey(t)))
}

func claimNames[V any](claims map[string]V) []string {
	var names []string
	for name := range claims {
		names = append(names, name)
	}
	slices.Sort(names)
	return names
}

// The decoded ID token on Add sign-in to a web app names every claim the sign-in's ID token carries,
// and nothing else.
func TestGuideDocs_TheWebAppsIDTokenIsWhatTheSignInIssues(t *testing.T) {
	assertExampleToken(t, filepath.Dir(guard.SourceRoot(t)), signedInIDTokenSection,
		signedInIDTokenClaims(t), "the ID token of a sign-in")
}

// The decoded access token on Protect an API names every claim the client credentials grant writes,
// and nothing else.
func TestGuideDocs_TheServicesTokenIsWhatTheGrantIssues(t *testing.T) {
	assertExampleToken(t, filepath.Dir(guard.SourceRoot(t)), serviceTokenSection,
		serviceAccessTokenClaims(t), "a client credentials token")
}

func TestGuideDocs_AnExampleTokenDisagreeingWithTheGrantFails(t *testing.T) {
	root := t.TempDir()
	writeGuideFixture(t, root, "site/api.mdx", "### The token\n\n```json\n"+
		`{"iss": "https://auth.example.com", "sub": "billing-service", "sid": "x"}`+"\n```\n")

	report := guard.Run(func(r guard.Reporter) {
		assertExampleToken(r, root, guideSection{"site/api.mdx", "### The token"},
			[]string{"exp", "iss", "sub"}, "a client credentials token")
	})

	if report.Stopped {
		t.Fatalf("the check stopped rather than reporting: %s", report.Fatal)
	}
	want := []string{
		"site/api.mdx: ### The token's example token has sid, which a client credentials token never carries",
		"site/api.mdx: ### The token's example token has no exp, which a client credentials token carries",
	}
	if !slices.Equal(report.Errors, want) {
		t.Errorf("failures\n%q\nwant\n%q", report.Errors, want)
	}
}

func TestGuideDocs_AnExampleTokenAgreeingWithTheGrantPasses(t *testing.T) {
	root := t.TempDir()
	writeGuideFixture(t, root, "site/api.mdx", "### The token\n\nIt looks like this:\n\n```json\n"+
		"{\n  \"iss\": \"https://auth.example.com\",\n  \"sub\": \"billing-service\",\n  \"exp\": 1760000300\n}\n```\n")

	report := guard.Run(func(r guard.Reporter) {
		assertExampleToken(r, root, guideSection{"site/api.mdx", "### The token"},
			[]string{"exp", "iss", "sub"}, "a client credentials token")
	})

	if report.Stopped || len(report.Errors) > 0 {
		t.Errorf("an example naming exactly the grant's claims was refused: %+v", report)
	}
}

func TestGuideDocs_AMissingTokenSectionStops(t *testing.T) {
	root := t.TempDir()
	writeGuideFixture(t, root, "site/api.mdx", "### A token\n\n```json\n{\"iss\": \"x\"}\n```\n")

	report := guard.Run(func(r guard.Reporter) {
		assertExampleToken(r, root, guideSection{"site/api.mdx", "### The token"}, []string{"iss"}, "a token")
	})

	if !report.Stopped || !strings.Contains(report.Fatal, "### The token") {
		t.Errorf("a page without the section did not stop the check naming it: %+v", report)
	}
}

func TestGuideDocs_ATokenSectionWithNoExampleStops(t *testing.T) {
	root := t.TempDir()
	writeGuideFixture(t, root, "site/api.mdx", "### The token\n\nIt carries iss.\n\n### Next\n\n```json\n{\"iss\": \"x\"}\n```\n")

	report := guard.Run(func(r guard.Reporter) {
		assertExampleToken(r, root, guideSection{"site/api.mdx", "### The token"}, []string{"iss"}, "a token")
	})

	if !report.Stopped || !strings.Contains(report.Fatal, "no json example") {
		t.Errorf("a section with no example did not stop the check: %+v", report)
	}
}

// assertExampleToken is the reporting half of the example token checks: one failure per claim the
// example names that the token never carries, and per claim the token carries that the example
// leaves out; a stop for a section, or an example in it, not found or not read. token names the
// token in the failure.
func assertExampleToken(r guard.Reporter, root string, section guideSection, claims []string, token string) {
	r.Helper()
	example, err := guideExampleClaims(root, section)
	if err != nil {
		r.Fatalf("%v", err)
		return
	}
	for _, claim := range example {
		if !slices.Contains(claims, claim) {
			r.Errorf("%s: %s's example token has %s, which %s never carries", section.page, section.heading, claim, token)
		}
	}
	for _, claim := range claims {
		if !slices.Contains(example, claim) {
			r.Errorf("%s: %s's example token has no %s, which %s carries", section.page, section.heading, claim, token)
		}
	}
}

// guideExampleClaims is the top-level names of the first json code block in a section, the section
// being the text under its heading up to the next heading of the same level or above.
func guideExampleClaims(root string, section guideSection) ([]string, error) {
	content, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(section.page)))
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", section.page, err)
	}
	level := guideHeadingLevel(section.heading)
	var block []string
	inSection, inExample, inFence := false, false, false
	for _, line := range strings.Split(string(content), "\n") {
		fence := strings.HasPrefix(strings.TrimSpace(line), "```")
		switch {
		case inExample && fence:
			var claims map[string]json.RawMessage
			if err := json.Unmarshal([]byte(strings.Join(block, "\n")), &claims); err != nil {
				return nil, fmt.Errorf("%s: %s's json example does not read as an object: %w", section.page, section.heading, err)
			}
			return claimNames(claims), nil
		case inExample:
			block = append(block, line)
		case inFence:
			inFence = !fence
		case fence:
			inExample = inSection && strings.TrimSpace(line) == "```json"
			inFence = !inExample
		case !inSection:
			inSection = strings.TrimRight(line, " \r") == section.heading
		default:
			if headingLevel := guideHeadingLevel(line); headingLevel > 0 && headingLevel <= level {
				return nil, fmt.Errorf("%s: %s has no json example", section.page, section.heading)
			}
		}
	}
	if !inSection {
		return nil, fmt.Errorf("%s has no section headed %q", section.page, section.heading)
	}
	return nil, fmt.Errorf("%s: %s has no json example", section.page, section.heading)
}

// guideHeadingLevel is the number of #s a Markdown heading line opens with, or 0 for any other line.
func guideHeadingLevel(line string) int {
	level := len(line) - len(strings.TrimLeft(line, "#"))
	if level == 0 || !strings.HasPrefix(line[level:], " ") {
		return 0
	}
	return level
}

func writeGuideFixture(t *testing.T, root, name, content string) {
	t.Helper()
	path := filepath.Join(root, filepath.FromSlash(name))
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("creating %s: %v", filepath.Dir(path), err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("writing %s: %v", path, err)
	}
}
