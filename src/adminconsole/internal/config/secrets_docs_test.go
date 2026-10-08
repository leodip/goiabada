package config

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/leodip/goiabada/core/guard"
)

// The pages that document the deployment's secrets, relative to the repository root, and the
// sections of each that name them. A section runs from its heading to the next heading of the same
// level, and a section with no heading is the whole page. The auth server's tier reads the same
// sections.
const (
	kubernetesSecretsPage = "site/src/content/docs/deploy/kubernetes/secrets.mdx"
	secretsPage           = "site/src/content/docs/deploy/secrets.mdx"
	rotatePage            = "site/src/content/docs/deploy/rotate-secrets.mdx"
	upgradePage           = "site/src/content/docs/deploy/upgrade-goiabada.mdx"
)

type docSection struct{ page, heading string }

func (s docSection) String() string {
	if s.heading == "" {
		return s.page
	}
	return s.page + ": " + s.heading
}

var secretsDocs = []docSection{
	{kubernetesSecretsPage, ""},
	{secretsPage, ""},
	{rotatePage, ""},
	{upgradePage, "## Update to a new release"},
}

// rotationPlatforms are the tabs Rotate secrets tells every rotation in.
var rotationPlatforms = []string{"Docker Compose", "Native binaries", "Kubernetes"}

// The secrets docs name only admin console variables this console reads. A misspelt variable in
// a rotation procedure is ignored, and the rotation then signs every administrator out. Every
// other GOIABADA_ variable is the auth server's tier to check (#396 decision 18).
func TestSecretsDocs_NameOnlyVariablesTheServersRead(t *testing.T) {
	assertSecretsDocsVariables(t, filepath.Dir(guard.SourceRoot(t)), secretsDocs, readVariables())
}

// Every rotation is told once, on Rotate secrets, with a tab per platform, so each platform's tabs
// name every _PREVIOUS variable this console reads (#522 decision 15).
func TestRotateSecretsDocs_EveryPlatformTellsEveryRotation(t *testing.T) {
	assertRotationTabs(t, filepath.Dir(guard.SourceRoot(t)), rotatePage, rotationPlatforms, readVariables())
}

func TestSecretsDocs_AnUnreadVariableFails(t *testing.T) {
	root := t.TempDir()
	writeManifestFixture(t, root, "site/k8s.mdx", "intro GOIABADA_ADMINCONSOLE_OUTSIDE\n\n"+
		"## Secrets\n\nSet GOIABADA_ADMINCONSOLE_BASEURL and GOIABADA_ADMINCONSOLE_SESSION_KEY_TYPO.\n\n"+
		"```bash\n## not a heading inside a fence: GOIABADA_ADMINCONSOLE_IN_FENCE\n```\n\n"+
		"Ignored here: GOIABADA_AUTHSERVER_ANYTHING.\n\n"+
		"## Next\n\nGOIABADA_ADMINCONSOLE_AFTER_THE_SECTION\n")
	writeManifestFixture(t, root, "site/rotate.mdx", "GOIABADA_ADMINCONSOLE_BASEURL_PREVIOUS\n\n"+
		"## Anything\n\nGOIABADA_ADMINCONSOLE_ROTATION_TYPO\n")

	report := guard.Run(func(r guard.Reporter) {
		assertSecretsDocsVariables(r, root,
			[]docSection{{"site/k8s.mdx", "## Secrets"}, {"site/rotate.mdx", ""}},
			map[string]bool{"GOIABADA_ADMINCONSOLE_BASEURL": true, "GOIABADA_ADMINCONSOLE_BASEURL_PREVIOUS": true})
	})

	if report.Stopped {
		t.Fatalf("the check stopped rather than reporting: %s", report.Fatal)
	}
	text := report.Text()
	for _, want := range []string{
		"site/k8s.mdx: ## Secrets names GOIABADA_ADMINCONSOLE_SESSION_KEY_TYPO",
		"site/k8s.mdx: ## Secrets names GOIABADA_ADMINCONSOLE_IN_FENCE",
		"site/rotate.mdx names GOIABADA_ADMINCONSOLE_ROTATION_TYPO",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("no failure says %q:\n%s", want, text)
		}
	}
	for _, unwanted := range []string{"OUTSIDE", "AFTER_THE_SECTION", "AUTHSERVER_ANYTHING", "BASEURL_PREVIOUS"} {
		if strings.Contains(text, unwanted) {
			t.Errorf("a failure names %s, which is outside the sections, read, or the auth server's to check:\n%s", unwanted, text)
		}
	}
	if len(report.Errors) != 3 {
		t.Errorf("%d failures, want 3:\n%s", len(report.Errors), text)
	}
}

func TestSecretsDocs_AMissingSectionStops(t *testing.T) {
	root := t.TempDir()
	writeManifestFixture(t, root, "site/k8s.mdx", "## Secret\n\nGOIABADA_ADMINCONSOLE_BASEURL\n")

	report := guard.Run(func(r guard.Reporter) {
		assertSecretsDocsVariables(r, root, []docSection{{"site/k8s.mdx", "## Secrets"}},
			map[string]bool{"GOIABADA_ADMINCONSOLE_BASEURL": true})
	})

	if !report.Stopped || !strings.Contains(report.Fatal, "## Secrets") {
		t.Errorf("a page without the section did not stop the check naming it: %+v", report)
	}
}

// rotationFixture tells the session keys in two tabs, the second leaving its previous variable
// out, with no tab at all for a third platform.
const rotationFixture = "Before the tabs: GOIABADA_ADMINCONSOLE_SESSION_ENCRYPTION_KEY_PREVIOUS.\n\n<Tabs>\n" +
	"  <TabItem label=\"Docker Compose\">\n    GOIABADA_ADMINCONSOLE_SESSION_ENCRYPTION_KEY_PREVIOUS\n  </TabItem>\n" +
	"  <TabItem label=\"Native binaries\">\n    GOIABADA_ADMINCONSOLE_SESSION_ENCRYPTION_KEY\n  </TabItem>\n" +
	"</Tabs>\n\nAfter the tabs: GOIABADA_ADMINCONSOLE_SESSION_ENCRYPTION_KEY_PREVIOUS.\n"

var rotationFixtureRead = map[string]bool{
	"GOIABADA_ADMINCONSOLE_SESSION_ENCRYPTION_KEY":          true,
	"GOIABADA_ADMINCONSOLE_SESSION_ENCRYPTION_KEY_PREVIOUS": true,
}

func TestRotateSecretsDocs_APlatformMissingARotationFails(t *testing.T) {
	root := t.TempDir()
	writeManifestFixture(t, root, "site/rotate.mdx", rotationFixture)

	report := guard.Run(func(r guard.Reporter) {
		assertRotationTabs(r, root, "site/rotate.mdx", []string{"Docker Compose", "Native binaries", "Kubernetes"}, rotationFixtureRead)
	})

	if report.Stopped {
		t.Fatalf("the check stopped rather than reporting: %s", report.Fatal)
	}
	text := report.Text()
	for _, want := range []string{
		"site/rotate.mdx: the Native binaries tabs never name GOIABADA_ADMINCONSOLE_SESSION_ENCRYPTION_KEY_PREVIOUS, so they do not tell its rotation",
		"site/rotate.mdx has no tab labelled Kubernetes",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("no failure says %q:\n%s", want, text)
		}
	}
	if strings.Contains(text, "Docker Compose") {
		t.Errorf("a failure names the platform whose tabs tell the rotation:\n%s", text)
	}
	if len(report.Errors) != 2 {
		t.Errorf("%d failures, want 2:\n%s", len(report.Errors), text)
	}
}

func TestRotateSecretsDocs_EveryPlatformTellingEveryRotationPasses(t *testing.T) {
	root := t.TempDir()
	writeManifestFixture(t, root, "site/rotate.mdx", strings.Replace(rotationFixture,
		"    GOIABADA_ADMINCONSOLE_SESSION_ENCRYPTION_KEY\n", "    GOIABADA_ADMINCONSOLE_SESSION_ENCRYPTION_KEY_PREVIOUS\n", 1))

	report := guard.Run(func(r guard.Reporter) {
		assertRotationTabs(r, root, "site/rotate.mdx", []string{"Docker Compose", "Native binaries"}, rotationFixtureRead)
	})

	if report.Stopped || len(report.Errors) != 0 {
		t.Errorf("tabs naming every previous variable failed: %+v", report)
	}
}

func TestRotateSecretsDocs_APageWithNoTabsStops(t *testing.T) {
	root := t.TempDir()
	writeManifestFixture(t, root, "site/rotate.mdx", "## The session keys\n\nGOIABADA_ADMINCONSOLE_SESSION_ENCRYPTION_KEY_PREVIOUS\n")

	report := guard.Run(func(r guard.Reporter) {
		assertRotationTabs(r, root, "site/rotate.mdx", []string{"Docker Compose"}, rotationFixtureRead)
	})

	if !report.Stopped || !strings.Contains(report.Fatal, "<TabItem") {
		t.Errorf("a page with no tabs did not stop the check naming them: %+v", report)
	}
}

// assertSecretsDocsVariables is the reporting half of the variables check.
func assertSecretsDocsVariables(r guard.Reporter, root string, sections []docSection, read map[string]bool) {
	r.Helper()
	findings, err := secretsDocsVariableFindings(root, sections, read)
	if err != nil {
		r.Fatalf("%v", err)
	}
	for _, finding := range findings {
		r.Errorf("%s", finding)
	}
}

// docVariable is one admin console variable as the docs spell it.
var docVariable = regexp.MustCompile(`GOIABADA_ADMINCONSOLE_[A-Z0-9_]*[A-Z0-9]`)

// secretsDocsVariableFindings returns one line per admin console variable a section names that
// read does not hold.
func secretsDocsVariableFindings(root string, sections []docSection, read map[string]bool) ([]string, error) {
	var findings []string
	for _, s := range sections {
		text, err := docSectionText(root, s)
		if err != nil {
			return nil, err
		}
		seen := map[string]bool{}
		for _, name := range docVariable.FindAllString(text, -1) {
			if seen[name] || read[name] {
				continue
			}
			seen[name] = true
			findings = append(findings, fmt.Sprintf("%s names %s, which this console does not read", s, name))
		}
	}
	return findings, nil
}

// assertRotationTabs is the reporting half of the rotation check.
func assertRotationTabs(r guard.Reporter, root, page string, platforms []string, read map[string]bool) {
	r.Helper()
	findings, err := rotationTabFindings(root, page, platforms, read)
	if err != nil {
		r.Fatalf("%v", err)
	}
	for _, finding := range findings {
		r.Errorf("%s", finding)
	}
}

// tabItem is one Starlight tab: its label and what it holds, up to its closing tag.
var tabItem = regexp.MustCompile(`(?s)<TabItem label="([^"]+)"[^>]*>(.*?)</TabItem>`)

// rotationTabFindings returns one line per platform with no tab on the page, and one per
// _PREVIOUS variable read holds that a platform's tabs, taken together, never name. A page with no
// tab at all is an error, since the check would then read nothing.
func rotationTabFindings(root, page string, platforms []string, read map[string]bool) ([]string, error) {
	text, err := docSectionText(root, docSection{page, ""})
	if err != nil {
		return nil, err
	}
	tabs := tabItem.FindAllStringSubmatch(text, -1)
	if len(tabs) == 0 {
		return nil, fmt.Errorf("%s holds no <TabItem label=...>, so this check read nothing", page)
	}
	named := map[string]map[string]bool{}
	for _, tab := range tabs {
		if named[tab[1]] == nil {
			named[tab[1]] = map[string]bool{}
		}
		for _, name := range docVariable.FindAllString(tab[2], -1) {
			named[tab[1]][name] = true
		}
	}
	var previous []string
	for name := range read {
		if strings.HasSuffix(name, "_PREVIOUS") {
			previous = append(previous, name)
		}
	}
	sort.Strings(previous)
	var findings []string
	for _, platform := range platforms {
		if named[platform] == nil {
			findings = append(findings, fmt.Sprintf("%s has no tab labelled %s", page, platform))
			continue
		}
		for _, name := range previous {
			if !named[platform][name] {
				findings = append(findings, fmt.Sprintf("%s: the %s tabs never name %s, so they do not tell its rotation", page, platform, name))
			}
		}
	}
	return findings, nil
}

// docSectionText is a page's section: the lines after its heading up to the next heading of the
// same or a higher level, a line in a fenced code block being no heading. A section with no
// heading is the whole page.
func docSectionText(root string, s docSection) (string, error) {
	content, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(s.page)))
	if err != nil {
		return "", err
	}
	if s.heading == "" {
		return string(content), nil
	}
	level := strings.Index(s.heading, " ")
	var b strings.Builder
	inSection, inFence, found := false, false, false
	scanner := bufio.NewScanner(bytes.NewReader(content))
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(strings.TrimSpace(line), "```") {
			inFence = !inFence
		}
		if !inFence && strings.HasPrefix(line, "#") {
			hashes := len(line) - len(strings.TrimLeft(line, "#"))
			if line == s.heading {
				inSection, found = true, true
				continue
			}
			if hashes <= level && strings.HasPrefix(line[hashes:], " ") {
				inSection = false
			}
		}
		if inSection {
			b.WriteString(line)
			b.WriteByte('\n')
		}
	}
	if err := scanner.Err(); err != nil {
		return "", err
	}
	if !found {
		return "", fmt.Errorf("%s has no %q section, so this check read nothing", s.page, s.heading)
	}
	return b.String(), nil
}
