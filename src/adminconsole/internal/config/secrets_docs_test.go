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
// sections of each that do. Each section runs from its heading to the next heading of the same
// level. The auth server's tier reads the same sections.
type docSection struct{ page, heading string }

var secretsDocs = []docSection{
	{"site/src/content/docs/production-deployment/kubernetes.mdx", "## Secrets"},
	{"site/src/content/docs/production-deployment/kubernetes.mdx", "## Updating Goiabada"},
	{"site/src/content/docs/production-deployment/index.mdx", "## Secrets"},
	{"site/src/content/docs/production-deployment/native-binaries.mdx", "## Secrets"},
}

// The secrets docs name only admin console variables this console reads, and every _PREVIOUS
// variable it reads is named on each page, which is where its rotation is told. A misspelt
// variable in a rotation procedure is ignored, and the rotation then signs every administrator
// out. Every other GOIABADA_ variable is the auth server's tier to check (#396 decision 18).
func TestSecretsDocs_NameOnlyVariablesTheServersRead(t *testing.T) {
	assertSecretsDocsVariables(t, filepath.Dir(guard.SourceRoot(t)), secretsDocs, readVariables())
}

func TestSecretsDocs_AnUnreadVariableAndAMissingRotationFail(t *testing.T) {
	root := t.TempDir()
	writeManifestFixture(t, root, "site/k8s.mdx", "intro GOIABADA_ADMINCONSOLE_OUTSIDE\n\n"+
		"## Secrets\n\nSet GOIABADA_ADMINCONSOLE_BASEURL and GOIABADA_ADMINCONSOLE_SESSION_KEY_TYPO.\n\n"+
		"```bash\n## not a heading inside a fence: GOIABADA_ADMINCONSOLE_IN_FENCE\n```\n\n"+
		"Ignored here: GOIABADA_AUTHSERVER_ANYTHING.\n\n"+
		"## Next\n\nGOIABADA_ADMINCONSOLE_AFTER_THE_SECTION\n")
	writeManifestFixture(t, root, "site/native.mdx", "## Secrets\n\nGOIABADA_ADMINCONSOLE_BASEURL_PREVIOUS\n")

	report := guard.Run(func(r guard.Reporter) {
		assertSecretsDocsVariables(r, root,
			[]docSection{{"site/k8s.mdx", "## Secrets"}, {"site/native.mdx", "## Secrets"}},
			map[string]bool{"GOIABADA_ADMINCONSOLE_BASEURL": true, "GOIABADA_ADMINCONSOLE_BASEURL_PREVIOUS": true})
	})

	if report.Stopped {
		t.Fatalf("the check stopped rather than reporting: %s", report.Fatal)
	}
	text := report.Text()
	for _, want := range []string{
		"site/k8s.mdx: ## Secrets names GOIABADA_ADMINCONSOLE_SESSION_KEY_TYPO",
		"site/k8s.mdx: ## Secrets names GOIABADA_ADMINCONSOLE_IN_FENCE",
		"site/k8s.mdx never names GOIABADA_ADMINCONSOLE_BASEURL_PREVIOUS",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("no failure says %q:\n%s", want, text)
		}
	}
	for _, unwanted := range []string{"OUTSIDE", "AFTER_THE_SECTION", "AUTHSERVER_ANYTHING", "native.mdx"} {
		if strings.Contains(text, unwanted) {
			t.Errorf("a failure names %s, which is outside the sections or the auth server's to check:\n%s", unwanted, text)
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
// read does not hold, and one per page that never names a _PREVIOUS variable read holds.
func secretsDocsVariableFindings(root string, sections []docSection, read map[string]bool) ([]string, error) {
	var findings []string
	named := map[string]map[string]bool{}
	var pages []string
	for _, s := range sections {
		text, err := docSectionText(root, s)
		if err != nil {
			return nil, err
		}
		if named[s.page] == nil {
			named[s.page] = map[string]bool{}
			pages = append(pages, s.page)
		}
		seen := map[string]bool{}
		for _, name := range docVariable.FindAllString(text, -1) {
			named[s.page][name] = true
			if seen[name] || read[name] {
				continue
			}
			seen[name] = true
			findings = append(findings, fmt.Sprintf("%s: %s names %s, which this console does not read", s.page, s.heading, name))
		}
	}
	var previous []string
	for name := range read {
		if strings.HasSuffix(name, "_PREVIOUS") {
			previous = append(previous, name)
		}
	}
	sort.Strings(previous)
	for _, page := range pages {
		for _, name := range previous {
			if !named[page][name] {
				findings = append(findings, fmt.Sprintf("%s never names %s, so it does not tell its rotation", page, name))
			}
		}
	}
	return findings, nil
}

// docSectionText is a page's section: the lines after its heading up to the next heading of the
// same or a higher level, a line in a fenced code block being no heading.
func docSectionText(root string, s docSection) (string, error) {
	content, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(s.page)))
	if err != nil {
		return "", err
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
