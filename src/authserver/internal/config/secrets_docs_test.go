package config

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/leodip/goiabada/core/guard"
	"gopkg.in/yaml.v3"
)

// adminConsoleImage is the image reference every manifest running the admin console names. The
// Secret contract says which of the two servers reads each key, so this tier tells them apart.
const adminConsoleImage = "leodip/goiabada:adminconsole-"

// The pages that document the deployment's secrets, relative to the repository root.
const (
	kubernetesSecretsPage = "site/src/content/docs/deploy/kubernetes/secrets.mdx"
	secretsPage           = "site/src/content/docs/deploy/secrets.mdx"
	rotatePage            = "site/src/content/docs/deploy/rotate-secrets.mdx"
	upgradePage           = "site/src/content/docs/deploy/upgrade-goiabada.mdx"
)

// contractSection is the section of the Kubernetes Secrets page holding the Secret contract: the
// Secrets, keys and variables the generated manifests read.
const contractSection = "### The Secrets the manifest reads"

// docSection is one section of a page: the lines after its heading up to the next heading of the
// same or a higher level. A section with no heading is the whole page.
type docSection struct{ page, heading string }

func (s docSection) String() string {
	if s.heading == "" {
		return s.page
	}
	return s.page + ": " + s.heading
}

// secretsDocs is every section that names the deployment's secrets: what each protects, where
// Kubernetes keeps them, how each rotates, and the update that must leave them alone.
var secretsDocs = []docSection{
	{kubernetesSecretsPage, ""},
	{secretsPage, ""},
	{rotatePage, ""},
	{upgradePage, "## Update to a new release"},
}

// rotationPlatforms are the tabs Rotate secrets tells every rotation in, one per way the setup
// wizard deploys Goiabada.
var rotationPlatforms = []string{"Docker Compose", "Native binaries", "Kubernetes"}

// The secrets docs name only variables a server reads. A misspelt variable in a rotation procedure
// is ignored by the server it was meant for, and the rotation then signs everybody out or, for the
// AES key, leaves the auth server unable to read the database. The admin console's own variables
// are held by that console's tier (#396 decision 18).
func TestSecretsDocs_NameOnlyVariablesTheServersRead(t *testing.T) {
	assertSecretsDocsVariables(t, filepath.Dir(guard.SourceRoot(t)), secretsDocs, readVariables())
}

// Every rotation is told once, on Rotate secrets, with a tab per platform for what differs, so
// each platform's tabs name every _PREVIOUS variable this server reads: a platform whose tabs
// never name one does not tell that rotation, and a reader of that tab is left with no way to
// rotate without signing everybody out or, for the AES key, losing the database (#522 decision 15).
func TestRotateSecretsDocs_EveryPlatformTellsEveryRotation(t *testing.T) {
	assertRotationTabs(t, filepath.Dir(guard.SourceRoot(t)), rotatePage, rotationPlatforms, readVariables())
}

// The Secret contract on the Kubernetes Secrets page is what the generated manifests read: every Secret, key
// and variable, which server reads it, and whether its reference is optional, row for row in both
// directions. Every `kubectl create secret generic` the secrets docs print creates exactly the
// keys the manifests require from that Secret, so a Secret created by any route the docs show is
// one the manifest can start from; the optional ones are the previous keys a rotation fills
// (#396 decision 18).
func TestKubernetesDocs_TheSecretContractIsWhatTheManifestsRead(t *testing.T) {
	assertSecretContract(t, filepath.Dir(guard.SourceRoot(t)))
}

func TestSecretsDocs_AnUnreadVariableFails(t *testing.T) {
	root := t.TempDir()
	writeManifestFixture(t, root, "site/k8s.mdx", "intro GOIABADA_NEVER_READ_OUTSIDE\n\n"+
		"## Secrets\n\nSet GOIABADA_APPNAME and GOIABADA_ADMIN_PASSWORD_TYPO.\n\n"+
		"```bash\n## not a heading inside a fence: GOIABADA_IN_FENCE\n```\n\n"+
		"Ignored here: GOIABADA_ADMINCONSOLE_ANYTHING.\n\n"+
		"## Next\n\nGOIABADA_AFTER_THE_SECTION\n")
	writeManifestFixture(t, root, "site/rotate.mdx", "---\ntitle: Rotate\n---\n\nGOIABADA_APPNAME_PREVIOUS\n\n"+
		"## Anything\n\nGOIABADA_ROTATION_TYPO\n")

	report := guard.Run(func(r guard.Reporter) {
		assertSecretsDocsVariables(r, root,
			[]docSection{{"site/k8s.mdx", "## Secrets"}, {"site/rotate.mdx", ""}},
			map[string]bool{"GOIABADA_APPNAME": true, "GOIABADA_APPNAME_PREVIOUS": true, "GOIABADA_ADMIN_PASSWORD": true})
	})

	if report.Stopped {
		t.Fatalf("the check stopped rather than reporting: %s", report.Fatal)
	}
	text := report.Text()
	for _, want := range []string{
		"site/k8s.mdx: ## Secrets names GOIABADA_ADMIN_PASSWORD_TYPO",
		"site/k8s.mdx: ## Secrets names GOIABADA_IN_FENCE",
		"site/rotate.mdx names GOIABADA_ROTATION_TYPO",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("no failure says %q:\n%s", want, text)
		}
	}
	for _, unwanted := range []string{"NEVER_READ_OUTSIDE", "AFTER_THE_SECTION", "ADMINCONSOLE_ANYTHING", "APPNAME_PREVIOUS"} {
		if strings.Contains(text, unwanted) {
			t.Errorf("a failure names %s, which is outside the sections, read, or this server's to check:\n%s", unwanted, text)
		}
	}
	if len(report.Errors) != 3 {
		t.Errorf("%d failures, want 3:\n%s", len(report.Errors), text)
	}
}

func TestSecretsDocs_AMissingSectionStops(t *testing.T) {
	root := t.TempDir()
	writeManifestFixture(t, root, "site/k8s.mdx", "## Secret\n\nGOIABADA_APPNAME\n")

	report := guard.Run(func(r guard.Reporter) {
		assertSecretsDocsVariables(r, root, []docSection{{"site/k8s.mdx", "## Secrets"}},
			map[string]bool{"GOIABADA_APPNAME": true})
	})

	if !report.Stopped || !strings.Contains(report.Fatal, "## Secrets") {
		t.Errorf("a page without the section did not stop the check naming it: %+v", report)
	}
}

// rotationFixture tells two rotations in two tabs each, the second platform's AES tab leaving its
// previous variable out, and a third platform with no tab at all.
const rotationFixture = "Before the tabs: GOIABADA_AES_ENCRYPTION_KEY_PREVIOUS.\n\n" +
	"## The session keys\n\n<Tabs>\n" +
	"  <TabItem label=\"Docker Compose\">\n    GOIABADA_AUTHSERVER_SESSION_AUTHENTICATION_KEY_PREVIOUS\n  </TabItem>\n" +
	"  <TabItem label=\"Native binaries\">\n    GOIABADA_AUTHSERVER_SESSION_AUTHENTICATION_KEY_PREVIOUS\n  </TabItem>\n" +
	"</Tabs>\n\n## The AES key\n\n<Tabs>\n" +
	"  <TabItem label=\"Docker Compose\">\n    GOIABADA_AES_ENCRYPTION_KEY_PREVIOUS\n  </TabItem>\n" +
	"  <TabItem label=\"Native binaries\">\n    GOIABADA_AES_ENCRYPTION_KEY\n  </TabItem>\n" +
	"</Tabs>\n\nAfter the tabs: GOIABADA_AES_ENCRYPTION_KEY_PREVIOUS.\n"

var rotationFixtureRead = map[string]bool{
	"GOIABADA_AES_ENCRYPTION_KEY":                             true,
	"GOIABADA_AES_ENCRYPTION_KEY_PREVIOUS":                    true,
	"GOIABADA_AUTHSERVER_SESSION_AUTHENTICATION_KEY_PREVIOUS": true,
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
		"site/rotate.mdx: the Native binaries tabs never name GOIABADA_AES_ENCRYPTION_KEY_PREVIOUS, so they do not tell its rotation",
		"site/rotate.mdx has no tab labelled Kubernetes",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("no failure says %q:\n%s", want, text)
		}
	}
	if strings.Contains(text, "Docker Compose") {
		t.Errorf("a failure names the platform whose tabs tell every rotation:\n%s", text)
	}
	if len(report.Errors) != 2 {
		t.Errorf("%d failures, want 2:\n%s", len(report.Errors), text)
	}
}

func TestRotateSecretsDocs_EveryPlatformTellingEveryRotationPasses(t *testing.T) {
	root := t.TempDir()
	writeManifestFixture(t, root, "site/rotate.mdx", strings.Replace(rotationFixture,
		"    GOIABADA_AES_ENCRYPTION_KEY\n", "    GOIABADA_AES_ENCRYPTION_KEY_PREVIOUS\n", 1))

	report := guard.Run(func(r guard.Reporter) {
		assertRotationTabs(r, root, "site/rotate.mdx", []string{"Docker Compose", "Native binaries"}, rotationFixtureRead)
	})

	if report.Stopped || len(report.Errors) != 0 {
		t.Errorf("tabs naming every previous variable failed: %+v", report)
	}
}

func TestRotateSecretsDocs_APageWithNoTabsStops(t *testing.T) {
	root := t.TempDir()
	writeManifestFixture(t, root, "site/rotate.mdx", "## The AES key\n\nGOIABADA_AES_ENCRYPTION_KEY_PREVIOUS\n")

	report := guard.Run(func(r guard.Reporter) {
		assertRotationTabs(r, root, "site/rotate.mdx", []string{"Docker Compose"}, rotationFixtureRead)
	})

	if !report.Stopped || !strings.Contains(report.Fatal, "<TabItem") {
		t.Errorf("a page with no tabs did not stop the check naming them: %+v", report)
	}
}

const contractManifest = `
apiVersion: apps/v1
kind: Deployment
metadata:
  name: auth
spec:
  template:
    spec:
      containers:
      - name: authserver
        image: leodip/goiabada:authserver-1.0
        env:
        - name: GOIABADA_APPNAME
          value: x
        - name: GOIABADA_DB_PASSWORD
          valueFrom:
            secretKeyRef:
              name: goiabada-secrets
              key: db-password
        - name: GOIABADA_ADMINCONSOLE_OAUTH_CLIENT_SECRET
          valueFrom:
            secretKeyRef:
              name: goiabada-secrets
              key: oauth-client-secret
        - name: GOIABADA_AES_ENCRYPTION_KEY
          valueFrom:
            secretKeyRef:
              name: goiabada-encryption-key
              key: aes-encryption-key
        - name: GOIABADA_AES_ENCRYPTION_KEY_PREVIOUS
          valueFrom:
            secretKeyRef:
              name: goiabada-encryption-key
              key: aes-encryption-key-previous
              optional: true
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: console
spec:
  template:
    spec:
      containers:
      - name: adminconsole
        image: leodip/goiabada:adminconsole-1.0
        env:
        - name: GOIABADA_ADMINCONSOLE_OAUTH_CLIENT_SECRET
          valueFrom:
            secretKeyRef:
              name: goiabada-secrets
              key: oauth-client-secret
`

const contractPage = contractSection + "\n\n" +
	"| Secret | Key | Variable | Read by | Value |\n" +
	"|--------|-----|----------|---------|-------|\n" +
	"| `goiabada-secrets` | `db-password` | `GOIABADA_DB_PASSWORD` | auth server | the password |\n" +
	"| `goiabada-secrets` | `oauth-client-secret` | `GOIABADA_ADMINCONSOLE_OAUTH_CLIENT_SECRET` | both | a secret |\n" +
	"| `goiabada-encryption-key` | `aes-encryption-key` | `GOIABADA_AES_ENCRYPTION_KEY` | auth server | a key |\n" +
	"| `goiabada-encryption-key` | `aes-encryption-key-previous` | `GOIABADA_AES_ENCRYPTION_KEY_PREVIOUS` | auth server | Optional. A key |\n\n" +
	"## Create the Secrets another way\n\n" +
	"```bash\nkubectl create secret generic goiabada-secrets -n goiabada \\\n" +
	"  --from-file=db-password=<(printf %s \"$DB_PASSWORD\") \\\n" +
	"  --from-file=oauth-client-secret=<(openssl rand -hex 32)\n```\n\n" +
	"A rotation step merges one key into a sealed file, creating no Secret:\n\n" +
	"```bash\nkubectl create secret generic goiabada-secrets -n goiabada --dry-run=client -o json \\\n" +
	"  --from-file=db-password-previous=<(openssl rand -hex 32) \\\n" +
	"  | kubeseal --format yaml --merge-into goiabada-secrets.sealed.yaml\n```\n"

// contractGatewayPage is a Kubernetes page outside the secrets docs, whose create command the
// contract does not hold.
const contractGatewayPage = "## Deploy\n\n" +
	"```bash\nkubectl create secret generic goiabada-secrets -n goiabada --from-file=outside=x\n```\n"

// contractRotatePage and contractUpgradePage each print a create command the contract holds.
const (
	contractRotatePage  = "## The AES key\n\n```bash\nprintf x | kubectl create secret generic goiabada-encryption-key -n goiabada --from-file=aes-encryption-key=/dev/stdin\n```\n"
	contractUpgradePage = "## Update to a new release\n\n```bash\nkubectl create secret generic goiabada-encryption-key -n goiabada \\\n  --from-file=aes-encryption-key=<(openssl rand -hex 32)\n```\n"
)

func writeContractPages(t *testing.T, root, kubernetes, upgrade string) {
	t.Helper()
	writeManifestFixture(t, root, kubernetesSecretsPage, kubernetes)
	writeManifestFixture(t, root, "site/src/content/docs/deploy/kubernetes/gateway-and-certificates.mdx", contractGatewayPage)
	writeManifestFixture(t, root, rotatePage, contractRotatePage)
	writeManifestFixture(t, root, upgradePage, upgrade)
}

func TestKubernetesDocs_ADriftedContractFails(t *testing.T) {
	root := t.TempDir()
	writeManifestFixture(t, root, "src/cmd/goiabada-setup/testdata/kubernetes-postgres.golden", contractManifest)
	writeManifestFixture(t, root, "src/cmd/goiabada-setup/testdata/kubernetes-postgres.secrets.golden",
		"apiVersion: v1\nkind: Secret\nmetadata:\n  name: goiabada-secrets\n")
	page := strings.NewReplacer(
		// A row whose reader is wrong, a row the manifest does not read, and a key left out of a
		// create command.
		"`GOIABADA_DB_PASSWORD` | auth server", "`GOIABADA_DB_PASSWORD` | both",
		"| `goiabada-encryption-key` | `aes-encryption-key` | `GOIABADA_AES_ENCRYPTION_KEY` | auth server | a key |\n",
		"| `goiabada-secrets` | `extra` | `GOIABADA_EXTRA` | auth server | x |\n",
		" \\\n  --from-file=oauth-client-secret=<(openssl rand -hex 32)", "",
		// An optional reference the table does not say is optional.
		"| auth server | Optional. A key |", "| auth server | A key |",
	).Replace(contractPage)
	// A create command on another page of the secrets docs that creates a key the manifest does
	// not read.
	writeContractPages(t, root, page, strings.Replace(contractUpgradePage, "aes-encryption-key=", "aes-key=", 1))

	report := guard.Run(func(r guard.Reporter) { assertSecretContract(r, root) })

	if report.Stopped {
		t.Fatalf("the check stopped rather than reporting: %s", report.Fatal)
	}
	text := report.Text()
	for _, want := range []string{
		"kubernetes-postgres.golden: the manifest reads goiabada-secrets/db-password as GOIABADA_DB_PASSWORD, read by auth server; the docs' table says both",
		"kubernetes-postgres.golden: the manifest reads goiabada-encryption-key/aes-encryption-key as GOIABADA_AES_ENCRYPTION_KEY, read by auth server; the docs' table lacks it",
		"kubernetes-postgres.golden: the docs' table has goiabada-secrets/extra as GOIABADA_EXTRA, which the manifest does not read",
		"`kubectl create secret generic goiabada-secrets` creates [db-password], want [db-password oauth-client-secret]",
		"kubernetes-postgres.golden: the manifest reads goiabada-encryption-key/aes-encryption-key-previous as GOIABADA_AES_ENCRYPTION_KEY_PREVIOUS, read by auth server, optional; the docs' table says auth server",
		upgradePage + ": `kubectl create secret generic goiabada-encryption-key` creates [aes-key], want [aes-encryption-key]",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("no failure says %q:\n%s", want, text)
		}
	}
	if strings.Contains(text, "secrets.golden") || strings.Contains(text, rotatePage) || strings.Contains(text, "[outside]") {
		t.Errorf("a failure names the secrets golden, the correct create command or one outside the section:\n%s", text)
	}
	if len(report.Errors) != 6 {
		t.Errorf("%d failures, want 6:\n%s", len(report.Errors), text)
	}
}

func TestKubernetesDocs_AMatchingContractPasses(t *testing.T) {
	root := t.TempDir()
	writeManifestFixture(t, root, "src/cmd/goiabada-setup/testdata/kubernetes-postgres.golden", contractManifest)
	writeContractPages(t, root, contractPage, contractUpgradePage)

	report := guard.Run(func(r guard.Reporter) { assertSecretContract(r, root) })

	if report.Stopped || len(report.Errors) != 0 {
		t.Errorf("a contract matching the manifest failed: %+v", report)
	}
}

func TestKubernetesDocs_AContractWithNoTableStops(t *testing.T) {
	root := t.TempDir()
	writeManifestFixture(t, root, "src/cmd/goiabada-setup/testdata/kubernetes-postgres.golden", contractManifest)
	writeContractPages(t, root, contractSection+"\n\nNo table.\n", contractUpgradePage)

	report := guard.Run(func(r guard.Reporter) { assertSecretContract(r, root) })

	if !report.Stopped || !strings.Contains(report.Fatal, "| Secret | Key | Variable | Read by |") {
		t.Errorf("a section with no contract table did not stop the check naming the table: %+v", report)
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

// docVariable is one GOIABADA_ variable as the docs spell it.
var docVariable = regexp.MustCompile(`GOIABADA_[A-Z0-9_]*[A-Z0-9]`)

// secretsDocsVariableFindings returns one line per variable a section names that read does not
// hold, the admin console's own (GOIABADA_ADMINCONSOLE_) excepted unless read holds it.
func secretsDocsVariableFindings(root string, sections []docSection, read map[string]bool) ([]string, error) {
	var findings []string
	for _, s := range sections {
		text, err := docSectionText(root, s)
		if err != nil {
			return nil, err
		}
		seen := map[string]bool{}
		for _, name := range docVariable.FindAllString(text, -1) {
			if seen[name] || read[name] || strings.HasPrefix(name, "GOIABADA_ADMINCONSOLE_") {
				continue
			}
			seen[name] = true
			findings = append(findings, fmt.Sprintf("%s names %s, which this server does not read", s, name))
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

// secretRef is one variable a container reads from a Secret.
type secretRef struct{ secret, key, variable string }

func (r secretRef) String() string { return r.secret + "/" + r.key + " as " + r.variable }

// secretReader is which of the two servers reads a key, "auth server", "admin console" or "both",
// and whether its reference is optional, which the table says by opening the row's Value with
// "Optional". A pod starts with an optional key missing, so no route the docs show has to create it.
type secretReader struct {
	reader   string
	optional bool
}

func (r secretReader) String() string {
	if r.optional {
		return r.reader + ", optional"
	}
	return r.reader
}

const contractHeader = "| Secret | Key | Variable | Read by |"

// assertSecretContract is the reporting half of the contract check.
func assertSecretContract(r guard.Reporter, root string) {
	r.Helper()
	findings, err := secretContractFindings(root)
	if err != nil {
		r.Fatalf("%v", err)
	}
	for _, finding := range findings {
		r.Errorf("%s", finding)
	}
}

// createCommandDocs is every section whose `kubectl create secret generic` commands the contract
// holds: the Kubernetes Secrets page, every rotation, and the update.
var createCommandDocs = []docSection{
	{kubernetesSecretsPage, ""},
	{rotatePage, ""},
	{upgradePage, ""},
}

// secretContractFindings holds the contract table, in the Kubernetes Secrets page's
// contractSection, to every Kubernetes golden, and each `kubectl create secret generic` in
// createCommandDocs to the keys the goldens read from that Secret.
func secretContractFindings(root string) ([]string, error) {
	section, err := docSectionText(root, docSection{kubernetesSecretsPage, contractSection})
	if err != nil {
		return nil, err
	}
	documented, err := contractTable(section)
	if err != nil {
		return nil, err
	}

	paths, err := filepath.Glob(filepath.Join(root, "src", filepath.FromSlash(kubernetesManifests)))
	if err != nil {
		return nil, err
	}
	var findings []string
	examined := 0
	keysRead := map[string]map[string]bool{}
	for _, path := range paths {
		if strings.HasSuffix(path, ".secrets.golden") {
			continue
		}
		content, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		if !bytes.Contains(content, []byte(authServerImage)) {
			continue
		}
		rel := filepath.Base(path)
		read, deployments, err := secretReferences(content)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", rel, err)
		}
		if deployments == 0 {
			// A Compose golden runs the image too, and holds no Deployment.
			continue
		}
		examined++
		for ref, reader := range read {
			if keysRead[ref.secret] == nil {
				keysRead[ref.secret] = map[string]bool{}
			}
			if !reader.optional {
				keysRead[ref.secret][ref.key] = true
			}
			docReader, ok := documented[ref]
			switch {
			case !ok:
				findings = append(findings, fmt.Sprintf("%s: the manifest reads %s, read by %s; the docs' table lacks it", rel, ref, reader))
			case docReader != reader:
				findings = append(findings, fmt.Sprintf("%s: the manifest reads %s, read by %s; the docs' table says %s", rel, ref, reader, docReader))
			}
		}
		for ref := range documented {
			if _, ok := read[ref]; !ok {
				findings = append(findings, fmt.Sprintf("%s: the docs' table has %s, which the manifest does not read", rel, ref))
			}
		}
	}
	if examined == 0 {
		return nil, fmt.Errorf("no file matching %s runs %s, so this check read nothing", kubernetesManifests, authServerImage)
	}

	for _, section := range createCommandDocs {
		text, err := docSectionText(root, section)
		if err != nil {
			return nil, err
		}
		for _, command := range createSecretCommands(text) {
			want := sortedKeys(keysRead[command.secret])
			if got := sortedKeys(command.keys); strings.Join(got, " ") != strings.Join(want, " ") {
				findings = append(findings, fmt.Sprintf("%s: `kubectl create secret generic %s` creates %v, want %v",
					section, command.secret, got, want))
			}
		}
	}
	sort.Strings(findings)
	return findings, nil
}

// contractTable reads the table whose header begins contractHeader: each row's Secret, Key and
// Variable, its Read by, and whether its Value opens with "Optional".
func contractTable(section string) (map[secretRef]secretReader, error) {
	rows := map[secretRef]secretReader{}
	inTable := false
	for _, line := range strings.Split(section, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, contractHeader) {
			inTable = true
			continue
		}
		if !inTable {
			continue
		}
		if !strings.HasPrefix(line, "|") {
			break
		}
		cells := strings.Split(strings.Trim(line, "|"), "|")
		if len(cells) < 5 || strings.HasPrefix(strings.TrimSpace(cells[0]), "---") {
			continue
		}
		cell := func(i int) string { return strings.Trim(strings.TrimSpace(cells[i]), "`") }
		rows[secretRef{cell(0), cell(1), cell(2)}] = secretReader{cell(3), strings.HasPrefix(cell(4), "Optional")}
	}
	if len(rows) == 0 {
		return nil, fmt.Errorf("%s: %s holds no table headed %s", kubernetesSecretsPage, contractSection, contractHeader)
	}
	return rows, nil
}

// secretReferences is every Secret key a Deployment's container in one manifest reads, with which
// of the two servers reads it and whether every reference to it is optional, and how many
// Deployments the manifest holds.
func secretReferences(content []byte) (map[secretRef]secretReader, int, error) {
	readers := map[secretRef]map[string]bool{}
	required := map[secretRef]bool{}
	deployments := 0
	decoder := yaml.NewDecoder(bytes.NewReader(content))
	for {
		var doc map[string]any
		err := decoder.Decode(&doc)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, 0, err
		}
		if doc["kind"] != "Deployment" {
			continue
		}
		deployments++
		containers, _ := mapAt(doc, "spec", "template", "spec")["containers"].([]any)
		for _, c := range containers {
			container, _ := c.(map[string]any)
			image, _ := container["image"].(string)
			reader := ""
			switch {
			case strings.HasPrefix(image, authServerImage):
				reader = "auth server"
			case strings.HasPrefix(image, adminConsoleImage):
				reader = "admin console"
			default:
				continue
			}
			env, _ := container["env"].([]any)
			for _, e := range env {
				entry, _ := e.(map[string]any)
				ref := mapAt(entry, "valueFrom", "secretKeyRef")
				if ref == nil {
					continue
				}
				key := secretRef{fmt.Sprint(ref["name"]), fmt.Sprint(ref["key"]), fmt.Sprint(entry["name"])}
				if readers[key] == nil {
					readers[key] = map[string]bool{}
				}
				readers[key][reader] = true
				if ref["optional"] != true {
					required[key] = true
				}
			}
		}
	}
	read := map[secretRef]secretReader{}
	for ref, by := range readers {
		reader := "admin console"
		switch {
		case by["auth server"] && by["admin console"]:
			reader = "both"
		case by["auth server"]:
			reader = "auth server"
		}
		read[ref] = secretReader{reader, !required[ref]}
	}
	return read, deployments, nil
}

type createCommand struct {
	secret string
	keys   map[string]bool
}

var (
	createSecret = regexp.MustCompile(`kubectl create secret generic (\S+)`)
	createKey    = regexp.MustCompile(`--from-(?:file|literal)=([^=\s]+)=`)
	// mergedIntoSealedFile is a pipe into kubeseal --merge-into.
	mergedIntoSealedFile = regexp.MustCompile(`\|\s*kubeseal\b[^|]*--merge-into`)
)

// createSecretCommands is every `kubectl create secret generic` in a section, its continuation
// lines joined, with the keys its --from-file and --from-literal arguments create. One whose output
// kubeseal merges into an existing sealed file creates no Secret: it writes the keys it names into
// one beside those already sealed, as a rotation step does, so it is not one of them.
func createSecretCommands(section string) []createCommand {
	var commands []createCommand
	joined := strings.ReplaceAll(section, "\\\n", " ")
	for _, line := range strings.Split(joined, "\n") {
		match := createSecret.FindStringSubmatchIndex(line)
		if match == nil || mergedIntoSealedFile.MatchString(line[match[1]:]) {
			continue
		}
		command := createCommand{secret: line[match[2]:match[3]], keys: map[string]bool{}}
		for _, key := range createKey.FindAllStringSubmatch(line[match[1]:], -1) {
			command.keys[key[1]] = true
		}
		commands = append(commands, command)
	}
	return commands
}
