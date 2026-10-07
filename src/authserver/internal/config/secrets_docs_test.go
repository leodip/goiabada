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

// The pages that document the deployment's secrets, relative to the repository root, and the
// sections of each that do. Each section runs from its heading to the next heading of the same
// level.
const (
	kubernetesPage = "site/src/content/docs/deploy/kubernetes.mdx"
	composePage    = "site/src/content/docs/deploy/docker-compose.mdx"
	nativePage     = "site/src/content/docs/deploy/native-binaries.mdx"
)

type docSection struct{ page, heading string }

var secretsDocs = []docSection{
	{kubernetesPage, "## Secrets"},
	{kubernetesPage, "## Updating Goiabada"},
	{composePage, "## Secrets"},
	{nativePage, "## Secrets"},
}

// The secrets docs name only variables a server reads, and every _PREVIOUS variable this server
// reads is named on each page, which is where its rotation is told. A misspelt variable in a
// rotation procedure is ignored by the server it was meant for, and the rotation then signs
// everybody out or, for the AES key, leaves the auth server unable to read the database. The
// admin console's own variables are held by that console's tier (#396 decision 18).
func TestSecretsDocs_NameOnlyVariablesTheServersRead(t *testing.T) {
	assertSecretsDocsVariables(t, filepath.Dir(guard.SourceRoot(t)), secretsDocs, readVariables())
}

// The Secret contract in kubernetes.mdx is what the generated manifests read: every Secret, key
// and variable, which server reads it, and whether its reference is optional, row for row in both
// directions. Every `kubectl create secret generic` the Kubernetes sections print creates exactly
// the keys the manifests require from that Secret, so a Secret created by any route the docs show
// is one the manifest can start from; the optional ones are the previous keys a rotation fills
// (#396 decision 18).
func TestKubernetesDocs_TheSecretContractIsWhatTheManifestsRead(t *testing.T) {
	assertSecretContract(t, filepath.Dir(guard.SourceRoot(t)))
}

func TestSecretsDocs_AnUnreadVariableAndAMissingRotationFail(t *testing.T) {
	root := t.TempDir()
	writeManifestFixture(t, root, "site/k8s.mdx", "intro GOIABADA_NEVER_READ_OUTSIDE\n\n"+
		"## Secrets\n\nSet GOIABADA_APPNAME and GOIABADA_ADMIN_PASSWORD_TYPO.\n\n"+
		"```bash\n## not a heading inside a fence: GOIABADA_IN_FENCE\n```\n\n"+
		"Ignored here: GOIABADA_ADMINCONSOLE_ANYTHING.\n\n"+
		"## Next\n\nGOIABADA_AFTER_THE_SECTION\n")
	writeManifestFixture(t, root, "site/native.mdx", "## Secrets\n\nGOIABADA_APPNAME_PREVIOUS\n")

	report := guard.Run(func(r guard.Reporter) {
		assertSecretsDocsVariables(r, root,
			[]docSection{{"site/k8s.mdx", "## Secrets"}, {"site/native.mdx", "## Secrets"}},
			map[string]bool{"GOIABADA_APPNAME": true, "GOIABADA_APPNAME_PREVIOUS": true, "GOIABADA_ADMIN_PASSWORD": true})
	})

	if report.Stopped {
		t.Fatalf("the check stopped rather than reporting: %s", report.Fatal)
	}
	text := report.Text()
	for _, want := range []string{
		"site/k8s.mdx: ## Secrets names GOIABADA_ADMIN_PASSWORD_TYPO",
		"site/k8s.mdx: ## Secrets names GOIABADA_IN_FENCE",
		"site/k8s.mdx never names GOIABADA_APPNAME_PREVIOUS",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("no failure says %q:\n%s", want, text)
		}
	}
	for _, unwanted := range []string{"NEVER_READ_OUTSIDE", "AFTER_THE_SECTION", "ADMINCONSOLE_ANYTHING", "native.mdx"} {
		if strings.Contains(text, unwanted) {
			t.Errorf("a failure names %s, which is outside the sections or this server's to check:\n%s", unwanted, text)
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

const contractPage = "## Secrets\n\n" +
	"| Secret | Key | Variable | Read by | Value |\n" +
	"|--------|-----|----------|---------|-------|\n" +
	"| `goiabada-secrets` | `db-password` | `GOIABADA_DB_PASSWORD` | auth server | the password |\n" +
	"| `goiabada-secrets` | `oauth-client-secret` | `GOIABADA_ADMINCONSOLE_OAUTH_CLIENT_SECRET` | both | a secret |\n" +
	"| `goiabada-encryption-key` | `aes-encryption-key` | `GOIABADA_AES_ENCRYPTION_KEY` | auth server | a key |\n" +
	"| `goiabada-encryption-key` | `aes-encryption-key-previous` | `GOIABADA_AES_ENCRYPTION_KEY_PREVIOUS` | auth server | Optional. A key |\n\n" +
	"```bash\nkubectl create secret generic goiabada-secrets -n goiabada \\\n" +
	"  --from-file=db-password=<(printf %s \"$DB_PASSWORD\") \\\n" +
	"  --from-file=oauth-client-secret=<(openssl rand -hex 32)\n```\n\n" +
	"A rotation step merges one key into a sealed file, creating no Secret:\n\n" +
	"```bash\nkubectl create secret generic goiabada-secrets -n goiabada --dry-run=client -o json \\\n" +
	"  --from-file=db-password-previous=<(openssl rand -hex 32) \\\n" +
	"  | kubeseal --format yaml --merge-into goiabada-secrets.sealed.yaml\n```\n\n" +
	"## Updating Goiabada\n\n" +
	"```bash\nprintf x | kubectl create secret generic goiabada-encryption-key -n goiabada --from-file=aes-encryption-key=/dev/stdin\n```\n"

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
	writeManifestFixture(t, root, kubernetesPage, page)

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
	} {
		if !strings.Contains(text, want) {
			t.Errorf("no failure says %q:\n%s", want, text)
		}
	}
	if strings.Contains(text, "secrets.golden") || strings.Contains(text, "goiabada-encryption-key` creates") {
		t.Errorf("a failure names the secrets golden or the correct create command:\n%s", text)
	}
	if len(report.Errors) != 5 {
		t.Errorf("%d failures, want 5:\n%s", len(report.Errors), text)
	}
}

func TestKubernetesDocs_AMatchingContractPasses(t *testing.T) {
	root := t.TempDir()
	writeManifestFixture(t, root, "src/cmd/goiabada-setup/testdata/kubernetes-postgres.golden", contractManifest)
	writeManifestFixture(t, root, kubernetesPage, contractPage)

	report := guard.Run(func(r guard.Reporter) { assertSecretContract(r, root) })

	if report.Stopped || len(report.Errors) != 0 {
		t.Errorf("a contract matching the manifest failed: %+v", report)
	}
}

func TestKubernetesDocs_AContractWithNoTableStops(t *testing.T) {
	root := t.TempDir()
	writeManifestFixture(t, root, "src/cmd/goiabada-setup/testdata/kubernetes-postgres.golden", contractManifest)
	writeManifestFixture(t, root, kubernetesPage, "## Secrets\n\nNo table.\n\n## Updating Goiabada\n")

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
// hold, the admin console's own (GOIABADA_ADMINCONSOLE_) excepted unless read holds it, and one per
// page that never names a _PREVIOUS variable read holds.
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
			if seen[name] || read[name] || strings.HasPrefix(name, "GOIABADA_ADMINCONSOLE_") {
				continue
			}
			seen[name] = true
			findings = append(findings, fmt.Sprintf("%s: %s names %s, which this server does not read", s.page, s.heading, name))
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

// secretContractFindings holds the contract table in kubernetes.mdx's Secrets section to every
// Kubernetes golden, and each `kubectl create secret generic` in its Kubernetes sections to the
// keys the goldens read from that Secret.
func secretContractFindings(root string) ([]string, error) {
	section, err := docSectionText(root, docSection{kubernetesPage, "## Secrets"})
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

	for _, heading := range []string{"## Secrets", "## Updating Goiabada"} {
		text, err := docSectionText(root, docSection{kubernetesPage, heading})
		if err != nil {
			return nil, err
		}
		for _, command := range createSecretCommands(text) {
			want := sortedKeys(keysRead[command.secret])
			if got := sortedKeys(command.keys); strings.Join(got, " ") != strings.Join(want, " ") {
				findings = append(findings, fmt.Sprintf("%s: %s: `kubectl create secret generic %s` creates %v, want %v",
					kubernetesPage, heading, command.secret, got, want))
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
		return nil, fmt.Errorf("%s: ## Secrets holds no table headed %s", kubernetesPage, contractHeader)
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
