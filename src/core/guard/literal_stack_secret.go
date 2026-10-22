package guard

import (
	"bytes"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// AssertNoLiteralStackSecrets holds every runnable file in the repository to supplying no data key
// and no database password by literal (#501). The hand-written Compose samples shipped one data key
// and three database passwords, so every deployment started from them sealed its client secrets,
// authenticator seeds, SMTP password and signing keys under a key anyone could read; the samples
// are gone, the auth server refuses that key as the current one, and the dev and CI stacks draw
// fresh values for every stack instead. This is the test that fails when a literal comes back.
//
// The runnable files are every YAML file (the GitHub workflows and actions, Compose files and any
// manifest), devcontainer.json and the editor's .vscode configurations, the Dockerfiles, the
// Makefiles, the committed env files, the shell scripts, the Go mains under a cmd/ directory, and
// the fenced code blocks of every Markdown page, the docs site's included, since a reader runs what
// a page prints. In those it reports a literal value given to one of stackSecretVariables, as a
// YAML or JSON key, a shell, Makefile or Dockerfile assignment (`ENV NAME value` among them), a
// `name: NAME` entry whose next line's `value:` is a literal, a `${NAME:-fallback}`, or a
// `${OTHER:-fallback}` assigned to it; a `-p<password>` or `--password` to mysql or mysqladmin; a
// `-P <password>` to sqlcmd; and, in a Go main, a `password:` field or an `os.Setenv` of one of the
// variables set to a string literal. A value passes when it is empty, an interpolation (`$NAME`,
// `${NAME}`, `$(command)`, `${{ expression }}`) or a placeholder in angle brackets.
//
// The bare .env a directory holds is not read: generate-env.sh writes src/.devcontainer/.env with
// the dev stack's real values, and .gitignore keeps it out of the repository.
//
// Separately, the published data key and the three published passwords are reported in any text
// file outside the few that name them to refuse them (publishedValueOwners), whatever its kind.
//
// Out of its scope are unit-test fixtures that configure no running stack: the config tests' data
// keys, the process tests' generated ones, and the setup wizard's testdata goldens, which record
// what the wizard writes for the values a test hands it. Each module's unit tier calls this, and
// the walk is the whole repository, from the parent of the source root.
func AssertNoLiteralStackSecrets(t *testing.T) {
	t.Helper()

	assertNoLiteralStackSecrets(t, filepath.Dir(SourceRoot(t)))
}

// assertNoLiteralStackSecrets is the reporting half. See Reporter in guard.go for why both halves
// exist.
func assertNoLiteralStackSecrets(r Reporter, repoRoot string) {
	r.Helper()

	findings, files, err := findLiteralStackSecrets(repoRoot)
	if err != nil {
		r.Fatalf("walking %s: %v", repoRoot, err)
	}
	if files == 0 {
		r.Fatalf("walked no runnable files under %s", repoRoot)
	}
	if len(findings) > 0 {
		r.Errorf("%d lines supply a data key or a database password by literal; draw it from the "+
			"environment, as the dev and CI stacks do (#501):\n\t%s", len(findings), strings.Join(findings, "\n\t"))
	}
}

// stackSecretVariables are the variables a stack hands its data key and database passwords in:
// the auth server's own, and the official database images'.
var stackSecretVariables = []string{
	"GOIABADA_AES_ENCRYPTION_KEY",
	"GOIABADA_AES_ENCRYPTION_KEY_PREVIOUS",
	"GOIABADA_DB_PASSWORD",
	"MYSQL_ROOT_PASSWORD",
	"MYSQL_PASSWORD",
	"POSTGRES_PASSWORD",
	"PGPASSWORD",
	"MSSQL_SA_PASSWORD",
	"SA_PASSWORD",
}

// publishedDataKey is the data key the Compose samples published, compared ignoring case as the
// auth server's refusal compares it; publishedPasswords are the three database passwords the
// samples, the devcontainer and CI used.
const publishedDataKey = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"

var publishedPasswords = []string{"mySqlPass123", "myPostgresPass123", "YourStr0ngPassw0rd!"}

// publishedValueOwners are the files, relative to the repository root, that name a published value
// to refuse it or to prove the refusal: this list, the auth server's refusal and its tests.
var publishedValueOwners = map[string]bool{
	"src/core/guard/literal_stack_secret.go":                       true,
	"src/authserver/internal/config/config.go":                     true,
	"src/authserver/internal/config/config_test.go":                true,
	"src/authserver/cmd/goiabada-authserver/main_data_key_test.go": true,
}

// skippedDirs are never walked: version control, installed packages, build output and the
// untracked scratch directories a checkout accumulates, none of them the repository's own files.
var skippedDirs = map[string]bool{
	".git": true, "node_modules": true, "testdata": true, "tmp": true, ".devdata": true,
	"dist": true, ".astro": true, "test-results": true, "playwright-report": true, ".state": true,
}

// textExtensions are the files the published values are looked for in.
var textExtensions = map[string]bool{
	".go": true, ".sh": true, ".yml": true, ".yaml": true, ".json": true, ".md": true, ".mdx": true,
	".toml": true, ".txt": true, ".html": true, ".ts": true, ".js": true, ".mjs": true, ".example": true,
	".mk": true,
}

type runnableKind int

const (
	notRunnable runnableKind = iota
	runnableConfig
	runnableShell
	runnableDockerfile
	runnableGoMain
	runnableMarkdown
)

// kindOf is what a file is to this guard, by its path relative to the repository root.
func kindOf(rel string) runnableKind {
	base := path.Base(rel)
	ext := path.Ext(base)
	switch {
	case ext == ".yml" || ext == ".yaml":
		return runnableConfig
	case base == "devcontainer.json", ext == ".json" && strings.Contains("/"+rel, "/.vscode/"):
		return runnableConfig
	case ext == ".dockerignore":
		return notRunnable
	case base == "Dockerfile", strings.HasPrefix(base, "Dockerfile-"), strings.HasPrefix(base, "Dockerfile."),
		ext == ".Dockerfile":
		return runnableDockerfile
	case ext == ".sh", base == "Makefile", ext == ".mk":
		return runnableShell
	case base != ".env" && (ext == ".env" || strings.HasSuffix(base, ".env.example")):
		return runnableShell
	case ext == ".go" && !strings.HasSuffix(base, "_test.go") && strings.Contains("/"+rel, "/cmd/"):
		return runnableGoMain
	case ext == ".md" || ext == ".mdx":
		return runnableMarkdown
	}
	return notRunnable
}

var (
	stackSecretNames = strings.Join(stackSecretVariables, "|")
	// A variable named, then `=` or `:` before its value, the name perhaps quoted: YAML, JSON and
	// shell all spell an assignment this way, and a Makefile also as `?=`, `:=` or `+=`. A name
	// inside ${...} is an expansion, read below.
	assignedVariable = regexp.MustCompile(`(?:^|[^A-Za-z0-9_${])(` + stackSecretNames + `)["']?\s*(?:[?+:]?=|:)`)
	// A Dockerfile's other spelling, `ENV NAME value`, with no `=`.
	dockerfileEnv = regexp.MustCompile(`(?i)^\s*ENV\s+(` + stackSecretNames + `)\s+([^=\s].*)$`)
	// A variable's fallback inside an expansion: ${NAME:-value}, ${NAME-value}, ${NAME:=value}.
	fallbackVariable = regexp.MustCompile(`\$\{(` + stackSecretNames + `):?[-=]([^}]*)\}`)
	// The fallback of an expansion of any variable, which an assignment's value opens with.
	anyFallback = regexp.MustCompile(`^["']?\$\{[A-Za-z_][A-Za-z0-9_]*:?[-=]([^}]*)\}`)
	// A Kubernetes-style entry: `name: NAME`, then `value:` on the next line.
	namedEntry      = regexp.MustCompile(`^\s*(?:-\s+)?name:\s*["']?(` + stackSecretNames + `)["']?\s*$`)
	namedEntryValue = regexp.MustCompile(`^\s*value:(.*)$`)
	mysqlClient     = regexp.MustCompile(`\bmysql(admin)?\b`)
	mysqlPassword   = regexp.MustCompile(`(?:^|\s)(?:-p|--password=)(\S+)|(?:^|\s)--password\s+([^-\s]\S*)`)
	sqlcmdClient    = regexp.MustCompile(`\bsqlcmd\b`)
	sqlcmdPassword  = regexp.MustCompile(`(?:^|\s)-P\s+(\S+)`)
	goPasswordField = regexp.MustCompile(`(?i)\bpassword:\s*("[^"]+"|` + "`[^`]+`" + `)`)
	goSetenv        = regexp.MustCompile(`\bos\.Setenv\(\s*"(` + stackSecretNames + `)"\s*,\s*("[^"]*"|` + "`[^`]*`" + `)`)
	markdownFence   = regexp.MustCompile("^\\s*(```|~~~)")
)

// findLiteralStackSecrets walks the repository under root and returns one finding per line that
// supplies a stack secret by literal or spells a published value, as `path:line: text` with the path
// relative to root, along with the number of runnable files it read.
func findLiteralStackSecrets(root string) ([]string, int, error) {
	var findings []string
	files := 0
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if p != root && skippedDirs[d.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		rel, relErr := filepath.Rel(root, p)
		if relErr != nil {
			return relErr
		}
		rel = filepath.ToSlash(rel)
		kind := kindOf(rel)
		if kind == notRunnable && !textExtensions[path.Ext(rel)] {
			return nil
		}
		content, readErr := os.ReadFile(p)
		if readErr != nil {
			return readErr
		}
		if !publishedValueOwners[rel] {
			findings = append(findings, publishedValuesIn(rel, content)...)
		}
		if kind != notRunnable {
			files++
			findings = append(findings, literalSecretsIn(rel, kind, content)...)
		}
		return nil
	})
	if err != nil {
		return nil, 0, err
	}
	return findings, files, nil
}

// publishedValuesIn reports each line of content spelling a published value.
func publishedValuesIn(rel string, content []byte) []string {
	lower := bytes.ToLower(content)
	if !bytes.Contains(lower, []byte(publishedDataKey)) && !containsAny(content, publishedPasswords) {
		return nil
	}
	var findings []string
	for i, line := range strings.Split(string(content), "\n") {
		if strings.Contains(strings.ToLower(line), publishedDataKey) || containsAny([]byte(line), publishedPasswords) {
			findings = append(findings, finding(rel, i+1, "a published value: "+strings.TrimSpace(line)))
		}
	}
	return findings
}

func containsAny(content []byte, values []string) bool {
	for _, v := range values {
		if bytes.Contains(content, []byte(v)) {
			return true
		}
	}
	return false
}

// logicalLine is one command or entry as a reader runs it: a line with the lines a trailing
// backslash continues it onto, numbered by its first.
type logicalLine struct {
	number int
	text   string
}

// logicalLines splits content into logical lines; for a Markdown page, only those inside a fenced
// code block.
func logicalLines(content []byte, kind runnableKind) []logicalLine {
	var out []logicalLine
	inFence := false
	var pending *logicalLine
	for i, line := range strings.Split(string(content), "\n") {
		if kind == runnableMarkdown {
			if markdownFence.MatchString(line) {
				inFence = !inFence
				pending = nil
				continue
			}
			if !inFence {
				continue
			}
		}
		trimmed := strings.TrimRight(line, " \t\r")
		continued := strings.HasSuffix(trimmed, `\`)
		if continued {
			trimmed = strings.TrimSuffix(trimmed, `\`)
		}
		if pending != nil {
			pending.text += " " + strings.TrimSpace(trimmed)
		} else {
			out = append(out, logicalLine{number: i + 1, text: trimmed})
			pending = &out[len(out)-1]
		}
		if !continued {
			pending = nil
		}
	}
	return out
}

// literalSecretsIn reports each logical line of a runnable file that supplies a stack secret by
// literal.
func literalSecretsIn(rel string, kind runnableKind, content []byte) []string {
	var findings []string
	named := ""
	for _, line := range logicalLines(content, kind) {
		reason := literalSecretIn(line.text, kind)
		if named != "" && reason == "" {
			if m := namedEntryValue.FindStringSubmatch(line.text); m != nil && isLiteral(firstValue(m[1])) {
				reason = named + " set to a literal by the value after its name"
			}
		}
		if reason != "" {
			findings = append(findings, finding(rel, line.number, reason+": "+strings.TrimSpace(line.text)))
		}
		named = ""
		if kind == runnableConfig || kind == runnableMarkdown {
			if m := namedEntry.FindStringSubmatch(line.text); m != nil {
				named = m[1]
			}
		}
	}
	return findings
}

// literalSecretIn is why line supplies a stack secret by literal, or "" when it does not.
func literalSecretIn(line string, kind runnableKind) string {
	if kind == runnableGoMain {
		if m := goPasswordField.FindStringSubmatch(line); m != nil {
			return "a password field set to a literal"
		}
		if m := goSetenv.FindStringSubmatch(line); m != nil && isLiteral(m[2][1:len(m[2])-1]) {
			return m[1] + " set to a literal by os.Setenv"
		}
		return ""
	}
	if kind == runnableDockerfile {
		if m := dockerfileEnv.FindStringSubmatch(line); m != nil && isLiteral(firstValue(m[2])) {
			return m[1] + " set to a literal"
		}
	}
	for _, m := range fallbackVariable.FindAllStringSubmatch(line, -1) {
		if isLiteral(m[2]) {
			return m[1] + " falls back to a literal"
		}
	}
	for _, m := range assignedVariable.FindAllStringSubmatchIndex(line, -1) {
		rest := strings.TrimSpace(line[m[1]:])
		if f := anyFallback.FindStringSubmatch(rest); f != nil && isLiteral(f[1]) {
			return line[m[2]:m[3]] + " falls back to a literal"
		}
		if isLiteral(firstValue(rest)) {
			return line[m[2]:m[3]] + " set to a literal"
		}
	}
	if mysqlClient.MatchString(line) {
		for _, m := range mysqlPassword.FindAllStringSubmatch(line, -1) {
			if isLiteral(m[1] + m[2]) {
				return "a literal password to mysql"
			}
		}
	}
	if sqlcmdClient.MatchString(line) {
		for _, m := range sqlcmdPassword.FindAllStringSubmatch(line, -1) {
			if isLiteral(m[1]) {
				return "a literal -P password to sqlcmd"
			}
		}
	}
	return ""
}

// firstValue is the value an assignment's right-hand side opens with: up to a closing quote when
// it is quoted, up to the closing bracket when it is a placeholder, up to whitespace or a comma
// otherwise, so a YAML comment or a JSON comma after it is not read as part of it.
func firstValue(rest string) string {
	rest = strings.TrimSpace(rest)
	if rest == "" {
		return ""
	}
	if rest[0] == '<' {
		if end := strings.IndexByte(rest, '>'); end >= 0 {
			return rest[:end+1]
		}
	}
	if q := rest[0]; q == '"' || q == '\'' {
		if end := strings.IndexByte(rest[1:], q); end >= 0 {
			return rest[1 : end+1]
		}
		return rest[1:]
	}
	if end := strings.IndexAny(rest, " \t,"); end >= 0 {
		return rest[:end]
	}
	return rest
}

// isLiteral reports whether value, with the quotes and escapes around it stripped, is a literal:
// not empty, not an interpolation and not a placeholder.
func isLiteral(value string) bool {
	v := strings.Trim(strings.TrimSpace(value), `"'\`)
	switch {
	case v == "":
		return false
	case strings.HasPrefix(v, "$"):
		return false
	case strings.HasPrefix(v, "<") && strings.HasSuffix(v, ">"):
		return false
	}
	return true
}

func finding(rel string, line int, text string) string {
	return rel + ":" + strconv.Itoa(line) + ": " + strings.TrimSpace(text)
}
