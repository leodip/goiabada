package guard

// The Check workflow pulls nothing from Docker Hub and logs in to no registry (#867 decision 5).
// Every image it names, a job's container, a service, the BuildKit image Buildx starts from, an
// image a run step pulls with docker pull, comes from CI's mirror, ghcr.io/leodip/goiabada-ci, whose public packages need no login, with the
// registry and the repository written out and a pin only in the tag; SQL Server's image, on
// Microsoft's registry, which needs no login either, is the one it names outside the mirror. Each
// mirror address is one the mirror's list holds, .github/mirror/images as mirror.sh list reads it,
// so the Mirror workflow copies it. Check names no registry credentials, logs in nowhere and takes
// no Docker Hub secret, so a fork's run, Dependabot's and the maintainer's pull the same way: no
// login step, and no registry login in a run step.
//
// The Versions job, which every job that pulls an image waits for, runs mirror.sh missing on every
// run, so a mirror that lacks a tag the branch's list names fails the run at once, saying which and
// what to do, rather than at a job's first pull with Docker's message (decision 4). It runs it in a
// step of its own, with no if: and no continue-on-error, so the check's failure is the job's.
//
// The Release workflow passes Check no secret, and its Images job logs in to Docker Hub, in a step
// that runs unconditionally, before it starts Buildx, so the BuildKit image Buildx pulls there
// counts against the account's allowance rather than the one the runners share by address.
//
// A job that pulls runs only when the Versions job succeeded: its if: holds no status function,
// always(), failure(), cancelled() or success(), any of which replaces the implicit success() check
// of the jobs it needs, or success() is an operand of the && that joins the whole condition,
// (a && b) && c counting as a && b && c, so the condition requires it. Actions binds && more
// tightly than ||, so success() && a || b requires no success(), and success() && (a || b) does.
// The Versions job runs mirror.sh missing alone in its step's script, in the foreground, so its
// exit status is the step's. A docker logout from Docker Hub between the Release workflow's login and its Buildx
// undoes the login.
//
// Jobs' containers, services, needs and if:, and steps' fields and scripts, are read as YAML reads
// them (workflow_yaml_test.go), in block or flow style; a run step's commands with the shell reader,
// sudo before one included; and driver-opts as Buildx reads each of its lines, CSV fields of
// key=value.

import (
	"encoding/csv"
	"fmt"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.yaml.in/yaml/v3"
)

const (
	// releaseWorkflow is relative to the repository root.
	releaseWorkflow = ".github/workflows/release.yml"
	// sqlServerRepository is SQL Server's image, on Microsoft's registry: the one Check names outside
	// the mirror.
	sqlServerRepository = "mcr.microsoft.com/mssql/server"
	// missingCheck is the command the Versions job checks the mirror with.
	missingCheck = mirrorScript + " missing"
)

var (
	wholeExpression = regexp.MustCompile(`^\$\{\{\s*(.+?)\s*\}\}$`)
	// choiceExpression is cond && A || B, split at the last && before the first || after it, so a
	// condition can itself join comparisons with &&.
	choiceExpression = regexp.MustCompile(`^(.+)\s*&&\s*(.+?)\s*\|\|\s*(.+)$`)
	formatExpression = regexp.MustCompile(`^format\(\s*'((?:[^']|'')*)'\s*((?:,\s*[A-Za-z0-9_.-]+\s*)*)\)$`)
	quotedExpression = regexp.MustCompile(`^'((?:[^']|'')*)'$`)
	pinExpression    = regexp.MustCompile(`\$\{\{\s*needs\.versions\.outputs\.([A-Za-z0-9_-]+)\s*\}\}`)
	// statusFunction is a status check function, which Actions' expressions name in any case.
	statusFunction = regexp.MustCompile(`(?i)\b(always|failure|cancelled|success)\s*\(`)
	// standaloneMirrorCheck is a script that is the mirror's check alone, once comments are removed.
	standaloneMirrorCheck = regexp.MustCompile(`^(\./)?` + regexp.QuoteMeta(mirrorScript) + `[ \t]+missing$`)
)

// conjuncts are the operands an expression requires: its operands of && outside parentheses and
// quoted strings, each with the parentheses that wrap all of it removed and its own operands of &&
// in its place, so (a && b) && c gives a, b and c. Actions binds && more tightly than ||, so an
// expression with || outside parentheses and quoted strings, a && b || c, requires none of its
// operands and is returned whole.
func conjuncts(expression string) []string {
	expression = strings.TrimSpace(expression)
	for len(expression) > 1 && expression[0] == '(' && closingParenthesis(expression) == len(expression)-1 {
		expression = strings.TrimSpace(expression[1 : len(expression)-1])
	}
	var parts []string
	depth, quoted, start := 0, false, 0
	for i := 0; i < len(expression); i++ {
		switch c := expression[i]; {
		case c == '\'':
			quoted = !quoted
		case quoted:
		case c == '(':
			depth++
		case c == ')':
			depth--
		case depth == 0 && strings.HasPrefix(expression[i:], "||"):
			return []string{expression}
		case depth == 0 && strings.HasPrefix(expression[i:], "&&"):
			parts = append(parts, expression[start:i])
			start, i = i+2, i+1
		}
	}
	parts = append(parts, expression[start:])
	if len(parts) == 1 {
		return parts
	}
	var out []string
	for _, part := range parts {
		out = append(out, conjuncts(part)...)
	}
	return out
}

// closingParenthesis is the place of the parenthesis that closes the one expression opens with,
// outside quoted strings, or -1.
func closingParenthesis(expression string) int {
	depth, quoted := 0, false
	for i := 0; i < len(expression); i++ {
		switch c := expression[i]; {
		case c == '\'':
			quoted = !quoted
		case quoted:
		case c == '(':
			depth++
		case c == ')':
			depth--
			if depth == 0 {
				return i
			}
		}
	}
	return -1
}

// requiresSuccess is whether a job's if: holds only when the jobs it needs succeeded: it names no
// status function, so Actions adds success() to it, or success() is one of its operands of && (in
// ${{ }} or not, in any case and spacing), which the whole condition then requires.
func requiresSuccess(condition string) bool {
	if !statusFunction.MatchString(condition) {
		return true
	}
	condition = strings.TrimSpace(condition)
	if whole := wholeExpression.FindStringSubmatch(condition); whole != nil {
		condition = whole[1]
	}
	return slices.ContainsFunc(conjuncts(condition), func(part string) bool {
		return strings.EqualFold(strings.Join(strings.Fields(part), ""), "success()")
	})
}

// lineFinding is a finding and the line it is about, so findings are reported in the file's order.
type lineFinding struct {
	line int
	text string
}

// imageWrittenForms returns the images an image value can name, each as written, with a pin the
// Versions job gives as ${{ needs.versions.outputs.<name> }}. A value is text with such pins in it,
// or one expression that is a quoted text, a format('<text>', <pin>...) or a choice between two of
// them, cond && A || B, an empty text being no image. Anything else returns ok false.
func imageWrittenForms(value string) (forms []string, ok bool) {
	whole := wholeExpression.FindStringSubmatch(value)
	if whole == nil || strings.Contains(whole[1], "${{") {
		return []string{value}, true
	}
	operands := []string{whole[1]}
	if choice := choiceExpression.FindStringSubmatch(whole[1]); choice != nil {
		operands = choice[2:]
	}
	for _, operand := range operands {
		operand = strings.TrimSpace(operand)
		if quoted := quotedExpression.FindStringSubmatch(operand); quoted != nil {
			if text := strings.ReplaceAll(quoted[1], "''", "'"); text != "" {
				forms = append(forms, text)
			}
			continue
		}
		format := formatExpression.FindStringSubmatch(operand)
		if format == nil {
			return nil, false
		}
		text := strings.ReplaceAll(format[1], "''", "'")
		for i, arg := range strings.FieldsFunc(format[2], func(r rune) bool { return r == ',' || r == ' ' }) {
			text = strings.ReplaceAll(text, fmt.Sprintf("{%d}", i), "${{ "+arg+" }}")
		}
		forms = append(forms, text)
	}
	return forms, true
}

// imageName is an image reference without its tag or digest: its registry and repository.
func imageName(image string) string {
	if i := strings.Index(image, "@"); i >= 0 {
		image = image[:i]
	}
	if i := strings.LastIndex(image, ":"); i > strings.LastIndex(image, "/") {
		return image[:i]
	}
	return image
}

// imageRegistry is the registry an image reference names, docker.io when it names none.
func imageRegistry(image string) string {
	first, _, found := strings.Cut(image, "/")
	if found && (strings.ContainsAny(first, ".:") || first == "localhost") {
		return first
	}
	return "docker.io"
}

// checkImageFinding holds one image a Check line names to the mirror, or to SQL Server's registry,
// and returns what is wrong with it, or "". pins are the Versions job's outputs, by name, and
// mirrored the mirror addresses the list holds at those pins.
func checkImageFinding(at, value string, pins map[string]string, mirrored map[string]bool) []string {
	forms, ok := imageWrittenForms(value)
	if !ok {
		return []string{fmt.Sprintf("%s names the image %s through an expression this check cannot read: write ghcr.io/leodip/goiabada-ci/<image>:<tag>, with a pin from the Versions job only in the tag", at, value)}
	}
	var findings []string
	for _, form := range forms {
		if strings.Contains(imageName(form), "${{") {
			findings = append(findings, fmt.Sprintf("%s names the image %s, whose registry or repository comes from an expression: write them out, ghcr.io/leodip/goiabada-ci/<image>:<tag>, with a pin only in the tag", at, form))
			continue
		}
		resolved, unknown := form, ""
		resolved = pinExpression.ReplaceAllStringFunc(resolved, func(expression string) string {
			name := pinExpression.FindStringSubmatch(expression)[1]
			pin, ok := pins[name]
			if !ok {
				unknown = name
			}
			return pin
		})
		if unknown != "" || strings.Contains(resolved, "${{") {
			findings = append(findings, fmt.Sprintf("%s names the image %s, whose tag holds an expression that is not a pin of versions.yaml the Versions job gives", at, form))
			continue
		}
		name := imageName(resolved)
		switch {
		case strings.HasPrefix(name, ciMirror+"/"):
			if !mirrored[resolved] {
				findings = append(findings, fmt.Sprintf("%s names %s, which %s does not hold, so the mirror lacks it: add the image's Docker Hub address to %s, with {tools.<name>} where a pin of versions.yaml goes, and take that pin from the Versions job",
					at, form, mirrorList, mirrorList))
			}
		case name == sqlServerRepository:
		case imageRegistry(resolved) == "docker.io":
			findings = append(findings, fmt.Sprintf("%s names %s, from Docker Hub, which Check pulls nothing from: pull %s/%s from the mirror, adding the image to %s if it lacks it",
				at, form, ciMirror, form[strings.LastIndex(form[:len(imageName(form))], "/")+1:], mirrorList))
		default:
			findings = append(findings, fmt.Sprintf("%s names %s, from %s: Check pulls from the mirror, %s, and from Microsoft's registry SQL Server's image alone",
				at, form, imageRegistry(resolved), ciMirror))
		}
	}
	return findings
}

// namedImage is an image a job's container or a service names, the line its value is on, and the
// line of credentials given beside it, or 0.
type namedImage struct {
	image             string
	line, credentials int
}

// jobImages are the images a job runs in and beside: its container, written as an image or as a
// mapping holding one, and each of its services' images, in block or flow style. An empty image
// starts nothing, as a service's empty image does in a matrix entry that needs none.
func jobImages(job workflowJob) []namedImage {
	var images []namedImage
	add := func(holder *yaml.Node) {
		if value, ok := yamlScalar(holder); ok {
			if value != "" {
				images = append(images, namedImage{image: value, line: holder.Line})
			}
			return
		}
		var named namedImage
		if _, image := yamlField(holder, "image"); image != nil {
			if value, ok := yamlScalar(image); ok && value != "" {
				named.image, named.line = value, image.Line
			}
		}
		if key, _ := yamlField(holder, "credentials"); key != nil {
			named.credentials = key.Line
		}
		if named.image != "" || named.credentials != 0 {
			images = append(images, named)
		}
	}
	if _, container := job.field("container"); container != nil {
		add(container)
	}
	if _, services := job.field("services"); services != nil && services.Kind == yaml.MappingNode {
		for i := 1; i < len(services.Content); i += 2 {
			add(yamlResolved(services.Content[i]))
		}
	}
	return images
}

// registryClients are the commands that log in to a registry with a login subcommand: docker login,
// skopeo login, helm registry login, and the like.
var registryClients = map[string]bool{"docker": true, "podman": true, "skopeo": true, "buildah": true, "crane": true, "oras": true, "regctl": true, "helm": true}

// sudoValueOptions are sudo's options that take the next word as their value, as -u root does.
var sudoValueOptions = wordSet("-u", "--user", "-g", "--group", "-C", "--close-from", "-D", "--chdir", "-h", "--host",
	"-p", "--prompt", "-R", "--chroot", "-T", "--command-timeout", "-U", "--other-user")

// withoutSudo is a command's words with a sudo before them taken off, with its options, so sudo
// docker pull is read as the docker pull it runs.
func withoutSudo(w []shellWord) []shellWord {
	if len(w) == 0 || w[0].value != "sudo" {
		return w
	}
	w = w[1:]
	for len(w) > 0 && strings.HasPrefix(w[0].value, "-") {
		option := w[0].value
		w = w[1:]
		if option == "--" {
			break
		}
		if sudoValueOptions[option] && len(w) > 0 {
			w = w[1:]
		}
	}
	return w
}

// runStepRegistryUse reads one command of a run step and returns the image it pulls, as a shell word,
// docker pull's or podman pull's, and whether it logs in to a registry, sudo before it or not.
func runStepRegistryUse(c shellCommand) (image *shellWord, login bool) {
	w := withoutSudo(c.words)
	if len(w) < 2 || !registryClients[w[0].value] {
		return nil, false
	}
	for _, word := range w[1:min(len(w), 3)] {
		if word.value == "login" {
			return nil, true
		}
	}
	if w[0].value != "docker" && w[0].value != "podman" {
		return nil, false
	}
	args := w[1:]
	if len(args) >= 2 && args[0].value == "image" {
		args = args[1:]
	}
	if args[0].value != "pull" {
		return nil, false
	}
	for i := 1; i < len(args); i++ {
		switch {
		case args[i].value == "--platform":
			i++
		case strings.HasPrefix(args[i].value, "-"):
		default:
			return &args[i], false
		}
	}
	return nil, false
}

// isMirrorCheck is whether a command runs the mirror's check, mirror.sh missing.
func isMirrorCheck(c shellCommand) bool {
	w := c.words
	return len(w) >= 2 && (w[0].value == mirrorScript || w[0].value == "./"+mirrorScript) && w[1].value == "missing"
}

// dockerHubHosts are the names Docker's configuration keeps a Docker Hub login under.
var dockerHubHosts = wordSet("docker.io", "index.docker.io", "registry-1.docker.io")

// isDockerHubLogout is whether a command logs Docker out of Docker Hub, sudo before it or not:
// docker logout naming no registry, Docker Hub's, or one a shell expansion gives, which may be.
func isDockerHubLogout(c shellCommand) bool {
	w := withoutSudo(c.words)
	if len(w) < 2 || w[0].value != "docker" || w[1].value != "logout" {
		return false
	}
	for _, arg := range w[2:] {
		if strings.HasPrefix(arg.value, "-") {
			continue
		}
		if arg.expands {
			return true
		}
		host := arg.value
		for _, scheme := range []string{"https://", "http://"} {
			host = strings.TrimPrefix(host, scheme)
		}
		host, _, _ = strings.Cut(host, "/")
		return dockerHubHosts[host]
	}
	return true
}

// buildkitImages are the images driver-opts gives Buildx's container driver, with the line each is
// on, the option's text beginning on first. The setup action hands Buildx each line as one
// --driver-opt, which Buildx reads as CSV fields of key=value, so a field is an option only as a
// whole, quoted or not, and image=<ref> one whose key is image.
func buildkitImages(opts string, first int) (images []string, lines []int) {
	for i, line := range strings.Split(opts, "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		fields, err := csv.NewReader(strings.NewReader(strings.TrimSpace(line))).Read()
		if err != nil {
			continue
		}
		for _, field := range fields {
			if key, image, ok := strings.Cut(field, "="); ok && key == "image" {
				images, lines = append(images, image), append(lines, first+i)
			}
		}
	}
	return images, lines
}

// checkRegistryFindings reads the Check workflow and returns every image it pulls from outside the
// mirror or names in a way this check cannot read, a job's container, a service, a docker:// step
// or a docker pull in a run step, every credential, login and Docker Hub secret it names, a Buildx
// whose with: driver-opts gives no BuildKit image of the mirror, a job that pulls without needing
// the Versions job, and a Versions job that does not check the mirror on every run, in a step of
// its own whose failure fails the job. pins are the Versions job's outputs, by name, and mirrored
// the mirror addresses the list holds at those pins.
func checkRegistryFindings(file, text string, pins map[string]string, mirrored map[string]bool) []string {
	read, err := readWorkflowJobs(text)
	if err != nil {
		return []string{fmt.Sprintf("check mirror: %s cannot be read as YAML, so this check cannot tell what it pulls: %v", file, err)}
	}
	lines := workflowLines(text)
	jobs := workflowJobs(lines)
	jobOf := map[int]string{}
	for job, numbers := range jobs {
		for _, n := range numbers {
			jobOf[n] = job
		}
	}
	var found []lineFinding
	add := func(line int, format string, args ...any) {
		found = append(found, lineFinding{line, fmt.Sprintf(format, args...)})
	}
	at := func(n int) string {
		if job := jobOf[n]; job != "" {
			return fmt.Sprintf("check mirror: %s:%d (%s)", file, n, job)
		}
		return fmt.Sprintf("check mirror: %s:%d", file, n)
	}

	images := 0
	pulls := map[string]bool{}
	for i, line := range lines {
		n := i + 1
		trimmed := strings.TrimSpace(line)
		if trimmed != "" && !strings.HasPrefix(trimmed, "#") && strings.Contains(line, "DOCKERHUB") {
			add(n, "%s names a Docker Hub secret: Check takes none, so a fork's run, Dependabot's and the maintainer's pull the same way; remove it", at(n))
		}
	}

	var versions *workflowJob
	for i, job := range read {
		if job.name == "versions" {
			versions = &read[i]
		}
		for _, named := range jobImages(job) {
			if named.image != "" {
				images++
				pulls[job.name] = true
				for _, f := range checkImageFinding(at(named.line), named.image, pins, mirrored) {
					add(named.line, "%s", f)
				}
			}
			if n := named.credentials; n != 0 {
				add(n, "%s gives registry credentials: Check pulls anonymously from the public mirror, so remove them", at(n))
			}
		}
		for _, step := range job.steps {
			if src, ok := step.run(); ok {
				if strings.Contains(src.text, "docker build") || strings.Contains(src.text, "docker buildx build") {
					pulls[job.name] = true
				}
				for _, c := range readShell(src.text).commands {
					n := src.offset + c.line
					image, login := runStepRegistryUse(c)
					switch {
					case login:
						add(n, "%s logs in to a registry with %s: Check pulls anonymously from the public mirror and logs in nowhere, so remove it", at(n), withoutSudo(c.words)[0].value)
					case image == nil:
					case image.expands:
						images++
						pulls[job.name] = true
						add(n, "%s pulls the image %s, which a shell expansion gives, so this check cannot tell where from: write it out, %s/<image>:<tag>", at(n), image.raw, ciMirror)
					default:
						images++
						pulls[job.name] = true
						for _, f := range checkImageFinding(at(n), image.value, pins, mirrored) {
							add(n, "%s", f)
						}
					}
				}
			}
			uses, n := step.uses()
			switch {
			case strings.HasPrefix(uses, "docker://"):
				images++
				pulls[job.name] = true
				for _, f := range checkImageFinding(at(n), strings.TrimPrefix(uses, "docker://"), pins, mirrored) {
					add(n, "%s", f)
				}
			case strings.HasPrefix(uses, "docker/login-action@"):
				add(n, "%s logs in to a registry: Check pulls anonymously from the public mirror and logs in nowhere, so remove the step", at(n))
			case strings.HasPrefix(uses, "docker/setup-buildx-action@"):
				pulls[job.name] = true
				opts, node := step.input("driver-opts")
				var buildkit []string
				var imageLines []int
				if node != nil {
					buildkit, imageLines = buildkitImages(opts, yamlContentLine(node))
				}
				for i, image := range buildkit {
					images++
					for _, f := range checkImageFinding(at(imageLines[i]), image, pins, mirrored) {
						add(imageLines[i], "%s", f)
					}
				}
				if len(buildkit) == 0 {
					add(step.line, "%s starts Buildx from its default BuildKit image, which it pulls from Docker Hub: give the step with: driver-opts: image=%s/buildkit:<tag>, a tag %s holds",
						at(step.line), ciMirror, mirrorList)
				}
			}
		}
		if job.name != "versions" && pulls[job.name] {
			if !job.needs("versions") {
				add(job.line, "%s pulls an image and does not need versions, so it can pull before the Versions job has checked that the mirror holds every tag", at(job.line))
			} else if n, v := job.field("if"); n != 0 {
				condition, _ := yamlScalar(v)
				if m := statusFunction.FindStringSubmatch(condition); m != nil && !requiresSuccess(condition) {
					add(n, "%s runs under %s(), which drops the check that the jobs it needs succeeded, so it can pull after the Versions job has found a tag missing: "+
						"write the if: with no status function, or as success() && (<the rest>), so the job runs only when Versions succeeded", at(n), m[1])
				}
			}
		}
	}

	if versions == nil {
		add(len(lines), "check mirror: %s has no versions job, which checks that the mirror holds every tag before a job pulls one", file)
	} else {
		checked := false
		for _, step := range versions.steps {
			src, ok := step.run()
			if !ok {
				continue
			}
			script := readShell(src.text)
			if !slices.ContainsFunc(script.commands, isMirrorCheck) {
				continue
			}
			checked = true
			if n := step.conditional(); n != 0 {
				add(n, "%s runs %s under a condition: it checks the mirror on every run, whichever tags the run's jobs pull", at(n), missingCheck)
			}
			if n := toleratesFailure(step.field("continue-on-error")); n != 0 {
				add(n, "%s lets the Versions job go on when %s fails, so a tag the mirror lacks fails the run at a job's pull: remove continue-on-error", at(n), missingCheck)
			}
			if !standaloneMirrorCheck.MatchString(strings.TrimSpace(script.bare)) {
				add(step.line, "%s runs %s beside other commands or shell operators, which can hide its failure, as || true or a & that runs it in the background does: "+
					"give it a step whose run is %s alone", at(step.line), missingCheck, missingCheck)
			}
		}
		if n, _ := versions.field("if"); n != 0 {
			add(n, "%s runs under a condition: it checks the mirror on every run, and a job skipped because it did not run counts as passing", at(n))
		}
		if n := toleratesFailure(versions.field("continue-on-error")); n != 0 {
			add(n, "%s lets the run go on when the Versions job fails, so a tag the mirror lacks fails the run at a job's pull: remove continue-on-error", at(n))
		}
		if !checked {
			add(versions.line, "%s does not run %s, so a run whose mirror lacks a tag fails at its first pull with Docker's message rather than at once with what to do",
				at(versions.line), missingCheck)
		}
	}

	sort.SliceStable(found, func(a, b int) bool { return found[a].line < found[b].line })
	var findings []string
	for _, f := range found {
		findings = append(findings, f.text)
	}
	if images == 0 {
		findings = append(findings, fmt.Sprintf("check mirror: %s names no image, so this check read nothing", file))
	}
	return findings
}

// releaseRegistryFindings reads the Release workflow and returns a call of Check that passes it
// secrets, and a job that starts Buildx before it logs in to Docker Hub: in a docker/login-action
// step that names no registry and runs unconditionally, with no if: and no continue-on-error, and
// no docker logout from Docker Hub in a run step between the two. It
// reports a file holding neither a call of Check nor a Buildx, since a check that read nothing
// would pass on any file.
func releaseRegistryFindings(file, text string) []string {
	jobs, err := readWorkflowJobs(text)
	if err != nil {
		return []string{fmt.Sprintf("check mirror: %s cannot be read as YAML, so this check read nothing: %v", file, err)}
	}
	var findings []string
	calls, buildx := 0, 0
	for _, job := range jobs {
		_, called := job.field("uses")
		if uses, _ := yamlScalar(called); uses == "./"+checkWorkflow {
			calls++
			if n, _ := job.field("secrets"); n != 0 {
				findings = append(findings, fmt.Sprintf("check mirror: %s:%d (%s) passes Check secrets, which takes none: remove secrets:", file, n, job.name))
			}
		}
		loggedIn := false
		for _, step := range job.steps {
			if src, ok := step.run(); ok && slices.ContainsFunc(readShell(src.text).commands, isDockerHubLogout) {
				loggedIn = false
			}
			uses, _ := step.uses()
			if strings.HasPrefix(uses, "docker/login-action@") {
				_, registry := step.input("registry")
				unconditional := step.conditional() == 0 && toleratesFailure(step.field("continue-on-error")) == 0
				loggedIn = loggedIn || (registry == nil && unconditional)
			}
			if strings.HasPrefix(uses, "docker/setup-buildx-action@") {
				buildx++
				if !loggedIn {
					findings = append(findings, fmt.Sprintf("check mirror: %s:%d (%s) starts Buildx before it logs in to Docker Hub, so Buildx pulls its BuildKit image anonymously, against the allowance GitHub's runners share by address: log in first, in a step with no if: or continue-on-error",
						file, step.line, job.name))
				}
			}
		}
	}
	if calls == 0 {
		findings = append(findings, fmt.Sprintf("check mirror: %s holds no job that calls ./%s, so this check read no call of it", file, checkWorkflow))
	}
	if buildx == 0 {
		findings = append(findings, fmt.Sprintf("check mirror: %s starts no Buildx, so this check read no login before one", file))
	}
	return findings
}

// versionsPins are the tools pins of a versions.yaml, by name, as the Versions job gives them.
func versionsPins(versions string) map[string]string {
	pins := map[string]string{}
	for _, m := range regexp.MustCompile(`(?m)^  ([A-Za-z0-9_-]+): "([^"]+)"$`).FindAllStringSubmatch(versions, -1) {
		pins[m[1]] = m[2]
	}
	return pins
}

// mirroredAddresses are the mirror addresses mirror.sh list prints for the committed list over
// versions.
func mirroredAddresses(t *testing.T, versions string) map[string]bool {
	t.Helper()
	run := runMirror(t, "list", versions, mirrorRegistry{})
	require.True(t, run.ok, "mirror.sh list failed:\n%s", run.out)
	mirrored := map[string]bool{}
	for line := range strings.SplitSeq(strings.TrimSpace(run.out), "\n") {
		_, mirror, ok := strings.Cut(line, " ")
		require.True(t, ok, "list printed %q, not an upstream and a mirror address", line)
		mirrored[mirror] = true
	}
	return mirrored
}

// assertCheckRegistries is the reporting half of the Check workflow's registry guard, over the
// workflow under repoRoot: each finding of checkRegistryFindings an error, and a workflow that
// cannot be read, or no mirror address to hold its images to, fatal.
func assertCheckRegistries(r Reporter, repoRoot string, pins map[string]string, mirrored map[string]bool) {
	r.Helper()
	if len(mirrored) == 0 {
		r.Fatalf("check mirror: the mirror's list gave no address, so this check has nothing to hold Check's images to")
	}
	assertWorkflowFindings(r, "check mirror", repoRoot, checkWorkflow, func(file, text string) []string {
		return checkRegistryFindings(file, text, pins, mirrored)
	})
}

// Check's images are read with the Versions job's pins at mirrorVersions', none of the committed
// ones, so a pin written into Check rather than taken from the Versions job is told apart.
func TestCheckWorkflow_PullsOnlyFromTheMirrorAndLogsInNowhere(t *testing.T) {
	assertCheckRegistries(t, filepath.Dir(SourceRoot(t)), versionsPins(mirrorVersions), mirroredAddresses(t, mirrorVersions))
}

func TestReleaseWorkflow_PassesCheckNoSecretAndLogsInBeforeBuildx(t *testing.T) {
	assertWorkflowFindings(t, "check mirror", filepath.Dir(SourceRoot(t)), releaseWorkflow, releaseRegistryFindings)
}

// The reporting halves of the guards that read one workflow pass the workflow as it is committed,
// report a workflow that breaks their rule, and are fatal on a tree without it.
func TestWorkflowGuards_Reporting(t *testing.T) {
	pins, mirrored := versionsPins(mirrorVersions), mirroredAddresses(t, mirrorVersions)
	guards := []struct {
		name   string
		file   string
		assert func(r Reporter, root string)
		edit   [2]string
		want   string
	}{
		{
			"Check's registries", checkWorkflow,
			func(r Reporter, root string) { assertCheckRegistries(r, root, pins, mirrored) },
			[2]string{"          docker run --rm goiabada-docs-sources:ci npm test\n", "          docker run --rm goiabada-docs-sources:ci npm test\n          docker pull docker.io/library/hello-world:latest\n"},
			"(docs) names docker.io/library/hello-world:latest, from Docker Hub",
		},
		{
			"the Release workflow's registries", releaseWorkflow,
			func(r Reporter, root string) {
				assertWorkflowFindings(r, "check mirror", root, releaseWorkflow, releaseRegistryFindings)
			},
			[2]string{"    uses: ./.github/workflows/check.yml\n", "    uses: ./.github/workflows/check.yml\n    secrets: inherit\n"},
			"passes Check secrets",
		},
		{
			"the docs job", checkWorkflow,
			func(r Reporter, root string) {
				assertWorkflowFindings(r, "base registry", root, checkWorkflow, docsJobFindings)
			},
			[2]string{"node-version: ${{ needs.versions.outputs.node }}", "node-version: '24'"},
			"runs the docs browser test on Node 24",
		},
		{
			"the module tiers on the runner", checkWorkflow,
			func(r Reporter, root string) {
				assertWorkflowFindings(r, "runner jobs", root, checkWorkflow, runnerJobFindings)
			},
			[2]string{"    needs: versions\n    runs-on: ubuntu-latest\n    services:\n      # emaildelivery's TestSendEmail", "    needs: versions\n    runs-on: ubuntu-latest\n    container: ghcr.io/leodip/goiabada-ci/golang:1.28.0-bookworm\n    services:\n      # emaildelivery's TestSendEmail"},
			"(unit-authserver) runs the internal tier in a job container",
		},
	}
	for _, g := range guards {
		t.Run(g.name, func(t *testing.T) {
			pass := Run(func(r Reporter) { g.assert(r, repositoryTree(t, []string{g.file}, nil)) })
			assert.False(t, pass.Failed(), "the committed workflow failed: %s", pass.Text())

			fail := Run(func(r Reporter) {
				g.assert(r, repositoryTree(t, []string{g.file}, map[string][2]string{g.file: g.edit}))
			})
			assert.False(t, fail.Stopped, "a finding is an error, not a fatal: %s", fail.Text())
			require.NotEmpty(t, fail.Errors, "a workflow breaking the rule passed")
			assert.Contains(t, fail.Text(), g.want)

			empty := Run(func(r Reporter) { g.assert(r, t.TempDir()) })
			require.True(t, empty.Stopped, "a tree without the workflow passed: %s", empty.Text())
			assert.Contains(t, empty.Fatal, g.file+" cannot be read, so this check read nothing")
		})
	}
	t.Run("Check's registries with a list that gave no address", func(t *testing.T) {
		report := Run(func(r Reporter) {
			assertCheckRegistries(r, repositoryTree(t, []string{checkWorkflow}, nil), pins, map[string]bool{})
		})
		require.True(t, report.Stopped, "%s", report.Text())
		assert.Contains(t, report.Fatal, "the mirror's list gave no address")
	})
}

func TestCheckWorkflow_RegistryFindings(t *testing.T) {
	pins := map[string]string{"go": "1.28.0", "mailpit": "1.40.2"}
	mirrored := map[string]bool{
		"ghcr.io/leodip/goiabada-ci/golang:1.28.0-bookworm":   true,
		"ghcr.io/leodip/goiabada-ci/mysql:26":                 true,
		"ghcr.io/leodip/goiabada-ci/mailpit:v1.40.2":          true,
		"ghcr.io/leodip/goiabada-ci/buildkit:buildx-stable-1": true,
	}
	const workflow = "on:\n" + // 1
		"  workflow_call:\n" + // 2
		"    inputs:\n" + // 3
		"      full:\n" + // 4
		"        type: boolean\n" + // 5
		"jobs:\n" + // 6
		"  versions:\n" + // 7
		"    runs-on: ubuntu-latest\n" + // 8
		"    steps:\n" + // 9
		"      - uses: actions/checkout@0000000000000000000000000000000000000000 # v7\n" + // 10
		"      - name: The mirror holds every tag\n" + // 11
		"        run: .github/mirror/mirror.sh missing\n" + // 12
		"  tests:\n" + // 13
		"    needs: versions\n" + // 14
		"    strategy:\n" + // 15
		"      matrix:\n" + // 16
		"        include:\n" + // 17
		"          - { tier: data }\n" + // 18
		"          - { tier: integration }\n" + // 19
		"    container:\n" + // 20
		"      image: ghcr.io/leodip/goiabada-ci/golang:${{ needs.versions.outputs.go }}-bookworm\n" + // 21
		"    services:\n" + // 22
		"      mysql-server:\n" + // 23
		"        image: ghcr.io/leodip/goiabada-ci/mysql:26\n" + // 24
		"      mssql-server:\n" + // 25
		"        image: mcr.microsoft.com/mssql/server:2022-latest\n" + // 26
		"      mailpit:\n" + // 27
		"        image: ${{ matrix.tier == 'integration' && format('ghcr.io/leodip/goiabada-ci/mailpit:v{0}', needs.versions.outputs.mailpit) || '' }}\n" + // 28
		"    steps:\n" + // 29
		"      - run: ./run-tests.sh\n" + // 30
		"  build:\n" + // 31
		"    needs: [lint, versions]\n" + // 32
		"    steps:\n" + // 33
		"      # The image Buildx starts from is the mirror's.\n" + // 34
		"      - uses: docker/setup-buildx-action@0000000000000000000000000000000000000000 # v4\n" + // 35
		"        with:\n" + // 36
		"          driver-opts: image=ghcr.io/leodip/goiabada-ci/buildkit:buildx-stable-1\n" + // 37
		"      - run: docker buildx build --load -f Dockerfile .\n" + // 38
		"  lint:\n" + // 39
		"    steps:\n" + // 40
		"      - run: go vet ./...\n" // 41
	edit := func(t *testing.T, old, with string) string {
		t.Helper()
		require.Equal(t, 1, strings.Count(workflow, old), old)
		return strings.Replace(workflow, old, with, 1)
	}
	findings := func(src string) []string { return checkRegistryFindings("check.yml", src, pins, mirrored) }

	t.Run("images from the mirror at the Versions job's pins, and SQL Server's, pass", func(t *testing.T) {
		assertFindings(t, findings(workflow))
	})
	t.Run("a container from Docker Hub", func(t *testing.T) {
		assertFindings(t, findings(edit(t, "image: ghcr.io/leodip/goiabada-ci/golang:", "image: golang:")),
			"check mirror: check.yml:21 (tests) names golang:${{ needs.versions.outputs.go }}-bookworm, from Docker Hub, which Check pulls nothing from: pull ghcr.io/leodip/goiabada-ci/golang:${{ needs.versions.outputs.go }}-bookworm from the mirror")
	})
	t.Run("a service from Docker Hub written out in full", func(t *testing.T) {
		assertFindings(t, findings(edit(t, "ghcr.io/leodip/goiabada-ci/mysql:26", "docker.io/library/mysql:26")),
			"check mirror: check.yml:24 (tests) names docker.io/library/mysql:26, from Docker Hub, which Check pulls nothing from: pull ghcr.io/leodip/goiabada-ci/mysql:26")
	})
	t.Run("a Docker Hub image inside a choice by the matrix", func(t *testing.T) {
		assertFindings(t, findings(edit(t, "format('ghcr.io/leodip/goiabada-ci/mailpit:v{0}'", "format('axllent/mailpit:v{0}'")),
			"check mirror: check.yml:28 (tests) names axllent/mailpit:v${{ needs.versions.outputs.mailpit }}, from Docker Hub")
	})
	t.Run("a mirror address the list does not hold", func(t *testing.T) {
		assertFindings(t, findings(edit(t, "ghcr.io/leodip/goiabada-ci/mysql:26", "ghcr.io/leodip/goiabada-ci/mysql:27")),
			"check mirror: check.yml:24 (tests) names ghcr.io/leodip/goiabada-ci/mysql:27, which .github/mirror/images does not hold")
	})
	t.Run("a pin written into Check rather than taken from the Versions job", func(t *testing.T) {
		assertFindings(t, findings(edit(t, "${{ needs.versions.outputs.go }}-bookworm", "1.27.4-bookworm")),
			"check mirror: check.yml:21 (tests) names ghcr.io/leodip/goiabada-ci/golang:1.27.4-bookworm, which .github/mirror/images does not hold")
	})
	t.Run("a registry from an expression", func(t *testing.T) {
		assertFindings(t, findings(edit(t, "image: ghcr.io/leodip/goiabada-ci/golang:", "image: ${{ env.REGISTRY }}/golang:")),
			"check mirror: check.yml:21 (tests) names the image ${{ env.REGISTRY }}/golang:${{ needs.versions.outputs.go }}-bookworm, whose registry or repository comes from an expression")
	})
	t.Run("a repository from an expression inside a format", func(t *testing.T) {
		assertFindings(t, findings(edit(t, "format('ghcr.io/leodip/goiabada-ci/mailpit:v{0}', needs.versions.outputs.mailpit)",
			"format('ghcr.io/leodip/goiabada-ci/{0}:v{1}', env.MAILPIT, needs.versions.outputs.mailpit)")),
			"check mirror: check.yml:28 (tests) names the image ghcr.io/leodip/goiabada-ci/${{ env.MAILPIT }}:v${{ needs.versions.outputs.mailpit }}, whose registry or repository comes from an expression")
	})
	t.Run("an image from an expression this check cannot read", func(t *testing.T) {
		assertFindings(t, findings(edit(t, "image: ghcr.io/leodip/goiabada-ci/mysql:26", "image: ${{ needs.versions.outputs.mysql-image }}")),
			"check mirror: check.yml:24 (tests) names the image ${{ needs.versions.outputs.mysql-image }} through an expression this check cannot read")
	})
	t.Run("a tag holding an expression that is no pin", func(t *testing.T) {
		assertFindings(t, findings(edit(t, "ghcr.io/leodip/goiabada-ci/mysql:26", "ghcr.io/leodip/goiabada-ci/mysql:${{ matrix.mysql }}")),
			"check mirror: check.yml:24 (tests) names the image ghcr.io/leodip/goiabada-ci/mysql:${{ matrix.mysql }}, whose tag holds an expression that is not a pin")
	})
	t.Run("an image from another registry than the mirror and SQL Server's", func(t *testing.T) {
		assertFindings(t, findings(edit(t, "mcr.microsoft.com/mssql/server:2022-latest", "mcr.microsoft.com/azure-sql-edge:latest")),
			"check mirror: check.yml:26 (tests) names mcr.microsoft.com/azure-sql-edge:latest, from mcr.microsoft.com: Check pulls from the mirror")
	})
	t.Run("a container written on one line", func(t *testing.T) {
		src := edit(t, "    container:\n      image: ghcr.io/leodip/goiabada-ci/golang:${{ needs.versions.outputs.go }}-bookworm\n",
			"    container: golang:1.28.0-bookworm\n      \n")
		assertFindings(t, findings(src), "check mirror: check.yml:20 (tests) names golang:1.28.0-bookworm, from Docker Hub")
	})
	t.Run("a step running a Docker Hub image", func(t *testing.T) {
		assertFindings(t, findings(edit(t, "      - run: ./run-tests.sh\n", "      - uses: docker://alpine:3.24\n")),
			"check mirror: check.yml:30 (tests) names alpine:3.24, from Docker Hub")
	})
	t.Run("credentials on a container", func(t *testing.T) {
		assertFindings(t, findings(edit(t, "-bookworm\n", "-bookworm\n      credentials: ${{ fromJSON('{}') }}\n")),
			"check mirror: check.yml:22 (tests) gives registry credentials: Check pulls anonymously from the public mirror, so remove them")
	})
	t.Run("a login step", func(t *testing.T) {
		assertFindings(t, findings(edit(t, "      # The image Buildx", "      - uses: docker/login-action@0000000000000000000000000000000000000000 # v4\n        with:\n          registry: ghcr.io\n      # The image Buildx")),
			"check mirror: check.yml:34 (build) logs in to a registry: Check pulls anonymously from the public mirror and logs in nowhere")
	})
	t.Run("Docker Hub's secrets declared for a caller to pass", func(t *testing.T) {
		assertFindings(t, findings(edit(t, "        type: boolean\n", "        type: boolean\n    secrets:\n      DOCKERHUB_TOKEN:\n        required: false\n")),
			"check mirror: check.yml:7 names a Docker Hub secret: Check takes none")
	})
	t.Run("a Docker Hub secret in a job's env", func(t *testing.T) {
		assertFindings(t, findings(edit(t, "    needs: [lint, versions]\n", "    needs: [lint, versions]\n    env:\n      DOCKERHUB_USERNAME: ${{ secrets.DOCKERHUB_USERNAME }}\n")),
			"check mirror: check.yml:34 (build) names a Docker Hub secret")
	})
	t.Run("a Buildx started from its default image", func(t *testing.T) {
		assertFindings(t, findings(edit(t, "        with:\n          driver-opts: image=ghcr.io/leodip/goiabada-ci/buildkit:buildx-stable-1\n", "")),
			"check mirror: check.yml:35 (build) starts Buildx from its default BuildKit image, which it pulls from Docker Hub: give the step with: driver-opts: image=ghcr.io/leodip/goiabada-ci/buildkit:<tag>")
	})
	t.Run("a Buildx started from Docker Hub's BuildKit image", func(t *testing.T) {
		assertFindings(t, findings(edit(t, "image=ghcr.io/leodip/goiabada-ci/buildkit:", "image=moby/buildkit:")),
			"check mirror: check.yml:37 (build) names moby/buildkit:buildx-stable-1, from Docker Hub, which Check pulls nothing from: pull ghcr.io/leodip/goiabada-ci/buildkit:buildx-stable-1")
	})
	t.Run("a job that pulls without waiting for Versions", func(t *testing.T) {
		assertFindings(t, findings(edit(t, "    needs: [lint, versions]\n", "    needs: [lint]\n")),
			"check mirror: check.yml:31 (build) pulls an image and does not need versions")
	})
	t.Run("a Versions job that does not check the mirror", func(t *testing.T) {
		assertFindings(t, findings(edit(t, "        run: .github/mirror/mirror.sh missing\n", "        run: .github/mirror/mirror.sh list\n")),
			"check mirror: check.yml:7 (versions) does not run .github/mirror/mirror.sh missing, so a run whose mirror lacks a tag fails at its first pull with Docker's message")
	})
	t.Run("a Versions job that checks the mirror only on some runs", func(t *testing.T) {
		assertFindings(t, findings(edit(t, "      - name: The mirror holds every tag\n", "      - name: The mirror holds every tag\n        if: github.event_name == 'push'\n")),
			"check mirror: check.yml:12 (versions) runs .github/mirror/mirror.sh missing under a condition: it checks the mirror on every run")
	})
	t.Run("a Versions job that runs only on some runs", func(t *testing.T) {
		assertFindings(t, findings(edit(t, "    runs-on: ubuntu-latest\n", "    if: github.event_name == 'pull_request'\n    runs-on: ubuntu-latest\n")),
			"check mirror: check.yml:8 (versions) runs under a condition")
	})
	t.Run("no Versions job", func(t *testing.T) {
		src := edit(t, "  versions:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@0000000000000000000000000000000000000000 # v7\n      - name: The mirror holds every tag\n        run: .github/mirror/mirror.sh missing\n", "")
		got := findings(src)
		assert.Contains(t, strings.Join(got, "\n"), "check mirror: check.yml has no versions job")
	})
	t.Run("a docker pull from the mirror in a run step passes", func(t *testing.T) {
		assertFindings(t, findings(edit(t, "      - run: ./run-tests.sh\n", "      - run: |\n          ./run-tests.sh\n          docker pull --quiet ghcr.io/leodip/goiabada-ci/mysql:26\n")))
	})
	t.Run("a docker pull from Docker Hub in a run step", func(t *testing.T) {
		assertFindings(t, findings(edit(t, "      - run: ./run-tests.sh\n", "      - run: |\n          ./run-tests.sh\n          docker pull docker.io/library/hello-world:latest\n")),
			"check mirror: check.yml:32 (tests) names docker.io/library/hello-world:latest, from Docker Hub, which Check pulls nothing from")
	})
	t.Run("a docker image pull with a platform, of an image the list does not hold", func(t *testing.T) {
		assertFindings(t, findings(edit(t, "      - run: ./run-tests.sh\n", "      - run: docker image pull --platform linux/arm64 ghcr.io/leodip/goiabada-ci/mysql:27\n")),
			"check mirror: check.yml:30 (tests) names ghcr.io/leodip/goiabada-ci/mysql:27, which .github/mirror/images does not hold")
	})
	t.Run("a docker pull of an image a shell expansion gives", func(t *testing.T) {
		assertFindings(t, findings(edit(t, "      - run: ./run-tests.sh\n", "      - run: docker pull \"$IMAGE\"\n")),
			"check mirror: check.yml:30 (tests) pulls the image \"$IMAGE\", which a shell expansion gives")
	})
	t.Run("a docker pull in a job that does not wait for Versions", func(t *testing.T) {
		assertFindings(t, findings(edit(t, "      - run: go vet ./...\n", "      - run: go vet ./... && docker pull ghcr.io/leodip/goiabada-ci/mysql:26\n")),
			"check mirror: check.yml:39 (lint) pulls an image and does not need versions")
	})
	t.Run("a registry login in a run step", func(t *testing.T) {
		assertFindings(t, findings(edit(t, "      - run: ./run-tests.sh\n", "      - run: |\n          echo \"$TOKEN\" | docker login ghcr.io -u me --password-stdin\n          ./run-tests.sh\n")),
			"check mirror: check.yml:31 (tests) logs in to a registry with docker: Check pulls anonymously from the public mirror and logs in nowhere")
	})
	t.Run("a skopeo login in a run step", func(t *testing.T) {
		assertFindings(t, findings(edit(t, "      - run: go vet ./...\n", "      - run: skopeo login --username me docker.io\n")),
			"check mirror: check.yml:41 (lint) logs in to a registry with skopeo")
	})
	t.Run("a workflow naming no image read nothing", func(t *testing.T) {
		assertFindings(t, findings("jobs:\n  versions:\n    steps:\n      - run: .github/mirror/mirror.sh missing\n"),
			"check mirror: check.yml names no image, so this check read nothing")
	})
	t.Run("a workflow YAML cannot read", func(t *testing.T) {
		assertFindings(t, findings(workflow+"  broken: [\n"), "check mirror: check.yml cannot be read as YAML")
	})

	// The same rules, read as YAML reads the workflow rather than line by line.
	t.Run("needs written as a block sequence passes", func(t *testing.T) {
		assertFindings(t, findings(edit(t, "    needs: [lint, versions]\n", "    needs:\n      - lint\n      - versions\n")))
	})
	t.Run("a docker pull from Docker Hub through sudo", func(t *testing.T) {
		assertFindings(t, findings(edit(t, "      - run: ./run-tests.sh\n", "      - run: |\n          ./run-tests.sh\n          sudo docker pull docker.io/library/hello-world:latest\n")),
			"check mirror: check.yml:32 (tests) names docker.io/library/hello-world:latest, from Docker Hub, which Check pulls nothing from")
	})
	t.Run("a docker pull from Docker Hub through sudo with options", func(t *testing.T) {
		assertFindings(t, findings(edit(t, "      - run: ./run-tests.sh\n", "      - run: sudo -E -u root docker pull hello-world\n")),
			"check mirror: check.yml:30 (tests) names hello-world, from Docker Hub")
	})
	t.Run("a registry login through sudo", func(t *testing.T) {
		assertFindings(t, findings(edit(t, "      - run: go vet ./...\n", "      - run: sudo docker login ghcr.io\n")),
			"check mirror: check.yml:41 (lint) logs in to a registry with docker")
	})
	for _, quoted := range []string{"'docker://alpine:3.24'", `"docker://alpine:3.24"`} {
		t.Run("a step running a Docker Hub image, its uses quoted "+quoted[:1], func(t *testing.T) {
			assertFindings(t, findings(edit(t, "      - run: ./run-tests.sh\n", "      - uses: "+quoted+" # a comment\n")),
				"check mirror: check.yml:30 (tests) names alpine:3.24, from Docker Hub")
		})
	}
	t.Run("a login step whose uses is quoted", func(t *testing.T) {
		assertFindings(t, findings(edit(t, "      - run: go vet ./...\n", "      - uses: 'docker/login-action@0000000000000000000000000000000000000000'\n")),
			"check mirror: check.yml:41 (lint) logs in to a registry")
	})
	t.Run("a step written in flow style running a Docker Hub image", func(t *testing.T) {
		assertFindings(t, findings(edit(t, "      - run: ./run-tests.sh\n", "      - {name: Probe, uses: docker://alpine:3.24}\n")),
			"check mirror: check.yml:30 (tests) names alpine:3.24, from Docker Hub")
	})
	t.Run("the mirror's BuildKit image written in env rather than driver-opts", func(t *testing.T) {
		assertFindings(t, findings(edit(t, "        with:\n          driver-opts: image=", "        env:\n          OPTS: image=")),
			"check mirror: check.yml:35 (build) starts Buildx from its default BuildKit image")
	})
	t.Run("driver-opts as a block, the mirror's image among its options, passes", func(t *testing.T) {
		assertFindings(t, findings(edit(t, "          driver-opts: image=ghcr.io/leodip/goiabada-ci/buildkit:buildx-stable-1\n",
			"          driver-opts: |\n            network=host\n            image=ghcr.io/leodip/goiabada-ci/buildkit:buildx-stable-1\n")))
	})
	t.Run("driver-opts as a block giving Docker Hub's BuildKit image", func(t *testing.T) {
		assertFindings(t, findings(edit(t, "          driver-opts: image=ghcr.io/leodip/goiabada-ci/buildkit:buildx-stable-1\n",
			"          driver-opts: |\n            network=host\n            image=moby/buildkit:buildx-stable-1\n")),
			"check mirror: check.yml:39 (build) names moby/buildkit:buildx-stable-1, from Docker Hub")
	})
	t.Run("the mirror's check written in a step's name but not run", func(t *testing.T) {
		assertFindings(t, findings(edit(t, "      - name: The mirror holds every tag\n        run: .github/mirror/mirror.sh missing\n",
			"      - name: .github/mirror/mirror.sh missing\n        run: 'true'\n")),
			"check mirror: check.yml:7 (versions) does not run .github/mirror/mirror.sh missing")
	})
	t.Run("the mirror's check whose failure the step tolerates", func(t *testing.T) {
		assertFindings(t, findings(edit(t, "        run: .github/mirror/mirror.sh missing\n", "        run: .github/mirror/mirror.sh missing\n        continue-on-error: true\n")),
			"check mirror: check.yml:13 (versions) lets the Versions job go on when .github/mirror/mirror.sh missing fails")
	})
	t.Run("the mirror's check with continue-on-error false passes", func(t *testing.T) {
		assertFindings(t, findings(edit(t, "        run: .github/mirror/mirror.sh missing\n", "        run: .github/mirror/mirror.sh missing\n        continue-on-error: false\n")))
	})
	t.Run("a Versions job whose failure the run tolerates", func(t *testing.T) {
		assertFindings(t, findings(edit(t, "  versions:\n    runs-on: ubuntu-latest\n", "  versions:\n    continue-on-error: true\n    runs-on: ubuntu-latest\n")),
			"check mirror: check.yml:8 (versions) lets the run go on when the Versions job fails")
	})
	t.Run("the mirror's check beside a command that hides its failure", func(t *testing.T) {
		assertFindings(t, findings(edit(t, "        run: .github/mirror/mirror.sh missing\n", "        run: .github/mirror/mirror.sh missing || true\n")),
			"check mirror: check.yml:11 (versions) runs .github/mirror/mirror.sh missing beside other commands")
	})
	t.Run("the mirror's check run in the background", func(t *testing.T) {
		assertFindings(t, findings(edit(t, "        run: .github/mirror/mirror.sh missing\n", "        run: .github/mirror/mirror.sh missing &\n")),
			"check mirror: check.yml:11 (versions) runs .github/mirror/mirror.sh missing beside other commands or shell operators")
	})
	t.Run("the mirror's check alone in a block, under a comment, passes", func(t *testing.T) {
		assertFindings(t, findings(edit(t, "        run: .github/mirror/mirror.sh missing\n", "        run: |\n          # Every tag of the list.\n          ./.github/mirror/mirror.sh missing\n")))
	})
	t.Run("a job that pulls after the Versions job has failed", func(t *testing.T) {
		assertFindings(t, findings(edit(t, "    needs: versions\n    strategy:\n", "    needs: versions\n    if: ${{ always() }}\n    strategy:\n")),
			"check mirror: check.yml:15 (tests) runs under always(), which drops the check that the jobs it needs succeeded")
	})
	t.Run("a job that pulls unless the run was cancelled", func(t *testing.T) {
		assertFindings(t, findings(edit(t, "    needs: versions\n    strategy:\n", "    needs: versions\n    if: \"!Cancelled() && inputs.full\"\n    strategy:\n")),
			"check mirror: check.yml:15 (tests) runs under Cancelled(), which drops the check")
	})
	t.Run("a job that pulls under an event condition passes", func(t *testing.T) {
		assertFindings(t, findings(edit(t, "    needs: versions\n    strategy:\n",
			"    needs: versions\n    if: github.event_name != 'pull_request' || github.event.pull_request.draft == false\n    strategy:\n")))
	})
	t.Run("a job that pulls under an explicit success() passes", func(t *testing.T) {
		assertFindings(t, findings(edit(t, "    needs: versions\n    strategy:\n", "    needs: versions\n    if: ${{ success() }}\n    strategy:\n")))
	})
	t.Run("a job that pulls under success() and an event condition passes", func(t *testing.T) {
		assertFindings(t, findings(edit(t, "    needs: versions\n    strategy:\n",
			"    needs: versions\n    if: (Success ( ) && !cancelled()) && (github.event_name != 'pull_request' || github.event.pull_request.draft == false)\n    strategy:\n")))
	})
	t.Run("a job that pulls when success() binds only the left side of ||", func(t *testing.T) {
		assertFindings(t, findings(edit(t, "    needs: versions\n    strategy:\n",
			"    needs: versions\n    if: success() && github.event_name != 'pull_request' || github.event.pull_request.draft == false\n    strategy:\n")),
			"check mirror: check.yml:15 (tests) runs under success(), which drops the check that the jobs it needs succeeded, so it can pull after the Versions job has found a tag missing: "+
				"write the if: with no status function, or as success() && (<the rest>), so the job runs only when Versions succeeded")
	})
	t.Run("a job that pulls under success() and a grouped event condition passes", func(t *testing.T) {
		assertFindings(t, findings(edit(t, "    needs: versions\n    strategy:\n",
			"    needs: versions\n    if: success() && (github.event_name != 'pull_request' || github.event.pull_request.draft == false)\n    strategy:\n")))
	})
	t.Run("a job that pulls when a grouped success() binds only one side of ||", func(t *testing.T) {
		assertFindings(t, findings(edit(t, "    needs: versions\n    strategy:\n",
			"    needs: versions\n    if: (success() && inputs.full || github.event.pull_request.draft == false) && inputs.other\n    strategy:\n")),
			"check mirror: check.yml:15 (tests) runs under success(), which drops the check")
	})
	t.Run("a job that pulls when success() or another status function holds", func(t *testing.T) {
		assertFindings(t, findings(edit(t, "    needs: versions\n    strategy:\n", "    needs: versions\n    if: success() || failure()\n    strategy:\n")),
			"check mirror: check.yml:15 (tests) runs under success(), which drops the check")
	})
	t.Run("a job that pulls when success() is negated or quoted", func(t *testing.T) {
		assertFindings(t, findings(edit(t, "    needs: versions\n    strategy:\n", "    needs: versions\n    if: \"!(success() && inputs.full) && 'success()'\"\n    strategy:\n")),
			"check mirror: check.yml:15 (tests) runs under success(), which drops the check")
	})
	t.Run("a container written as a flow mapping, from Docker Hub", func(t *testing.T) {
		src := edit(t, "    container:\n      image: ghcr.io/leodip/goiabada-ci/golang:${{ needs.versions.outputs.go }}-bookworm\n",
			"    container: {image: golang:1.28.0-bookworm}\n      \n")
		assertFindings(t, findings(src), "check mirror: check.yml:20 (tests) names golang:1.28.0-bookworm, from Docker Hub")
	})
	t.Run("a service written as a flow mapping, from Docker Hub", func(t *testing.T) {
		src := edit(t, "      mysql-server:\n        image: ghcr.io/leodip/goiabada-ci/mysql:26\n", "      mysql-server: {image: mysql:26}\n      \n")
		assertFindings(t, findings(src), "check mirror: check.yml:23 (tests) names mysql:26, from Docker Hub")
	})
	t.Run("a service written as a flow mapping, from the mirror, passes", func(t *testing.T) {
		assertFindings(t, findings(edit(t, "      mysql-server:\n        image: ghcr.io/leodip/goiabada-ci/mysql:26\n",
			"      mysql-server: { image: 'ghcr.io/leodip/goiabada-ci/mysql:26' }\n      \n")))
	})
	t.Run("credentials on a container written as a flow mapping", func(t *testing.T) {
		src := edit(t, "    container:\n      image: ghcr.io/leodip/goiabada-ci/golang:${{ needs.versions.outputs.go }}-bookworm\n",
			"    container: {image: 'ghcr.io/leodip/goiabada-ci/golang:${{ needs.versions.outputs.go }}-bookworm', credentials: {username: me}}\n      \n")
		assertFindings(t, findings(src), "check mirror: check.yml:20 (tests) gives registry credentials")
	})
	t.Run("a step written in flow style pulling from Docker Hub", func(t *testing.T) {
		assertFindings(t, findings(edit(t, "      - run: ./run-tests.sh\n", "      - {name: Probe, run: docker pull docker.io/library/hello-world:latest}\n")),
			"check mirror: check.yml:30 (tests) names docker.io/library/hello-world:latest, from Docker Hub")
	})
	t.Run("the mirror's BuildKit image inside a quoted driver-opts field", func(t *testing.T) {
		assertFindings(t, findings(edit(t, "          driver-opts: image=ghcr.io/leodip/goiabada-ci/buildkit:buildx-stable-1\n",
			"          driver-opts: |\n            \"env.LABELS=mode=ci,image=ghcr.io/leodip/goiabada-ci/buildkit:buildx-stable-1\"\n")),
			"check mirror: check.yml:35 (build) starts Buildx from its default BuildKit image")
	})
	t.Run("the mirror's BuildKit image as a quoted field beside another option passes", func(t *testing.T) {
		assertFindings(t, findings(edit(t, "          driver-opts: image=ghcr.io/leodip/goiabada-ci/buildkit:buildx-stable-1\n",
			"          driver-opts: |\n            \"env.LABELS=mode=ci,team=a\",\"image=ghcr.io/leodip/goiabada-ci/buildkit:buildx-stable-1\"\n")))
	})
}

func TestReleaseWorkflow_RegistryFindings(t *testing.T) {
	const workflow = "jobs:\n" + // 1
		"  checks:\n" + // 2
		"    needs: verify\n" + // 3
		"    uses: ./.github/workflows/check.yml\n" + // 4
		"    with:\n" + // 5
		"      full: true\n" + // 6
		"  images:\n" + // 7
		"    needs: checks\n" + // 8
		"    steps:\n" + // 9
		"      - uses: actions/checkout@0000000000000000000000000000000000000000 # v7\n" + // 10
		"      - uses: docker/login-action@0000000000000000000000000000000000000000 # v4\n" + // 11
		"        with:\n" + // 12
		"          username: ${{ secrets.DOCKER_USERNAME }}\n" + // 13
		"          password: ${{ secrets.DOCKER_PASSWORD }}\n" + // 14
		"      - uses: docker/setup-buildx-action@0000000000000000000000000000000000000000 # v4\n" + // 15
		"      - uses: docker/login-action@0000000000000000000000000000000000000000 # v4\n" + // 16
		"        with:\n" + // 17
		"          registry: ghcr.io\n" + // 18
		"          username: ${{ github.actor }}\n" // 19
	edit := func(t *testing.T, src, old, with string) string {
		t.Helper()
		require.Equal(t, 1, strings.Count(src, old), old)
		return strings.Replace(src, old, with, 1)
	}
	dockerHubLogin := "      - uses: docker/login-action@0000000000000000000000000000000000000000 # v4\n        with:\n          username: ${{ secrets.DOCKER_USERNAME }}\n          password: ${{ secrets.DOCKER_PASSWORD }}\n"
	buildx := "      - uses: docker/setup-buildx-action@0000000000000000000000000000000000000000 # v4\n"

	t.Run("a call passing no secret and a login before Buildx pass", func(t *testing.T) {
		assertFindings(t, releaseRegistryFindings("release.yml", workflow))
	})
	t.Run("a call passing Check secrets", func(t *testing.T) {
		assertFindings(t, releaseRegistryFindings("release.yml", edit(t, workflow, "      full: true\n",
			"      full: true\n    secrets:\n      DOCKERHUB_TOKEN: ${{ secrets.DOCKERHUB_TOKEN }}\n")),
			"check mirror: release.yml:7 (checks) passes Check secrets, which takes none: remove secrets:")
	})
	t.Run("a call passing every secret", func(t *testing.T) {
		assertFindings(t, releaseRegistryFindings("release.yml", edit(t, workflow, "      full: true\n", "      full: true\n    secrets: inherit\n")),
			"check mirror: release.yml:7 (checks) passes Check secrets")
	})
	t.Run("Buildx started before the Docker Hub login", func(t *testing.T) {
		src := edit(t, edit(t, workflow, buildx, ""), dockerHubLogin, buildx+dockerHubLogin)
		assertFindings(t, releaseRegistryFindings("release.yml", src),
			"check mirror: release.yml:11 (images) starts Buildx before it logs in to Docker Hub")
	})
	t.Run("a login to GHCR alone before Buildx is not Docker Hub's", func(t *testing.T) {
		src := "jobs:\n" + // 1
			"  checks:\n" + // 2
			"    uses: ./.github/workflows/check.yml\n" + // 3
			"  images:\n" + // 4
			"    steps:\n" + // 5
			"      - uses: docker/login-action@0000000000000000000000000000000000000000 # v4\n" + // 6
			"        with:\n" + // 7
			"          registry: ghcr.io\n" + // 8
			"      - uses: docker/setup-buildx-action@0000000000000000000000000000000000000000 # v4\n" + // 9
			dockerHubLogin // 10
		assertFindings(t, releaseRegistryFindings("release.yml", src),
			"check mirror: release.yml:9 (images) starts Buildx before it logs in to Docker Hub")
	})
	t.Run("a Docker Hub login skipped by its condition", func(t *testing.T) {
		src := edit(t, workflow, dockerHubLogin, strings.Replace(dockerHubLogin, " # v4\n", " # v4\n        if: ${{ false }}\n", 1))
		assertFindings(t, releaseRegistryFindings("release.yml", src),
			"check mirror: release.yml:16 (images) starts Buildx before it logs in to Docker Hub")
	})
	t.Run("a Docker Hub login whose failure the job tolerates", func(t *testing.T) {
		src := edit(t, workflow, dockerHubLogin, dockerHubLogin+"        continue-on-error: true\n")
		assertFindings(t, releaseRegistryFindings("release.yml", src),
			"check mirror: release.yml:16 (images) starts Buildx before it logs in to Docker Hub")
	})
	t.Run("a Docker Hub logout between the login and Buildx", func(t *testing.T) {
		src := edit(t, workflow, buildx, "      - run: docker logout\n"+buildx)
		assertFindings(t, releaseRegistryFindings("release.yml", src),
			"check mirror: release.yml:16 (images) starts Buildx before it logs in to Docker Hub")
	})
	t.Run("a Docker Hub logout naming the registry, through sudo", func(t *testing.T) {
		src := edit(t, workflow, buildx, "      - run: sudo docker logout https://index.docker.io/v1/\n"+buildx)
		assertFindings(t, releaseRegistryFindings("release.yml", src),
			"check mirror: release.yml:16 (images) starts Buildx before it logs in to Docker Hub")
	})
	t.Run("a GHCR logout between the login and Buildx passes", func(t *testing.T) {
		assertFindings(t, releaseRegistryFindings("release.yml", edit(t, workflow, buildx, "      - run: docker logout ghcr.io\n"+buildx)))
	})
	t.Run("a Check call and a login written with quotes pass", func(t *testing.T) {
		src := edit(t, workflow, "    uses: ./.github/workflows/check.yml\n", "    uses: './.github/workflows/check.yml'\n")
		src = edit(t, src, dockerHubLogin, strings.Replace(dockerHubLogin, "uses: docker/login-action@0000000000000000000000000000000000000000 # v4", `uses: "docker/login-action@0000000000000000000000000000000000000000"`, 1))
		assertFindings(t, releaseRegistryFindings("release.yml", src))
	})
	t.Run("a workflow with neither read nothing", func(t *testing.T) {
		assertFindings(t, releaseRegistryFindings("release.yml", "jobs:\n  verify:\n    steps:\n      - run: true\n"),
			"check mirror: release.yml holds no job that calls ./.github/workflows/check.yml",
			"check mirror: release.yml starts no Buildx")
	})
}
