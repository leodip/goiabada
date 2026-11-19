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
// what to do, rather than at a job's first pull with Docker's message (decision 4).
//
// The Release workflow passes Check no secret, and its Images job logs in to Docker Hub before it
// starts Buildx, so the BuildKit image Buildx pulls there counts against the account's allowance
// rather than the one the runners share by address.

import (
	"fmt"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
	wholeExpression  = regexp.MustCompile(`^\$\{\{\s*(.+?)\s*\}\}$`)
	choiceExpression = regexp.MustCompile(`^(.+?)\s*&&\s*(.+?)\s*\|\|\s*(.+)$`)
	formatExpression = regexp.MustCompile(`^format\(\s*'((?:[^']|'')*)'\s*((?:,\s*[A-Za-z0-9_.-]+\s*)*)\)$`)
	quotedExpression = regexp.MustCompile(`^'((?:[^']|'')*)'$`)
	pinExpression    = regexp.MustCompile(`\$\{\{\s*needs\.versions\.outputs\.([A-Za-z0-9_-]+)\s*\}\}`)
	buildkitImage    = regexp.MustCompile(`(?:^|[\s,])image=(\S+)`)
	containerValue   = regexp.MustCompile(`^    container:\s*(\S.*)$`)
)

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

// stepKeyValue returns the key and value of a line of a step, the line's leading "- " taken off.
func stepKeyValue(line string) (key, value string) {
	trimmed := strings.TrimPrefix(strings.TrimSpace(line), "- ")
	key, value, _ = strings.Cut(trimmed, ":")
	return strings.TrimSpace(key), strings.TrimSpace(value)
}

// jobNeeds is whether a job's needs: names job, read from its lines.
func jobNeeds(lines []string, numbers []int, job string) bool {
	for _, n := range numbers {
		if v, ok := strings.CutPrefix(lines[n-1], "    needs:"); ok {
			for _, name := range strings.FieldsFunc(v, func(r rune) bool { return r == '[' || r == ']' || r == ',' || r == ' ' }) {
				if name == job {
					return true
				}
			}
		}
	}
	return false
}

// jobSteps splits a job's lines into its steps, each the numbers of its lines, a step beginning at
// a line "      - ".
func jobSteps(lines []string, numbers []int) [][]int {
	var steps [][]int
	open := false
	for _, n := range numbers {
		line := lines[n-1]
		if indent := len(line) - len(strings.TrimLeft(line, " ")); strings.TrimSpace(line) != "" && indent <= 4 {
			open = false
			continue
		}
		if strings.HasPrefix(line, "      - ") {
			steps = append(steps, nil)
			open = true
		}
		if open {
			steps[len(steps)-1] = append(steps[len(steps)-1], n)
		}
	}
	return steps
}

// stepUses is the action a step uses, or "".
func stepUses(lines []string, step []int) string {
	for _, n := range step {
		if m := workflowUses.FindStringSubmatch(lines[n-1]); m != nil {
			return m[1]
		}
	}
	return ""
}

// registryClients are the commands that log in to a registry with a login subcommand: docker login,
// skopeo login, helm registry login, and the like.
var registryClients = map[string]bool{"docker": true, "podman": true, "skopeo": true, "buildah": true, "crane": true, "oras": true, "regctl": true, "helm": true}

// runStepRegistryUse reads one command of a run step and returns the image it pulls, as a shell word,
// docker pull's or podman pull's, and whether it logs in to a registry.
func runStepRegistryUse(c shellCommand) (image *shellWord, login bool) {
	w := c.words
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

// checkRegistryFindings reads the Check workflow and returns every image it pulls from outside the
// mirror or names in a way this check cannot read, a job's container, a service, a docker:// step
// or a docker pull in a run step, every credential, login and Docker Hub secret it names, a Buildx started from Docker Hub's BuildKit image, a job that pulls without waiting for
// the Versions job, and a Versions job that does not check the mirror on every run. pins are the
// Versions job's outputs, by name, and mirrored the mirror addresses the list holds at those pins.
func checkRegistryFindings(file, text string, pins map[string]string, mirrored map[string]bool) []string {
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
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		key, value := stepKeyValue(line)
		image := ""
		switch {
		case key == "image" && value != "":
			image = yamlLineScalar(value)
		case containerValue.MatchString(line):
			image = yamlLineScalar(containerValue.FindStringSubmatch(line)[1])
		case key == "uses" && strings.HasPrefix(value, "docker://"):
			image = strings.TrimPrefix(value, "docker://")
		}
		if image != "" {
			images++
			pulls[jobOf[n]] = true
			for _, f := range checkImageFinding(at(n), image, pins, mirrored) {
				add(n, "%s", f)
			}
		}
		switch {
		case key == "credentials":
			add(n, "%s gives registry credentials: Check pulls anonymously from the public mirror, so remove them", at(n))
		case key == "uses" && strings.HasPrefix(value, "docker/login-action@"):
			add(n, "%s logs in to a registry: Check pulls anonymously from the public mirror and logs in nowhere, so remove the step", at(n))
		case strings.Contains(line, "DOCKERHUB"):
			add(n, "%s names a Docker Hub secret: Check takes none, so a fork's run, Dependabot's and the maintainer's pull the same way; remove it", at(n))
		}
		if strings.Contains(line, "docker build") || strings.Contains(line, "docker buildx build") {
			pulls[jobOf[n]] = true
		}
	}
	for _, run := range workflowRuns(lines) {
		for _, c := range readShell(run.script.text).commands {
			n := run.script.offset + c.line
			image, login := runStepRegistryUse(c)
			switch {
			case login:
				add(n, "%s logs in to a registry with %s: Check pulls anonymously from the public mirror and logs in nowhere, so remove it", at(n), c.words[0].value)
			case image == nil:
			case image.expands:
				images++
				pulls[jobOf[n]] = true
				add(n, "%s pulls the image %s, which a shell expansion gives, so this check cannot tell where from: write it out, %s/<image>:<tag>", at(n), image.raw, ciMirror)
			default:
				images++
				pulls[jobOf[n]] = true
				for _, f := range checkImageFinding(at(n), image.value, pins, mirrored) {
					add(n, "%s", f)
				}
			}
		}
	}

	names := make([]string, 0, len(jobs))
	for job := range jobs {
		names = append(names, job)
	}
	sort.Slice(names, func(a, b int) bool { return jobs[names[a]][0] < jobs[names[b]][0] })
	for _, job := range names {
		numbers := jobs[job]
		for _, step := range jobSteps(lines, numbers) {
			if !strings.HasPrefix(stepUses(lines, step), "docker/setup-buildx-action@") {
				continue
			}
			pulls[job] = true
			buildkit := 0
			for _, n := range step {
				if m := buildkitImage.FindStringSubmatch(lines[n-1]); m != nil && !strings.HasPrefix(strings.TrimSpace(lines[n-1]), "#") {
					buildkit = n
					images++
					for _, f := range checkImageFinding(at(n), m[1], pins, mirrored) {
						add(n, "%s", f)
					}
				}
			}
			if buildkit == 0 {
				add(step[0], "%s starts Buildx from its default BuildKit image, which it pulls from Docker Hub: give the step driver-opts: image=%s/buildkit:<tag>, a tag %s holds",
					at(step[0]), ciMirror, mirrorList)
			}
		}
		if job != "versions" && pulls[job] && !jobNeeds(lines, numbers, "versions") {
			add(numbers[0], "%s pulls an image and does not need versions, so it can pull before the Versions job has checked that the mirror holds every tag", at(numbers[0]))
		}
	}

	versions, ok := jobs["versions"]
	switch {
	case !ok:
		add(len(lines), "check mirror: %s has no versions job, which checks that the mirror holds every tag before a job pulls one", file)
	default:
		checked := 0
		for _, step := range jobSteps(lines, versions) {
			runs, conditional := false, 0
			for _, n := range step {
				if strings.Contains(lines[n-1], missingCheck) {
					runs = true
				}
				if key, _ := stepKeyValue(lines[n-1]); key == "if" {
					conditional = n
				}
			}
			if !runs {
				continue
			}
			checked = step[0]
			if conditional != 0 {
				add(conditional, "%s runs %s under a condition: it checks the mirror on every run, whichever tags the run's jobs pull", at(conditional), missingCheck)
			}
		}
		for _, n := range versions {
			if strings.HasPrefix(lines[n-1], "    if:") {
				add(n, "%s runs under a condition: it checks the mirror on every run, and a job skipped because it did not run counts as passing", at(n))
			}
		}
		if checked == 0 {
			add(versions[0], "%s does not run %s, so a run whose mirror lacks a tag fails at its first pull with Docker's message rather than at once with what to do",
				at(versions[0]), missingCheck)
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
// secrets, and a job that starts Buildx before it logs in to Docker Hub, a docker/login-action step
// that names no registry. It reports a file holding neither a call of Check nor a Buildx, since a
// check that read nothing would pass on any file.
func releaseRegistryFindings(file, text string) []string {
	lines := workflowLines(text)
	jobs := workflowJobs(lines)
	names := make([]string, 0, len(jobs))
	for job := range jobs {
		names = append(names, job)
	}
	sort.Slice(names, func(a, b int) bool { return jobs[names[a]][0] < jobs[names[b]][0] })

	var findings []string
	calls, buildx := 0, 0
	for _, job := range names {
		numbers := jobs[job]
		callsCheck := false
		for _, n := range numbers {
			if v, ok := strings.CutPrefix(lines[n-1], "    uses:"); ok && strings.TrimSpace(v) == "./"+checkWorkflow {
				callsCheck = true
				calls++
			}
		}
		for _, n := range numbers {
			if callsCheck && strings.HasPrefix(lines[n-1], "    secrets:") {
				findings = append(findings, fmt.Sprintf("check mirror: %s:%d (%s) passes Check secrets, which takes none: remove secrets:", file, n, job))
			}
		}
		loggedIn := false
		for _, step := range jobSteps(lines, numbers) {
			uses := stepUses(lines, step)
			if strings.HasPrefix(uses, "docker/login-action@") {
				registry := false
				for _, n := range step {
					if key, _ := stepKeyValue(lines[n-1]); key == "registry" {
						registry = true
					}
				}
				loggedIn = loggedIn || !registry
			}
			if strings.HasPrefix(uses, "docker/setup-buildx-action@") {
				buildx++
				if !loggedIn {
					findings = append(findings, fmt.Sprintf("check mirror: %s:%d (%s) starts Buildx before it logs in to Docker Hub, so Buildx pulls its BuildKit image anonymously, against the allowance GitHub's runners share by address: log in first",
						file, step[0], job))
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
			"check mirror: check.yml:35 (build) starts Buildx from its default BuildKit image, which it pulls from Docker Hub: give the step driver-opts: image=ghcr.io/leodip/goiabada-ci/buildkit:<tag>")
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
	t.Run("a workflow with neither read nothing", func(t *testing.T) {
		assertFindings(t, releaseRegistryFindings("release.yml", "jobs:\n  verify:\n    steps:\n      - run: true\n"),
			"check mirror: release.yml holds no job that calls ./.github/workflows/check.yml",
			"check mirror: release.yml starts no Buildx")
	})
}
