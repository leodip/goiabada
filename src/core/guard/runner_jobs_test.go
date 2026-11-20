package guard

// The module tiers' jobs in Check run on the hosted runner, with Go from actions/setup-go as Lint
// and Vulnerabilities have it, and pull no job container (#867 decision 1): Unit / core,
// authserver, adminconsole and setup, and the three Unit / race jobs. A job keeps a container when
// it needs the database network, which the data and integration jobs do.
//
// TestSendEmail, in the internal tier, sends through Mailpit at the dev container's names,
// mailpit:1025 and mailpit:8025 (decision 2). In a container job the service is reached by that
// name; on the runner it is reached only through its ports mapped to the runner's and a line
// `127.0.0.1 mailpit` in the runner's hosts file, so a job on the runner with a Mailpit service
// has both, the hosts line added on every run in a step before the internal tier's.
//
// Each module tier runs after the step that sets Go up at the pin, which has no if:, and the
// internal tier's first call after the hosts line, so no call runs on the runner's own Go or
// before mailpit resolves.
//
// The Go cache splits with the environments, which keep it under different paths: one runner job,
// Unit / authserver, saves the runner's, and one container job's entry, Data / sqlite, saves the
// container's and compiles what the other database jobs run, so they restore its build rather
// than compile it. Two savers of one cache race for its key; none leaves every job compiling, as
// does a saver's setup step skipped by an if:. The two setup actions save when save-cache is
// 'true', compared as Actions compares it, ignoring case and keeping spaces, so the guard reads it
// for each matrix entry of the job: 'true' in every entry, or ${{ <condition> && '<a>' || '<b>' }}
// giving 'true' in the entries it does, <b> wherever the condition fails or <a> is empty, a
// condition being comparisons of matrix values joined by &&, as the compile step's if: is read too.

import (
	"fmt"
	"maps"
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

const checkWorkflow = ".github/workflows/check.yml"

// moduleTiers are run-tests.sh's tiers that need no database: the ones that run on the runner.
var moduleTiers = []string{"internal", "core", "adminconsole", "setup"}

// mailpitPorts are the SMTP and API ports TestSendEmail reaches Mailpit on.
var mailpitPorts = []string{"1025", "8025"}

// tierCall is one run-tests.sh call of a module tier: its line, and the place of its step among the
// job's steps.
type tierCall struct {
	line, step int
}

// cacheSave is a setup step's save-cache input: its line, its value, and the line of an if: that
// skips the step on some runs, or 0.
type cacheSave struct {
	line   int
	value  string
	ifLine int
}

// compileStep is a step that compiles the data and integration test binaries: its line and its if:,
// "" when it has none.
type compileStep struct {
	line      int
	condition string
}

// checkJob is what runnerJobFindings reads of one job, each line numbered from 1.
type checkJob struct {
	name string
	// container is the line of the job's container: key, or 0 when it runs on the runner.
	container int
	// tiers maps each module tier the job runs to its run-tests.sh calls, in the order they run.
	tiers map[string][]tierCall
	// setupGoStep is the place of the first step that sets Go up with actions/setup-go, itself or
	// through the runner's test setup, whenever the job reaches it, or -1, and setupGoLine its line;
	// setupGoIf is the line of the if: of the first one that sets it up only under a condition,
	// or 0.
	setupGoStep, setupGoLine, setupGoIf int
	// entries are the job's matrix entries, one without values when it has no matrix, and
	// matrixProblem why the guard cannot list them, or "".
	entries       []map[string]string
	matrixProblem string
	// dbTiers are the tiers its run-tests.sh calls name, as written: data, or ${{ matrix.tier }}.
	dbTiers []string
	// mailpit is the line of the job's Mailpit service, or 0, and mapped the ports it maps as
	// host:container.
	mailpit int
	mapped  []string
	// hostsStep is the place of the first step that adds 127.0.0.1 mailpit to /etc/hosts whenever
	// the job reaches it, or -1, and hostsLine its line; hostsIf is the line of the if: of one that
	// adds it only under a condition, or 0.
	hostsStep, hostsLine, hostsIf int
	// runnerSaves and containerSaves are the save-cache inputs of the job's two kinds of test setup.
	runnerSaves, containerSaves []cacheSave
	// compiles are the steps that compile the data and integration test binaries.
	compiles []compileStep
}

// saver is one matrix entry of a job that saves a cache, from the save-cache input on line.
type saver struct {
	job   checkJob
	entry map[string]string
	line  int
}

// describe is the saver's job, with its matrix entry's values when it has some.
func (s saver) describe() string {
	if len(s.entry) == 0 {
		return s.job.name
	}
	return s.job.name + " " + describeEntry(s.entry)
}

// describeEntry is a matrix entry's values, by key: (shard: 1/1, tier: data).
func describeEntry(entry map[string]string) string {
	keys := slices.Sorted(maps.Keys(entry))
	var parts []string
	for _, k := range keys {
		parts = append(parts, k+": "+entry[k])
	}
	return "(" + strings.Join(parts, ", ") + ")"
}

var (
	matrixComparison = regexp.MustCompile(`^matrix\.([A-Za-z0-9_-]+)\s*(==|!=)\s*'((?:[^']|'')*)'$`)
	matrixValue      = regexp.MustCompile(`^\$\{\{\s*matrix\.([A-Za-z0-9_-]+)\s*\}\}$`)
	runTestsAnyTier  = regexp.MustCompile(`run-tests\.sh\b[^\n]*--type\s+(\$\{\{[^}]*\}\}|[A-Za-z]+)`)
)

// matrixCondition is whether a condition holds for a matrix entry: no condition, or comparisons
// matrix.<key> == '<value>' or != joined by &&, compared as Actions compares text, ignoring case,
// in ${{ }} or not. ok is false for any other form.
func matrixCondition(condition string, entry map[string]string) (holds, ok bool) {
	condition = strings.TrimSpace(condition)
	if whole := wholeExpression.FindStringSubmatch(condition); whole != nil {
		condition = whole[1]
	}
	if condition == "" {
		return true, true
	}
	holds = true
	for part := range strings.SplitSeq(condition, "&&") {
		m := matrixComparison.FindStringSubmatch(strings.TrimSpace(part))
		if m == nil {
			return false, false
		}
		equal := strings.EqualFold(entry[m[1]], strings.ReplaceAll(m[3], "''", "'"))
		holds = holds && equal == (m[2] == "==")
	}
	return holds, true
}

// savesCache is whether a setup action saves the cache in a matrix entry, given its save-cache: when
// the input is 'true', or ${{ <condition> && '<a>' || '<b>' }} gives 'true'. Actions passes the
// input on with its spaces and compares it to 'true' ignoring case alone, so ' true ' saves nothing.
// The expression gives <a> when the condition holds and <a> is not empty, and <b> otherwise, since
// && gives a false condition or <a>, and || passes over either when it is false or empty. ok is false
// for any other expression.
func savesCache(value string, entry map[string]string) (saves, ok bool) {
	whole := wholeExpression.FindStringSubmatch(value)
	if whole == nil {
		return strings.EqualFold(value, "true"), true
	}
	condition, first, second, ok := choice(whole[1])
	if !ok {
		return false, false
	}
	holds, ok := matrixCondition(condition, entry)
	a, b := quotedExpression.FindStringSubmatch(first), quotedExpression.FindStringSubmatch(second)
	if !ok || a == nil || b == nil {
		return false, false
	}
	result := b[1]
	if holds && a[1] != "" {
		result = a[1]
	}
	return strings.EqualFold(strings.ReplaceAll(result, "''", "'"), "true"), true
}

// matrixEntries lists a job's matrix entries: one without values when it has no matrix, its include
// entries, or the combinations of its lists. A matrix holding both, an exclude or an expression is
// one this guard does not list, and problem says so.
func matrixEntries(job workflowJob) (entries []map[string]string, problem string) {
	_, strategy := job.field("strategy")
	_, matrix := yamlField(strategy, "matrix")
	if matrix == nil {
		return []map[string]string{{}}, ""
	}
	if matrix.Kind != yaml.MappingNode {
		return nil, "its matrix is not a mapping of lists or include entries"
	}
	combinations := []map[string]string{{}}
	lists := false
	for i := 0; i+1 < len(matrix.Content); i += 2 {
		key, value := matrix.Content[i].Value, yamlResolved(matrix.Content[i+1])
		switch {
		case key == "include" && value.Kind == yaml.SequenceNode:
			for _, item := range value.Content {
				item = yamlResolved(item)
				if item.Kind != yaml.MappingNode {
					return nil, "an include entry is not a mapping"
				}
				entry := map[string]string{}
				for j := 0; j+1 < len(item.Content); j += 2 {
					entry[item.Content[j].Value], _ = yamlScalar(yamlResolved(item.Content[j+1]))
				}
				entries = append(entries, entry)
			}
		case key != "include" && key != "exclude" && value.Kind == yaml.SequenceNode:
			lists = true
			var next []map[string]string
			for _, combination := range combinations {
				for _, item := range value.Content {
					v, _ := yamlScalar(yamlResolved(item))
					entry := maps.Clone(combination)
					entry[key] = v
					next = append(next, entry)
				}
			}
			combinations = next
		default:
			return nil, "its matrix holds " + key + ", which this guard does not read"
		}
	}
	switch {
	case lists && entries != nil:
		return nil, "its matrix holds both lists and include entries"
	case lists:
		return combinations, ""
	}
	return entries, ""
}

const (
	setupTestRunner    = "./.github/actions/setup-test-runner"
	setupTestContainer = "./.github/actions/setup-test-container"
)

var (
	runTestsTier = regexp.MustCompile(`run-tests\.sh\b[^\n]*--type\s+([A-Za-z]+)`)
	workflowUses = regexp.MustCompile(`^\s*(?:- )?uses:\s*(\S+)`)
)

// readCheckJobs reads each job of a workflow, its steps in the order they run.
func readCheckJobs(text string) ([]checkJob, error) {
	read, err := readWorkflowJobs(text)
	if err != nil {
		return nil, err
	}
	var jobs []checkJob
	for _, w := range read {
		job := checkJob{name: w.name, tiers: map[string][]tierCall{}, setupGoStep: -1, hostsStep: -1}
		job.entries, job.matrixProblem = matrixEntries(w)
		job.container, _ = w.field("container")
		_, services := w.field("services")
		if key, mailpit := yamlField(services, "mailpit"); key != nil {
			job.mailpit = key.Line
			if _, ports := yamlField(mailpit, "ports"); ports != nil && ports.Kind == yaml.SequenceNode {
				for _, port := range ports.Content {
					if value, ok := yamlScalar(yamlResolved(port)); ok {
						job.mapped = append(job.mapped, strings.TrimSpace(value))
					}
				}
			}
		}

		for _, step := range w.steps {
			uses, _ := step.uses()
			if strings.HasPrefix(uses, "actions/setup-go@") || uses == setupTestRunner {
				switch n := step.conditional(); {
				case n != 0:
					if job.setupGoIf == 0 {
						job.setupGoIf = n
					}
				case job.setupGoStep < 0:
					job.setupGoStep, job.setupGoLine = step.index, step.line
				}
			}
			if value, node := step.input("save-cache"); node != nil {
				save := cacheSave{line: node.Line, value: value, ifLine: step.conditional()}
				switch uses {
				case setupTestRunner:
					job.runnerSaves = append(job.runnerSaves, save)
				case setupTestContainer:
					job.containerSaves = append(job.containerSaves, save)
				}
			}

			src, ok := step.run()
			if !ok {
				continue
			}
			for i, scriptLine := range strings.Split(src.text, "\n") {
				if m := runTestsTier.FindStringSubmatch(scriptLine); m != nil && slices.Contains(moduleTiers, m[1]) {
					job.tiers[m[1]] = append(job.tiers[m[1]], tierCall{line: src.offset + i + 1, step: step.index})
				}
				if m := runTestsAnyTier.FindStringSubmatch(scriptLine); m != nil {
					job.dbTiers = append(job.dbTiers, m[1])
				}
			}
			if strings.Contains(src.text, "127.0.0.1 mailpit") && strings.Contains(src.text, "/etc/hosts") {
				switch n := step.conditional(); {
				case n != 0:
					job.hostsIf = n
				case job.hostsStep < 0:
					job.hostsStep, job.hostsLine = step.index, step.line
				}
			}
			if strings.Contains(src.text, "go test -c") && strings.Contains(src.text, "./tests/data") && strings.Contains(src.text, "./tests/integration") {
				_, condition := step.field("if")
				text, _ := yamlScalar(condition)
				job.compiles = append(job.compiles, compileStep{line: step.line, condition: text})
			}
		}
		jobs = append(jobs, job)
	}
	sort.Slice(jobs, func(i, j int) bool { return jobs[i].name < jobs[j].name })
	return jobs, nil
}

// runnerJobFindings holds the jobs of a workflow to the rules above.
func runnerJobFindings(file, text string) []string {
	var findings []string
	at := func(job checkJob, line int) string {
		if line == 0 {
			return fmt.Sprintf("%s (%s)", file, job.name)
		}
		return fmt.Sprintf("%s:%d (%s)", file, line, job.name)
	}

	jobs, err := readCheckJobs(text)
	if err != nil {
		return []string{fmt.Sprintf("runner jobs: %s cannot be read as YAML, so this guard read nothing: %v", file, err)}
	}
	reached := false
	var runnerSavers, containerSavers []saver
	for _, job := range jobs {
		for _, tier := range moduleTiers {
			calls := job.tiers[tier]
			if len(calls) == 0 {
				continue
			}
			reached = true
			early := slices.IndexFunc(calls, func(c tierCall) bool { return c.step < job.setupGoStep })
			switch {
			case job.container != 0:
				findings = append(findings, fmt.Sprintf("runner jobs: %s runs the %s tier in a job container; "+
					"run it on the runner with actions/setup-go, as Lint does, so the job pulls no image", at(job, job.container), tier))
			case job.setupGoStep < 0 && job.setupGoIf != 0:
				findings = append(findings, fmt.Sprintf("runner jobs: %s runs the %s tier on the runner, where each step that sets Go up has an if:, as at line %d: "+
					"set Go up in a step with no if:, before the tests", at(job, calls[0].line), tier, job.setupGoIf))
			case job.setupGoStep < 0:
				findings = append(findings, fmt.Sprintf("runner jobs: %s runs the %s tier on the runner without actions/setup-go; "+
					"set Go up at the pin with it, or with ./.github/actions/setup-test-runner", at(job, calls[0].line), tier))
			case early >= 0:
				findings = append(findings, fmt.Sprintf("runner jobs: %s runs the %s tier before the step at line %d sets Go up, so it runs on the runner's own Go: "+
					"set Go up in a step before the tests", at(job, calls[early].line), tier, job.setupGoLine))
			}
		}
		if calls := job.tiers["internal"]; len(calls) > 0 && job.mailpit == 0 {
			findings = append(findings, fmt.Sprintf("runner jobs: %s runs the internal tier, whose TestSendEmail sends through Mailpit, "+
				"with no mailpit service", at(job, calls[0].line)))
		}
		if job.mailpit != 0 && job.container == 0 {
			for _, port := range mailpitPorts {
				if !slices.Contains(job.mapped, port+":"+port) {
					findings = append(findings, fmt.Sprintf("runner jobs: %s maps no %s:%s for its mailpit service; on the runner "+
						"TestSendEmail reaches mailpit:%s only through the port mapped to the runner's own", at(job, job.mailpit), port, port, port))
				}
			}
			switch {
			case job.hostsStep < 0 && job.hostsIf != 0:
				findings = append(findings, fmt.Sprintf("runner jobs: %s adds `127.0.0.1 mailpit` to /etc/hosts only under a condition; on the runner "+
					"the name mailpit resolves only through that line, so add it on every run", at(job, job.hostsIf)))
			case job.hostsStep < 0:
				findings = append(findings, fmt.Sprintf("runner jobs: %s adds no `127.0.0.1 mailpit` to /etc/hosts; on the runner "+
					"the name mailpit resolves only through that line", at(job, job.mailpit)))
			default:
				if calls := job.tiers["internal"]; len(calls) > 0 && calls[0].step < job.hostsStep {
					findings = append(findings, fmt.Sprintf("runner jobs: %s runs the internal tier before the step at line %d adds `127.0.0.1 mailpit` to /etc/hosts, "+
						"so TestSendEmail cannot resolve mailpit: add the line in a step before the tests", at(job, calls[0].line), job.hostsLine))
				}
			}
		}
		savers := func(saves []cacheSave, cache, advice string) []saver {
			var out []saver
			for _, save := range saves {
				var entries []map[string]string
				for _, entry := range job.entries {
					saves, ok := savesCache(save.value, entry)
					if !ok {
						findings = append(findings, fmt.Sprintf("runner jobs: %s gives save-cache %s, which this guard cannot read: write 'true', "+
							"or ${{ matrix.<key> == '<value>' && 'true' || 'false' }} to choose the matrix entry", at(job, save.line), save.value))
						entries = nil
						break
					}
					if saves {
						entries = append(entries, entry)
					}
				}
				if job.matrixProblem != "" && strings.TrimSpace(save.value) != "" && !strings.EqualFold(strings.TrimSpace(save.value), "false") {
					findings = append(findings, fmt.Sprintf("runner jobs: %s gives save-cache in a job whose matrix entries this guard cannot list: %s",
						at(job, save.line), job.matrixProblem))
				}
				if len(entries) > 0 && save.ifLine != 0 {
					findings = append(findings, fmt.Sprintf("runner jobs: %s saves the %s Go cache from a step under a condition, so a run that skips it "+
						"saves none: save it from a setup step with no if:%s", at(job, save.ifLine), cache, advice))
				}
				for _, entry := range entries {
					out = append(out, saver{job: job, entry: entry, line: save.line})
				}
			}
			return out
		}
		runnerSavers = append(runnerSavers, savers(job.runnerSaves, "runner's", "")...)
		containerSavers = append(containerSavers, savers(job.containerSaves, "container's", ", choosing the matrix entry in save-cache")...)
	}
	if !reached {
		return []string{fmt.Sprintf("runner jobs: %s runs no module tier with run-tests.sh, so this guard read nothing", file)}
	}

	names := func(savers []saver) string {
		var out []string
		for _, s := range savers {
			out = append(out, s.describe())
		}
		return strings.Join(out, ", ")
	}
	switch len(runnerSavers) {
	case 0:
		findings = append(findings, fmt.Sprintf("runner jobs: %s saves the runner's Go cache in no job; "+
			"pass save-cache: 'true' to ./.github/actions/setup-test-runner in Unit / authserver", file))
	case 1:
		if s := runnerSavers[0]; len(s.job.tiers["internal"]) == 0 {
			findings = append(findings, fmt.Sprintf("runner jobs: %s saves the runner's Go cache from a job that does not run "+
				"the internal tier, whose modules hold the other tiers'; save it from Unit / authserver", at(s.job, s.line)))
		}
	default:
		findings = append(findings, fmt.Sprintf("runner jobs: %s saves the runner's Go cache in %d jobs or matrix entries (%s), which race for one key; "+
			"save it from Unit / authserver alone", file, len(runnerSavers), names(runnerSavers)))
	}
	switch len(containerSavers) {
	case 0:
		findings = append(findings, fmt.Sprintf("runner jobs: %s saves the container's Go cache in no job; "+
			"pass save-cache to ./.github/actions/setup-test-container for Data / sqlite", file))
	case 1:
		findings = append(findings, containerSaverFindings(containerSavers[0], at)...)
	default:
		findings = append(findings, fmt.Sprintf("runner jobs: %s saves the container's Go cache in %d jobs or matrix entries (%s), which race for one key; "+
			"save it from Data / sqlite alone", file, len(containerSavers), names(containerSavers)))
	}
	return findings
}

// containerSaverFindings holds the one entry that saves the container's Go cache to running the data
// tier and to compiling, in that entry, what the database jobs run.
func containerSaverFindings(s saver, at func(checkJob, int) string) []string {
	var findings []string
	where := "in its job"
	if len(s.entry) > 0 {
		where = "from the entry " + describeEntry(s.entry)
		data := slices.ContainsFunc(s.job.dbTiers, func(tier string) bool {
			if m := matrixValue.FindStringSubmatch(tier); m != nil {
				tier = s.entry[m[1]]
			}
			return tier == "data"
		})
		if !data {
			findings = append(findings, fmt.Sprintf("runner jobs: %s saves the container's Go cache %s, which runs no data tier; "+
				"save it from Data / sqlite, choosing its entry in save-cache", at(s.job, s.line), where))
		}
	}
	compiled, unread := false, 0
	for _, c := range s.job.compiles {
		holds, ok := matrixCondition(c.condition, s.entry)
		if !ok {
			unread = c.line
		}
		compiled = compiled || (ok && holds)
	}
	switch {
	case compiled:
	case unread != 0:
		findings = append(findings, fmt.Sprintf("runner jobs: %s compiles what the database jobs run under an if: this guard cannot read; "+
			"write no if:, or comparisons of matrix values joined by &&", at(s.job, unread)))
	case len(s.job.compiles) == 0:
		findings = append(findings, fmt.Sprintf("runner jobs: %s saves the container's Go cache without compiling what the database "+
			"jobs run; build the server and droptestdb and go test -c ./tests/data ./tests/integration in it", at(s.job, s.line)))
	default:
		findings = append(findings, fmt.Sprintf("runner jobs: %s saves the container's Go cache %s, where no step compiles what the database jobs run; "+
			"run the compile step in that entry, with no if: or under the condition that chooses it", at(s.job, s.line), where))
	}
	return findings
}

func TestCheckWorkflow_TheModuleTiersRunOnTheRunner(t *testing.T) {
	file := checkWorkflow
	text := repositoryFiles(t, []string{file})[file]
	assertWorkflowFindings(t, "runner jobs", filepath.Dir(SourceRoot(t)), file, runnerJobFindings)

	// The seven jobs the decision names, so a job renamed or folded into another is noticed here
	// rather than by the benchmark.
	onRunner := map[string]bool{}
	jobs, err := readCheckJobs(text)
	require.NoError(t, err)
	for _, job := range jobs {
		if len(job.tiers) > 0 && job.container == 0 {
			onRunner[job.name] = true
		}
	}
	for _, name := range []string{"unit-core", "unit-authserver", "unit-adminconsole", "unit-setup",
		"unit-race-internal", "unit-race-core", "unit-race-adminconsole"} {
		assert.True(t, onRunner[name], "%s: %s should run a module tier on the runner", file, name)
	}
}

func TestCheckWorkflow_RunnerJobFindings(t *testing.T) {
	const workflow = "jobs:\n" + // 1
		"  unit-authserver:\n" + // 2
		"    runs-on: ubuntu-latest\n" + // 3
		"    services:\n" + // 4
		"      mailpit:\n" + // 5
		"        image: mailpit:v1\n" + // 6
		"        ports:\n" + // 7
		"          - 1025:1025\n" + // 8
		"          - '8025:8025'\n" + // 9
		"    steps:\n" + // 10
		"      - uses: ./.github/actions/setup-test-runner\n" + // 11
		"        with:\n" + // 12
		"          save-cache: 'true'\n" + // 13
		"      - name: Reach Mailpit by its name\n" + // 14
		"        run: echo '127.0.0.1 mailpit' | sudo tee -a /etc/hosts\n" + // 15
		"      - run: ./run-tests.sh --type internal --no-build\n" + // 16
		"  unit-setup:\n" + // 17
		"    runs-on: ubuntu-latest\n" + // 18
		"    steps:\n" + // 19
		"      - uses: actions/setup-go@0123 # v7\n" + // 20
		"        with:\n" + // 21
		"          cache: false\n" + // 22
		"      - run: ./run-tests.sh --type setup --no-build\n" + // 23
		"  tests-sqlite:\n" + // 24
		"    strategy:\n" + // 25
		"      matrix:\n" + // 26
		"        include:\n" + // 27
		"          - { tier: data, shard: 1/1 }\n" + // 28
		"          - { tier: integration, shard: 1/2 }\n" + // 29
		"          - { tier: integration, shard: 2/2 }\n" + // 30
		"    container:\n" + // 31
		"      image: golang:1-bookworm\n" + // 32
		"    steps:\n" + // 33
		"      - uses: ./.github/actions/setup-test-container\n" + // 34
		"        with:\n" + // 35
		"          save-cache: ${{ matrix.tier == 'data' && 'true' || 'false' }}\n" + // 36
		"      - run: ./run-tests.sh --type ${{ matrix.tier }} --db sqlite --no-build\n" + // 37
		"      - if: matrix.tier == 'data'\n" + // 38
		"        run: |\n" + // 39
		"          go build -o \"$RUNNER_TEMP/droptestdb\" ./cmd/droptestdb\n" + // 40
		"          go test -c -o \"$RUNNER_TEMP/\" ./tests/data ./tests/integration\n" + // 41
		"  tests-mysql:\n" + // 42
		"    container:\n" + // 43
		"      image: golang:1-bookworm\n" + // 44
		"    steps:\n" + // 45
		"      - uses: ./.github/actions/setup-test-container\n" + // 46
		"      - run: ./run-tests.sh --type ${{ matrix.tier }} --db mysql --no-build\n" // 47
	findings := func(src string) []string { return runnerJobFindings("check.yml", src) }
	replace := func(t *testing.T, src, old, with string) string {
		t.Helper()
		require.Equal(t, 1, strings.Count(src, old), "%q is not in the fixture exactly once", old)
		return strings.Replace(src, old, with, 1)
	}

	t.Run("module tiers on the runner, Mailpit mapped and named, one saver per cache, passes", func(t *testing.T) {
		assertFindings(t, findings(workflow))
	})
	t.Run("a module tier in a job container", func(t *testing.T) {
		assertFindings(t, findings(replace(t, workflow, "  unit-setup:\n    runs-on: ubuntu-latest\n",
			"  unit-setup:\n    runs-on: ubuntu-latest\n    container:\n      image: golang:1-bookworm\n")),
			"runner jobs: check.yml:19 (unit-setup) runs the setup tier in a job container")
	})
	t.Run("a module tier on the runner without setup-go", func(t *testing.T) {
		assertFindings(t, findings(replace(t, workflow, "      - uses: actions/setup-go@0123 # v7\n        with:\n          cache: false\n", "")),
			"runner jobs: check.yml:20 (unit-setup) runs the setup tier on the runner without actions/setup-go")
	})
	t.Run("the internal tier with no Mailpit", func(t *testing.T) {
		assertFindings(t, findings(replace(t, workflow,
			"    services:\n      mailpit:\n        image: mailpit:v1\n        ports:\n          - 1025:1025\n          - '8025:8025'\n", "")),
			"runner jobs: check.yml:10 (unit-authserver) runs the internal tier, whose TestSendEmail sends through Mailpit, with no mailpit service")
	})
	t.Run("Mailpit on the runner with one port unmapped", func(t *testing.T) {
		assertFindings(t, findings(replace(t, workflow, "          - '8025:8025'\n", "")),
			"runner jobs: check.yml:5 (unit-authserver) maps no 8025:8025 for its mailpit service")
	})
	t.Run("Mailpit on the runner with its ports mapped elsewhere", func(t *testing.T) {
		assertFindings(t, findings(replace(t, workflow, "          - 1025:1025\n", "          - 11025:1025\n")),
			"runner jobs: check.yml:5 (unit-authserver) maps no 1025:1025 for its mailpit service")
	})
	t.Run("Mailpit on the runner with no hosts line", func(t *testing.T) {
		assertFindings(t, findings(replace(t, workflow, "      - name: Reach Mailpit by its name\n        run: echo '127.0.0.1 mailpit' | sudo tee -a /etc/hosts\n", "")),
			"runner jobs: check.yml:5 (unit-authserver) adds no `127.0.0.1 mailpit` to /etc/hosts")
	})
	t.Run("Mailpit in a container job needs neither", func(t *testing.T) {
		assertFindings(t, findings(replace(t, workflow,
			"  unit-authserver:\n    runs-on: ubuntu-latest\n",
			"  unit-authserver:\n    runs-on: ubuntu-latest\n    container:\n      image: golang:1-bookworm\n")),
			"runner jobs: check.yml:4 (unit-authserver) runs the internal tier in a job container")
	})
	t.Run("no job saves the runner's cache", func(t *testing.T) {
		assertFindings(t, findings(replace(t, workflow, "          save-cache: 'true'\n", "          save-cache: 'false'\n")),
			"runner jobs: check.yml saves the runner's Go cache in no job")
	})
	t.Run("two jobs save the runner's cache", func(t *testing.T) {
		assertFindings(t, findings(replace(t, workflow, "      - uses: actions/setup-go@0123 # v7\n        with:\n          cache: false\n",
			"      - uses: ./.github/actions/setup-test-runner\n        with:\n          save-cache: true\n")),
			"runner jobs: check.yml saves the runner's Go cache in 2 jobs or matrix entries (unit-authserver, unit-setup)")
	})
	t.Run("the runner's cache saved by a job that runs another tier", func(t *testing.T) {
		src := replace(t, workflow, "          save-cache: 'true'\n", "")
		src = replace(t, src, "      - uses: actions/setup-go@0123 # v7\n        with:\n          cache: false\n",
			"      - uses: ./.github/actions/setup-test-runner\n        with:\n          save-cache: 'true'\n")
		assertFindings(t, findings(src),
			"runner jobs: check.yml:21 (unit-setup) saves the runner's Go cache from a job that does not run the internal tier")
	})
	t.Run("no job saves the container's cache", func(t *testing.T) {
		assertFindings(t, findings(replace(t, workflow, "          save-cache: ${{ matrix.tier == 'data' && 'true' || 'false' }}\n", "")),
			"runner jobs: check.yml saves the container's Go cache in no job")
	})
	t.Run("two jobs save the container's cache", func(t *testing.T) {
		assertFindings(t, findings(replace(t, workflow,
			"      - uses: ./.github/actions/setup-test-container\n      - run: ./run-tests.sh --type ${{ matrix.tier }} --db mysql",
			"      - uses: ./.github/actions/setup-test-container\n        with:\n          save-cache: 'true'\n      - run: ./run-tests.sh --type ${{ matrix.tier }} --db mysql")),
			"runner jobs: check.yml saves the container's Go cache in 2 jobs or matrix entries (tests-mysql, tests-sqlite (shard: 1/1, tier: data))")
	})
	t.Run("the container's cache saved without compiling what the database jobs run", func(t *testing.T) {
		assertFindings(t, findings(replace(t, workflow, " ./tests/data ./tests/integration\n", " ./tests/data\n")),
			"runner jobs: check.yml:36 (tests-sqlite) saves the container's Go cache without compiling what the database jobs run")
	})
	t.Run("the runner's cache saved from a step its condition skips", func(t *testing.T) {
		assertFindings(t, findings(replace(t, workflow, "      - uses: ./.github/actions/setup-test-runner\n        with:\n",
			"      - uses: ./.github/actions/setup-test-runner\n        if: ${{ false }}\n        with:\n")),
			"runner jobs: check.yml:17 (unit-authserver) runs the internal tier on the runner, where each step that sets Go up has an if:, as at line 12",
			"runner jobs: check.yml:12 (unit-authserver) saves the runner's Go cache from a step under a condition")
	})
	t.Run("the container's cache saved from a step its condition skips", func(t *testing.T) {
		assertFindings(t, findings(replace(t, workflow, "      - uses: ./.github/actions/setup-test-container\n        with:\n",
			"      - uses: ./.github/actions/setup-test-container\n        if: matrix.tier == 'data'\n        with:\n")),
			"runner jobs: check.yml:35 (tests-sqlite) saves the container's Go cache from a step under a condition")
	})
	t.Run("the hosts line added after the internal tier runs", func(t *testing.T) {
		hosts := "      - name: Reach Mailpit by its name\n        run: echo '127.0.0.1 mailpit' | sudo tee -a /etc/hosts\n"
		tests := "      - run: ./run-tests.sh --type internal --no-build\n"
		assertFindings(t, findings(replace(t, workflow, hosts+tests, tests+hosts)),
			"runner jobs: check.yml:14 (unit-authserver) runs the internal tier before the step at line 15 adds `127.0.0.1 mailpit` to /etc/hosts")
	})
	t.Run("the hosts line added only under a condition", func(t *testing.T) {
		assertFindings(t, findings(replace(t, workflow, "      - name: Reach Mailpit by its name\n",
			"      - name: Reach Mailpit by its name\n        if: github.event_name == 'push'\n")),
			"runner jobs: check.yml:15 (unit-authserver) adds `127.0.0.1 mailpit` to /etc/hosts only under a condition")
	})
	t.Run("a module tier after a setup-go step its condition skips", func(t *testing.T) {
		assertFindings(t, findings(replace(t, workflow, "      - uses: actions/setup-go@0123 # v7\n",
			"      - uses: actions/setup-go@0123 # v7\n        if: ${{ false }}\n")),
			"runner jobs: check.yml:24 (unit-setup) runs the setup tier on the runner, where each step that sets Go up has an if:, as at line 21: "+
				"set Go up in a step with no if:, before the tests")
	})
	t.Run("a module tier before a setup-go step under a condition", func(t *testing.T) {
		setup := "      - uses: actions/setup-go@0123 # v7\n        with:\n          cache: false\n"
		tests := "      - run: ./run-tests.sh --type setup --no-build\n"
		conditional := "      - uses: actions/setup-go@0123 # v7\n        if: github.event_name == 'push'\n        with:\n          cache: false\n"
		assertFindings(t, findings(replace(t, workflow, setup+tests, tests+conditional)),
			"runner jobs: check.yml:20 (unit-setup) runs the setup tier on the runner, where each step that sets Go up has an if:, as at line 22")
	})
	t.Run("a module tier run before Go is set up", func(t *testing.T) {
		setup := "      - uses: actions/setup-go@0123 # v7\n        with:\n          cache: false\n"
		tests := "      - run: ./run-tests.sh --type setup --no-build\n"
		assertFindings(t, findings(replace(t, workflow, setup+tests, tests+setup)),
			"runner jobs: check.yml:20 (unit-setup) runs the setup tier before the step at line 21 sets Go up")
	})
	t.Run("an internal tier call before the hosts line, and another after it", func(t *testing.T) {
		assertFindings(t, findings(replace(t, workflow, "      - name: Reach Mailpit by its name\n",
			"      - run: ./run-tests.sh --type internal --run TestSendEmail\n      - name: Reach Mailpit by its name\n")),
			"runner jobs: check.yml:14 (unit-authserver) runs the internal tier before the step at line 15 adds `127.0.0.1 mailpit` to /etc/hosts")
	})
	t.Run("an empty save-cache saves no runner cache", func(t *testing.T) {
		assertFindings(t, findings(replace(t, workflow, "          save-cache: 'true'\n", "          save-cache: ''\n")),
			"runner jobs: check.yml saves the runner's Go cache in no job")
	})
	t.Run("an empty save-cache saves no container cache", func(t *testing.T) {
		assertFindings(t, findings(replace(t, workflow, "          save-cache: ${{ matrix.tier == 'data' && 'true' || 'false' }}\n", "          save-cache:\n")),
			"runner jobs: check.yml saves the container's Go cache in no job")
	})
	t.Run("a save-cache 'true' within spaces saves no runner cache", func(t *testing.T) {
		assertFindings(t, findings(replace(t, workflow, "          save-cache: 'true'\n", "          save-cache: ' true '\n")),
			"runner jobs: check.yml saves the runner's Go cache in no job")
	})
	t.Run("a save-cache 'true' in another case passes", func(t *testing.T) {
		assertFindings(t, findings(replace(t, workflow, "          save-cache: 'true'\n", "          save-cache: 'TrUe'\n")))
	})
	t.Run("a selector whose empty choice falls through to 'true' saves the container's cache from every entry", func(t *testing.T) {
		assertFindings(t, findings(replace(t, workflow, "matrix.tier == 'data' && 'true' || 'false'", "matrix.tier != 'data' && '' || 'true'")),
			"runner jobs: check.yml saves the container's Go cache in 3 jobs or matrix entries (tests-sqlite (shard: 1/1, tier: data), "+
				"tests-sqlite (shard: 1/2, tier: integration), tests-sqlite (shard: 2/2, tier: integration))")
	})
	t.Run("a selector whose condition joins comparisons with && passes", func(t *testing.T) {
		assertFindings(t, findings(replace(t, workflow, "matrix.tier == 'data' && 'true'", "matrix.tier == 'data' && matrix.shard == '1/1' && 'true'")))
	})
	t.Run("a selector that chooses 'false' outside the data entry passes", func(t *testing.T) {
		assertFindings(t, findings(replace(t, workflow, "matrix.tier == 'data' && 'true' || 'false'", "matrix.tier != 'data' && 'false' || 'true'")))
	})
	t.Run("a selector that saves the container's cache from both integration entries", func(t *testing.T) {
		assertFindings(t, findings(replace(t, workflow, "matrix.tier == 'data' && 'true'", "matrix.tier == 'integration' && 'true'")),
			"runner jobs: check.yml saves the container's Go cache in 2 jobs or matrix entries (tests-sqlite (shard: 1/2, tier: integration), tests-sqlite (shard: 2/2, tier: integration))")
	})
	t.Run("a selector that saves the container's cache from one integration entry", func(t *testing.T) {
		assertFindings(t, findings(replace(t, workflow, "matrix.tier == 'data' && 'true'", "matrix.shard == '1/2' && 'true'")),
			"runner jobs: check.yml:36 (tests-sqlite) saves the container's Go cache from the entry (shard: 1/2, tier: integration), which runs no data tier",
			"runner jobs: check.yml:36 (tests-sqlite) saves the container's Go cache from the entry (shard: 1/2, tier: integration), where no step compiles what the database jobs run")
	})
	t.Run("the compile step restricted to the entries that restore the cache", func(t *testing.T) {
		assertFindings(t, findings(replace(t, workflow, "      - if: matrix.tier == 'data'\n", "      - if: matrix.tier == 'integration'\n")),
			"runner jobs: check.yml:36 (tests-sqlite) saves the container's Go cache from the entry (shard: 1/1, tier: data), where no step compiles what the database jobs run")
	})
	t.Run("the compile step under an expression selecting the saving entry passes", func(t *testing.T) {
		assertFindings(t, findings(replace(t, workflow, "      - if: matrix.tier == 'data'\n", "      - if: ${{ matrix.tier == 'data' && matrix.shard == '1/1' }}\n")))
	})
	t.Run("a matrix written as lists, one entry saving and compiling, passes", func(t *testing.T) {
		assertFindings(t, findings(replace(t, workflow,
			"        include:\n          - { tier: data, shard: 1/1 }\n          - { tier: integration, shard: 1/2 }\n          - { tier: integration, shard: 2/2 }\n",
			"        tier: [data, integration]\n        engine: [sqlite]\n")))
	})
	t.Run("a save-cache this guard cannot read", func(t *testing.T) {
		assertFindings(t, findings(replace(t, workflow, "matrix.tier == 'data' && 'true'", "inputs.full && 'true'")),
			"runner jobs: check.yml:36 (tests-sqlite) gives save-cache ${{ inputs.full && 'true' || 'false' }}, which this guard cannot read",
			"runner jobs: check.yml saves the container's Go cache in no job")
	})
	t.Run("a save-cache choice with no condition this guard cannot read", func(t *testing.T) {
		assertFindings(t, findings(replace(t, workflow, "matrix.tier == 'data' && 'true'", "&& 'true'")),
			"runner jobs: check.yml:36 (tests-sqlite) gives save-cache ${{ && 'true' || 'false' }}, which this guard cannot read",
			"runner jobs: check.yml saves the container's Go cache in no job")
	})
	t.Run("Mailpit's ports in a flow sequence pass", func(t *testing.T) {
		assertFindings(t, findings(replace(t, workflow, "        ports:\n          - 1025:1025\n          - '8025:8025'\n",
			"        ports: ['1025:1025', \"8025:8025\"]\n")))
	})
	t.Run("a workflow YAML cannot read", func(t *testing.T) {
		assertFindings(t, findings(workflow+"  broken: [\n"), "runner jobs: check.yml cannot be read as YAML")
	})
	t.Run("a workflow that runs no module tier", func(t *testing.T) {
		assertFindings(t, findings("jobs:\n  lint:\n    steps:\n      - run: ./run-tests.sh --type lint\n"),
			"runner jobs: check.yml runs no module tier with run-tests.sh, so this guard read nothing")
	})
}
