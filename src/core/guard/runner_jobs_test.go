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
// The Go cache splits with the environments, which keep it under different paths: one runner job,
// Unit / authserver, saves the runner's, and one container job, Data / sqlite, saves the
// container's and compiles what the other database jobs run, so they restore its build rather
// than compile it. Two savers of one cache race for its key; none leaves every job compiling, as
// does a saver's setup step skipped by an if:.

import (
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

const checkWorkflow = ".github/workflows/check.yml"

// moduleTiers are run-tests.sh's tiers that need no database: the ones that run on the runner.
var moduleTiers = []string{"internal", "core", "adminconsole", "setup"}

// mailpitPorts are the SMTP and API ports TestSendEmail reaches Mailpit on.
var mailpitPorts = []string{"1025", "8025"}

// checkJob is what runnerJobFindings reads of one job, each line numbered from 1.
type checkJob struct {
	name string
	// container is the line of the job's container: key, or 0 when it runs on the runner.
	container int
	// tiers maps each module tier the job runs to the line of its run-tests.sh call, and tierSteps
	// to the place of that call's step among the job's steps.
	tiers     map[string]int
	tierSteps map[string]int
	// setupGo is whether the job sets Go up with actions/setup-go, itself or through the runner's
	// test setup.
	setupGo bool
	// mailpit is the line of the job's Mailpit service, or 0, and mapped the ports it maps as
	// host:container.
	mailpit int
	mapped  []string
	// hostsStep is the place of the first step that adds 127.0.0.1 mailpit to /etc/hosts whenever
	// the job reaches it, or -1, and hostsLine its line; hostsIf is the line of the if: of one that
	// adds it only under a condition, or 0.
	hostsStep, hostsLine, hostsIf int
	// savesRunnerCache and savesContainerCache are the lines where the job's test setup is asked to
	// save the Go cache, or 0, and runnerSaveIf and containerSaveIf the lines of an if: that skips
	// that setup step on some runs, or 0.
	savesRunnerCache, savesContainerCache int
	runnerSaveIf, containerSaveIf         int
	// compiles is whether a step compiles the data and integration test binaries.
	compiles bool
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
		job := checkJob{name: w.name, tiers: map[string]int{}, tierSteps: map[string]int{}, hostsStep: -1}
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
				job.setupGo = true
			}
			if value, node := step.input("save-cache"); node != nil && strings.TrimSpace(value) != "false" {
				switch uses {
				case setupTestRunner:
					job.savesRunnerCache, job.runnerSaveIf = node.Line, step.conditional()
				case setupTestContainer:
					job.savesContainerCache, job.containerSaveIf = node.Line, step.conditional()
				}
			}

			src, ok := step.run()
			if !ok {
				continue
			}
			for i, scriptLine := range strings.Split(src.text, "\n") {
				if m := runTestsTier.FindStringSubmatch(scriptLine); m != nil && slices.Contains(moduleTiers, m[1]) {
					job.tiers[m[1]] = src.offset + i + 1
					job.tierSteps[m[1]] = step.index
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
			job.compiles = job.compiles || (strings.Contains(src.text, "go test -c") &&
				strings.Contains(src.text, "./tests/data") && strings.Contains(src.text, "./tests/integration"))
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
	var runnerSavers, containerSavers []checkJob
	for _, job := range jobs {
		for _, tier := range moduleTiers {
			line, ok := job.tiers[tier]
			if !ok {
				continue
			}
			reached = true
			if job.container != 0 {
				findings = append(findings, fmt.Sprintf("runner jobs: %s runs the %s tier in a job container; "+
					"run it on the runner with actions/setup-go, as Lint does, so the job pulls no image", at(job, job.container), tier))
			} else if !job.setupGo {
				findings = append(findings, fmt.Sprintf("runner jobs: %s runs the %s tier on the runner without actions/setup-go; "+
					"set Go up at the pin with it, or with ./.github/actions/setup-test-runner", at(job, line), tier))
			}
		}
		if line, ok := job.tiers["internal"]; ok && job.mailpit == 0 {
			findings = append(findings, fmt.Sprintf("runner jobs: %s runs the internal tier, whose TestSendEmail sends through Mailpit, "+
				"with no mailpit service", at(job, line)))
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
				if step, ok := job.tierSteps["internal"]; ok && step < job.hostsStep {
					findings = append(findings, fmt.Sprintf("runner jobs: %s runs the internal tier before the step at line %d adds `127.0.0.1 mailpit` to /etc/hosts, "+
						"so TestSendEmail cannot resolve mailpit: add the line in a step before the tests", at(job, job.tiers["internal"]), job.hostsLine))
				}
			}
		}
		if job.runnerSaveIf != 0 {
			findings = append(findings, fmt.Sprintf("runner jobs: %s saves the runner's Go cache from a step under a condition, so a run that skips it "+
				"saves none: save it from a setup step with no if:", at(job, job.runnerSaveIf)))
		}
		if job.containerSaveIf != 0 {
			findings = append(findings, fmt.Sprintf("runner jobs: %s saves the container's Go cache from a step under a condition, so a run that skips it "+
				"saves none: save it from a setup step with no if:, choosing the matrix entry in save-cache", at(job, job.containerSaveIf)))
		}
		if job.savesRunnerCache != 0 {
			runnerSavers = append(runnerSavers, job)
		}
		if job.savesContainerCache != 0 {
			containerSavers = append(containerSavers, job)
		}
	}
	if !reached {
		return []string{fmt.Sprintf("runner jobs: %s runs no module tier with run-tests.sh, so this guard read nothing", file)}
	}

	names := func(jobs []checkJob) string {
		var out []string
		for _, job := range jobs {
			out = append(out, job.name)
		}
		return strings.Join(out, ", ")
	}
	switch len(runnerSavers) {
	case 0:
		findings = append(findings, fmt.Sprintf("runner jobs: %s saves the runner's Go cache in no job; "+
			"pass save-cache: 'true' to ./.github/actions/setup-test-runner in Unit / authserver", file))
	case 1:
		if _, ok := runnerSavers[0].tiers["internal"]; !ok {
			findings = append(findings, fmt.Sprintf("runner jobs: %s saves the runner's Go cache from a job that does not run "+
				"the internal tier, whose modules hold the other tiers'; save it from Unit / authserver", at(runnerSavers[0], runnerSavers[0].savesRunnerCache)))
		}
	default:
		findings = append(findings, fmt.Sprintf("runner jobs: %s saves the runner's Go cache in %d jobs (%s), which race for one key; "+
			"save it from Unit / authserver alone", file, len(runnerSavers), names(runnerSavers)))
	}
	switch len(containerSavers) {
	case 0:
		findings = append(findings, fmt.Sprintf("runner jobs: %s saves the container's Go cache in no job; "+
			"pass save-cache to ./.github/actions/setup-test-container for Data / sqlite", file))
	case 1:
		if !containerSavers[0].compiles {
			findings = append(findings, fmt.Sprintf("runner jobs: %s saves the container's Go cache without compiling what the database "+
				"jobs run; build the server and droptestdb and go test -c ./tests/data ./tests/integration in it", at(containerSavers[0], containerSavers[0].savesContainerCache)))
		}
	default:
		findings = append(findings, fmt.Sprintf("runner jobs: %s saves the container's Go cache in %d jobs (%s), which race for one key; "+
			"save it from Data / sqlite alone", file, len(containerSavers), names(containerSavers)))
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
		"    container:\n" + // 25
		"      image: golang:1-bookworm\n" + // 26
		"    steps:\n" + // 27
		"      - uses: ./.github/actions/setup-test-container\n" + // 28
		"        with:\n" + // 29
		"          save-cache: ${{ matrix.tier == 'data' && 'true' || 'false' }}\n" + // 30
		"      - run: ./run-tests.sh --type ${{ matrix.tier }} --db sqlite --no-build\n" + // 31
		"      - if: matrix.tier == 'data'\n" + // 32
		"        run: |\n" + // 33
		"          go build -o \"$RUNNER_TEMP/droptestdb\" ./cmd/droptestdb\n" + // 34
		"          go test -c -o \"$RUNNER_TEMP/\" ./tests/data ./tests/integration\n" + // 35
		"  tests-mysql:\n" + // 36
		"    container:\n" + // 37
		"      image: golang:1-bookworm\n" + // 38
		"    steps:\n" + // 39
		"      - uses: ./.github/actions/setup-test-container\n" + // 40
		"      - run: ./run-tests.sh --type ${{ matrix.tier }} --db mysql --no-build\n" // 41
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
			"runner jobs: check.yml saves the runner's Go cache in 2 jobs (unit-authserver, unit-setup)")
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
			"runner jobs: check.yml saves the container's Go cache in 2 jobs (tests-mysql, tests-sqlite)")
	})
	t.Run("the container's cache saved without compiling what the database jobs run", func(t *testing.T) {
		assertFindings(t, findings(replace(t, workflow, " ./tests/data ./tests/integration\n", " ./tests/data\n")),
			"runner jobs: check.yml:30 (tests-sqlite) saves the container's Go cache without compiling what the database jobs run")
	})
	t.Run("the runner's cache saved from a step its condition skips", func(t *testing.T) {
		assertFindings(t, findings(replace(t, workflow, "      - uses: ./.github/actions/setup-test-runner\n        with:\n",
			"      - uses: ./.github/actions/setup-test-runner\n        if: ${{ false }}\n        with:\n")),
			"runner jobs: check.yml:12 (unit-authserver) saves the runner's Go cache from a step under a condition")
	})
	t.Run("the container's cache saved from a step its condition skips", func(t *testing.T) {
		assertFindings(t, findings(replace(t, workflow, "      - uses: ./.github/actions/setup-test-container\n        with:\n",
			"      - uses: ./.github/actions/setup-test-container\n        if: matrix.tier == 'data'\n        with:\n")),
			"runner jobs: check.yml:29 (tests-sqlite) saves the container's Go cache from a step under a condition")
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
