package main

import (
	"bufio"
	"bytes"
	"flag"
	"fmt"
	"io"
	"os"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// setupWizardPage is the docs page about this wizard, flagsHeading its section listing every flag,
// one table row per flag, and questionsHeading its section listing the questions, one row each.
const (
	setupWizardPage  = "../../../site/src/content/docs/get-started/setup-wizard.mdx"
	flagsHeading     = "### Flags"
	questionsHeading = "### The questions"
)

// The setup wizard page's flags table lists every flag the wizard declares, and names none it does
// not, so a flag added, renamed or removed fails here until the page says so. The rows for --type
// and --db name every deployment type and every database the wizard accepts.
func TestSetupWizardDocs_TheFlagTableIsTheWizardsFlags(t *testing.T) {
	page, err := os.ReadFile(setupWizardPage)
	if err != nil {
		t.Fatalf("unable to read the setup wizard page: %v", err)
	}
	rows, err := readFlagRows(page, flagsHeading)
	if err != nil {
		t.Fatalf("%s: %v", setupWizardPage, err)
	}
	for _, finding := range flagTableFindings(rows, declaredFlags(), flagValues()) {
		t.Errorf("%s, %s: %s", setupWizardPage, flagsHeading, finding)
	}
}

// declaredFlags is every flag name the wizard declares, without its dashes.
func declaredFlags() map[string]bool {
	declared := map[string]bool{}
	newFlagSet(&CLIFlags{}, io.Discard).VisitAll(func(f *flag.Flag) { declared[f.Name] = true })
	return declared
}

// flagValues is, for each flag whose values come from the wizard's own tables, the values its row
// must name.
func flagValues() map[string][]string {
	return map[string][]string{"type": deploymentNames(), "db": engineNames()}
}

// flagRow is one row of the flags table: the flags its first cell names and the whole row's text.
type flagRow struct {
	flags []string
	text  string
}

// readFlagRows reads the table in the section that heading opens. A page without the section, or a
// section with no row naming a flag, is an error: a check that read nothing would pass whatever the
// page said.
func readFlagRows(page []byte, heading string) ([]flagRow, error) {
	lines, found := sectionTableLines(page, heading)
	if !found {
		return nil, fmt.Errorf("no %q section", heading)
	}
	var rows []flagRow
	for _, line := range lines {
		var names []string
		for _, match := range flagCode.FindAllStringSubmatch(firstCell(line), -1) {
			names = append(names, match[1])
		}
		if len(names) > 0 {
			rows = append(rows, flagRow{flags: names, text: line})
		}
	}
	if len(rows) == 0 {
		return nil, fmt.Errorf("the %q section has no table row naming a flag", heading)
	}
	return rows, nil
}

// sectionTableLines is every table line in the section that heading opens, which runs to the next
// heading of its level or above, with fenced code ignored. found is false when the page has no such
// section.
func sectionTableLines(page []byte, heading string) (lines []string, found bool) {
	level := strings.Index(heading, " ")
	inSection, inFence := false, false
	scanner := bufio.NewScanner(bytes.NewReader(page))
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(strings.TrimSpace(line), "```") {
			inFence = !inFence
			continue
		}
		if inFence {
			continue
		}
		if hashes := headingLevel(line); hashes > 0 {
			if inSection && hashes <= level {
				break
			}
			if strings.TrimSpace(line) == heading {
				inSection, found = true, true
			}
			continue
		}
		if inSection && strings.HasPrefix(line, "|") {
			lines = append(lines, line)
		}
	}
	return lines, found
}

// firstCell is the text of a table line's first cell.
func firstCell(line string) string {
	return strings.TrimSpace(strings.Split(strings.Trim(line, "| "), "|")[0])
}

// flagCode is a flag in a code span, `--name` or `-n`, with its value if the span shows one.
var flagCode = regexp.MustCompile("`--?([a-z][a-z0-9-]*)[^`]*`")

// headingLevel is the number of #s opening a Markdown heading, and 0 for any other line.
func headingLevel(line string) int {
	hashes := len(line) - len(strings.TrimLeft(line, "#"))
	if hashes == 0 || hashes > 6 || !strings.HasPrefix(line[hashes:], " ") {
		return 0
	}
	return hashes
}

// flagTableFindings compares the table with the flags the wizard declares, in both directions, and
// each row of values with the values it must name.
func flagTableFindings(rows []flagRow, declared map[string]bool, values map[string][]string) []string {
	var findings []string
	named := map[string]bool{}
	for _, row := range rows {
		for _, name := range row.flags {
			if named[name] {
				findings = append(findings, fmt.Sprintf("--%s has two rows", name))
			}
			named[name] = true
			if !declared[name] {
				findings = append(findings, fmt.Sprintf("names --%s, which the wizard does not declare", name))
			}
			for _, value := range values[name] {
				if !strings.Contains(row.text, "`"+value+"`") {
					findings = append(findings, fmt.Sprintf("the --%s row does not name `%s`", name, value))
				}
			}
		}
	}
	for _, name := range sortedKeys(declared) {
		if !named[name] {
			findings = append(findings, fmt.Sprintf("no row names --%s, which the wizard declares", name))
		}
	}
	return findings
}

func sortedKeys(set map[string]bool) []string {
	keys := make([]string, 0, len(set))
	for key := range set {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

const flagsFixture = "# Setup wizard\n\n`--ghost` above the section is not read.\n\n" +
	"## How it works\n\n### Flags\n\n" +
	"| Flag | What it does |\n|---|---|\n" +
	"| `--type`, `-t` | `local` or `native` |\n" +
	"| `--db=NAME` | `sqlite` |\n" +
	"```\n| `--in-fence` | a fenced row is not read |\n```\n" +
	"#### Examples\n\n| `--nested` | a subsection is part of the section |\n\n" +
	"### Next\n\n| `--after` | not read |\n"

func TestFlagTable_FindsWhatDisagreesInBothDirections(t *testing.T) {
	rows, err := readFlagRows([]byte(flagsFixture), flagsHeading)
	if err != nil {
		t.Fatal(err)
	}
	declared := map[string]bool{"type": true, "t": true, "db": true, "output": true, "nested": true}
	values := map[string][]string{"type": {"local", "kubernetes"}, "db": {"sqlite"}}

	got := strings.Join(flagTableFindings(rows, declared, values), "\n")

	for _, want := range []string{
		"the --type row does not name `kubernetes`",
		"no row names --output, which the wizard declares",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("no finding says %q:\n%s", want, got)
		}
	}
	for _, unwanted := range []string{"ghost", "in-fence", "after", "--db", "local`"} {
		if strings.Contains(got, unwanted) {
			t.Errorf("a finding mentions %q, which agrees or is outside the section:\n%s", unwanted, got)
		}
	}
	if n := strings.Count(got, "\n") + 1; n != 2 {
		t.Errorf("%d findings, want 2:\n%s", n, got)
	}

	undeclared := flagTableFindings(rows, map[string]bool{"type": true, "t": true, "nested": true}, nil)
	if !strings.Contains(strings.Join(undeclared, "\n"), "names --db, which the wizard does not declare") {
		t.Errorf("a row naming a flag the wizard lacks was not found: %q", undeclared)
	}
}

func TestFlagTable_PassesWhenTheyAgree(t *testing.T) {
	rows, err := readFlagRows([]byte(flagsFixture), flagsHeading)
	if err != nil {
		t.Fatal(err)
	}
	declared := map[string]bool{"type": true, "t": true, "db": true, "nested": true}
	values := map[string][]string{"type": {"local", "native"}, "db": {"sqlite"}}
	if findings := flagTableFindings(rows, declared, values); len(findings) != 0 {
		t.Errorf("findings on a table that agrees: %q", findings)
	}
}

func TestFlagTable_AMissingSectionOrTableStops(t *testing.T) {
	for name, page := range map[string]string{
		"no section":     "## How it works\n\n### Flag\n\n| `--type` | x |\n",
		"no flag in it":  "### Flags\n\nSee the usage text.\n\n### Next\n\n| `--type` | x |\n",
		"fenced heading": "```\n### Flags\n| `--type` | x |\n```\n",
	} {
		t.Run(name, func(t *testing.T) {
			if rows, err := readFlagRows([]byte(page), flagsHeading); err == nil {
				t.Errorf("read %d rows from a page with no flags table, want an error", len(rows))
			}
		})
	}
}

// The setup wizard page's questions table lists the questions the wizard asks, in the order it asks
// them, each under the title its STEP heading prints, so a question added, removed, renamed or moved
// fails here until the page says so. Which deployments each is asked for, and its default, are the
// table's prose and are not read.
func TestSetupWizardDocs_TheQuestionsTableIsTheWizardsQuestions(t *testing.T) {
	page, err := os.ReadFile(setupWizardPage)
	if err != nil {
		t.Fatalf("unable to read the setup wizard page: %v", err)
	}
	table, err := readQuestions(page, questionsHeading)
	if err != nil {
		t.Fatalf("%s: %v", setupWizardPage, err)
	}
	for _, finding := range questionTableFindings(table, wizardQuestions()) {
		t.Errorf("%s, %s: %s", setupWizardPage, questionsHeading, finding)
	}
}

// wizardQuestions is the title of every step that asks something, in the order the wizard runs
// them: a step with no title prints no heading, and an announced one reports work it does.
func wizardQuestions() []string {
	var questions []string
	for _, step := range wizardSteps {
		if step.title != "" && !step.announced {
			questions = append(questions, step.title)
		}
	}
	return questions
}

// tableDelimiter is the line under a table's header row.
var tableDelimiter = regexp.MustCompile(`^\|[\s:|-]+$`)

// readQuestions reads the first cell of every body row of the table in the section that heading
// opens: a header row, the one above a delimiter line, names no question. A page without the
// section, or a section with no question row, is an error.
func readQuestions(page []byte, heading string) ([]string, error) {
	lines, found := sectionTableLines(page, heading)
	if !found {
		return nil, fmt.Errorf("no %q section", heading)
	}
	var questions []string
	for i, line := range lines {
		if tableDelimiter.MatchString(line) || (i+1 < len(lines) && tableDelimiter.MatchString(lines[i+1])) {
			continue
		}
		questions = append(questions, firstCell(line))
	}
	if len(questions) == 0 {
		return nil, fmt.Errorf("the %q section has no table row naming a question", heading)
	}
	return questions, nil
}

// questionTableFindings compares the table's questions with the wizard's, in both directions, and
// their order when both name the same ones.
func questionTableFindings(table, asked []string) []string {
	var findings []string
	inTable, isAsked := map[string]bool{}, map[string]bool{}
	for _, question := range table {
		if inTable[question] {
			findings = append(findings, fmt.Sprintf("%q has two rows", question))
		}
		inTable[question] = true
	}
	for _, question := range asked {
		isAsked[question] = true
		if !inTable[question] {
			findings = append(findings, fmt.Sprintf("no row names %q, which the wizard asks", question))
		}
	}
	for _, question := range table {
		if !isAsked[question] {
			findings = append(findings, fmt.Sprintf("names %q, which the wizard does not ask", question))
		}
	}
	if len(findings) == 0 && strings.Join(table, "\n") != strings.Join(asked, "\n") {
		findings = append(findings, fmt.Sprintf("the rows are in the order %q, and the wizard asks %q", table, asked))
	}
	return findings
}

const questionsFixture = "# Setup wizard\n\n| Question | x |\n|---|---|\n| Above | not read |\n\n" +
	"## How it works\n\n### The questions\n\n" +
	"| Question | Asked for | Default |\n|---|---|---|\n" +
	"| Deployment type | Always | none |\n" +
	"| Database type | Always | none |\n" +
	"```\n| In a fence | not read | |\n```\n" +
	"| Metrics | Kubernetes | None |\n\n" +
	"### Next\n\n| After | not read |\n"

func TestQuestionTable_FindsWhatDisagreesInBothDirections(t *testing.T) {
	table, err := readQuestions([]byte(questionsFixture), questionsHeading)
	if err != nil {
		t.Fatal(err)
	}

	got := strings.Join(questionTableFindings(table, []string{"Deployment type", "Database type", "Admin credentials"}), "\n")

	for _, want := range []string{
		`no row names "Admin credentials", which the wizard asks`,
		`names "Metrics", which the wizard does not ask`,
	} {
		if !strings.Contains(got, want) {
			t.Errorf("no finding says %q:\n%s", want, got)
		}
	}
	for _, unwanted := range []string{"Above", "In a fence", "After", "Question"} {
		if strings.Contains(got, unwanted) {
			t.Errorf("a finding mentions %q, which is outside the table's body:\n%s", unwanted, got)
		}
	}
	if n := strings.Count(got, "\n") + 1; n != 2 {
		t.Errorf("%d findings, want 2:\n%s", n, got)
	}

	moved := questionTableFindings(table, []string{"Database type", "Deployment type", "Metrics"})
	if len(moved) != 1 || !strings.Contains(moved[0], "the rows are in the order") {
		t.Errorf("a table in another order than the wizard's was not found: %q", moved)
	}

	twice := questionTableFindings(append(table, "Metrics"), []string{"Deployment type", "Database type", "Metrics"})
	if len(twice) != 1 || twice[0] != `"Metrics" has two rows` {
		t.Errorf("a question with two rows was not found: %q", twice)
	}
}

func TestQuestionTable_PassesWhenTheyAgree(t *testing.T) {
	table, err := readQuestions([]byte(questionsFixture), questionsHeading)
	if err != nil {
		t.Fatal(err)
	}
	if findings := questionTableFindings(table, []string{"Deployment type", "Database type", "Metrics"}); len(findings) != 0 {
		t.Errorf("findings on a table that agrees: %q", findings)
	}
}

func TestQuestionTable_AMissingSectionOrTableStops(t *testing.T) {
	for name, page := range map[string]string{
		"no section":     "## How it works\n\n### Questions\n\n| Question |\n|---|\n| Metrics |\n",
		"header only":    "### The questions\n\n| Question | Default |\n|---|---|\n\n### Next\n\n| Metrics |\n",
		"fenced heading": "```\n### The questions\n| Metrics |\n```\n",
	} {
		t.Run(name, func(t *testing.T) {
			if questions, err := readQuestions([]byte(page), questionsHeading); err == nil {
				t.Errorf("read %q from a page with no questions table, want an error", questions)
			}
		})
	}
}
