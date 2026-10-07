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

// setupWizardPage is the docs page about this wizard, and flagsHeading its section listing every
// flag, one table row per flag.
const (
	setupWizardPage = "../../../site/src/content/docs/get-started/setup-wizard.mdx"
	flagsHeading    = "### Flags"
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

// readFlagRows reads the table in the section that heading opens, which runs to the next heading
// of its level or above, with fenced code ignored. A page without the section, or a section with no
// row naming a flag, is an error: a check that read nothing would pass whatever the page said.
func readFlagRows(page []byte, heading string) ([]flagRow, error) {
	level := strings.Index(heading, " ")
	var rows []flagRow
	inSection, found, inFence := false, false, false
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
		if !inSection || !strings.HasPrefix(line, "|") {
			continue
		}
		cells := strings.Split(strings.Trim(line, "| "), "|")
		var names []string
		for _, match := range flagCode.FindAllStringSubmatch(cells[0], -1) {
			names = append(names, match[1])
		}
		if len(names) > 0 {
			rows = append(rows, flagRow{flags: names, text: line})
		}
	}
	if !found {
		return nil, fmt.Errorf("no %q section", heading)
	}
	if len(rows) == 0 {
		return nil, fmt.Errorf("the %q section has no table row naming a flag", heading)
	}
	return rows, nil
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
