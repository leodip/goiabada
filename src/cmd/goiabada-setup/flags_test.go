package main

import (
	"bytes"
	"fmt"
	"regexp"
	"strings"
	"testing"
)

// The usage text -h prints is written by hand, apart from the help strings the flags are declared
// with, which it never shows, so a flag declared without a line there works but is missing from -h.
// Every declared flag has an entry in it, and every entry names a declared flag.
func TestUsage_ListsEveryDeclaredFlag(t *testing.T) {
	var usage bytes.Buffer
	newFlagSet(&CLIFlags{}, &usage).Usage()
	for _, finding := range usageFlagFindings(usage.String(), declaredFlags()) {
		t.Error(finding)
	}
}

// usageEntry is a line of the usage text opening a flag's entry: indented two spaces, with the
// shorthand first when there is one, as in "  -o, --output PATH". A description's continuation is
// indented further, and an example names its flags after the program's name or further in.
var usageEntry = regexp.MustCompile(`^  (?:-([a-z]), )?--([a-z][a-z0-9-]*)`)

// usageFlagFindings compares the usage text's entries with the flags the wizard declares, in both
// directions.
func usageFlagFindings(usage string, declared map[string]bool) []string {
	var findings []string
	listed := map[string]bool{}
	for _, line := range strings.Split(usage, "\n") {
		match := usageEntry.FindStringSubmatch(line)
		if match == nil {
			continue
		}
		for _, name := range match[1:] {
			if name == "" {
				continue
			}
			if listed[name] {
				findings = append(findings, fmt.Sprintf("-h lists %s twice", dashed(name)))
			}
			listed[name] = true
			if !declared[name] {
				findings = append(findings, fmt.Sprintf("-h lists %s, which the wizard does not declare", dashed(name)))
			}
		}
	}
	for _, name := range sortedKeys(declared) {
		if !listed[name] {
			findings = append(findings, fmt.Sprintf("-h has no entry for %s, which the wizard declares", dashed(name)))
		}
	}
	return findings
}

// dashed spells a flag's name as the usage text does: one dash for a shorthand, two otherwise.
func dashed(name string) string {
	if len(name) == 1 {
		return "-" + name
	}
	return "--" + name
}

const usageFixture = "Usage: goiabada-setup [options]\n\n" +
	"General Options:\n" +
	"  -v, --version          Show version and exit\n" +
	"  --db TYPE              Database\n" +
	"                         --type is named in a description, not an entry\n" +
	"  --db TYPE              Database, again\n" +
	"  --ghost                Not declared\n\n" +
	"Examples:\n" +
	"    goiabada-setup --type=local\n" +
	"      --output=/tmp \\\n"

func TestUsageFlags_FindsWhatDisagreesInBothDirections(t *testing.T) {
	declared := map[string]bool{"v": true, "version": true, "db": true, "type": true, "output": true}

	got := strings.Join(usageFlagFindings(usageFixture, declared), "\n")

	for _, want := range []string{
		"-h lists --db twice",
		"-h lists --ghost, which the wizard does not declare",
		"-h has no entry for --output, which the wizard declares",
		"-h has no entry for --type, which the wizard declares",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("no finding says %q:\n%s", want, got)
		}
	}
	if n := strings.Count(got, "\n") + 1; n != 4 {
		t.Errorf("%d findings, want 4:\n%s", n, got)
	}
}

func TestUsageFlags_PassesWhenTheyAgree(t *testing.T) {
	declared := map[string]bool{"v": true, "version": true, "db": true, "ghost": true}
	usage := strings.Replace(usageFixture, "  --db TYPE              Database, again\n", "", 1)
	if findings := usageFlagFindings(usage, declared); len(findings) != 0 {
		t.Errorf("findings on a usage that agrees: %q", findings)
	}
}

func TestUsageFlags_AUsageListingNothingFails(t *testing.T) {
	findings := usageFlagFindings("Usage: goiabada-setup [options]\n", map[string]bool{"type": true})
	if len(findings) != 1 || findings[0] != "-h has no entry for --type, which the wizard declares" {
		t.Errorf("findings on a usage with no entry: %q", findings)
	}
}
