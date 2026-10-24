package main

import (
	"cmp"
	"fmt"
	"slices"
	"strings"
	"unicode"
)

// finding is one advisory in one package at one installed version in one image, as every scanner
// that reported it saw it.
type finding struct {
	advisory    string // the identifier the advisory's others are merged under
	image       string
	pkg         string
	installed   string
	fixed       map[string]bool
	scanners    map[scanner]bool
	goPackage   bool
	govulncheck bool // govulncheck reported it
	reachable   bool
	symbols     map[string]bool
}

// listed is what the report says about a finding: it has a fix to move to, or govulncheck finds the
// Go code that carries it called.
func (f *finding) listed() bool {
	return len(f.fixed) > 0 || (f.goPackage && f.reachable)
}

// advisory is one advisory under every identifier any scanner gave it, and its findings.
type advisory struct {
	ids      []string
	findings []*finding
}

// classify merges the records into advisories, joining two identifiers whenever one scanner gives
// them for the same advisory, and splits each advisory's findings into those the report lists and
// those left to the log. Both lists are sorted by identifier.
func classify(records []record) (listed, left []advisory) {
	parent := map[string]string{}
	var root func(string) string
	root = func(id string) string {
		p, ok := parent[id]
		if !ok || p == id {
			parent[id] = id
			return id
		}
		r := root(p)
		parent[id] = r
		return r
	}
	for _, r := range records {
		for _, id := range r.ids[1:] {
			a, b := root(r.ids[0]), root(id)
			if a != b {
				// The smaller identifier is the root, so the merge does not depend on the order the
				// records were read in.
				parent[max(a, b)] = min(a, b)
			}
		}
	}

	findings := map[string]*finding{}
	ids := map[string]map[string]bool{}
	for _, r := range records {
		advisoryRoot := root(r.ids[0])
		if ids[advisoryRoot] == nil {
			ids[advisoryRoot] = map[string]bool{}
		}
		for _, id := range r.ids {
			ids[advisoryRoot][id] = true
		}
		installed := normalizeVersion(r.installed)
		k := strings.Join([]string{advisoryRoot, r.image, r.pkg, installed}, "\x00")
		f := findings[k]
		if f == nil {
			f = &finding{
				advisory: advisoryRoot, image: r.image, pkg: r.pkg, installed: installed,
				fixed: map[string]bool{}, scanners: map[scanner]bool{}, symbols: map[string]bool{},
			}
			findings[k] = f
		}
		f.scanners[r.scanner] = true
		f.goPackage = f.goPackage || r.goPackage
		f.govulncheck = f.govulncheck || r.scanner == govulncheck
		f.reachable = f.reachable || r.reachable
		for _, v := range r.fixed {
			f.fixed[normalizeVersion(v)] = true
		}
		for _, s := range r.symbols {
			f.symbols[s] = true
		}
	}

	listedBy, leftBy := map[string]*advisory{}, map[string]*advisory{}
	for _, f := range findings {
		into := leftBy
		if f.listed() {
			into = listedBy
		}
		a := into[f.advisory]
		if a == nil {
			a = &advisory{ids: sortedKeys(ids[f.advisory], strings.Compare)}
			into[f.advisory] = a
		}
		a.findings = append(a.findings, f)
	}
	return sortedAdvisories(listedBy), sortedAdvisories(leftBy)
}

func sortedAdvisories(by map[string]*advisory) []advisory {
	var out []advisory
	for _, a := range by {
		slices.SortFunc(a.findings, func(x, y *finding) int {
			return cmp.Or(strings.Compare(x.image, y.image), strings.Compare(x.pkg, y.pkg), compareVersions(x.installed, y.installed))
		})
		out = append(out, *a)
	}
	slices.SortFunc(out, func(x, y advisory) int { return slices.Compare(x.ids, y.ids) })
	return out
}

const reportIntro = "The weekly scan of the published images found %d %s someone can act on: each has a fixed version, or is in Go code that govulncheck reports reachable. The scan's other findings are in its run's log. The Image scan workflow rewrites this list when it changes, and closes this issue once it is empty.\n"

// renderReport writes the issue's body, or nothing when no advisory is listed.
func renderReport(advisories []advisory) string {
	if len(advisories) == 0 {
		return ""
	}
	var b strings.Builder
	noun := "advisories"
	if len(advisories) == 1 {
		noun = "advisory"
	}
	fmt.Fprintf(&b, reportIntro, len(advisories), noun)
	for _, a := range advisories {
		var links []string
		for _, id := range a.ids {
			links = append(links, link(id))
		}
		fmt.Fprintf(&b, "\n### %s\n\n", strings.Join(links, " · "))
		fmt.Fprintf(&b, "- **Images:** %s\n", strings.Join(images(a.findings), ", "))
		fmt.Fprintf(&b, "- **Packages:** %s\n", strings.Join(packages(a.findings, true), "; "))
		fmt.Fprintf(&b, "- **Reported by:** %s\n", strings.Join(scanners(a.findings), ", "))
		if reach := reachability(a.findings); reach != "" {
			fmt.Fprintf(&b, "- **Reachable:** %s\n", reach)
		}
	}
	return b.String()
}

// renderLog writes one line per advisory left out of the report, saying why.
func renderLog(advisories []advisory) []string {
	var lines []string
	for _, a := range advisories {
		reason := "no fixed version"
		if slices.ContainsFunc(a.findings, func(f *finding) bool { return f.goPackage }) {
			if slices.ContainsFunc(a.findings, func(f *finding) bool { return f.govulncheck }) {
				reason += ", and govulncheck finds no call to it"
			} else {
				reason += ", and govulncheck does not report it"
			}
		}
		lines = append(lines, fmt.Sprintf("not listed: %s in %s (%s), reported by %s: %s",
			strings.Join(a.ids, ", "), strings.Join(packages(a.findings, false), ", "),
			strings.Join(images(a.findings), ", "), strings.Join(scanners(a.findings), ", "), reason))
	}
	return lines
}

func link(id string) string {
	switch {
	case strings.HasPrefix(id, "CVE-"):
		return fmt.Sprintf("[%s](https://nvd.nist.gov/vuln/detail/%s)", id, id)
	case strings.HasPrefix(id, "GO-"):
		return fmt.Sprintf("[%s](https://pkg.go.dev/vuln/%s)", id, id)
	case strings.HasPrefix(id, "GHSA-"):
		return fmt.Sprintf("[%s](https://github.com/advisories/%s)", id, id)
	}
	return id
}

func images(findings []*finding) []string {
	set := map[string]bool{}
	for _, f := range findings {
		set[f.image] = true
	}
	return sortedKeys(set, strings.Compare)
}

func scanners(findings []*finding) []string {
	set := map[scanner]bool{}
	for _, f := range findings {
		for s := range f.scanners {
			set[s] = true
		}
	}
	var names []string
	for _, s := range sortedKeys(set, cmp.Compare[scanner]) {
		names = append(names, s.String())
	}
	return names
}

// packages names each package and installed version once, with the versions that fix it when
// withFixes is set: `musl` 1.2.6-r2, fixed in 1.2.6-r3.
func packages(findings []*finding, withFixes bool) []string {
	type installed struct{ pkg, version string }
	fixes := map[installed]map[string]bool{}
	for _, f := range findings {
		k := installed{f.pkg, f.installed}
		if fixes[k] == nil {
			fixes[k] = map[string]bool{}
		}
		for v := range f.fixed {
			fixes[k][v] = true
		}
	}
	var out []string
	for _, k := range sortedKeys(fixes, func(x, y installed) int {
		return cmp.Or(strings.Compare(x.pkg, y.pkg), compareVersions(x.version, y.version))
	}) {
		if !withFixes {
			out = append(out, strings.TrimSpace(k.pkg+" "+k.version))
			continue
		}
		line := strings.TrimSpace("`"+k.pkg+"` "+k.version) + ", no fixed version"
		if fixed := sortedKeys(fixes[k], compareVersions); len(fixed) > 0 {
			line = strings.TrimSpace("`"+k.pkg+"` "+k.version) + ", fixed in " + strings.Join(fixed, ", ")
		}
		out = append(out, line)
	}
	return out
}

// reachability says, for an advisory in Go code, whether govulncheck finds it called in each image,
// or nothing for an advisory in no Go code.
func reachability(findings []*finding) string {
	reached, called, unreached, unreported := map[string]bool{}, map[string]bool{}, map[string]bool{}, map[string]bool{}
	for _, f := range findings {
		if f.goPackage && f.reachable {
			reached[f.image] = true
			for s := range f.symbols {
				called["`"+s+"`"] = true
			}
		}
	}
	for _, f := range findings {
		switch {
		case !f.goPackage || reached[f.image]:
		case f.govulncheck:
			unreached[f.image] = true
		default:
			unreported[f.image] = true
		}
	}
	for image := range unreached {
		delete(unreported, image)
	}
	if len(reached)+len(unreached)+len(unreported) == 0 {
		return ""
	}
	symbols := strings.Join(sortedKeys(called, strings.Compare), ", ")
	switch {
	case len(unreached)+len(unreported) == 0:
		return "yes, govulncheck finds " + symbols + " called in every image listed"
	case len(reached)+len(unreported) == 0:
		return "no, govulncheck finds no call to it"
	case len(reached)+len(unreached) == 0:
		return "govulncheck does not report it"
	}
	var parts []string
	if len(reached) > 0 {
		parts = append(parts, "yes in "+strings.Join(sortedKeys(reached, strings.Compare), ", ")+" ("+symbols+")")
	}
	if len(unreached) > 0 {
		parts = append(parts, "govulncheck finds no call to it in "+strings.Join(sortedKeys(unreached, strings.Compare), ", "))
	}
	if len(unreported) > 0 {
		parts = append(parts, "govulncheck does not report it in "+strings.Join(sortedKeys(unreported, strings.Compare), ", "))
	}
	return strings.Join(parts, "; ")
}

// normalizeVersion writes a Go version as the other scanners do, without the go or v that Grype,
// Trivy and govulncheck each put in front of some of them: go1.27.2 and v1.27.2 are both 1.27.2.
func normalizeVersion(v string) string {
	for _, prefix := range []string{"go", "v"} {
		if rest, ok := strings.CutPrefix(v, prefix); ok && rest != "" && unicode.IsDigit(rune(rest[0])) {
			return rest
		}
	}
	return v
}

// compareVersions orders versions by their runs of digits as numbers and the text between them as
// text, so 1.9 comes before 1.10 and 1.2.6-r2 before 1.2.6-r10.
func compareVersions(x, y string) int {
	for x != "" && y != "" {
		xs, xrest := splitRun(x)
		ys, yrest := splitRun(y)
		if c := compareRun(xs, ys); c != 0 {
			return c
		}
		x, y = xrest, yrest
	}
	return cmp.Compare(len(x), len(y))
}

func splitRun(s string) (string, string) {
	digit := unicode.IsDigit(rune(s[0]))
	i := 1
	for i < len(s) && unicode.IsDigit(rune(s[i])) == digit {
		i++
	}
	return s[:i], s[i:]
}

func compareRun(x, y string) int {
	if unicode.IsDigit(rune(x[0])) && unicode.IsDigit(rune(y[0])) {
		x, y = strings.TrimLeft(x, "0"), strings.TrimLeft(y, "0")
		return cmp.Or(cmp.Compare(len(x), len(y)), strings.Compare(x, y))
	}
	return strings.Compare(x, y)
}

func sortedKeys[K comparable, V any](m map[K]V, compare func(K, K) int) []K {
	keys := make([]K, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.SortFunc(keys, compare)
	return keys
}
