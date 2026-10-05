package guard

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"github.com/leodip/goiabada/core/errs"
)

// assertMetricsQueries holds the queries the Monitoring page shows to the catalog table on the same
// page: every metric the page names is a family the catalog lists, a histogram's series named by
// its `_bucket`, `_sum` or `_count` suffix; and in every promql or yaml block and every inline code
// span, every label a selector or a grouping names is one the family declares, and every value a
// selector compares a listed label with is in its set. page is relative to the repository root.
//
// The catalog is held to each server's registry by AssertMetricsCatalog, so this closes the chain
// from a suggested alert to the code. An alert written against a value the label never takes, such
// as `outcome="complete"` for `completed`, or a label the family does not carry, matches no series
// and never fires, and nothing on a dashboard says so: an alert that cannot fire looks exactly like
// a deployment with nothing to alert on (#400 decision 9).
//
// A regular-expression matcher is checked only when it is a plain alternation of values, such as
// `outcome=~"failed|interrupted"`; a pattern like `status=~"5.."` is left alone. A label described
// rather than listed, such as `route` or `status`, takes any value. The labels Prometheus attaches
// to every target, and `le` beside a `_bucket` series, are accepted on any query.
func assertMetricsQueries(r Reporter, repoRoot, page string) {
	r.Helper()

	findings, err := checkMetricsQueries(repoRoot, page)
	if err != nil {
		r.Fatalf("%v", err)
		return
	}
	for _, f := range findings {
		r.Errorf("%s", f)
	}
}

// The labels a scrape attaches to every series, so a query may select or group by them whatever
// the family declares.
var targetLabels = []string{"job", "instance", "namespace", "pod", "container"}

// The suffixes Prometheus gives a histogram's series.
var histogramSuffixes = []string{"_bucket", "_sum", "_count"}

var (
	// A metric name as the page spells it: a goiabada_ or go_ name not inside a longer word.
	queryMetricName = regexp.MustCompile(`(?:^|[^A-Za-z0-9_])((?:goiabada|go)_[a-z0-9_]*[a-z0-9])`)
	// One matcher of a selector: a label, an operator and a double-quoted value.
	queryMatcher = regexp.MustCompile(`^\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*(=~|!~|!=|=)\s*"([^"]*)"\s*$`)
	// A grouping or a vector match's label list.
	queryGrouping = regexp.MustCompile(`\b(?:by|without|on|ignoring|group_left|group_right)\s*\(([^)]*)\)`)
	// A regular expression that is nothing but an alternation of plain values.
	queryAlternation = regexp.MustCompile(`^[A-Za-z0-9_]+(?:\|[A-Za-z0-9_]+)*$`)
	// An inline code span in prose.
	inlineCode = regexp.MustCompile("`([^`]+)`")
)

// The fenced blocks whose content is read as queries.
var queryBlockLanguages = []string{"promql", "yaml"}

// queryBlock is one fenced promql or yaml block, or one inline code span: its lines and the line
// number of its first.
type queryBlock struct {
	first int
	lines []string
}

// checkMetricsQueries returns one finding per violation, in the page's order.
func checkMetricsQueries(repoRoot, page string) ([]string, error) {
	path := filepath.Join(repoRoot, page)
	rows, err := readMetricsCatalog(path)
	if err != nil {
		return nil, err
	}
	catalog := map[string]catalogRow{}
	for _, row := range rows {
		catalog[row.metric] = row
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, errs.Errorf("reading the Monitoring page: %w", err)
	}
	lines := strings.Split(string(data), "\n")

	var findings []string
	for i, line := range lines {
		for _, name := range metricNames(line) {
			if _, _, ok := resolveMetric(catalog, name); !ok {
				findings = append(findings, fmt.Sprintf("%s:%d names `%s`, which the catalog does not list", page, i+1, name))
			}
		}
	}

	// Only the fenced blocks count towards having read a query: the catalog's own cells are inline
	// spans naming every metric, so every page with a catalog would count as queried.
	queried := 0
	for _, block := range queryBlocks(lines) {
		blockFindings, references := checkQueryBlock(page, block, catalog)
		findings = append(findings, blockFindings...)
		queried += references
	}
	if queried == 0 {
		return nil, errs.Errorf("%s has no promql or yaml block naming a metric, so this check read no query", page)
	}
	for _, span := range inlineCodeSpans(lines) {
		spanFindings, _ := checkQueryBlock(page, span, catalog)
		findings = append(findings, spanFindings...)
	}
	return findings, nil
}

// metricNames returns the metric names a line spells, in order.
func metricNames(line string) []string {
	var names []string
	for _, m := range queryMetricName.FindAllStringSubmatch(line, -1) {
		names = append(names, m[1])
	}
	return names
}

// resolveMetric returns the catalog row a series name belongs to, and whether it names a
// histogram's buckets, which carry `le` besides the family's labels.
func resolveMetric(catalog map[string]catalogRow, name string) (catalogRow, bool, bool) {
	if row, ok := catalog[name]; ok {
		return row, false, true
	}
	for _, suffix := range histogramSuffixes {
		base, found := strings.CutSuffix(name, suffix)
		if row, ok := catalog[base]; found && ok && row.typ == "histogram" {
			return row, suffix == "_bucket", true
		}
	}
	return catalogRow{}, false, false
}

// queryBlocks returns the page's fenced blocks whose language is one queryBlockLanguages names.
func queryBlocks(lines []string) []queryBlock {
	var blocks []queryBlock
	var current *queryBlock
	inFence := false
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if !strings.HasPrefix(trimmed, "```") {
			if current != nil {
				current.lines = append(current.lines, line)
			}
			continue
		}
		if inFence {
			if current != nil {
				blocks = append(blocks, *current)
			}
			inFence, current = false, nil
			continue
		}
		inFence = true
		language, _, _ := strings.Cut(strings.TrimPrefix(trimmed, "```"), " ")
		if slices.Contains(queryBlockLanguages, language) {
			current = &queryBlock{first: i + 2}
		}
	}
	return blocks
}

// inlineCodeSpans returns every inline code span outside a fenced block, each as a block of its
// own, so a grouping in one is held to the metrics that span names.
func inlineCodeSpans(lines []string) []queryBlock {
	var spans []queryBlock
	inFence := false
	for i, line := range lines {
		if strings.HasPrefix(strings.TrimSpace(line), "```") {
			inFence = !inFence
			continue
		}
		if inFence {
			continue
		}
		for _, m := range inlineCode.FindAllStringSubmatch(line, -1) {
			spans = append(spans, queryBlock{first: i + 1, lines: []string{m[1]}})
		}
	}
	return spans
}

// checkQueryBlock checks every selector and grouping in one block, and returns how many metric
// references it read. A grouping's labels are checked against every family the block names, since
// an expression may span lines and a block may hold several.
func checkQueryBlock(page string, block queryBlock, catalog map[string]catalogRow) ([]string, int) {
	var findings []string
	references := 0
	groupable := map[string]bool{}
	for _, label := range targetLabels {
		groupable[label] = true
	}

	for offset, line := range block.lines {
		at := fmt.Sprintf("%s:%d", page, block.first+offset)
		for _, loc := range queryMetricName.FindAllStringSubmatchIndex(line, -1) {
			name := line[loc[2]:loc[3]]
			row, bucket, ok := resolveMetric(catalog, name)
			if !ok {
				continue
			}
			references++
			for _, label := range row.labels {
				groupable[label.name] = true
			}
			if bucket {
				groupable["le"] = true
			}

			rest := line[loc[3]:]
			if !strings.HasPrefix(rest, "{") {
				continue
			}
			selector, _, closed := strings.Cut(rest[1:], "}")
			if !closed {
				findings = append(findings, fmt.Sprintf("%s: the selector of `%s` does not close on its line", at, name))
				continue
			}
			findings = append(findings, checkSelector(at, name, selector, row, bucket)...)
		}
	}

	for offset, line := range block.lines {
		at := fmt.Sprintf("%s:%d", page, block.first+offset)
		for _, m := range queryGrouping.FindAllStringSubmatch(line, -1) {
			for _, label := range strings.Split(m[1], ",") {
				label = strings.TrimSpace(label)
				if label != "" && !groupable[label] {
					findings = append(findings, fmt.Sprintf(
						"%s groups by `%s`, which no metric this block names carries", at, label))
				}
			}
		}
	}
	return findings, references
}

// checkSelector holds one selector's matchers to the family it selects from.
func checkSelector(at, name, selector string, row catalogRow, bucket bool) []string {
	var findings []string
	for _, matcher := range strings.Split(selector, ",") {
		if strings.TrimSpace(matcher) == "" {
			continue
		}
		m := queryMatcher.FindStringSubmatch(matcher)
		if m == nil {
			findings = append(findings, fmt.Sprintf("%s: the matcher %q of `%s` is not label op \"value\"", at, strings.TrimSpace(matcher), name))
			continue
		}
		labelName, op, value := m[1], m[2], m[3]

		if slices.Contains(targetLabels, labelName) || (bucket && labelName == "le") {
			continue
		}
		index := slices.IndexFunc(row.labels, func(l catalogLabel) bool { return l.name == labelName })
		if index < 0 {
			findings = append(findings, fmt.Sprintf("%s selects `%s` by `%s`, which it does not carry", at, name, labelName))
			continue
		}
		label := row.labels[index]
		if !label.isList {
			continue
		}

		var values []string
		switch {
		case op == "=" || op == "!=":
			values = []string{value}
		case queryAlternation.MatchString(value):
			values = strings.Split(value, "|")
		}
		for _, v := range values {
			if !slices.Contains(label.listed, v) {
				findings = append(findings, fmt.Sprintf("%s compares `%s` of `%s` with %q, which is not one of its values: %s",
					at, labelName, name, v, strings.Join(label.listed, ", ")))
			}
		}
	}
	return findings
}
