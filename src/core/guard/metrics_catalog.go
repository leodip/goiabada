package guard

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"testing"

	"github.com/leodip/goiabada/core/errs"
	"github.com/leodip/goiabada/core/metrics"
)

// AssertMetricsCatalog holds one server's metrics registry to the metrics catalog table in the
// docs, in both directions: every family the server registers has a row, and every row naming that
// server names a family it registers, with the same type, the same labels and, for each label, the
// same set of values. page is the docs page holding the table, relative to the repository root;
// server is "auth server" or "admin console".
//
// The label rule is what makes a metrics endpoint safe to scrape: every label takes values from a
// set declared when its metric is registered, so a family cannot outgrow the product of its sets
// and nothing taken from a request reaches a label unmapped (#400 decision 4). core/metrics
// enforces the closed set; this puts each set in front of a reader, so a label whose set was built
// from something it should not have been is a change to the docs a reviewer sees, and a new family
// fails its server's tier until the docs describe it. AssertErrorCodeDoc is the same arrangement
// for the error-code document.
//
// The table is the one whose header row reads `| metric | type | labels | server | meaning |`.
// A row's labels cell is `none`, or `name`: set for each label, joined by "; ". A set the code
// declares with metrics.Enum is listed as backticked values joined by ", ", compared as a set; one
// declared with metrics.Described is the description itself, word for word. The server cell is
// `auth server`, `admin console` or `both`; the meaning cell is prose and is not read.
func AssertMetricsCatalog(t *testing.T, page, server string, families []metrics.Family) {
	t.Helper()

	assertMetricsCatalog(t, filepath.Dir(SourceRoot(t)), page, server, families)
}

// assertMetricsCatalog is the reporting half. A finder error is fatal: it means the page could not
// be read, held no catalog or none of this server's rows, or there was no registry to compare, and
// every per-family check would then pass vacuously. See Reporter in guard.go.
func assertMetricsCatalog(r Reporter, repoRoot, page, server string, families []metrics.Family) {
	r.Helper()

	findings, err := checkMetricsCatalog(repoRoot, page, server, families)
	if err != nil {
		r.Fatalf("%v", err)
		return
	}
	for _, f := range findings {
		r.Errorf("%s", f)
	}
}

// metricsCatalogFinding is one violation, named by the metric it is about.
type metricsCatalogFinding struct {
	Metric string
	Reason string
}

func (f metricsCatalogFinding) String() string {
	return fmt.Sprintf("%s: %s", f.Metric, f.Reason)
}

// The catalog's header row, and the values its type and server cells may take.
const metricsCatalogHeader = "| metric | type | labels | server | meaning |"

var (
	metricsCatalogTypes   = []string{"counter", "gauge", "histogram"}
	metricsCatalogServers = []string{"auth server", "admin console"}
)

const metricsCatalogBoth = "both"

// catalogRow is one row of the table as read.
type catalogRow struct {
	line   int
	metric string
	typ    string
	labels []catalogLabel
	server string
}

// catalogLabel is one label as a row's labels cell gives it: the text after the colon, and the
// backticked values that text lists when it is nothing but a list.
type catalogLabel struct {
	name   string
	text   string
	listed []string
	isList bool
}

// checkMetricsCatalog returns one finding per violation, sorted by metric so the message is stable.
func checkMetricsCatalog(repoRoot, page, server string, families []metrics.Family) ([]metricsCatalogFinding, error) {
	if !slices.Contains(metricsCatalogServers, server) {
		return nil, errs.Errorf("the metrics catalog has no server %q; it knows %s", server, strings.Join(metricsCatalogServers, " and "))
	}
	if len(families) == 0 {
		return nil, errs.Errorf("the %s registry holds no families; every comparison below would pass vacuously", server)
	}

	rows, err := readMetricsCatalog(filepath.Join(repoRoot, page))
	if err != nil {
		return nil, err
	}

	ours := map[string][]catalogRow{}
	for _, row := range rows {
		if row.server == server || row.server == metricsCatalogBoth {
			ours[row.metric] = append(ours[row.metric], row)
		}
	}
	if len(ours) == 0 {
		return nil, errs.Errorf("%s: the metrics catalog has no row for the %s; every comparison below would pass vacuously", page, server)
	}

	var findings []metricsCatalogFinding
	registered := map[string]bool{}
	for _, family := range families {
		registered[family.Name] = true
		matching := ours[family.Name]
		switch {
		case len(matching) == 0:
			findings = append(findings, metricsCatalogFinding{family.Name, fmt.Sprintf(
				"the %s registers this family but %s has no row for it; add one: %s",
				server, page, catalogRowFor(family, server))})
		case len(matching) > 1:
			findings = append(findings, metricsCatalogFinding{family.Name, fmt.Sprintf(
				"%s has %d rows for this family that apply to the %s; one metric has one row per server",
				page, len(matching), server)})
		default:
			findings = append(findings, compareCatalogRow(family, matching[0], page)...)
		}
	}
	for metric, matching := range ours {
		if !registered[metric] {
			findings = append(findings, metricsCatalogFinding{metric, fmt.Sprintf(
				"%s:%d says the %s exposes this family, which it does not register; either the family was renamed or the row is stale",
				page, matching[0].line, server)})
		}
	}

	sort.Slice(findings, func(i, j int) bool {
		if findings[i].Metric != findings[j].Metric {
			return findings[i].Metric < findings[j].Metric
		}
		return findings[i].Reason < findings[j].Reason
	})
	return findings, nil
}

// compareCatalogRow holds one row to the family it names.
func compareCatalogRow(family metrics.Family, row catalogRow, page string) []metricsCatalogFinding {
	var findings []metricsCatalogFinding
	add := func(format string, args ...any) {
		findings = append(findings, metricsCatalogFinding{family.Name,
			fmt.Sprintf("%s:%d ", page, row.line) + fmt.Sprintf(format, args...)})
	}

	if row.typ != family.Type {
		add("says %s and the code registers a %s", row.typ, family.Type)
	}

	documented := map[string]catalogLabel{}
	for _, label := range row.labels {
		documented[label.name] = label
	}
	declared := map[string]bool{}
	for _, label := range family.Labels {
		declared[label.Name()] = true
		doc, ok := documented[label.Name()]
		if !ok {
			add("leaves out the label `%s`, which the code declares: %s", label.Name(), catalogLabelFor(label))
			continue
		}
		if label.Description() != "" {
			if doc.text != label.Description() {
				add("describes `%s` as %q and the code describes its set as %q", label.Name(), doc.text, label.Description())
			}
			continue
		}
		if !doc.isList {
			add("describes `%s` as %q, but the code declares a set to list: %s", label.Name(), doc.text, catalogLabelFor(label))
			continue
		}
		missing, extra := setDifference(label.Values(), doc.listed), setDifference(doc.listed, label.Values())
		if len(missing) > 0 {
			add("leaves out values of `%s` the code declares: %s", label.Name(), strings.Join(missing, ", "))
		}
		if len(extra) > 0 {
			add("lists values of `%s` the code does not declare: %s", label.Name(), strings.Join(extra, ", "))
		}
	}
	for _, label := range row.labels {
		if !declared[label.name] {
			add("documents the label `%s`, which the code does not declare", label.name)
		}
	}
	return findings
}

// setDifference returns what a holds that b does not, in a's order.
func setDifference(a, b []string) []string {
	var out []string
	for _, v := range a {
		if !slices.Contains(b, v) {
			out = append(out, v)
		}
	}
	return out
}

// catalogRowFor renders the row a family needs, so the finding for a missing one is the fix.
func catalogRowFor(family metrics.Family, server string) string {
	labels := "none"
	if len(family.Labels) > 0 {
		cells := make([]string, len(family.Labels))
		for i, label := range family.Labels {
			cells[i] = catalogLabelFor(label)
		}
		labels = strings.Join(cells, "; ")
	}
	return fmt.Sprintf("| `%s` | %s | %s | %s | <what it measures> |", family.Name, family.Type, labels, server)
}

func catalogLabelFor(label metrics.Label) string {
	if label.Description() != "" {
		return fmt.Sprintf("`%s`: %s", label.Name(), label.Description())
	}
	values := label.Values()
	for i, v := range values {
		values[i] = "`" + v + "`"
	}
	return fmt.Sprintf("`%s`: %s", label.Name(), strings.Join(values, ", "))
}

// readMetricsCatalog returns the catalog table's rows. A page with no catalog table, or two, and a
// row that cannot be read are errors rather than findings: a row skipped for its shape would drop
// out of the comparison entirely.
func readMetricsCatalog(path string) ([]catalogRow, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, errs.Errorf("reading the metrics catalog: %w", err)
	}

	var rows []catalogRow
	tables := 0
	inTable := false
	for i, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "|") {
			inTable = false
			continue
		}
		if line == metricsCatalogHeader {
			tables++
			inTable = true
			continue
		}
		if !inTable || strings.HasPrefix(line, "|---") || strings.HasPrefix(line, "| ---") {
			continue
		}
		row, err := parseCatalogRow(path, i+1, line)
		if err != nil {
			return nil, err
		}
		rows = append(rows, row)
	}

	switch tables {
	case 0:
		return nil, errs.Errorf("%s has no catalog table, whose header row is %q", path, metricsCatalogHeader)
	case 1:
		return rows, nil
	default:
		return nil, errs.Errorf("%s has %d catalog tables; the guard reads one", path, tables)
	}
}

func parseCatalogRow(path string, lineNo int, line string) (catalogRow, error) {
	cells := strings.Split(strings.Trim(line, "|"), "|")
	if len(cells) != 5 {
		return catalogRow{}, errs.Errorf("%s:%d has %d cells rather than 5; an unescaped | in a cell is the usual cause",
			path, lineNo, len(cells))
	}
	for i := range cells {
		cells[i] = strings.TrimSpace(cells[i])
	}

	metric, ok := backtickedCode(cells[0])
	if !ok {
		return catalogRow{}, errs.Errorf("%s:%d: the metric cell %q is not one backticked name", path, lineNo, cells[0])
	}
	row := catalogRow{line: lineNo, metric: metric, typ: cells[1], server: cells[3]}
	if !slices.Contains(metricsCatalogTypes, row.typ) {
		return catalogRow{}, errs.Errorf("%s:%d: %q is not a type this catalog knows; it knows %s",
			path, lineNo, row.typ, strings.Join(metricsCatalogTypes, ", "))
	}
	if row.server != metricsCatalogBoth && !slices.Contains(metricsCatalogServers, row.server) {
		return catalogRow{}, errs.Errorf("%s:%d: %q is not a server; the cell is %s or %s",
			path, lineNo, row.server, strings.Join(metricsCatalogServers, ", "), metricsCatalogBoth)
	}

	if cells[2] == "none" {
		return row, nil
	}
	for _, part := range strings.Split(cells[2], "; ") {
		nameCell, text, found := strings.Cut(part, ": ")
		name, ok := backtickedCode(nameCell)
		if !found || !ok {
			return catalogRow{}, errs.Errorf("%s:%d: the label %q is not `name`: set", path, lineNo, part)
		}
		label := catalogLabel{name: name, text: text, isList: true}
		for _, item := range strings.Split(text, ", ") {
			value, isValue := backtickedCode(item)
			if !isValue {
				label.isList = false
				label.listed = nil
				break
			}
			label.listed = append(label.listed, value)
		}
		row.labels = append(row.labels, label)
	}
	return row, nil
}
