package config

// The environment-variables page's tables, held to configVariables (#519 decision 6).
//
// The page is where an operator learns what each variable does, the flag that beats it, what the
// console does with it unset and which of the two servers reads it. configVariables is every live
// variable this console loads, held to every GOIABADA_ name config.go mentions by
// TestConfigSource_EveryVariableAndFlagHasARow. This holds the page to that table in both
// directions: a variable this console gains without its row fails, and so does a row saying this
// console reads a variable it does not, or giving one a flag or a default it does not have. The
// auth server's tier holds the same page to its own table, so between the two every row is held
// to the binary it names.
//
// It reads files and nothing else.

import (
	"fmt"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/leodip/goiabada/core/guard"
)

const environmentVariablesPage = "site/src/content/docs/reference/environment-variables.mdx"

// environmentVariablesSection is the page's section holding every variable's row, in as many
// tables as it has topics.
var environmentVariablesSection = docSection{environmentVariablesPage, "## Every variable"}

// The three answers the page's Read by lines give, and the one this tier is.
const (
	readByAuthServer   = "auth server"
	readByAdminConsole = "admin console"
	readByBoth         = "both"

	thisServer  = readByAdminConsole
	otherServer = readByAuthServer
)

// docVariableCell is a table cell holding one backticked GOIABADA_ variable and nothing else.
var docVariableCell = regexp.MustCompile("^`(GOIABADA_[A-Z0-9_]*[A-Z0-9])`$")

func TestEnvironmentVariablesDocs_TheTablesAreTheConsolesVariables(t *testing.T) {
	assertEnvironmentVariablesDocs(t, filepath.Dir(guard.SourceRoot(t)), environmentVariablesSection, configVariables)
}

func TestEnvironmentVariablesDocs_ATableDisagreeingWithTheCodeFails(t *testing.T) {
	root := t.TempDir()
	writeManifestFixture(t, root, "site/env.mdx", "## Every variable\n\n"+
		"### Network\n\n"+
		"| Variable | What it does |\n"+
		"|---|---|\n"+
		"| `GOIABADA_ADMINCONSOLE_BASEURL`<br/>Flag: `--adminconsole-base-url`<br/>Default: `http://localhost:9091`<br/>Read by: both | The public URL. |\n"+
		"| `GOIABADA_ADMINCONSOLE_LISTEN_PORT_HTTP`<br/>Flag: `--adminconsole-listen-port-http`<br/>Default: `8080`<br/>Read by: admin console | The port. |\n"+
		"| `GOIABADA_ADMINCONSOLE_RETIRED`<br/>Flag: none<br/>Default: empty<br/>Read by: admin console | Gone from the code. |\n"+
		"| `GOIABADA_AUTHSERVER_BASEURL`<br/>Flag: `--authserver-baseurl`<br/>Default: `http://localhost:9090`<br/>Read by: auth server | Read here too. |\n"+
		"| `GOIABADA_AUTHSERVER_LISTEN_PORT_HTTP`<br/>Flag: `--authserver-listen-port-http`<br/>Default: `9090`<br/>Read by: auth server | The auth server's own. |\n\n"+
		"### Keys\n\n"+
		"| Variable | What it does |\n"+
		"|---|---|\n"+
		"| `GOIABADA_ADMINCONSOLE_BASEURL`<br/>Flag: `--adminconsole-baseurl`<br/>Default: `http://localhost:9091`<br/>Read by: both | Listed twice. |\n"+
		"| `GOIABADA_ADMINCONSOLE_SESSION_ENCRYPTION_KEY`<br/>Flag: `--adminconsole-session-encryption-key`<br/>Default: `secret`<br/>Read by: admin console | Neither a flag nor a default. |\n"+
		"| `GOIABADA_ADMINCONSOLE_LOG_LEVEL`<br/>Flag: `--adminconsole-log-level`<br/>Default: `info`<br/>Read by: admin console | |\n"+
		"| `GOIABADA_ADMINCONSOLE_METRICS_ENABLED`<br/>Flag: `--adminconsole-metrics-enabled`<br/>Default: `false`<br/>Read by: the admin console | Not a reader. |\n"+
		"| GOIABADA_ADMINCONSOLE_LOG_FORMAT<br/>Flag: `--adminconsole-log-format`<br/>Default: `text`<br/>Read by: admin console | Not backticked. |\n"+
		"| `GOIABADA_ADMINCONSOLE_TEMPLATEDIR`<br/>Flag: `--adminconsole-templatedir`<br/>Default: empty | No reader. |\n"+
		"| `GOIABADA_ADMINCONSOLE_LISTEN_PORT_METRICS`<br/>Flag: `--adminconsole-listen-port-metrics`<br/>Default: `9191`<br/>Read by: admin console |\n\n"+
		"## Next\n\n| `GOIABADA_ADMINCONSOLE_STATICDIR`<br/>Flag: `--adminconsole-staticdir`<br/>Default: empty<br/>Read by: admin console | Outside the section. |\n")

	vars := []configVar{
		{env: "GOIABADA_ADMINCONSOLE_BASEURL", flag: "adminconsole-baseurl", def: "http://localhost:9091"},
		{env: "GOIABADA_ADMINCONSOLE_LISTEN_PORT_HTTP", flag: "adminconsole-listen-port-http", def: 9091},
		{env: "GOIABADA_AUTHSERVER_BASEURL", flag: "authserver-baseurl", def: "http://localhost:9090"},
		{env: "GOIABADA_ADMINCONSOLE_SESSION_ENCRYPTION_KEY", def: ""},
		{env: "GOIABADA_ADMINCONSOLE_LOG_LEVEL", flag: "adminconsole-log-level", def: "info"},
		{env: "GOIABADA_ADMINCONSOLE_METRICS_ENABLED", flag: "adminconsole-metrics-enabled", def: false},
		{env: "GOIABADA_ADMINCONSOLE_LOG_FORMAT", flag: "adminconsole-log-format", def: "text"},
		{env: "GOIABADA_ADMINCONSOLE_LISTEN_PORT_METRICS", flag: "adminconsole-listen-port-metrics", def: 9191},
		{env: "GOIABADA_ADMINCONSOLE_STATICDIR", flag: "adminconsole-staticdir", def: ""},
	}
	report := guard.Run(func(r guard.Reporter) {
		assertEnvironmentVariablesDocs(r, root, docSection{"site/env.mdx", "## Every variable"}, vars)
	})

	if report.Stopped {
		t.Fatalf("the check stopped rather than reporting: %s", report.Fatal)
	}
	where := "site/env.mdx: ## Every variable"
	want := []string{
		where + " gives GOIABADA_ADMINCONSOLE_BASEURL the flag `--adminconsole-base-url`, want `--adminconsole-baseurl`",
		where + " gives GOIABADA_ADMINCONSOLE_LISTEN_PORT_HTTP the default `8080`, want `9091`",
		where + " says the admin console reads GOIABADA_ADMINCONSOLE_RETIRED, which it does not",
		where + " says only the auth server reads GOIABADA_AUTHSERVER_BASEURL, which the admin console reads too",
		where + " lists GOIABADA_ADMINCONSOLE_BASEURL twice",
		where + " gives GOIABADA_ADMINCONSOLE_SESSION_ENCRYPTION_KEY the flag `--adminconsole-session-encryption-key`, want none",
		where + " gives GOIABADA_ADMINCONSOLE_SESSION_ENCRYPTION_KEY the default `secret`, want empty",
		where + " gives GOIABADA_ADMINCONSOLE_LOG_LEVEL no meaning",
		where + ` gives GOIABADA_ADMINCONSOLE_METRICS_ENABLED the reader "the admin console", want auth server, admin console or both`,
		where + ` has a row whose variable is not one backticked GOIABADA_ variable: "GOIABADA_ADMINCONSOLE_LOG_FORMAT"`,
		where + ` has a row whose variable cell is not the variable over its Flag, Default and Read by lines: "` + "`GOIABADA_ADMINCONSOLE_TEMPLATEDIR`<br/>Flag: `--adminconsole-templatedir`<br/>Default: empty" + `"`,
		where + ` has a row that is not two cells, the variable and its meaning: ["` + "`GOIABADA_ADMINCONSOLE_LISTEN_PORT_METRICS`<br/>Flag: `--adminconsole-listen-port-metrics`<br/>Default: `9191`<br/>Read by: admin console" + `"]`,
		where + " does not list GOIABADA_ADMINCONSOLE_LOG_FORMAT",
		where + " does not list GOIABADA_ADMINCONSOLE_LISTEN_PORT_METRICS",
		where + " does not list GOIABADA_ADMINCONSOLE_STATICDIR",
	}
	if !slices.Equal(report.Errors, want) {
		t.Errorf("failures\n%q\nwant\n%q", report.Errors, want)
	}
}

func TestEnvironmentVariablesDocs_ATableMatchingTheCodePasses(t *testing.T) {
	root := t.TempDir()
	writeManifestFixture(t, root, "site/env.mdx", "## Every variable\n\n"+
		"### Network\n\n"+
		"| Variable | What it does |\n"+
		"|---|---|\n"+
		"| `GOIABADA_AUTHSERVER_BASEURL`<br/>Flag: `--authserver-baseurl`<br/>Default: `http://localhost:9090`<br/>Read by: both | The public URL. |\n"+
		"| `GOIABADA_ADMINCONSOLE_LISTEN_PORT_HTTP`<br/>Flag: `--adminconsole-listen-port-http`<br/>Default: `9091`<br/>Read by: admin console | The port. |\n"+
		"| `GOIABADA_AUTHSERVER_LISTEN_PORT_HTTP`<br/>Flag: `--authserver-listen-port-http`<br/>Default: `9090`<br/>Read by: auth server | The auth server's own. |\n\n"+
		"### Everything else\n\n"+
		"| Variable | What it does |\n"+
		"|---|---|\n"+
		"| `GOIABADA_ADMINCONSOLE_SESSION_ENCRYPTION_KEY`<br/>Flag: none<br/>Default: empty<br/>Read by: admin console | The key. |\n"+
		"| `GOIABADA_ADMINCONSOLE_TRUSTED_PROXIES`<br/>Flag: `--adminconsole-trusted-proxies`<br/>Default: empty<br/>Read by: admin console | The proxies. |\n"+
		"| `GOIABADA_ADMINCONSOLE_METRICS_ENABLED`<br/>Flag: `--adminconsole-metrics-enabled`<br/>Default: `false`<br/>Read by: admin console | The switch. |\n\n"+
		"## Next\n\nText.\n")

	vars := []configVar{
		{env: "GOIABADA_AUTHSERVER_BASEURL", flag: "authserver-baseurl", def: "http://localhost:9090"},
		{env: "GOIABADA_ADMINCONSOLE_LISTEN_PORT_HTTP", flag: "adminconsole-listen-port-http", def: 9091},
		{env: "GOIABADA_ADMINCONSOLE_SESSION_ENCRYPTION_KEY", def: ""},
		{env: "GOIABADA_ADMINCONSOLE_TRUSTED_PROXIES", flag: "adminconsole-trusted-proxies", def: []string(nil)},
		{env: "GOIABADA_ADMINCONSOLE_METRICS_ENABLED", flag: "adminconsole-metrics-enabled", def: false},
	}
	report := guard.Run(func(r guard.Reporter) {
		assertEnvironmentVariablesDocs(r, root, docSection{"site/env.mdx", "## Every variable"}, vars)
	})

	if report.Stopped || len(report.Errors) > 0 {
		t.Errorf("a table matching the code failed: %+v", report)
	}
}

func TestEnvironmentVariablesDocs_AMissingSectionStops(t *testing.T) {
	root := t.TempDir()
	writeManifestFixture(t, root, "site/env.mdx", "## Variables\n\n"+
		"| Variable | What it does |\n|---|---|\n"+
		"| `GOIABADA_ADMINCONSOLE_LOG_LEVEL`<br/>Flag: `--adminconsole-log-level`<br/>Default: `info`<br/>Read by: admin console | The level. |\n")

	report := guard.Run(func(r guard.Reporter) {
		assertEnvironmentVariablesDocs(r, root, docSection{"site/env.mdx", "## Every variable"},
			[]configVar{{env: "GOIABADA_ADMINCONSOLE_LOG_LEVEL", flag: "adminconsole-log-level", def: "info"}})
	})

	if !report.Stopped || !strings.Contains(report.Fatal, "## Every variable") {
		t.Errorf("a page without the section did not stop the check naming it: %+v", report)
	}
}

func TestEnvironmentVariablesDocs_ASectionWithNoTableStops(t *testing.T) {
	root := t.TempDir()
	writeManifestFixture(t, root, "site/env.mdx", "## Every variable\n\n- `GOIABADA_ADMINCONSOLE_LOG_LEVEL`: the level.\n")

	report := guard.Run(func(r guard.Reporter) {
		assertEnvironmentVariablesDocs(r, root, docSection{"site/env.mdx", "## Every variable"},
			[]configVar{{env: "GOIABADA_ADMINCONSOLE_LOG_LEVEL", flag: "adminconsole-log-level", def: "info"}})
	})

	if !report.Stopped || !strings.Contains(report.Fatal, "no table") {
		t.Errorf("a section without its table did not stop the check: %+v", report)
	}
}

// assertEnvironmentVariablesDocs is the reporting half of the check: one failure per finding of
// environmentVariablesDocsFindings; a stop for a section not found or holding no table, since a
// check that read no row proves nothing.
func assertEnvironmentVariablesDocs(r guard.Reporter, root string, section docSection, vars []configVar) {
	r.Helper()
	findings, err := environmentVariablesDocsFindings(root, section, vars)
	if err != nil {
		r.Fatalf("%v", err)
		return
	}
	for _, finding := range findings {
		r.Errorf("%s", finding)
	}
}

// environmentVariablesDocsFindings reads every table in section, one row per variable with its
// flag, its default, the server that reads it and its meaning, and returns one finding per row
// that is malformed, lists a variable a second time or gives it no meaning, says this server
// reads a variable it does not, says only the other server reads one this server reads, or gives
// one this server reads a flag or a default other than its own; then one per variable in vars with
// no row. A row naming only the other server's variable is that server's tier to check. It returns
// an error, and no findings, for a section not found or holding no table.
func environmentVariablesDocsFindings(root string, section docSection, vars []configVar) ([]string, error) {
	text, err := docSectionText(root, section)
	if err != nil {
		return nil, err
	}
	rows := docEveryTableRows(text)
	if len(rows) == 0 {
		return nil, fmt.Errorf("%s: %s holds no table of the environment variables", section.page, section.heading)
	}

	read := make(map[string]configVar, len(vars))
	for _, v := range vars {
		read[v.env] = v
	}

	where := section.page + ": " + section.heading
	var findings []string
	listed := make(map[string]bool)
	for _, cells := range rows {
		if len(cells) != 2 {
			findings = append(findings, fmt.Sprintf("%s has a row that is not two cells, the variable and its meaning: %q",
				where, cells))
			continue
		}
		row, ok := docVariableLines(cells[0])
		if !ok {
			findings = append(findings, fmt.Sprintf("%s has a row whose variable cell is not the variable over its Flag, Default and Read by lines: %q",
				where, cells[0]))
			continue
		}
		match := docVariableCell.FindStringSubmatch(row.variable)
		if match == nil {
			findings = append(findings, fmt.Sprintf("%s has a row whose variable is not one backticked GOIABADA_ variable: %q",
				where, row.variable))
			continue
		}
		name, flagCell, defaultCell, reader, meaning := match[1], row.flag, row.def, row.reader, cells[1]
		if listed[name] {
			findings = append(findings, where+" lists "+name+" twice")
			continue
		}
		listed[name] = true

		v, reads := read[name]
		switch reader {
		case thisServer, readByBoth:
			if !reads {
				findings = append(findings, where+" says the "+thisServer+" reads "+name+", which it does not")
			}
		case otherServer:
			if reads {
				findings = append(findings, where+" says only the "+otherServer+" reads "+name+", which the "+thisServer+" reads too")
			}
		default:
			findings = append(findings, fmt.Sprintf("%s gives %s the reader %q, want %s, %s or %s",
				where, name, reader, readByAuthServer, readByAdminConsole, readByBoth))
		}
		if reads {
			if want := docFlagCell(v.flag); flagCell != want {
				findings = append(findings, where+" gives "+name+" the flag "+flagCell+", want "+want)
			}
			if want := docDefaultCell(v.def); defaultCell != want {
				findings = append(findings, where+" gives "+name+" the default "+defaultCell+", want "+want)
			}
		}
		if meaning == "" {
			findings = append(findings, where+" gives "+name+" no meaning")
		}
	}
	for _, v := range vars {
		if !listed[v.env] {
			findings = append(findings, where+" does not list "+v.env)
		}
	}
	return findings, nil
}

// docVariableLabels are the labels of the lines under a variable's name in its cell, in order.
var docVariableLabels = []string{"Flag: ", "Default: ", "Read by: "}

// docVariableRow is a row's variable cell: the variable, and the three lines under it, each
// without its label.
type docVariableRow struct{ variable, flag, def, reader string }

// docVariableLines splits a row's variable cell at its line breaks into the variable and its flag,
// default and reader lines; ok is false for a cell of any other shape.
func docVariableLines(cell string) (docVariableRow, bool) {
	lines := strings.Split(cell, "<br/>")
	if len(lines) != 1+len(docVariableLabels) {
		return docVariableRow{}, false
	}
	values := make([]string, len(docVariableLabels))
	for i, label := range docVariableLabels {
		value, found := strings.CutPrefix(lines[i+1], label)
		if !found {
			return docVariableRow{}, false
		}
		values[i] = value
	}
	return docVariableRow{variable: lines[0], flag: values[0], def: values[1], reader: values[2]}, true
}

// docFlagCell is how the page writes a variable's flag: backticked with its two dashes, or none.
func docFlagCell(flagName string) string {
	if flagName == "" {
		return "none"
	}
	return "`--" + flagName + "`"
}

// docDefaultCell is how the page writes what Load lands with nothing set: empty for an empty
// string or list, and otherwise the value backticked as an operator would write it.
func docDefaultCell(def any) string {
	switch d := def.(type) {
	case string:
		if d == "" {
			return "empty"
		}
		return "`" + d + "`"
	case []string:
		if len(d) == 0 {
			return "empty"
		}
		return "`" + strings.Join(d, ",") + "`"
	case int:
		return "`" + strconv.Itoa(d) + "`"
	case bool:
		return "`" + strconv.FormatBool(d) + "`"
	default:
		return fmt.Sprintf("`%v`", d)
	}
}

// docEveryTableRows is the body rows of every Markdown table in text, in order, each trimmed cell
// in order: each table's header row and the delimiter row under it are left out.
func docEveryTableRows(text string) [][]string {
	var rows [][]string
	inTable := false
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "|") {
			inTable = false
			continue
		}
		cells := strings.Split(strings.Trim(line, "|"), "|")
		for i := range cells {
			cells[i] = strings.TrimSpace(cells[i])
		}
		if !inTable {
			inTable = true // a table's header row
			continue
		}
		if strings.Trim(strings.Join(cells, ""), "-: ") == "" {
			continue // the delimiter row
		}
		rows = append(rows, cells)
	}
	return rows
}
