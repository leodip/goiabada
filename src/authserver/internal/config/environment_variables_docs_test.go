package config

// The environment-variables page's tables, held to configVariables (#519 decision 6).
//
// The page is where an operator learns what each variable does, the flag that beats it, what the
// server does with it unset and which of the two servers reads it. configVariables is every live
// variable this server loads, held to every GOIABADA_ name config.go mentions by
// TestConfigSource_EveryVariableAndFlagHasARow. This holds the page to that table in both
// directions: a variable this server gains without its row fails, and so does a row saying this
// server reads a variable it does not, or giving one a flag or a default it does not have. The
// admin console's tier holds the same page to its own table, so between the two every row is held
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
	"time"

	"github.com/leodip/goiabada/core/guard"
)

const environmentVariablesPage = "site/src/content/docs/reference/environment-variables.mdx"

// environmentVariablesSection is the page's section holding every variable's row, in as many
// tables as it has topics.
var environmentVariablesSection = docSection{environmentVariablesPage, "## Every variable"}

// The three answers the page's Read by column gives, and the one this tier is.
const (
	readByAuthServer   = "auth server"
	readByAdminConsole = "admin console"
	readByBoth         = "both"

	thisServer  = readByAuthServer
	otherServer = readByAdminConsole
)

// docVariableCell is a table cell holding one backticked GOIABADA_ variable and nothing else.
var docVariableCell = regexp.MustCompile("^`(GOIABADA_[A-Z0-9_]*[A-Z0-9])`$")

func TestEnvironmentVariablesDocs_TheTablesAreTheServersVariables(t *testing.T) {
	assertEnvironmentVariablesDocs(t, filepath.Dir(guard.SourceRoot(t)), environmentVariablesSection, configVariables)
}

func TestEnvironmentVariablesDocs_ATableDisagreeingWithTheCodeFails(t *testing.T) {
	root := t.TempDir()
	writeManifestFixture(t, root, "site/env.mdx", "## Every variable\n\n"+
		"### Network\n\n"+
		"| Variable | Flag | Default | Read by | What it does |\n"+
		"|---|---|---|---|---|\n"+
		"| `GOIABADA_AUTHSERVER_BASEURL` | `--authserver-base-url` | `http://localhost:9090` | both | The public URL. |\n"+
		"| `GOIABADA_AUTHSERVER_LISTEN_PORT_HTTP` | `--authserver-listen-port-http` | `8080` | auth server | The port. |\n"+
		"| `GOIABADA_AUTHSERVER_RETIRED` | none | empty | auth server | Gone from the code. |\n"+
		"| `GOIABADA_ADMINCONSOLE_BASEURL` | `--adminconsole-baseurl` | `http://localhost:9091` | admin console | Read here too. |\n"+
		"| `GOIABADA_ADMINCONSOLE_LISTEN_PORT_HTTP` | `--adminconsole-listen-port-http` | `9091` | admin console | The console's own. |\n\n"+
		"### Keys\n\n"+
		"| Variable | Flag | Default | Read by | What it does |\n"+
		"|---|---|---|---|---|\n"+
		"| `GOIABADA_AUTHSERVER_BASEURL` | `--authserver-baseurl` | `http://localhost:9090` | both | Listed twice. |\n"+
		"| `GOIABADA_AES_ENCRYPTION_KEY` | `--aes-encryption-key` | `secret` | auth server | Neither a flag nor a default. |\n"+
		"| `GOIABADA_DB_CONN_MAX_LIFETIME` | `--db-conn-max-lifetime` | `30m` | auth server | |\n"+
		"| `GOIABADA_DB_CREATE` | `--db-create` | `true` | the auth server | Not a reader. |\n"+
		"| GOIABADA_DB_TYPE | `--db-type` | `sqlite` | auth server | Not backticked. |\n"+
		"| `GOIABADA_DB_PORT` | `--db-port` | `3306` | auth server |\n\n"+
		"## Next\n\n| `GOIABADA_APPNAME` | `--appname` | `Goiabada` | auth server | Outside the section. |\n")

	vars := []configVar{
		{env: "GOIABADA_AUTHSERVER_BASEURL", flag: "authserver-baseurl", def: "http://localhost:9090"},
		{env: "GOIABADA_AUTHSERVER_LISTEN_PORT_HTTP", flag: "authserver-listen-port-http", def: 9090},
		{env: "GOIABADA_ADMINCONSOLE_BASEURL", flag: "adminconsole-baseurl", def: "http://localhost:9091"},
		{env: "GOIABADA_AES_ENCRYPTION_KEY", def: ""},
		{env: "GOIABADA_DB_CONN_MAX_LIFETIME", flag: "db-conn-max-lifetime", def: 30 * time.Minute},
		{env: "GOIABADA_DB_CREATE", flag: "db-create", def: true},
		{env: "GOIABADA_DB_TYPE", flag: "db-type", def: "sqlite"},
		{env: "GOIABADA_DB_PORT", flag: "db-port", def: 3306},
		{env: "GOIABADA_APPNAME", flag: "appname", def: "Goiabada"},
	}
	report := guard.Run(func(r guard.Reporter) {
		assertEnvironmentVariablesDocs(r, root, docSection{"site/env.mdx", "## Every variable"}, vars)
	})

	if report.Stopped {
		t.Fatalf("the check stopped rather than reporting: %s", report.Fatal)
	}
	where := "site/env.mdx: ## Every variable"
	want := []string{
		where + " gives GOIABADA_AUTHSERVER_BASEURL the flag `--authserver-base-url`, want `--authserver-baseurl`",
		where + " gives GOIABADA_AUTHSERVER_LISTEN_PORT_HTTP the default `8080`, want `9090`",
		where + " says the auth server reads GOIABADA_AUTHSERVER_RETIRED, which it does not",
		where + " says only the admin console reads GOIABADA_ADMINCONSOLE_BASEURL, which the auth server reads too",
		where + " lists GOIABADA_AUTHSERVER_BASEURL twice",
		where + " gives GOIABADA_AES_ENCRYPTION_KEY the flag `--aes-encryption-key`, want none",
		where + " gives GOIABADA_AES_ENCRYPTION_KEY the default `secret`, want empty",
		where + " gives GOIABADA_DB_CONN_MAX_LIFETIME no meaning",
		where + ` gives GOIABADA_DB_CREATE the reader "the auth server", want auth server, admin console or both`,
		where + ` has a row whose variable is not one backticked GOIABADA_ variable: "GOIABADA_DB_TYPE"`,
		where + ` has a row of 4 cells, want variable, flag, default, read by and meaning: ["` + "`GOIABADA_DB_PORT`" + `" "` + "`--db-port`" + `" "` + "`3306`" + `" "auth server"]`,
		where + " does not list GOIABADA_DB_TYPE",
		where + " does not list GOIABADA_DB_PORT",
		where + " does not list GOIABADA_APPNAME",
	}
	if !slices.Equal(report.Errors, want) {
		t.Errorf("failures\n%q\nwant\n%q", report.Errors, want)
	}
}

func TestEnvironmentVariablesDocs_ATableMatchingTheCodePasses(t *testing.T) {
	root := t.TempDir()
	writeManifestFixture(t, root, "site/env.mdx", "## Every variable\n\n"+
		"### Network\n\n"+
		"| Variable | Flag | Default | Read by | What it does |\n"+
		"|---|---|---|---|---|\n"+
		"| `GOIABADA_AUTHSERVER_BASEURL` | `--authserver-baseurl` | `http://localhost:9090` | both | The public URL. |\n"+
		"| `GOIABADA_AUTHSERVER_LISTEN_PORT_HTTP` | `--authserver-listen-port-http` | `9090` | auth server | The port. |\n"+
		"| `GOIABADA_ADMINCONSOLE_LISTEN_PORT_HTTP` | `--adminconsole-listen-port-http` | `9091` | admin console | The console's own. |\n\n"+
		"### Everything else\n\n"+
		"| Variable | Flag | Default | Read by | What it does |\n"+
		"|---|---|---|---|---|\n"+
		"| `GOIABADA_AES_ENCRYPTION_KEY` | none | empty | auth server | The data key. |\n"+
		"| `GOIABADA_AUTHSERVER_TRUSTED_PROXIES` | `--authserver-trusted-proxies` | empty | auth server | The proxies. |\n"+
		"| `GOIABADA_DB_CONN_MAX_LIFETIME` | `--db-conn-max-lifetime` | `30m` | auth server | The lifetime. |\n"+
		"| `GOIABADA_DB_CONN_MAX_IDLE_TIME` | `--db-conn-max-idle-time` | `1h` | auth server | The idle time. |\n"+
		"| `GOIABADA_DB_CREATE` | `--db-create` | `true` | auth server | Create it. |\n"+
		"| `GOIABADA_PROFILE_PICTURE_MAX_SIZE_BYTES` | none | `3145728` | auth server | The size. |\n\n"+
		"## Next\n\nText.\n")

	vars := []configVar{
		{env: "GOIABADA_AUTHSERVER_BASEURL", flag: "authserver-baseurl", def: "http://localhost:9090"},
		{env: "GOIABADA_AUTHSERVER_LISTEN_PORT_HTTP", flag: "authserver-listen-port-http", def: 9090},
		{env: "GOIABADA_AES_ENCRYPTION_KEY", def: ""},
		{env: "GOIABADA_AUTHSERVER_TRUSTED_PROXIES", flag: "authserver-trusted-proxies", def: []string(nil)},
		{env: "GOIABADA_DB_CONN_MAX_LIFETIME", flag: "db-conn-max-lifetime", def: 30 * time.Minute},
		{env: "GOIABADA_DB_CONN_MAX_IDLE_TIME", flag: "db-conn-max-idle-time", def: time.Hour},
		{env: "GOIABADA_DB_CREATE", flag: "db-create", def: true},
		{env: "GOIABADA_PROFILE_PICTURE_MAX_SIZE_BYTES", def: int64(3 * 1024 * 1024)},
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
		"| Variable | Flag | Default | Read by | What it does |\n|---|---|---|---|---|\n"+
		"| `GOIABADA_APPNAME` | `--appname` | `Goiabada` | auth server | The name. |\n")

	report := guard.Run(func(r guard.Reporter) {
		assertEnvironmentVariablesDocs(r, root, docSection{"site/env.mdx", "## Every variable"},
			[]configVar{{env: "GOIABADA_APPNAME", flag: "appname", def: "Goiabada"}})
	})

	if !report.Stopped || !strings.Contains(report.Fatal, "## Every variable") {
		t.Errorf("a page without the section did not stop the check naming it: %+v", report)
	}
}

func TestEnvironmentVariablesDocs_ASectionWithNoTableStops(t *testing.T) {
	root := t.TempDir()
	writeManifestFixture(t, root, "site/env.mdx", "## Every variable\n\n- `GOIABADA_APPNAME`: the name.\n")

	report := guard.Run(func(r guard.Reporter) {
		assertEnvironmentVariablesDocs(r, root, docSection{"site/env.mdx", "## Every variable"},
			[]configVar{{env: "GOIABADA_APPNAME", flag: "appname", def: "Goiabada"}})
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
		if len(cells) != 5 {
			findings = append(findings, fmt.Sprintf("%s has a row of %d cells, want variable, flag, default, read by and meaning: %q",
				where, len(cells), cells))
			continue
		}
		match := docVariableCell.FindStringSubmatch(cells[0])
		if match == nil {
			findings = append(findings, fmt.Sprintf("%s has a row whose variable is not one backticked GOIABADA_ variable: %q",
				where, cells[0]))
			continue
		}
		name, flagCell, defaultCell, reader, meaning := match[1], cells[1], cells[2], cells[3], cells[4]
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

// docFlagCell is how the page writes a variable's flag: backticked with its two dashes, or none.
func docFlagCell(flagName string) string {
	if flagName == "" {
		return "none"
	}
	return "`--" + flagName + "`"
}

// docDefaultCell is how the page writes what Load lands with nothing set: empty for an empty
// string or list, and otherwise the value backticked as an operator would write it, a duration
// without the zero units Go's String appends (30m rather than 30m0s).
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
	case int64:
		return "`" + strconv.FormatInt(d, 10) + "`"
	case bool:
		return "`" + strconv.FormatBool(d) + "`"
	case time.Duration:
		s := d.String()
		if strings.HasSuffix(s, "m0s") {
			s = strings.TrimSuffix(s, "0s")
		}
		if strings.HasSuffix(s, "h0m") {
			s = strings.TrimSuffix(s, "0m")
		}
		return "`" + s + "`"
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
