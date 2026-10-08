package config

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/leodip/goiabada/core/guard"
)

// The header of the Logs page's table of the records worth knowing by name.
const logRecordsHeader = "| Record (`msg`) | Level | What it says |"

// Every record the Logs page names is one a server writes, at the level the page gives it. An
// operator searches the log for these messages and alerts on their level, so a record renamed or
// moved to another level in the code, with the page left saying the old one, is a search that
// finds nothing and an alert that never fires.
func TestLogsPage_EveryRecordItNamesIsWrittenAtItsLevel(t *testing.T) {
	repoRoot := filepath.Dir(guard.SourceRoot(t))
	assertLogRecordsWritten(t, repoRoot, logsPage, filepath.Join(repoRoot, "src"))
}

func TestLogsPage_ARecordWrittenNowhereOrAtAnotherLevelFails(t *testing.T) {
	root := t.TempDir()
	writeManifestFixture(t, root, "site/logs.mdx", "# Logs\n\n"+logRecordsHeader+"\n|---|---|---|\n"+
		"| `http request` | `INFO` | One per request. |\n"+
		"| `cross-origin request refused` | `INFO` | A refused request. |\n"+
		"| `never written` | `WARN` | Nothing. |\n")
	writeManifestFixture(t, root, "src/httpmw/logger.go", "package httpmw\n\nimport \"log/slog\"\n\n"+
		"func log(r *http.Request) {\n\tslog.InfoContext(r.Context(), \"http request\", \"status\", 200)\n"+
		"\tslog.WarnContext(r.Context(), \"cross-origin request refused\")\n}\n")
	writeManifestFixture(t, root, "src/httpmw/logger_test.go", "package httpmw\n\nimport \"log/slog\"\n\n"+
		"func test() { slog.WarnContext(nil, \"never written\") }\n")

	report := guard.Run(func(r guard.Reporter) {
		assertLogRecordsWritten(r, root, "site/logs.mdx", filepath.Join(root, "src"))
	})

	if report.Stopped {
		t.Fatalf("the check stopped rather than reporting: %s", report.Fatal)
	}
	want := []string{
		"site/logs.mdx: the record `cross-origin request refused` is listed at INFO, but written at WARN",
		"site/logs.mdx: the record `never written` is written by no production file",
	}
	if strings.Join(report.Errors, "\n") != strings.Join(want, "\n") {
		t.Errorf("failures %q, want exactly %q", report.Errors, want)
	}
}

func TestLogsPage_APageWithoutTheTableStops(t *testing.T) {
	root := t.TempDir()
	writeManifestFixture(t, root, "site/logs.mdx", "# Logs\n\n| Record | Level |\n|---|---|\n| `http request` | `INFO` |\n")
	writeManifestFixture(t, root, "src/httpmw/logger.go", "package httpmw\n")

	report := guard.Run(func(r guard.Reporter) {
		assertLogRecordsWritten(r, root, "site/logs.mdx", filepath.Join(root, "src"))
	})

	if !report.Stopped || !strings.Contains(report.Fatal, "site/logs.mdx") {
		t.Errorf("a page without the records table did not stop the check naming it: %+v", report)
	}
}

// assertLogRecordsWritten is the reporting half: one failure per record the page's table names
// that no production Go file under srcDir writes, or writes only at another level, and a stop for
// a page without the table or a tree in which no record is written at all.
func assertLogRecordsWritten(r guard.Reporter, repoRoot, page, srcDir string) {
	r.Helper()
	rows, err := logRecordRows(filepath.Join(repoRoot, filepath.FromSlash(page)))
	if err != nil {
		r.Fatalf("%s: %v", page, err)
		return
	}
	written, err := writtenLogRecords(srcDir)
	if err != nil {
		r.Fatalf("%v", err)
		return
	}
	if len(written) == 0 {
		r.Fatalf("no production file under %s writes a log record, so this check read nothing", srcDir)
		return
	}
	for _, row := range rows {
		levels := written[row.msg]
		switch {
		case len(levels) == 0:
			r.Errorf("%s: the record `%s` is written by no production file", page, row.msg)
		case !levels[row.level]:
			r.Errorf("%s: the record `%s` is listed at %s, but written at %s", page, row.msg, row.level, joinLevels(levels))
		}
	}
}

type logRecordRow struct{ msg, level string }

var logRecordCell = regexp.MustCompile("^`([^`]+)`$")

// logRecordRows reads the rows of the table under logRecordsHeader: the message and the level,
// each a code span.
func logRecordRows(path string) ([]logRecordRow, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var rows []logRecordRow
	inTable, found := false, false
	for _, line := range strings.Split(string(content), "\n") {
		line = strings.TrimSpace(line)
		if line == logRecordsHeader {
			inTable, found = true, true
			continue
		}
		if !inTable || strings.HasPrefix(line, "|---") {
			continue
		}
		if !strings.HasPrefix(line, "|") {
			inTable = false
			continue
		}
		cells := strings.Split(strings.Trim(line, "|"), "|")
		if len(cells) < 2 {
			return nil, fmt.Errorf("a row of the records table has %d cells: %s", len(cells), line)
		}
		msg := logRecordCell.FindStringSubmatch(strings.TrimSpace(cells[0]))
		level := logRecordCell.FindStringSubmatch(strings.TrimSpace(cells[1]))
		if msg == nil || level == nil {
			return nil, fmt.Errorf("a row of the records table names no message or level as a code span: %s", line)
		}
		rows = append(rows, logRecordRow{msg[1], level[1]})
	}
	if !found || len(rows) == 0 {
		return nil, fmt.Errorf("no table headed %q with a row in it, so this check read nothing", logRecordsHeader)
	}
	return rows, nil
}

// The slog functions a record is written through, by the level they write at.
var slogLevels = map[string]string{
	"Debug": "DEBUG", "DebugContext": "DEBUG",
	"Info": "INFO", "InfoContext": "INFO",
	"Warn": "WARN", "WarnContext": "WARN",
	"Error": "ERROR", "ErrorContext": "ERROR",
}

// writtenLogRecords returns, for every message a production Go file under srcDir writes through a
// slog level function, the levels it is written at. The logging convention makes every message a
// literal at the call, so a message found nowhere is one nothing writes.
func writtenLogRecords(srcDir string) (map[string]map[string]bool, error) {
	written := map[string]map[string]bool{}
	fset := token.NewFileSet()
	err := filepath.WalkDir(srcDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if d.Name() == "node_modules" || d.Name() == "testdata" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		file, err := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
		if err != nil {
			return err
		}
		ast.Inspect(file, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			pkg, ok := sel.X.(*ast.Ident)
			if !ok || pkg.Name != "slog" {
				return true
			}
			level, ok := slogLevels[sel.Sel.Name]
			if !ok || len(call.Args) == 0 {
				return true
			}
			msgArg := call.Args[0]
			if strings.HasSuffix(sel.Sel.Name, "Context") {
				if len(call.Args) < 2 {
					return true
				}
				msgArg = call.Args[1]
			}
			lit, ok := msgArg.(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING {
				return true
			}
			msg, err := strconv.Unquote(lit.Value)
			if err != nil {
				return true
			}
			if written[msg] == nil {
				written[msg] = map[string]bool{}
			}
			written[msg][level] = true
			return true
		})
		return nil
	})
	return written, err
}

func joinLevels(levels map[string]bool) string {
	var out []string
	for _, l := range []string{"DEBUG", "INFO", "WARN", "ERROR"} {
		if levels[l] {
			out = append(out, l)
		}
	}
	return strings.Join(out, ", ")
}
