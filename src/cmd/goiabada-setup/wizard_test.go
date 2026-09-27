package main

import (
	"bytes"
	"errors"
	"flag"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/leodip/goiabada/core/errs"
)

// connectionCall is one call of the wizard's connection check.
type connectionCall struct {
	engine, host, port, name, user, password string //nolint:unused // compared whole with ==, which the linter does not count as a read
}

// testWizard is a wizard over a scripted prompter writing into a fresh directory, whose connection
// check records its calls and answers from results in order, true once they run out.
func testWizard(t *testing.T, flags *CLIFlags, steps []scriptedStep, results ...bool) (*wizard, *scriptedPrompter, *bytes.Buffer, *[]connectionCall) {
	t.Helper()
	if flags.Output == "" {
		flags.Output = t.TempDir()
	}
	in := &scriptedPrompter{t: t, steps: steps}
	var buf bytes.Buffer
	w := newWizard(flags, in, &console{w: &buf})
	calls := &[]connectionCall{}
	w.testConnection = func(_ *console, e *engine, host, port, name, user, password string) bool {
		*calls = append(*calls, connectionCall{e.name, host, port, name, user, password})
		if len(results) == 0 {
			return true
		}
		ok := results[0]
		results = results[1:]
		return ok
	}
	return w, in, &buf, calls
}

var headingPattern = regexp.MustCompile(`(?m)^STEP (\d+): (.+)\n(-+)$`)

// headings reads the step headings out of the wizard's output and fails the test unless they are
// numbered 1, 2, 3 and so on in order, each underlined to its own length.
func headings(t *testing.T, output string) (numbers []int, titles []string) {
	t.Helper()
	for _, m := range headingPattern.FindAllStringSubmatch(output, -1) {
		number, _ := strconv.Atoi(m[1])
		numbers = append(numbers, number)
		titles = append(titles, m[2])
		if len(m[3]) != len("STEP "+m[1]+": "+m[2]) {
			t.Errorf("heading %q is underlined with %d dashes", m[2], len(m[3]))
		}
	}
	return numbers, titles
}

func assertNumberedFromOne(t *testing.T, numbers []int) {
	t.Helper()
	for i, number := range numbers {
		if number != i+1 {
			t.Errorf("headings are numbered %v, want 1 to %d with no gap or repeat", numbers, len(numbers))
			return
		}
	}
}

func assertNothingWritten(t *testing.T, dir string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Errorf("wrote %v, want nothing", entryNames(entries))
	}
}

// interactiveScript answers every prompt the wizard asks for a deployment type and engine, taking
// the defaults the Config below expects, and confirming the write.
func interactiveScript(d *deployment, e *engine) []scriptedStep {
	steps := []scriptedStep{
		{prompt: "Select deployment type [1-4]", answer: d.number},
		{prompt: "Select database [1-", answer: e.number},
	}
	if d.asksURLs {
		steps = append(steps,
			scriptedStep{prompt: "Auth server URL (e.g., https://auth.example.com) [https://auth.example.com]: ", answer: "https://auth.example.org"},
			scriptedStep{prompt: "Admin console URL (e.g., https://admin.example.com) [https://admin.example.org]: ", answer: ""},
		)
	}
	if d.asksNamespace {
		steps = append(steps, scriptedStep{prompt: "Namespace [goiabada]: ", answer: ""})
	}
	defaultEmail := "admin@example.com"
	if d.asksURLs {
		defaultEmail = "admin@example.org"
	}
	steps = append(steps,
		scriptedStep{prompt: "Admin email [" + defaultEmail + "]: ", answer: ""},
		scriptedStep{prompt: "Admin password [changeme]: ", answer: "Str0ng-Passw0rd!"},
	)
	switch {
	case e.hasServer && d.externalDatabase:
		steps = append(steps,
			scriptedStep{prompt: "Database host [", answer: "db.internal"},
			scriptedStep{prompt: "Database port [" + e.defaultPort + "]: ", answer: ""},
			scriptedStep{prompt: "Database name [goiabada]: ", answer: ""},
			scriptedStep{prompt: "Database username [" + e.defaultUser + "]: ", answer: ""},
			scriptedStep{prompt: "Database password [", answer: "db-secret"},
			scriptedStep{prompt: "Test database connection? [Y/n]: ", answer: ""},
		)
	case e.hasServer:
		steps = append(steps, scriptedStep{prompt: "Database password [", answer: "db-secret"})
	}
	return append(steps, scriptedStep{prompt: "Generate configuration files? [Y/n]: ", answer: ""})
}

// Every deployment type, with SQLite where it accepts it and with a server engine, runs to its file
// with its steps numbered 1 to n. Local testing read 1, 2, 4, 5, 6 and production with a server
// engine 1, 2, 3, 4, 5, 5, 6 while each branch numbered its own headings (#430).
func TestWizard_EveryDeploymentTypeRunsToItsFile(t *testing.T) {
	cases := []struct {
		deployment deploymentType
		engine     string
		titles     []string
	}{
		{deploymentLocal, "sqlite", []string{"Deployment type", "Database type", "Admin credentials", "Generating credentials", "Generating configuration"}},
		{deploymentLocal, "mysql", []string{"Deployment type", "Database type", "Admin credentials", "Database password", "Generating credentials", "Generating configuration"}},
		{deploymentProduction, "sqlite", []string{"Deployment type", "Database type", "Domain names", "Admin credentials", "Generating credentials", "Generating configuration"}},
		{deploymentProduction, "postgres", []string{"Deployment type", "Database type", "Domain names", "Admin credentials", "Database password", "Generating credentials", "Generating configuration"}},
		{deploymentKubernetes, "postgres", []string{"Deployment type", "Database type", "Domain names", "Kubernetes namespace", "Admin credentials", "Database connection", "Generating credentials", "Generating configuration"}},
		{deploymentKubernetes, "mssql", []string{"Deployment type", "Database type", "Domain names", "Kubernetes namespace", "Admin credentials", "Database connection", "Generating credentials", "Generating configuration"}},
		{deploymentNative, "sqlite", []string{"Deployment type", "Database type", "Domain names", "Admin credentials", "Generating credentials", "Generating configuration"}},
		{deploymentNative, "mysql", []string{"Deployment type", "Database type", "Domain names", "Admin credentials", "Database connection", "Generating credentials", "Generating configuration"}},
	}
	for _, tc := range cases {
		d := deployments[tc.deployment]
		e := testEngine(tc.engine)
		t.Run(d.name+"-"+e.name, func(t *testing.T) {
			w, in, out, calls := testWizard(t, &CLIFlags{}, interactiveScript(d, e))
			if err := w.setup(); err != nil {
				t.Fatalf("setup: %v\n%s", err, out)
			}
			in.assertConsumed()

			numbers, titles := headings(t, out.String())
			assertNumberedFromOne(t, numbers)
			if !slices.Equal(titles, tc.titles) {
				t.Errorf("headings %q, want %q", titles, tc.titles)
			}

			c := w.config
			if c.Deployment != d || c.Engine != e {
				t.Errorf("config is %s on %s, want %s on %s", c.Deployment.name, c.Engine.name, d.name, e.name)
			}
			wantAuth, wantAdmin, wantEmail := "http://localhost:9090", "http://localhost:9091", "admin@example.com"
			if d.asksURLs {
				wantAuth, wantAdmin, wantEmail = "https://auth.example.org", "https://admin.example.org", "admin@example.org"
			}
			if c.AuthServerURL != wantAuth || c.AdminConsoleURL != wantAdmin || c.AdminEmail != wantEmail {
				t.Errorf("URLs and email are %q, %q, %q; want %q, %q, %q",
					c.AuthServerURL, c.AdminConsoleURL, c.AdminEmail, wantAuth, wantAdmin, wantEmail)
			}
			if c.AdminPassword != "Str0ng-Passw0rd!" {
				t.Errorf("admin password is %q", c.AdminPassword)
			}
			wantNamespace := ""
			if d.asksNamespace {
				wantNamespace = "goiabada"
			}
			if c.K8sNamespace != wantNamespace {
				t.Errorf("namespace is %q, want %q", c.K8sNamespace, wantNamespace)
			}

			var wantCalls []connectionCall
			switch {
			case e.hasServer && d.externalDatabase:
				want := connectionCall{e.name, "db.internal", e.defaultPort, "goiabada", e.defaultUser, "db-secret"}
				got := connectionCall{e.name, c.DBHost, c.DBPort, c.DBName, c.DBUsername, c.DBPassword}
				if got != want {
					t.Errorf("database is %+v, want %+v", got, want)
				}
				wantCalls = []connectionCall{want}
			case e.hasServer:
				if c.DBPassword != "db-secret" || c.DBHost != "" || c.DBPort != e.defaultPort {
					t.Errorf("database is %q:%q with password %q, want no host, port %q and \"db-secret\"",
						c.DBHost, c.DBPort, c.DBPassword, e.defaultPort)
				}
			default:
				if c.DBHost != "" || c.DBPort != "" || c.DBPassword != "" {
					t.Errorf("SQLite has database fields %q, %q, %q", c.DBHost, c.DBPort, c.DBPassword)
				}
			}
			if !slices.Equal(*calls, wantCalls) {
				t.Errorf("connection checks %+v, want %+v", *calls, wantCalls)
			}
			for name, value := range map[string]string{
				"auth session auth key": c.AuthSessionAuthKey, "auth session encryption key": c.AuthSessionEncKey,
				"admin session auth key": c.AdminSessionAuthKey, "admin session encryption key": c.AdminSessionEncKey,
				"AES key": c.AESEncryptionKey, "OAuth client secret": c.OAuthClientSecret,
			} {
				if value == "" {
					t.Errorf("the %s was not generated", name)
				}
			}

			wantPath := filepath.Join(w.flags.Output, d.outputFile)
			if w.outputPath != wantPath {
				t.Errorf("output path %q, want %q", w.outputPath, wantPath)
			}
			written, err := os.ReadFile(wantPath)
			if err != nil {
				t.Fatal(err)
			}
			if _, content := generatedConfiguration(c); string(written) != content {
				t.Errorf("%s is not the generator's output for the Config", d.outputFile)
			}
			if !strings.Contains(out.String(), "SETUP COMPLETE!") {
				t.Errorf("no completion message:\n%s", out)
			}
		})
	}
}

func TestWizard_TheAbortWritesNothing(t *testing.T) {
	d, e := deployments[deploymentKubernetes], testEngine("postgres")
	full := interactiveScript(d, e)
	cases := map[string][]scriptedStep{
		"at the first prompt": {{prompt: "Select deployment type", err: errAborted}},
		"at an answer halfway": append(slices.Clone(full[:4]),
			scriptedStep{prompt: "Namespace [goiabada]: ", err: errAborted}),
		"declining the confirmation": append(slices.Clone(full[:len(full)-1]),
			scriptedStep{prompt: "Generate configuration files? [Y/n]: ", answer: "n"}),
	}
	for name, steps := range cases {
		t.Run(name, func(t *testing.T) {
			w, in, out, _ := testWizard(t, &CLIFlags{}, steps)
			err := w.setup()
			if !errors.Is(err, errAborted) {
				t.Fatalf("setup: %v, want errAborted", err)
			}
			in.assertConsumed()
			assertNothingWritten(t, w.flags.Output)
			if code := exitCode(w.out, err); code != 0 {
				t.Errorf("exit code %d, want 0", code)
			}
			if !strings.HasSuffix(out.String(), "\nAborted.\n") {
				t.Errorf("output does not end in \"Aborted.\":\n%s", out)
			}
		})
	}
}

// A read that fails at the final confirmation is the failure, and nothing is written: the default
// is yes, and taking it on a fault wrote the file (#430).
func TestWizard_AReadFaultAtTheConfirmationWritesNothing(t *testing.T) {
	d, e := deployments[deploymentProduction], testEngine("postgres")
	steps := interactiveScript(d, e)
	steps[len(steps)-1].err = errReadFault
	w, in, out, _ := testWizard(t, &CLIFlags{}, steps)
	err := w.setup()
	if !errors.Is(err, errReadFault) {
		t.Fatalf("setup: %v, want the read fault", err)
	}
	in.assertConsumed()
	assertNothingWritten(t, w.flags.Output)
	if code := exitCode(w.out, err); code != 1 {
		t.Errorf("exit code %d, want 1", code)
	}
	if !strings.Contains(out.String(), "Error: read fault") {
		t.Errorf("the fault is not reported:\n%s", out)
	}
}

// The three answers to a failed connection check: enter the details again, keep them, or abort.
func TestWizard_TheConnectionFailureMenu(t *testing.T) {
	d, e := deployments[deploymentNative], testEngine("postgres")
	full := interactiveScript(d, e)
	// full ends with the six database reads and the confirmation.
	before, database, confirmation := full[:len(full)-7], full[len(full)-7:len(full)-1], full[len(full)-1]
	menu := func(answer string) scriptedStep {
		return scriptedStep{prompt: "Select option [1-3] [1]: ", answer: answer}
	}

	t.Run("re-enter", func(t *testing.T) {
		again := slices.Clone(database)
		again[0].answer = "db2.internal"
		steps := slices.Concat(before, database, []scriptedStep{menu("")}, again, []scriptedStep{confirmation})
		w, in, _, calls := testWizard(t, &CLIFlags{}, steps, false, true)
		if err := w.setup(); err != nil {
			t.Fatal(err)
		}
		in.assertConsumed()
		if len(*calls) != 2 || (*calls)[1].host != "db2.internal" || w.config.DBHost != "db2.internal" {
			t.Errorf("checked %+v and kept host %q, want the second host checked and kept", *calls, w.config.DBHost)
		}
	})
	t.Run("continue anyway", func(t *testing.T) {
		steps := slices.Concat(before, database, []scriptedStep{menu("2"), confirmation})
		w, in, out, calls := testWizard(t, &CLIFlags{}, steps, false)
		if err := w.setup(); err != nil {
			t.Fatal(err)
		}
		in.assertConsumed()
		if len(*calls) != 1 || w.config.DBHost != "db.internal" {
			t.Errorf("checked %+v and kept host %q", *calls, w.config.DBHost)
		}
		if !strings.Contains(out.String(), "Continuing without successful database connection test.") {
			t.Errorf("no warning:\n%s", out)
		}
		if _, err := os.Stat(w.outputPath); err != nil {
			t.Errorf("the file was not written: %v", err)
		}
	})
	t.Run("abort", func(t *testing.T) {
		steps := slices.Concat(before, database, []scriptedStep{menu("3")})
		w, in, _, _ := testWizard(t, &CLIFlags{}, steps, false)
		if err := w.setup(); !errors.Is(err, errAborted) {
			t.Fatalf("setup: %v, want errAborted", err)
		}
		in.assertConsumed()
		assertNothingWritten(t, w.flags.Output)
	})
	t.Run("skip the check", func(t *testing.T) {
		skip := slices.Clone(database)
		skip[len(skip)-1].answer = "n"
		steps := slices.Concat(before, skip, []scriptedStep{confirmation})
		w, in, _, calls := testWizard(t, &CLIFlags{}, steps)
		if err := w.setup(); err != nil {
			t.Fatal(err)
		}
		in.assertConsumed()
		if len(*calls) != 0 {
			t.Errorf("checked %+v after the operator declined", *calls)
		}
	})
}

// With --type nothing is read, and the two steps that print their headings there are numbered as
// the interactive run numbers them.
func TestWizard_NonInteractiveRunsFromTheFlags(t *testing.T) {
	cases := []struct {
		flags    CLIFlags
		numbers  []int
		database connectionCall
		checked  bool
	}{
		{
			flags:   CLIFlags{DeploymentType: "local", DBType: "sqlite"},
			numbers: []int{4, 5},
		},
		{
			flags:    CLIFlags{DeploymentType: "production", DBType: "mysql", AuthServerURL: "https://auth.example.org", DBPassword: "db-secret"},
			numbers:  []int{6, 7},
			database: connectionCall{engine: "mysql", port: "3306", password: "db-secret"},
		},
		{
			flags: CLIFlags{
				DeploymentType: "k8s", DBType: "postgres", AuthServerURL: "https://auth.example.org",
				Namespace: "identity", DBHost: "pg.internal", DBPort: "6543", DBName: "gb", DBUsername: "gbuser", DBPassword: "db-secret",
			},
			numbers:  []int{7, 8},
			database: connectionCall{"postgres", "pg.internal", "6543", "gb", "gbuser", "db-secret"},
			checked:  true,
		},
		{
			flags:    CLIFlags{DeploymentType: "4", DBType: "mssql", AuthServerURL: "https://auth.example.org", DBHost: "sql.internal", DBPassword: "db-secret", SkipDBTest: true},
			numbers:  []int{6, 7},
			database: connectionCall{"mssql", "sql.internal", "1433", "goiabada", "sa", "db-secret"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.flags.DeploymentType+"-"+tc.flags.DBType, func(t *testing.T) {
			flags := tc.flags
			w, _, out, calls := testWizard(t, &flags, nil)
			if err := w.setup(); err != nil {
				t.Fatalf("setup: %v\n%s", err, out)
			}
			numbers, titles := headings(t, out.String())
			if !slices.Equal(numbers, tc.numbers) {
				t.Errorf("headings numbered %v, want %v", numbers, tc.numbers)
			}
			if !slices.Equal(titles, []string{"Generating credentials", "Generating configuration"}) {
				t.Errorf("headings %q, want only the two generating steps", titles)
			}
			c := w.config
			got := connectionCall{c.Engine.name, c.DBHost, c.DBPort, c.DBName, c.DBUsername, c.DBPassword}
			want := tc.database
			if want.engine == "" {
				want = connectionCall{engine: "sqlite"}
			}
			if got != want {
				t.Errorf("database is %+v, want %+v", got, want)
			}
			if tc.checked != (len(*calls) == 1) {
				t.Errorf("connection checks %+v, want checked=%v", *calls, tc.checked)
			}
			if tc.flags.Namespace != "" && c.K8sNamespace != tc.flags.Namespace {
				t.Errorf("namespace %q, want %q", c.K8sNamespace, tc.flags.Namespace)
			}
			if _, err := os.Stat(w.outputPath); err != nil {
				t.Errorf("the file was not written: %v", err)
			}
		})
	}
}

func TestWizard_NonInteractiveGeneratesWhatWasNotGiven(t *testing.T) {
	w, _, out, _ := testWizard(t, &CLIFlags{DeploymentType: "native", DBType: "postgres", AuthServerURL: "https://auth.example.org", DBHost: "pg.internal", SkipDBTest: true}, nil)
	if err := w.setup(); err != nil {
		t.Fatal(err)
	}
	c := w.config
	if c.AdminConsoleURL != "https://admin.example.org" || c.AdminEmail != "admin@example.org" {
		t.Errorf("defaults are %q and %q", c.AdminConsoleURL, c.AdminEmail)
	}
	if len(c.AdminPassword) != 16 || len(c.DBPassword) != 16 {
		t.Errorf("generated passwords %q and %q, want 16 characters each", c.AdminPassword, c.DBPassword)
	}
	for _, line := range []string{"Generated admin password: " + c.AdminPassword, "Generated database password: " + c.DBPassword} {
		if !strings.Contains(out.String(), line) {
			t.Errorf("output lacks %q", line)
		}
	}
}

func TestWizard_NonInteractiveWritesDespiteAFailedCheck(t *testing.T) {
	w, _, out, calls := testWizard(t, &CLIFlags{DeploymentType: "native", DBType: "postgres", AuthServerURL: "https://auth.example.org", DBHost: "pg.internal"}, nil, false)
	if err := w.setup(); err != nil {
		t.Fatal(err)
	}
	if len(*calls) != 1 || !strings.Contains(out.String(), "Database connection test failed. Configuration will still be generated.") {
		t.Errorf("checks %+v, output:\n%s", *calls, out)
	}
	if _, err := os.Stat(w.outputPath); err != nil {
		t.Errorf("the file was not written: %v", err)
	}
}

func TestWizard_NonInteractiveRefusals(t *testing.T) {
	native := func(change func(f *CLIFlags)) CLIFlags {
		f := CLIFlags{DeploymentType: "native", DBType: "postgres", AuthServerURL: "https://auth.example.org", DBHost: "pg.internal", SkipDBTest: true}
		change(&f)
		return f
	}
	cases := map[string]struct {
		flags CLIFlags
		want  string
	}{
		"an unknown type":          {CLIFlags{DeploymentType: "cloud"}, "invalid deployment type: cloud (use: local, production, kubernetes, or native)"},
		"an unknown engine":        {CLIFlags{DeploymentType: "local", DBType: "oracle"}, "invalid database type: oracle"},
		"Kubernetes on SQLite":     {CLIFlags{DeploymentType: "kubernetes", DBType: "sqlite"}, "is not supported for Kubernetes deployments"},
		"no auth URL":              {native(func(f *CLIFlags) { f.AuthServerURL = "" }), "--auth-url is required"},
		"an invalid auth URL":      {native(func(f *CLIFlags) { f.AuthServerURL = "auth.example.org" }), "invalid auth URL: URL must start with http:// or https://"},
		"an invalid admin URL":     {native(func(f *CLIFlags) { f.AdminConsoleURL = "ftp://admin" }), "invalid admin URL"},
		"an invalid admin email":   {native(func(f *CLIFlags) { f.AdminEmail = "admin" }), "invalid admin email"},
		"no database host":         {native(func(f *CLIFlags) { f.DBHost = "" }), "--db-host is required"},
		"an invalid database host": {native(func(f *CLIFlags) { f.DBHost = "pg_internal" }), "invalid database host"},
		"an invalid database port": {native(func(f *CLIFlags) { f.DBPort = "99999" }), "invalid database port"},
		"an invalid database name": {native(func(f *CLIFlags) { f.DBName = "1db" }), "invalid database name"},
		"an invalid namespace":     {CLIFlags{DeploymentType: "kubernetes", DBType: "postgres", AuthServerURL: "https://auth.example.org", Namespace: "Upper"}, "invalid namespace"},
	}
	// Every flag whose value is written into the file, refused by its name when it is not UTF-8 or
	// holds NUL, before a step reads it (#430). Each would otherwise be refused, if at all, by a
	// validator saying something else, or written as U+FFFD.
	for name, set := range map[string]func(f *CLIFlags, v string){
		"--auth-url":       func(f *CLIFlags, v string) { f.AuthServerURL = "https://auth.example.org/" + v },
		"--admin-url":      func(f *CLIFlags, v string) { f.AdminConsoleURL = "https://admin.example.org/" + v },
		"--namespace":      func(f *CLIFlags, v string) { f.Namespace = v },
		"--admin-email":    func(f *CLIFlags, v string) { f.AdminEmail = v + "@example.org" },
		"--admin-password": func(f *CLIFlags, v string) { f.AdminPassword = v },
		"--db-host":        func(f *CLIFlags, v string) { f.DBHost = v },
		"--db-port":        func(f *CLIFlags, v string) { f.DBPort = v },
		"--db-name":        func(f *CLIFlags, v string) { f.DBName = v },
		"--db-user":        func(f *CLIFlags, v string) { f.DBUsername = v },
		"--db-password":    func(f *CLIFlags, v string) { f.DBPassword = v },
	} {
		cases[name+" not UTF-8"] = struct {
			flags CLIFlags
			want  string
		}{native(func(f *CLIFlags) { set(f, "pa\xffss") }), name + " cannot be written to the configuration: it is not valid UTF-8"}
		cases[name+" holding NUL"] = struct {
			flags CLIFlags
			want  string
		}{native(func(f *CLIFlags) { set(f, "pa\x00ss") }), name + " cannot be written to the configuration: it contains a NUL character"}
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			flags := tc.flags
			w, _, out, _ := testWizard(t, &flags, nil)
			err := w.setup()
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("setup: %v, want an error containing %q", err, tc.want)
			}
			assertNothingWritten(t, w.flags.Output)
			if code := exitCode(w.out, err); code != 1 {
				t.Errorf("exit code %d, want 1", code)
			}
			if !strings.Contains(out.String(), "Error: "+err.Error()) {
				t.Errorf("the error is not reported:\n%s", out)
			}
		})
	}
}

func TestExitCode(t *testing.T) {
	cases := map[string]struct {
		err    error
		code   int
		output string
	}{
		"finished":        {nil, 0, ""},
		"aborted":         {errAborted, 0, "\nAborted.\n"},
		"any other error": {errReadFault, 1, "✗ Error: read fault\n"},
		"a wrapped abort": {errs.Wrap(errAborted, "at the namespace"), 0, "\nAborted.\n"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			var buf bytes.Buffer
			if code := exitCode(&console{w: &buf}, tc.err); code != tc.code {
				t.Errorf("exit code %d, want %d", code, tc.code)
			}
			if buf.String() != tc.output {
				t.Errorf("output %q, want %q", buf.String(), tc.output)
			}
		})
	}
}

func TestParseFlags(t *testing.T) {
	t.Run("help", func(t *testing.T) {
		var stderr bytes.Buffer
		if _, err := parseFlags([]string{"-h"}, &stderr); !errors.Is(err, flag.ErrHelp) {
			t.Errorf("parseFlags(-h): %v, want flag.ErrHelp", err)
		}
		if !strings.Contains(stderr.String(), "When run without options, starts an interactive wizard.") {
			t.Errorf("no usage on stderr:\n%s", stderr.String())
		}
	})
	t.Run("an unknown flag", func(t *testing.T) {
		if _, err := parseFlags([]string{"--bogus"}, io.Discard); err == nil || errors.Is(err, flag.ErrHelp) {
			t.Errorf("parseFlags(--bogus): %v, want a parse error", err)
		}
	})
	t.Run("values", func(t *testing.T) {
		flags, err := parseFlags([]string{"--type=native", "--db", "mysql", "-o", "out.env", "--skip-db-test", "--no-color"}, io.Discard)
		if err != nil {
			t.Fatal(err)
		}
		if flags.DeploymentType != "native" || flags.DBType != "mysql" || flags.Output != "out.env" || !flags.SkipDBTest || !flags.NoColor {
			t.Errorf("parsed %+v", flags)
		}
	})
}

// The palette colours what prints, and its zero value colours nothing.
func TestConsole_ThePaletteIsWhatColours(t *testing.T) {
	var plain, coloured bytes.Buffer
	(&console{w: &plain}).warning("careful")
	(&console{w: &coloured, palette: ansiColors}).warning("careful")
	if plain.String() != "⚠️  Warning: careful\n" {
		t.Errorf("plain output %q", plain.String())
	}
	if coloured.String() != "\033[33m⚠️  Warning:\033[0m careful\n" {
		t.Errorf("coloured output %q", coloured.String())
	}
}
