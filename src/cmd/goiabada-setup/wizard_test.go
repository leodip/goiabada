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
	// A password file named - reads this rather than the test binary's own standard input.
	w.stdin = strings.NewReader("")
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
	if d.servedByEnvoyGateway {
		steps = append(steps,
			scriptedStep{prompt: trafficPolicyPrompt, answer: ""},
			scriptedStep{prompt: networkPolicyPrompt, answer: ""},
		)
	}
	if d.kind == deploymentNative {
		steps = append(steps, scriptedStep{prompt: localProxyPrompt, answer: ""})
	}
	// The rate limiter is on by default but for Kubernetes, whose default traffic policy, Cluster,
	// turns it off.
	switch d.kind {
	case deploymentProduction, deploymentNative:
		steps = append(steps, scriptedStep{prompt: rateLimiterOnPrompt, answer: ""})
	case deploymentKubernetes:
		steps = append(steps, scriptedStep{prompt: rateLimiterOffPrompt, answer: ""})
	}
	defaultEmail := "admin@example.com"
	if d.asksURLs {
		defaultEmail = "admin@example.org"
	}
	steps = append(steps,
		scriptedStep{prompt: "Admin email [" + defaultEmail + "]: ", answer: ""},
		scriptedStep{prompt: "Admin password [generated]: ", hidden: true, answer: "Str0ng-Passw0rd!"},
	)
	switch {
	case e.hasServer && d.externalDatabase:
		steps = append(steps,
			scriptedStep{prompt: "Database host [", answer: "db.internal"},
			scriptedStep{prompt: "Database port [" + e.defaultPort + "]: ", answer: ""},
			scriptedStep{prompt: "Database name [goiabada]: ", answer: ""},
			scriptedStep{prompt: "Database username [" + e.defaultUser + "]: ", answer: ""},
			scriptedStep{prompt: "Database password [generated]: ", hidden: true, answer: "db-secret"},
			scriptedStep{prompt: "Test database connection? [Y/n]: ", answer: ""},
		)
	case e.hasServer:
		steps = append(steps, scriptedStep{prompt: "Database password [generated]: ", hidden: true, answer: "db-secret"})
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
		{deploymentProduction, "sqlite", []string{"Deployment type", "Database type", "Domain names", "Rate limiter", "Admin credentials", "Generating credentials", "Generating configuration"}},
		{deploymentProduction, "postgres", []string{"Deployment type", "Database type", "Domain names", "Rate limiter", "Admin credentials", "Database password", "Generating credentials", "Generating configuration"}},
		{deploymentKubernetes, "postgres", []string{"Deployment type", "Database type", "Domain names", "Kubernetes namespace", "Gateway traffic policy", "Network policy", "Rate limiter", "Admin credentials", "Database connection", "Generating credentials", "Generating configuration"}},
		{deploymentKubernetes, "mssql", []string{"Deployment type", "Database type", "Domain names", "Kubernetes namespace", "Gateway traffic policy", "Network policy", "Rate limiter", "Admin credentials", "Database connection", "Generating credentials", "Generating configuration"}},
		{deploymentNative, "sqlite", []string{"Deployment type", "Database type", "Domain names", "Reverse proxy", "Rate limiter", "Admin credentials", "Generating credentials", "Generating configuration"}},
		{deploymentNative, "mysql", []string{"Deployment type", "Database type", "Domain names", "Reverse proxy", "Rate limiter", "Admin credentials", "Database connection", "Generating credentials", "Generating configuration"}},
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
			if w.paths.description != wantPath {
				t.Errorf("output path %q, want %q", w.paths.description, wantPath)
			}
			written, err := os.ReadFile(wantPath)
			if err != nil {
				t.Fatal(err)
			}
			if string(written) != descriptionOf(c) {
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
		if _, err := os.Stat(w.paths.description); err != nil {
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
			numbers:  []int{7, 8},
			database: connectionCall{engine: "mysql", port: "3306", password: "db-secret"},
		},
		{
			flags: CLIFlags{
				DeploymentType: "k8s", DBType: "postgres", AuthServerURL: "https://auth.example.org",
				Namespace: "identity", DBHost: "pg.internal", DBPort: "6543", DBName: "gb", DBUsername: "gbuser", DBPassword: "db-secret",
			},
			numbers:  []int{10, 11},
			database: connectionCall{"postgres", "pg.internal", "6543", "gb", "gbuser", "db-secret"},
			checked:  true,
		},
		{
			flags:    CLIFlags{DeploymentType: "4", DBType: "mssql", AuthServerURL: "https://auth.example.org", DBHost: "sql.internal", DBPassword: "db-secret", SkipDBTest: true},
			numbers:  []int{8, 9},
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
			if _, err := os.Stat(w.paths.description); err != nil {
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
	for _, password := range []string{c.AdminPassword, c.DBPassword} {
		if len(password) != 16 || !hasThreeClasses(password) {
			t.Errorf("generated password %q, want 16 characters of three classes", password)
		}
	}
	// Each generated password is reported as generated, with where it is stored, and never printed
	// (#396 decision 17).
	for _, line := range []string{"Admin password: generated, stored in " + w.paths.secrets, "Database password: generated, stored in " + w.paths.secrets} {
		if !strings.Contains(out.String(), line) {
			t.Errorf("output lacks %q", line)
		}
	}
	for _, password := range []string{c.AdminPassword, c.DBPassword} {
		if strings.Contains(out.String(), password) {
			t.Errorf("output prints the generated password %q", password)
		}
	}
	// The wizard warned "Weak password: no special character" about the password it had just
	// generated (#430).
	if strings.Contains(out.String(), "Weak password") {
		t.Errorf("a generated password is judged:\n%s", out)
	}
	if len(c.OAuthClientSecret) != 60 {
		t.Errorf("client secret %q, want 60 characters", c.OAuthClientSecret)
	}
}

// Every password the wizard generates, in either mode, is one SQL Server accepts as its SA
// password, where one generated SQL Server deployment in 17 failed to start (#430).
func TestWizard_EveryGeneratedPasswordHoldsThreeClasses(t *testing.T) {
	d, e := deployments[deploymentLocal], testEngine("mssql")
	steps := interactiveScript(d, e)
	takeGeneratedPasswords(steps, "Admin password", "Database password")
	w, in, out, _ := testWizard(t, &CLIFlags{}, steps)
	if err := w.setup(); err != nil {
		t.Fatalf("setup: %v\n%s", err, out)
	}
	in.assertConsumed()
	for what, password := range map[string]string{"admin": w.config.AdminPassword, "database": w.config.DBPassword} {
		if len(password) != 16 || !hasThreeClasses(password) {
			t.Errorf("interactive default %s password %q, want 16 characters of three classes", what, password)
		}
	}
	if !w.config.AdminPasswordGenerated {
		t.Error("the interactive default admin password is not reported as generated")
	}

	for _, flags := range []CLIFlags{
		{DeploymentType: "local", DBType: "mssql"},
		{DeploymentType: "production", DBType: "mssql", AuthServerURL: "https://auth.example.org"},
		{DeploymentType: "kubernetes", DBType: "mssql", AuthServerURL: "https://auth.example.org", DBHost: "sql.internal", SkipDBTest: true},
	} {
		w, _, out, _ := testWizard(t, &flags, nil)
		if err := w.setup(); err != nil {
			t.Fatalf("%s: setup: %v\n%s", flags.DeploymentType, err, out)
		}
		for _, password := range []string{w.config.AdminPassword, w.config.DBPassword} {
			if len(password) != 16 || !hasThreeClasses(password) {
				t.Errorf("%s: generated password %q, want 16 characters of three classes", flags.DeploymentType, password)
			}
		}
	}
}

// A password the operator gave is still judged: the warning moved off generated passwords only.
func TestWizard_AChosenAdminPasswordIsJudged(t *testing.T) {
	w, _, out, _ := testWizard(t, &CLIFlags{DeploymentType: "local", DBType: "sqlite", AdminPassword: "weakpass"}, nil)
	if err := w.setup(); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "Weak password: no uppercase letter, no digit, no special character") {
		t.Errorf("a weak chosen password is not warned about:\n%s", out)
	}
	if w.config.AdminPassword != "weakpass" {
		t.Errorf("admin password %q, want the one given", w.config.AdminPassword)
	}
}

// A non-interactive run can be given an existing database's password, and the admin password, with
// nothing secret on its command line: --db-password and --admin-password reach shell history and the
// process list, and leaving them out generates a password no existing database user has. Each file
// loses one trailing line break, CRLF or LF, and its password is stored as given and never shown.
func TestWizard_PasswordFilesGiveThePasswords(t *testing.T) {
	const adminPassword, dbPassword = "Zq7AdminFromFile-Passw0rd", "Zq7DatabaseFromStdin-Passw0rd"
	for _, kind := range []deploymentType{deploymentKubernetes, deploymentNative} {
		t.Run(deployments[kind].name, func(t *testing.T) {
			adminFile := filepath.Join(t.TempDir(), "admin-password")
			if err := os.WriteFile(adminFile, []byte(adminPassword+"\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			flags := nonInteractiveFlags(kind, testEngine("postgres"), false)
			flags.AdminPasswordFile, flags.DBPasswordFile = adminFile, "-"
			w, _, out, _ := testWizard(t, flags, nil)
			w.stdin = strings.NewReader(dbPassword + "\r\n")
			if err := w.setup(); err != nil {
				t.Fatalf("setup: %v\n%s", err, out)
			}
			c := w.config
			if c.AdminPassword != adminPassword || c.AdminPasswordGenerated {
				t.Errorf("admin password %q, generated %v; want the file's, set", c.AdminPassword, c.AdminPasswordGenerated)
			}
			if c.DBPassword != dbPassword || c.DBPasswordGenerated {
				t.Errorf("database password %q, generated %v; want standard input's, set", c.DBPassword, c.DBPasswordGenerated)
			}
			secrets, err := os.ReadFile(w.paths.secrets)
			if err != nil {
				t.Fatal(err)
			}
			want := []string{`GOIABADA_ADMIN_PASSWORD="` + adminPassword + `"`, `GOIABADA_DB_PASSWORD="` + dbPassword + `"`}
			if kind == deploymentKubernetes {
				want = []string{"admin-password: " + base64Encode(adminPassword), "db-password: " + base64Encode(dbPassword)}
			}
			for _, line := range want {
				if !strings.Contains(string(secrets), line) {
					t.Errorf("the secrets file lacks %q:\n%s", line, secrets)
				}
			}
			for _, line := range []string{"Admin password: set, stored in ", "Database password: set, stored in "} {
				if !strings.Contains(out.String(), line) {
					t.Errorf("output lacks %q:\n%s", line, out)
				}
			}
			assertNoSecretShown(t, w, out.String())
		})
	}
}

// Without --admin-url and --admin-email the defaults follow the sibling rule, which the mismatch
// warning agrees with: only a URL outside the auth server's parent warns (#430).
func TestWizard_NonInteractiveDefaultsFollowTheSiblingRule(t *testing.T) {
	cases := []struct {
		auth, admin, email string
		wantAdmin          string
		wantEmail          string
		warning            string
	}{
		{auth: "https://auth.example.co.uk", wantAdmin: "https://admin.example.co.uk", wantEmail: "admin@example.co.uk"},
		{auth: "https://auth.eu.acme.com", wantAdmin: "https://admin.eu.acme.com", wantEmail: "admin@eu.acme.com"},
		{auth: "https://example.com", wantAdmin: "https://admin.example.com", wantEmail: "admin@example.com"},
		{auth: "https://auth.example.com:8443/base/", wantAdmin: "https://admin.example.com", wantEmail: "admin@example.com"},
		{auth: "https://auth.acme.io", admin: "https://console.acme.io", wantAdmin: "https://console.acme.io", wantEmail: "admin@acme.io"},
		{auth: "https://auth.example.co.uk", admin: "https://admin.other.co.uk", wantAdmin: "https://admin.other.co.uk", wantEmail: "admin@example.co.uk",
			warning: "Domain mismatch: auth=example.co.uk, admin=other.co.uk"},
		{auth: "https://10.0.0.5", admin: "https://10.0.0.5:8443", email: "ops@example.org", wantAdmin: "https://10.0.0.5:8443", wantEmail: "ops@example.org"},
		{auth: "https://10.0.0.5", admin: "https://10.0.0.6", email: "ops@example.org", wantAdmin: "https://10.0.0.6", wantEmail: "ops@example.org",
			warning: "Domain mismatch: auth=10.0.0.5, admin=10.0.0.6"},
	}
	for _, tc := range cases {
		t.Run(tc.auth+" "+tc.admin, func(t *testing.T) {
			flags := CLIFlags{DeploymentType: "native", DBType: "sqlite", AuthServerURL: tc.auth, AdminConsoleURL: tc.admin, AdminEmail: tc.email}
			w, _, out, _ := testWizard(t, &flags, nil)
			if err := w.setup(); err != nil {
				t.Fatalf("setup: %v\n%s", err, out)
			}
			if c := w.config; c.AdminConsoleURL != tc.wantAdmin || c.AdminEmail != tc.wantEmail {
				t.Errorf("admin URL and email %q, %q; want %q, %q", c.AdminConsoleURL, c.AdminEmail, tc.wantAdmin, tc.wantEmail)
			}
			warned := strings.Contains(out.String(), "Domain mismatch")
			if tc.warning == "" && warned || tc.warning != "" && !strings.Contains(out.String(), tc.warning) {
				t.Errorf("want warning %q, output:\n%s", tc.warning, out)
			}
		})
	}
}

// A host Kubernetes can route and certify is only checked for Kubernetes: the other types take an
// uppercase host, an IP address and one host for both URLs as they did.
func TestWizard_OnlyKubernetesHoldsTheHostsToTheListenerRule(t *testing.T) {
	for _, urls := range [][2]string{
		{"https://Auth.example.org", "https://Admin.example.org"},
		{"https://auth.example.org", "https://auth.example.org/admin"},
		{"https://10.0.0.5", "https://10.0.0.5:8443"},
	} {
		flags := CLIFlags{DeploymentType: "native", DBType: "sqlite", AuthServerURL: urls[0], AdminConsoleURL: urls[1], AdminEmail: "ops@example.org"}
		w, _, out, _ := testWizard(t, &flags, nil)
		if err := w.setup(); err != nil {
			t.Errorf("native with %v: setup: %v\n%s", urls, err, out)
		}
	}
}

// replaceURLSteps swaps the two URL reads of an interactive script for the ones given.
func replaceURLSteps(t *testing.T, steps []scriptedStep, urlSteps ...scriptedStep) []scriptedStep {
	t.Helper()
	if !strings.HasPrefix(steps[2].prompt, "Auth server URL") || !strings.HasPrefix(steps[3].prompt, "Admin console URL") {
		t.Fatalf("the script's URL reads are not its third and fourth: %q, %q", steps[2].prompt, steps[3].prompt)
	}
	return slices.Concat(steps[:2], urlSteps, steps[4:])
}

// An auth host with no parent offers no admin console URL and no admin email, so an empty answer
// is asked again rather than taken (#430).
func TestWizard_InteractiveOffersNoDefaultWithoutAParent(t *testing.T) {
	d, e := deployments[deploymentProduction], testEngine("sqlite")
	steps := replaceURLSteps(t, interactiveScript(d, e),
		scriptedStep{prompt: "Auth server URL (e.g., https://auth.example.com) [https://auth.example.com]: ", answer: "https://10.0.0.5"},
		scriptedStep{prompt: "Admin console URL (e.g., https://admin.example.com): ", answer: ""},
		scriptedStep{prompt: "Admin console URL (e.g., https://admin.example.com): ", answer: "https://10.0.0.5:8443"},
	)
	for i := range steps {
		if strings.HasPrefix(steps[i].prompt, "Admin email") {
			steps = slices.Insert(steps, i, scriptedStep{prompt: "Admin email: ", answer: ""})
			steps[i+1] = scriptedStep{prompt: "Admin email: ", answer: "ops@example.org"}
			break
		}
	}
	w, in, out, _ := testWizard(t, &CLIFlags{}, steps)
	if err := w.setup(); err != nil {
		t.Fatalf("setup: %v\n%s", err, out)
	}
	in.assertConsumed()
	c := w.config
	if c.AuthServerURL != "https://10.0.0.5" || c.AdminConsoleURL != "https://10.0.0.5:8443" || c.AdminEmail != "ops@example.org" {
		t.Errorf("URLs and email %q, %q, %q", c.AuthServerURL, c.AdminConsoleURL, c.AdminEmail)
	}
	for _, line := range []string{"Invalid URL: URL cannot be empty. Please try again.", "Invalid email: email cannot be empty. Please try again."} {
		if !strings.Contains(out.String(), line) {
			t.Errorf("output lacks %q:\n%s", line, out)
		}
	}
	if strings.Contains(out.String(), "Domain mismatch") {
		t.Errorf("one IP on two ports warned of a mismatch:\n%s", out)
	}
}

// Declining a URL outside the auth server's parent asks for both again, offering the sibling of
// the auth URL; a plain-HTTP URL that is not confirmed is asked for again as well.
func TestWizard_InteractiveMismatchAndHTTPAskAgain(t *testing.T) {
	d, e := deployments[deploymentProduction], testEngine("sqlite")
	steps := replaceURLSteps(t, interactiveScript(d, e),
		scriptedStep{prompt: "Auth server URL (e.g., https://auth.example.com) [https://auth.example.com]: ", answer: "http://auth.example.co.uk"},
		scriptedStep{prompt: "Continue with HTTP? [y/N]: ", answer: ""},
		scriptedStep{prompt: "Auth server URL (e.g., https://auth.example.com) [https://auth.example.com]: ", answer: "https://auth.example.co.uk"},
		scriptedStep{prompt: "Admin console URL (e.g., https://admin.example.com) [https://admin.example.co.uk]: ", answer: "https://admin.other.co.uk"},
		scriptedStep{prompt: "Continue with different domains? [y/N]: ", answer: ""},
		scriptedStep{prompt: "Auth server URL [https://auth.example.co.uk]: ", answer: ""},
		scriptedStep{prompt: "Admin console URL [https://admin.example.co.uk]: ", answer: ""},
	)
	for i := range steps {
		if strings.HasPrefix(steps[i].prompt, "Admin email") {
			steps[i].prompt = "Admin email [admin@example.co.uk]: "
		}
	}
	w, in, out, _ := testWizard(t, &CLIFlags{}, steps)
	if err := w.setup(); err != nil {
		t.Fatalf("setup: %v\n%s", err, out)
	}
	in.assertConsumed()
	c := w.config
	if c.AuthServerURL != "https://auth.example.co.uk" || c.AdminConsoleURL != "https://admin.example.co.uk" || c.AdminEmail != "admin@example.co.uk" {
		t.Errorf("URLs and email %q, %q, %q", c.AuthServerURL, c.AdminConsoleURL, c.AdminEmail)
	}
	for _, line := range []string{"Auth server domain:    example.co.uk", "Admin console domain:  other.co.uk"} {
		if !strings.Contains(out.String(), line) {
			t.Errorf("output lacks %q:\n%s", line, out)
		}
	}
}

// For Kubernetes an IP address, an uppercase host and the auth server's host for the admin console
// are each named and asked for again (#430).
func TestWizard_InteractiveKubernetesHostsAreAskedAgain(t *testing.T) {
	d, e := deployments[deploymentKubernetes], testEngine("postgres")
	authPrompt := "Auth server URL (e.g., https://auth.example.com) [https://auth.example.com]: "
	adminPrompt := "Admin console URL (e.g., https://admin.example.com) [https://admin.example.org]: "
	steps := replaceURLSteps(t, interactiveScript(d, e),
		scriptedStep{prompt: authPrompt, answer: "https://10.0.0.5"},
		scriptedStep{prompt: authPrompt, answer: "https://Auth.example.org"},
		scriptedStep{prompt: authPrompt, answer: "https://auth.example.org"},
		scriptedStep{prompt: adminPrompt, answer: "https://auth.example.org/admin"},
		scriptedStep{prompt: adminPrompt, answer: "https://ADMIN.example.org"},
		scriptedStep{prompt: adminPrompt, answer: ""},
	)
	w, in, out, _ := testWizard(t, &CLIFlags{}, steps)
	if err := w.setup(); err != nil {
		t.Fatalf("setup: %v\n%s", err, out)
	}
	in.assertConsumed()
	if c := w.config; c.AuthServerURL != "https://auth.example.org" || c.AdminConsoleURL != "https://admin.example.org" {
		t.Errorf("URLs %q, %q", c.AuthServerURL, c.AdminConsoleURL)
	}
	for _, line := range []string{
		"Invalid URL: 10.0.0.5 is an IP address, and a Kubernetes host must be a domain name. Please try again.",
		"Invalid URL: host Auth.example.org has 'A', and a Kubernetes host is lowercase a-z, 0-9 and '-'. Please try again.",
		"Invalid URL: the admin console URL has the auth server's host, auth.example.org, and each needs a host of its own. Please try again.",
		"Invalid URL: host ADMIN.example.org has 'A'",
	} {
		if !strings.Contains(out.String(), line) {
			t.Errorf("output lacks %q:\n%s", line, out)
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
	if _, err := os.Stat(w.paths.description); err != nil {
		t.Errorf("the file was not written: %v", err)
	}
}

// An IPv6 database host, bare or bracketed, is one the auth server accepts, so the wizard takes it
// from the flags and hands it to the check as given; the check's hostport.Join brackets it (#430).
func TestWizard_AnIPv6DatabaseHostReachesTheCheck(t *testing.T) {
	for _, host := range []string{"::1", "[::1]", "2001:db8::5"} {
		t.Run(host, func(t *testing.T) {
			w, _, out, calls := testWizard(t, &CLIFlags{DeploymentType: "native", DBType: "postgres", AuthServerURL: "https://auth.example.org", DBHost: host}, nil)
			if err := w.setup(); err != nil {
				t.Fatalf("setup: %v\n%s", err, out)
			}
			if len(*calls) != 1 || (*calls)[0].host != host {
				t.Errorf("checks %+v, want one on host %q", *calls, host)
			}
		})
	}
}

func TestWizard_NonInteractiveRefusals(t *testing.T) {
	native := func(change func(f *CLIFlags)) CLIFlags {
		f := CLIFlags{DeploymentType: "native", DBType: "postgres", AuthServerURL: "https://auth.example.org", DBHost: "pg.internal", SkipDBTest: true}
		change(&f)
		return f
	}
	kubernetes := func(change func(f *CLIFlags)) CLIFlags {
		f := native(change)
		f.DeploymentType = "kubernetes"
		return f
	}
	passwordFile := func(content string) string {
		file := filepath.Join(t.TempDir(), "password")
		if err := os.WriteFile(file, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		return file
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
		// A host with no parent offers no admin console URL or email to default to (#430).
		"no admin URL for an IP host":          {native(func(f *CLIFlags) { f.AuthServerURL = "https://10.0.0.5" }), "--admin-url is required when the auth URL's host, 10.0.0.5, is an IP address or a single label"},
		"no admin URL for a single-label host": {native(func(f *CLIFlags) { f.AuthServerURL = "https://goiabada:9090" }), "--admin-url is required when the auth URL's host, goiabada, is"},
		"no admin email for an IP host":        {native(func(f *CLIFlags) { f.AuthServerURL, f.AdminConsoleURL = "https://10.0.0.5", "https://10.0.0.5:8443" }), "--admin-email is required when the auth URL's host, 10.0.0.5, is an IP address or a single label"},
		"no admin email for a single-label host": {native(func(f *CLIFlags) {
			f.AuthServerURL, f.AdminConsoleURL = "https://goiabada:9090", "https://goiabada:9091"
		}), "--admin-email is required"},
		"an auth URL carrying userinfo": {native(func(f *CLIFlags) { f.AuthServerURL = "https://auth.example.org:x@evil.com/" }), "invalid auth URL: URL cannot carry a user name or password"},
		// Kubernetes routes and certifies each URL by its host, which a Gateway listener must be able
		// to carry, one host per listener (#430).
		"a Kubernetes auth host that is an IP": {kubernetes(func(f *CLIFlags) {
			f.AuthServerURL, f.AdminConsoleURL = "https://10.0.0.5", "https://admin.example.org"
		}), "invalid auth URL: 10.0.0.5 is an IP address, and a Kubernetes host must be a domain name"},
		"a Kubernetes admin host that is an IP": {kubernetes(func(f *CLIFlags) { f.AdminConsoleURL = "https://10.0.0.6" }), "invalid admin URL: 10.0.0.6 is an IP address"},
		"an uppercase Kubernetes auth host":     {kubernetes(func(f *CLIFlags) { f.AuthServerURL = "https://Auth.example.org" }), "invalid auth URL: host Auth.example.org has 'A', and a Kubernetes host is lowercase"},
		"an uppercase Kubernetes admin host":    {kubernetes(func(f *CLIFlags) { f.AdminConsoleURL = "https://admin.Example.org" }), "invalid admin URL: host admin.Example.org has 'E'"},
		"one Kubernetes host for both":          {kubernetes(func(f *CLIFlags) { f.AdminConsoleURL = "https://auth.example.org/admin" }), "invalid admin URL: the admin console URL has the auth server's host, auth.example.org, and each needs a host of its own"},
		"one Kubernetes host by the default":    {kubernetes(func(f *CLIFlags) { f.AuthServerURL = "https://admin.example.org" }), "invalid admin URL: the admin console URL has the auth server's host, admin.example.org"},
		// A password given twice is refused rather than one silently winning, and standard input
		// can be read once.
		"an admin password and its file":        {native(func(f *CLIFlags) { f.AdminPassword, f.AdminPasswordFile = "Zq7-Passw0rd", passwordFile("Zq7-Passw0rd") }), "give --admin-password or --admin-password-file, not both"},
		"a database password and its file":      {native(func(f *CLIFlags) { f.DBPassword, f.DBPasswordFile = "Zq7-Passw0rd", passwordFile("Zq7-Passw0rd") }), "give --db-password or --db-password-file, not both"},
		"both password files on standard input": {native(func(f *CLIFlags) { f.AdminPasswordFile, f.DBPasswordFile = "-", "-" }), "--admin-password-file and --db-password-file cannot both read standard input"},
		"a missing password file":               {native(func(f *CLIFlags) { f.DBPasswordFile = filepath.Join(t.TempDir(), "absent") }), "unable to read --db-password-file"},
		// Empty would otherwise read as "generate one", which leaving the flag out says.
		"an empty password file":          {native(func(f *CLIFlags) { f.DBPasswordFile = passwordFile("") }), "--db-password-file holds no password"},
		"a password file of a line break": {native(func(f *CLIFlags) { f.AdminPasswordFile = passwordFile("\n") }), "--admin-password-file holds no password"},
		"empty standard input":            {native(func(f *CLIFlags) { f.DBPasswordFile = "-" }), "--db-password-file holds no password"},
		"an oversized password file":      {native(func(f *CLIFlags) { f.DBPasswordFile = passwordFile(strings.Repeat("x", 4097)) }), "--db-password-file holds more than 4096 bytes"},
		"a password file not UTF-8":       {native(func(f *CLIFlags) { f.AdminPasswordFile = passwordFile("pa\xffss") }), "--admin-password-file cannot be written to the configuration: it is not valid UTF-8"},
		"a password file holding NUL":     {native(func(f *CLIFlags) { f.DBPasswordFile = passwordFile("pa\x00ss") }), "--db-password-file cannot be written to the configuration: it contains a NUL character"},
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
	// --local-proxy knows whether it was given, so left out it takes the default, and a value that
	// is not a boolean is refused by the flag's name (#396 decision 19).
	t.Run("--local-proxy", func(t *testing.T) {
		for args, want := range map[string]optionalBool{
			"":                    {},
			"--local-proxy":       {set: true, value: true},
			"--local-proxy=true":  {set: true, value: true},
			"--local-proxy=false": {set: true, value: false},
		} {
			flags, err := parseFlags(strings.Fields(args), io.Discard)
			if err != nil {
				t.Fatalf("parseFlags(%q): %v", args, err)
			}
			if flags.LocalProxy != want {
				t.Errorf("parseFlags(%q) reads %+v, want %+v", args, flags.LocalProxy, want)
			}
		}
		var stderr bytes.Buffer
		_, err := parseFlags([]string{"--local-proxy=maybe"}, &stderr)
		if err == nil || !strings.Contains(err.Error(), `invalid boolean value "maybe" for -local-proxy`) {
			t.Errorf("parseFlags(--local-proxy=maybe): %v, want the value refused by the flag's name", err)
		}
	})
	t.Run("the usage lists --local-proxy under native binaries", func(t *testing.T) {
		var stderr bytes.Buffer
		_, _ = parseFlags([]string{"-h"}, &stderr)
		usage := stderr.String()
		section := strings.Index(usage, "Native Binaries Options:")
		flag := strings.Index(usage, "--local-proxy")
		if section < 0 || flag < section {
			t.Errorf("--local-proxy is not listed under the native binaries options:\n%s", usage)
		}
	})
	// --gateway-traffic-policy reads cluster or local in any case, and anything else is refused by
	// the flag's name; --network-policy is a plain boolean (#396 decisions 4, 5 and 19).
	t.Run("--gateway-traffic-policy and --network-policy", func(t *testing.T) {
		for args, want := range map[string]struct {
			policy        trafficPolicy
			networkPolicy bool
		}{
			"":                                 {},
			"--gateway-traffic-policy=cluster": {trafficPolicyCluster, false},
			"--gateway-traffic-policy=local":   {trafficPolicyLocal, false},
			"--gateway-traffic-policy=Local":   {trafficPolicyLocal, false},
			"--gateway-traffic-policy cluster --network-policy": {trafficPolicyCluster, true},
			"--network-policy=false":                            {"", false},
		} {
			flags, err := parseFlags(strings.Fields(args), io.Discard)
			if err != nil {
				t.Fatalf("parseFlags(%q): %v", args, err)
			}
			if flags.GatewayTrafficPolicy != want.policy || flags.NetworkPolicy != want.networkPolicy {
				t.Errorf("parseFlags(%q) reads %q and %v, want %q and %v", args, flags.GatewayTrafficPolicy, flags.NetworkPolicy, want.policy, want.networkPolicy)
			}
		}
		for _, value := range []string{"nodes", "", "Cluster,Local"} {
			_, err := parseFlags([]string{"--gateway-traffic-policy=" + value}, io.Discard)
			if err == nil || !strings.Contains(err.Error(), "for flag -gateway-traffic-policy: use cluster or local") {
				t.Errorf("parseFlags(--gateway-traffic-policy=%s): %v, want the value refused by the flag's name", value, err)
			}
		}
	})
	t.Run("the usage lists the Kubernetes flags under Kubernetes", func(t *testing.T) {
		var stderr bytes.Buffer
		_, _ = parseFlags([]string{"-h"}, &stderr)
		usage := stderr.String()
		section := strings.Index(usage, "Kubernetes Options:")
		next := strings.Index(usage, "Native Binaries Options:")
		for _, name := range []string{"--gateway-traffic-policy", "--network-policy"} {
			at := strings.Index(usage, name)
			if section < 0 || at < section || at > next {
				t.Errorf("%s is not listed under the Kubernetes options:\n%s", name, usage)
			}
		}
	})
	// --rate-limiter knows whether it was given, so left out it takes the deployment's default, and
	// a value that is not a boolean is refused by the flag's name (#396 decisions 9 and 19).
	t.Run("--rate-limiter", func(t *testing.T) {
		for args, want := range map[string]optionalBool{
			"":                     {},
			"--rate-limiter":       {set: true, value: true},
			"--rate-limiter=true":  {set: true, value: true},
			"--rate-limiter=false": {set: true, value: false},
		} {
			flags, err := parseFlags(strings.Fields(args), io.Discard)
			if err != nil {
				t.Fatalf("parseFlags(%q): %v", args, err)
			}
			if flags.RateLimiter != want {
				t.Errorf("parseFlags(%q) reads %+v, want %+v", args, flags.RateLimiter, want)
			}
		}
		_, err := parseFlags([]string{"--rate-limiter=often"}, io.Discard)
		if err == nil || !strings.Contains(err.Error(), `invalid boolean value "often" for -rate-limiter`) {
			t.Errorf("parseFlags(--rate-limiter=often): %v, want the value refused by the flag's name", err)
		}
	})
	t.Run("the usage lists --rate-limiter under the types it applies to", func(t *testing.T) {
		var stderr bytes.Buffer
		_, _ = parseFlags([]string{"-h"}, &stderr)
		usage := stderr.String()
		at := strings.Index(usage, "--rate-limiter")
		if at < 0 {
			t.Fatalf("the usage does not list --rate-limiter:\n%s", usage)
		}
		heading := usage[strings.LastIndex(usage[:at], "\n\n")+2 : at]
		for _, name := range []string{"production", "kubernetes", "native"} {
			if !strings.Contains(heading, name) {
				t.Errorf("--rate-limiter is listed under %q, which does not name %s", heading, name)
			}
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

// localProxyPrompt is the native question, asked with yes as its default (#396 decision 7).
const localProxyPrompt = "Does a reverse proxy on this machine forward to Goiabada? [Y/n]: "

// Native binaries ask whether a reverse proxy on the same machine forwards to them, yes by default,
// and --local-proxy answers without a prompt, true when left out. The answer is what the env file
// is written from (#396 decisions 7 and 19).
func TestWizard_NativeAsksWhetherALocalProxyForwardsToIt(t *testing.T) {
	d, e := deployments[deploymentNative], testEngine("postgres")
	withAnswer := func(answer string) []scriptedStep {
		steps := interactiveScript(d, e)
		for i := range steps {
			if steps[i].prompt == localProxyPrompt {
				steps[i].answer = answer
				return steps
			}
		}
		t.Fatal("the script asks no local proxy question")
		return nil
	}
	nonInteractive := func(localProxy optionalBool) *CLIFlags {
		return &CLIFlags{DeploymentType: "native", DBType: "postgres", AuthServerURL: "https://auth.example.org",
			DBHost: "pg.internal", SkipDBTest: true, LocalProxy: localProxy}
	}
	cases := map[string]struct {
		flags *CLIFlags
		steps []scriptedStep
		want  bool
	}{
		"prompted, the default":        {&CLIFlags{}, withAnswer(""), true},
		"prompted, yes":                {&CLIFlags{}, withAnswer("y"), true},
		"prompted, no":                 {&CLIFlags{}, withAnswer("n"), false},
		"by flag, left out":            {nonInteractive(optionalBool{}), nil, true},
		"by flag, --local-proxy=true":  {nonInteractive(optionalBool{set: true, value: true}), nil, true},
		"by flag, --local-proxy=false": {nonInteractive(optionalBool{set: true, value: false}), nil, false},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			w, in, out, _ := testWizard(t, tc.flags, tc.steps)
			if err := w.setup(); err != nil {
				t.Fatalf("setup: %v\n%s", err, out)
			}
			in.assertConsumed()
			if w.config.LocalProxy != tc.want {
				t.Errorf("LocalProxy is %v, want %v", w.config.LocalProxy, tc.want)
			}
			written, err := os.ReadFile(w.paths.description)
			if err != nil {
				t.Fatal(err)
			}
			env, _, err := systemdEnvironmentFile(string(written))
			if err != nil {
				t.Fatal(err)
			}
			wantTrust := map[bool]string{true: "true", false: "false"}[tc.want]
			if got := env["GOIABADA_AUTHSERVER_TRUST_PROXY_HEADERS"]; got != wantTrust {
				t.Errorf("the file trusts forwarded headers: %q, want %q", got, wantTrust)
			}
		})
	}
}

// --local-proxy is ignored by every type that does not run native binaries, as --namespace and
// --db-host are: the file is the one the type writes without it (#396 decision 19).
func TestWizard_LocalProxyIsIgnoredOutsideNative(t *testing.T) {
	for _, flags := range []CLIFlags{
		{DeploymentType: "production", DBType: "postgres", AuthServerURL: "https://auth.example.org"},
		{DeploymentType: "kubernetes", DBType: "postgres", AuthServerURL: "https://auth.example.org", DBHost: "pg.internal", SkipDBTest: true},
		{DeploymentType: "local", DBType: "sqlite"},
	} {
		t.Run(flags.DeploymentType, func(t *testing.T) {
			flags.LocalProxy = optionalBool{set: true, value: false}
			w, _, out, _ := testWizard(t, &flags, nil)
			if err := w.setup(); err != nil {
				t.Fatalf("setup: %v\n%s", err, out)
			}
			if w.config.LocalProxy {
				t.Errorf("LocalProxy is set for %s", flags.DeploymentType)
			}
			if strings.Contains(out.String(), "reverse proxy on this machine") {
				t.Errorf("%s reports the native answer:\n%s", flags.DeploymentType, out)
			}
		})
	}
}

// trafficPolicyPrompt and networkPolicyPrompt are the two Kubernetes questions, the first Cluster
// by default and the second no (#396 decisions 4 and 5).
const (
	trafficPolicyPrompt = "Select traffic policy [1-2] [1]: "
	networkPolicyPrompt = "Restrict who can reach Goiabada with NetworkPolicies? [y/N]: "
)

// kubernetesFlags is a non-interactive Kubernetes run, its answers to the two questions left out.
func kubernetesFlags() *CLIFlags {
	return &CLIFlags{DeploymentType: "kubernetes", DBType: "postgres", AuthServerURL: "https://auth.example.org",
		DBHost: "pg.internal", SkipDBTest: true}
}

// withKubernetesAnswer is the interactive Kubernetes script with prompt answered by answer. The
// Local traffic policy, answer 2, turns the rate limiter question's default on.
func withKubernetesAnswer(t *testing.T, prompt, answer string) []scriptedStep {
	t.Helper()
	steps := withAnswers(t, deploymentKubernetes, map[string]string{prompt: answer})
	if prompt == trafficPolicyPrompt && answer == "2" {
		for i := range steps {
			if steps[i].prompt == rateLimiterOffPrompt {
				steps[i].prompt = rateLimiterOnPrompt
			}
		}
	}
	return steps
}

// Kubernetes asks which traffic policy the gateway uses, Cluster by default, and
// --gateway-traffic-policy answers without a prompt, Cluster when left out. The question says what
// each costs and that the EnvoyProxy is cluster-wide; the answer is the EnvoyProxy the completion
// message prints and what the manifest says the servers see (#396 decisions 4 and 19).
func TestWizard_KubernetesAsksTheGatewayTrafficPolicy(t *testing.T) {
	cases := map[string]struct {
		flags *CLIFlags
		steps []scriptedStep
		want  trafficPolicy
	}{
		"prompted, the default": {&CLIFlags{}, withKubernetesAnswer(t, trafficPolicyPrompt, ""), trafficPolicyCluster},
		"prompted, 1":           {&CLIFlags{}, withKubernetesAnswer(t, trafficPolicyPrompt, "1"), trafficPolicyCluster},
		"prompted, 2":           {&CLIFlags{}, withKubernetesAnswer(t, trafficPolicyPrompt, "2"), trafficPolicyLocal},
		"by flag, left out":     {kubernetesFlags(), nil, trafficPolicyCluster},
		"by flag, cluster": {func() *CLIFlags {
			f := kubernetesFlags()
			f.GatewayTrafficPolicy = trafficPolicyCluster
			return f
		}(), nil, trafficPolicyCluster},
		"by flag, local": {func() *CLIFlags {
			f := kubernetesFlags()
			f.GatewayTrafficPolicy = trafficPolicyLocal
			return f
		}(), nil, trafficPolicyLocal},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			w, in, out, _ := testWizard(t, tc.flags, tc.steps)
			if err := w.setup(); err != nil {
				t.Fatalf("setup: %v\n%s", err, out)
			}
			in.assertConsumed()
			if w.config.GatewayTrafficPolicy != tc.want {
				t.Errorf("GatewayTrafficPolicy is %q, want %q", w.config.GatewayTrafficPolicy, tc.want)
			}
			if !strings.Contains(out.String(), "externalTrafficPolicy: "+string(tc.want)) {
				t.Errorf("the completion message's EnvoyProxy does not set externalTrafficPolicy: %s:\n%s", tc.want, out)
			}
			written, err := os.ReadFile(w.paths.description)
			if err != nil {
				t.Fatal(err)
			}
			seen := map[trafficPolicy]string{trafficPolicyCluster: "a node's address", trafficPolicyLocal: "the client's address"}[tc.want]
			if !strings.Contains(strings.Join(strings.Fields(string(written)), " "), seen) {
				t.Errorf("the manifest does not say the servers see %s", seen)
			}
			if tc.steps != nil {
				for _, said := range []string{"Cluster", "node's address", "Local", "DaemonSet", "client's address", "cluster-wide"} {
					if !strings.Contains(out.String(), said) {
						t.Errorf("the question does not say %q:\n%s", said, out)
					}
				}
			}
		})
	}
}

// Kubernetes asks whether to restrict who can reach Goiabada, no by default, and --network-policy
// answers without a prompt, no when left out. The question says what stays open on no; the answer
// is whether the manifest carries the NetworkPolicies (#396 decisions 5 and 19).
func TestWizard_KubernetesAsksWhetherToRestrictWhoReachesIt(t *testing.T) {
	cases := map[string]struct {
		flags *CLIFlags
		steps []scriptedStep
		want  bool
	}{
		"prompted, the default": {&CLIFlags{}, withKubernetesAnswer(t, networkPolicyPrompt, ""), false},
		"prompted, yes":         {&CLIFlags{}, withKubernetesAnswer(t, networkPolicyPrompt, "y"), true},
		"prompted, no":          {&CLIFlags{}, withKubernetesAnswer(t, networkPolicyPrompt, "n"), false},
		"by flag, left out":     {kubernetesFlags(), nil, false},
		"by flag, --network-policy": {func() *CLIFlags {
			f := kubernetesFlags()
			f.NetworkPolicy = true
			return f
		}(), nil, true},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			w, in, out, _ := testWizard(t, tc.flags, tc.steps)
			if err := w.setup(); err != nil {
				t.Fatalf("setup: %v\n%s", err, out)
			}
			in.assertConsumed()
			if w.config.NetworkPolicy != tc.want {
				t.Errorf("NetworkPolicy is %v, want %v", w.config.NetworkPolicy, tc.want)
			}
			written, err := os.ReadFile(w.paths.description)
			if err != nil {
				t.Fatal(err)
			}
			policies := 0
			for _, doc := range yamlDocuments(t, string(written)) {
				if doc["kind"] == "NetworkPolicy" {
					policies++
				}
			}
			if want := map[bool]int{true: 2, false: 0}[tc.want]; policies != want {
				t.Errorf("the manifest carries %d NetworkPolicies, want %d", policies, want)
			}
			if tc.steps != nil && !strings.Contains(strings.Join(strings.Fields(out.String()), " "), "any pod in the cluster can reach both servers") {
				t.Errorf("the question does not say what stays open on no:\n%s", out)
			}
		})
	}
}

// --gateway-traffic-policy and --network-policy are ignored by every type that does not deploy to
// Kubernetes, as --namespace and --db-host are (#396 decision 19).
func TestWizard_KubernetesFlagsAreIgnoredElsewhere(t *testing.T) {
	for _, flags := range []CLIFlags{
		{DeploymentType: "production", DBType: "postgres", AuthServerURL: "https://auth.example.org"},
		{DeploymentType: "native", DBType: "postgres", AuthServerURL: "https://auth.example.org", DBHost: "pg.internal", SkipDBTest: true},
		{DeploymentType: "local", DBType: "sqlite"},
	} {
		t.Run(flags.DeploymentType, func(t *testing.T) {
			flags.GatewayTrafficPolicy, flags.NetworkPolicy = trafficPolicyLocal, true
			w, _, out, _ := testWizard(t, &flags, nil)
			if err := w.setup(); err != nil {
				t.Fatalf("setup: %v\n%s", err, out)
			}
			if w.config.GatewayTrafficPolicy != "" || w.config.NetworkPolicy {
				t.Errorf("%s holds traffic policy %q and NetworkPolicy %v", flags.DeploymentType, w.config.GatewayTrafficPolicy, w.config.NetworkPolicy)
			}
			for _, said := range []string{"traffic policy", "NetworkPolic"} {
				if strings.Contains(out.String(), said) {
					t.Errorf("%s reports %q:\n%s", flags.DeploymentType, said, out)
				}
			}
		})
	}
}

// rateLimiterOnPrompt and rateLimiterOffPrompt are the rate limiter question with each default: on
// for production Compose, native binaries and Kubernetes under Local, off for Kubernetes under
// Cluster (#396 decision 9).
const (
	rateLimiterOnPrompt  = "Turn on the rate limiter? [Y/n]: "
	rateLimiterOffPrompt = "Turn on the rate limiter? [y/N]: "
)

// withAnswers is the interactive script of a deployment on PostgreSQL with each prompt named
// answered as given.
func withAnswers(t *testing.T, kind deploymentType, answers map[string]string) []scriptedStep {
	t.Helper()
	steps := interactiveScript(deployments[kind], testEngine("postgres"))
	for prompt, answer := range answers {
		found := false
		for i := range steps {
			if steps[i].prompt == prompt {
				steps[i].answer, found = answer, true
			}
		}
		if !found {
			t.Fatalf("the %s script never asks %q", deployments[kind].name, prompt)
		}
	}
	return steps
}

// Production Compose, native binaries and Kubernetes ask whether to turn the rate limiter on: yes
// by default, but for Kubernetes under the Cluster traffic policy, where the per-IP limits would
// count everyone arriving through one node together. --rate-limiter answers without a prompt, the
// deployment's default when left out, and an explicit value wins. The answer is the switch the
// generated configuration hands the auth server (#396 decisions 9 and 19).
func TestWizard_AsksWhetherToTurnTheRateLimiterOn(t *testing.T) {
	nonInteractive := func(kind deploymentType, policy trafficPolicy, rateLimiter optionalBool) *CLIFlags {
		flags := &CLIFlags{DeploymentType: deployments[kind].name, DBType: "postgres", AuthServerURL: "https://auth.example.org",
			DBHost: "pg.internal", SkipDBTest: true, GatewayTrafficPolicy: policy, RateLimiter: rateLimiter}
		return flags
	}
	cases := map[string]struct {
		flags *CLIFlags
		steps []scriptedStep
		want  bool
	}{
		"production, prompted, the default":                      {&CLIFlags{}, withAnswers(t, deploymentProduction, nil), true},
		"production, prompted, no":                               {&CLIFlags{}, withAnswers(t, deploymentProduction, map[string]string{rateLimiterOnPrompt: "n"}), false},
		"native, prompted, the default":                          {&CLIFlags{}, withAnswers(t, deploymentNative, nil), true},
		"native, prompted, no":                                   {&CLIFlags{}, withAnswers(t, deploymentNative, map[string]string{rateLimiterOnPrompt: "n"}), false},
		"kubernetes under Cluster, prompted, the default":        {&CLIFlags{}, withAnswers(t, deploymentKubernetes, nil), false},
		"kubernetes under Cluster, prompted, yes":                {&CLIFlags{}, withAnswers(t, deploymentKubernetes, map[string]string{rateLimiterOffPrompt: "y"}), true},
		"kubernetes under Local, prompted, the default":          {&CLIFlags{}, withKubernetesAnswer(t, trafficPolicyPrompt, "2"), true},
		"production, by flag, left out":                          {nonInteractive(deploymentProduction, "", optionalBool{}), nil, true},
		"production, by flag, --rate-limiter=false":              {nonInteractive(deploymentProduction, "", optionalBool{set: true, value: false}), nil, false},
		"native, by flag, left out":                              {nonInteractive(deploymentNative, "", optionalBool{}), nil, true},
		"native, by flag, --rate-limiter=false":                  {nonInteractive(deploymentNative, "", optionalBool{set: true, value: false}), nil, false},
		"kubernetes, by flag, left out":                          {nonInteractive(deploymentKubernetes, "", optionalBool{}), nil, false},
		"kubernetes under cluster, by flag, left out":            {nonInteractive(deploymentKubernetes, trafficPolicyCluster, optionalBool{}), nil, false},
		"kubernetes under cluster, by flag, --rate-limiter=true": {nonInteractive(deploymentKubernetes, trafficPolicyCluster, optionalBool{set: true, value: true}), nil, true},
		"kubernetes under local, by flag, left out":              {nonInteractive(deploymentKubernetes, trafficPolicyLocal, optionalBool{}), nil, true},
		"kubernetes under local, by flag, --rate-limiter=false":  {nonInteractive(deploymentKubernetes, trafficPolicyLocal, optionalBool{set: true, value: false}), nil, false},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			w, in, out, _ := testWizard(t, tc.flags, tc.steps)
			if err := w.setup(); err != nil {
				t.Fatalf("setup: %v\n%s", err, out)
			}
			in.assertConsumed()
			if w.config.RateLimiter != tc.want {
				t.Errorf("RateLimiter is %v, want %v", w.config.RateLimiter, tc.want)
			}
			written, err := os.ReadFile(w.paths.description)
			if err != nil {
				t.Fatal(err)
			}
			want := map[bool]string{true: "true", false: "false"}[tc.want]
			if got := serverEnvironments(t, w.config, string(written))["AUTHSERVER"][rateLimiterVariable]; got != want {
				t.Errorf("the file sets %s to %q, want %q", rateLimiterVariable, got, want)
			}
		})
	}
}

// Under the Cluster traffic policy the question says why it is off by default: the per-IP limits,
// with two of their budgets, would count every user arriving through one node together, while the
// limits on failed credentials hold under either policy (#396 decision 9).
func TestWizard_TheRateLimiterQuestionSaysWhyItIsOffUnderCluster(t *testing.T) {
	w, in, out, _ := testWizard(t, &CLIFlags{}, withAnswers(t, deploymentKubernetes, nil))
	if err := w.setup(); err != nil {
		t.Fatalf("setup: %v\n%s", err, out)
	}
	in.assertConsumed()
	said := strings.Join(strings.Fields(out.String()), " ")
	for _, want := range []string{
		"through one node together",
		"30 password posts a minute",
		"20 forgot-password requests per 5 minutes",
		"hold under either traffic policy",
		rateLimitsDocs,
	} {
		if !strings.Contains(said, want) {
			t.Errorf("the question does not say %q:\n%s", want, out)
		}
	}
}

// --rate-limiter is ignored by local testing, which never asks and leaves the limiter off, as
// --namespace is by every type but Kubernetes (#396 decisions 9 and 19).
func TestWizard_RateLimiterFlagIsIgnoredByLocalTesting(t *testing.T) {
	flags := &CLIFlags{DeploymentType: "local", DBType: "sqlite", RateLimiter: optionalBool{set: true, value: true}}
	w, _, out, _ := testWizard(t, flags, nil)
	if err := w.setup(); err != nil {
		t.Fatalf("setup: %v\n%s", err, out)
	}
	if w.config.RateLimiter {
		t.Error("local testing turned the rate limiter on")
	}
	if strings.Contains(strings.ToLower(out.String()), "rate limiter") {
		t.Errorf("local testing reports the rate limiter:\n%s", out)
	}
	written, err := os.ReadFile(w.paths.description)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(written), rateLimiterVariable) {
		t.Errorf("local testing's file names %s", rateLimiterVariable)
	}
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
