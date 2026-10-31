package main

// The auth server refuses to start with an admin console URL that is plain http on a host other
// than loopback, since the console's redirect URIs, registered from it, would receive nothing at
// sign-in, so the wizard writes none: asked interactively, it explains and asks again, and through
// --admin-url it fails before writing anything. An auth server URL is never refused, and asks
// "Continue with HTTP?" or warns only off loopback, by core/loopback's test, so
// http://localhost.example.org is not taken for localhost (#590).

import (
	"slices"
	"strings"
	"testing"
)

// adminURLRefusal is the explanation the wizard gives for a plain-http admin console URL off
// loopback, written out here rather than built the way the wizard builds it.
const adminURLRefusal = "it is plain http on a host other than 127.0.0.1, [::1] or localhost, where the admin " +
	"console cannot sign in, and the auth server refuses to start with it; give an https URL"

// httpWarning is the line that warns of a plain-http URL given by flag.
const httpWarning = "Using HTTP for production is not recommended. Consider using HTTPS."

func TestWizard_AdminURLFlagPlainHTTPOffLoopbackIsRefusedBeforeAnythingIsWritten(t *testing.T) {
	for _, tc := range []struct {
		deployment, admin string
	}{
		{"native", "http://admin.example.org"},
		{"native", "http://admin.example.org:9091/"},
		{"production", "http://admin.example.org"},
		{"kubernetes", "http://admin.example.org"},
		{"native", "http://localhost.example.org"},
		{"native", "http://localhostx"},
		{"native", "http://127.0.0.2:9091"},
		{"native", "http://192.168.1.50:9091"},
	} {
		t.Run(tc.deployment+" "+tc.admin, func(t *testing.T) {
			flags := &CLIFlags{DeploymentType: tc.deployment, DBType: "postgres", AuthServerURL: "https://auth.example.org",
				AdminConsoleURL: tc.admin, DBHost: "pg.internal", SkipDBTest: true}
			w, _, out, _ := testWizard(t, flags, nil)
			err := w.setup()
			if err == nil {
				t.Fatalf("setup accepted %s\n%s", tc.admin, out)
			}
			if want := "invalid admin URL: " + adminURLRefusal; err.Error() != want {
				t.Errorf("setup: %q\nwant %q", err, want)
			}
			assertNothingWritten(t, flags.Output)
		})
	}
}

// The admin console URL that passes is https, or http on loopback, which the auth server accepts,
// and a loopback one is not warned of: it is what the auth server's own default is.
func TestWizard_AdminURLFlagLoopbackAndHTTPSAreAccepted(t *testing.T) {
	for _, admin := range []string{"http://localhost:9091", "http://127.0.0.1:9091", "http://LOCALHOST:9091", "https://admin.example.org"} {
		t.Run(admin, func(t *testing.T) {
			flags := &CLIFlags{DeploymentType: "native", DBType: "sqlite", AuthServerURL: "https://auth.example.org", AdminConsoleURL: admin}
			w, _, out, _ := testWizard(t, flags, nil)
			if err := w.setup(); err != nil {
				t.Fatalf("setup: %v\n%s", err, out)
			}
			if w.config.AdminConsoleURL != admin {
				t.Errorf("the admin console URL is %q, want %q", w.config.AdminConsoleURL, admin)
			}
			if strings.Contains(out.String(), httpWarning) {
				t.Errorf("warned of HTTP:\n%s", out)
			}
		})
	}
}

// An auth server URL given by flag is never refused for plain http; off loopback it is warned of,
// and on loopback it is not.
func TestWizard_AuthURLFlagWarnsOfPlainHTTPOnlyOffLoopback(t *testing.T) {
	for _, tc := range []struct {
		auth string
		warn bool
	}{
		{"http://auth.example.org", true},
		{"http://localhost.example.org", true},
		{"http://localhost:9090", false},
		{"http://127.0.0.1:9090", false},
		{"http://LOCALHOST:9090", false},
		{"https://auth.example.org", false},
	} {
		t.Run(tc.auth, func(t *testing.T) {
			flags := &CLIFlags{DeploymentType: "native", DBType: "sqlite", AuthServerURL: tc.auth,
				AdminConsoleURL: "https://admin.example.org", AdminEmail: "ops@example.org"}
			w, _, out, _ := testWizard(t, flags, nil)
			if err := w.setup(); err != nil {
				t.Fatalf("setup: %v\n%s", err, out)
			}
			if w.config.AuthServerURL != tc.auth {
				t.Errorf("the auth server URL is %q, want %q", w.config.AuthServerURL, tc.auth)
			}
			if warned := strings.Contains(out.String(), httpWarning); warned != tc.warn {
				t.Errorf("warned of HTTP: %v, want %v\n%s", warned, tc.warn, out)
			}
		})
	}
}

// Asked interactively, a plain-http admin console URL off loopback is explained and asked for
// again, with no "Continue with HTTP?" that could keep it, and the answer given after it is the
// one written.
func TestWizard_InteractiveAdminURLPlainHTTPOffLoopbackIsAskedAgain(t *testing.T) {
	const adminPrompt = "Admin console URL (e.g., https://admin.example.com) [https://admin.example.org]: "
	for name, tc := range map[string]struct {
		refused []string
		then    string
	}{
		"a public host, then https":          {[]string{"http://admin.example.org"}, "https://admin.example.org"},
		"a localhost prefix, then the offer": {[]string{"http://localhost.example.org"}, ""},
		"two refused, then loopback":         {[]string{"http://admin.example.org", "http://10.0.0.5:9091"}, "http://127.0.0.1:9091"},
	} {
		t.Run(name, func(t *testing.T) {
			urlSteps := []scriptedStep{{prompt: "Auth server URL (e.g., https://auth.example.com) [https://auth.example.com]: ", answer: "https://auth.example.org"}}
			for _, refused := range tc.refused {
				urlSteps = append(urlSteps, scriptedStep{prompt: adminPrompt, answer: refused})
			}
			urlSteps = append(urlSteps, scriptedStep{prompt: adminPrompt, answer: tc.then})
			if strings.HasPrefix(tc.then, "http://127.0.0.1") {
				urlSteps = append(urlSteps, scriptedStep{prompt: "Continue with different domains? [y/N]: ", answer: "y"})
			}
			steps := replaceURLSteps(t, interactiveScript(deployments[deploymentProduction], testEngine("sqlite")), urlSteps...)
			w, in, out, _ := testWizard(t, &CLIFlags{}, steps)
			if err := w.setup(); err != nil {
				t.Fatalf("setup: %v\n%s", err, out)
			}
			in.assertConsumed()
			want := tc.then
			if want == "" {
				want = "https://admin.example.org"
			}
			if w.config.AdminConsoleURL != want {
				t.Errorf("the admin console URL is %q, want %q", w.config.AdminConsoleURL, want)
			}
			line := "Invalid URL: " + adminURLRefusal + ". Please try again."
			if got := strings.Count(out.String(), line); got != len(tc.refused) {
				t.Errorf("the refusal was given %d times, want %d:\n%s", got, len(tc.refused), out)
			}
		})
	}
}

// Asked interactively, an auth server URL in plain http off loopback asks "Continue with HTTP?",
// a host that only starts with localhost among them, and one on loopback asks nothing.
func TestWizard_InteractiveAuthURLAsksToContinueWithHTTPOnlyOffLoopback(t *testing.T) {
	const authPrompt = "Auth server URL (e.g., https://auth.example.com) [https://auth.example.com]: "
	const continuePrompt = "Continue with HTTP? [y/N]: "
	for name, tc := range map[string]struct {
		steps     []scriptedStep
		wantAuth  string
		wantAdmin string
		email     bool // the auth host has no parent, so the admin email has no default
	}{
		"a localhost prefix asks": {[]scriptedStep{
			{prompt: authPrompt, answer: "http://localhost.example.org"},
			{prompt: continuePrompt, answer: "y"},
			{prompt: "Admin console URL (e.g., https://admin.example.com) [https://admin.example.org]: ", answer: ""},
		}, "http://localhost.example.org", "https://admin.example.org", false},
		"a public host asks, and declining asks again": {[]scriptedStep{
			{prompt: authPrompt, answer: "http://auth.example.org"},
			{prompt: continuePrompt, answer: ""},
			{prompt: authPrompt, answer: "https://auth.example.org"},
			{prompt: "Admin console URL (e.g., https://admin.example.com) [https://admin.example.org]: ", answer: ""},
		}, "https://auth.example.org", "https://admin.example.org", false},
		"127.0.0.1 asks nothing": {[]scriptedStep{
			{prompt: authPrompt, answer: "http://127.0.0.1:9090"},
			{prompt: "Admin console URL (e.g., https://admin.example.com): ", answer: "http://127.0.0.1:9091"},
		}, "http://127.0.0.1:9090", "http://127.0.0.1:9091", true},
		"localhost asks nothing": {[]scriptedStep{
			{prompt: authPrompt, answer: "http://localhost:9090"},
			{prompt: "Admin console URL (e.g., https://admin.example.com): ", answer: "http://localhost:9091"},
		}, "http://localhost:9090", "http://localhost:9091", true},
	} {
		t.Run(name, func(t *testing.T) {
			steps := replaceURLSteps(t, interactiveScript(deployments[deploymentProduction], testEngine("sqlite")), tc.steps...)
			if tc.email {
				at := slices.IndexFunc(steps, func(s scriptedStep) bool { return strings.HasPrefix(s.prompt, "Admin email") })
				steps[at] = scriptedStep{prompt: "Admin email: ", answer: "ops@example.org"}
			}
			w, in, out, _ := testWizard(t, &CLIFlags{}, steps)
			if err := w.setup(); err != nil {
				t.Fatalf("setup: %v\n%s", err, out)
			}
			in.assertConsumed()
			if c := w.config; c.AuthServerURL != tc.wantAuth || c.AdminConsoleURL != tc.wantAdmin {
				t.Errorf("URLs %q, %q; want %q, %q", c.AuthServerURL, c.AdminConsoleURL, tc.wantAuth, tc.wantAdmin)
			}
		})
	}
}
