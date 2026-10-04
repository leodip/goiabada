package main

import (
	"path/filepath"
	"strings"
	"testing"
)

// terminalSecrets is every secret a run put in its Config, by what it is: the wizard prints none of
// them, since each is in a file written 0600 and a terminal's output reaches scrollback, recordings
// and the log of every CI job that runs it (#396 decision 17).
func terminalSecrets(c *Config) map[string]string {
	secrets := map[string]string{
		"admin password":               c.AdminPassword,
		"auth server session auth key": c.AuthSessionAuthKey,
		"auth server session enc key":  c.AuthSessionEncKey,
		"admin console session auth":   c.AdminSessionAuthKey,
		"admin console session enc":    c.AdminSessionEncKey,
		"AES key":                      c.AESEncryptionKey,
		"OAuth client secret":          c.OAuthClientSecret,
	}
	if c.DBPassword != "" {
		secrets["database password"] = c.DBPassword
	}
	return secrets
}

// nonInteractiveFlags configures a deployment type on an engine from flags alone, with the admin
// and database passwords given when given is set and generated otherwise.
func nonInteractiveFlags(kind deploymentType, e *engine, given bool) *CLIFlags {
	flags := &CLIFlags{DeploymentType: deployments[kind].name, DBType: e.name, SkipDBTest: true}
	if deployments[kind].asksURLs {
		flags.AuthServerURL = "https://auth.example.org"
	}
	if e.hasServer && deployments[kind].externalDatabase {
		flags.DBHost = "db.internal"
	}
	if given {
		flags.AdminPassword = "Zq7AdminGiven-Passw0rd"
		flags.DBPassword = "Zq7DatabaseGiven-Passw0rd"
	}
	return flags
}

// engineCases are the engines each deployment type is run on here: SQLite where it accepts it, and
// a server engine.
func engineCases(kind deploymentType) []*engine {
	var cases []*engine
	if deployments[kind].accepts(testEngine("sqlite")) {
		cases = append(cases, testEngine("sqlite"))
	}
	return append(cases, testEngine("postgres"))
}

// assertNoSecretShown fails the test for each secret of the run's Config found in what the
// operator was shown: the console and every prompt.
func assertNoSecretShown(t *testing.T, w *wizard, shown string) {
	t.Helper()
	for what, secret := range terminalSecrets(w.config) {
		if secret == "" {
			t.Errorf("the run left the %s empty, so its absence proves nothing", what)
			continue
		}
		if strings.Contains(shown, secret) {
			t.Errorf("the %s reached the terminal:\n%s", what, shown)
		}
	}
}

// No secret reaches the terminal, generated or given, by flag or at a prompt, in any deployment
// type: the four places that printed one, the non-interactive admin step, the Kubernetes and native
// database step, the Compose database step even for a password passed with --db-password, and the
// completion message's login line, say where it is instead (#396 decision 17).
func TestWizard_NoSecretReachesTheTerminal(t *testing.T) {
	for _, kind := range []deploymentType{deploymentLocal, deploymentProduction, deploymentKubernetes, deploymentNative} {
		for _, e := range engineCases(kind) {
			for _, given := range []bool{false, true} {
				name := deployments[kind].name + "-" + e.name + "-generated"
				if given {
					name = deployments[kind].name + "-" + e.name + "-given"
				}
				t.Run("flags "+name, func(t *testing.T) {
					w, _, out, _ := testWizard(t, nonInteractiveFlags(kind, e, given), nil)
					if err := w.setup(); err != nil {
						t.Fatalf("setup: %v\n%s", err, out)
					}
					assertNoSecretShown(t, w, out.String())
				})
			}
			for _, typed := range []bool{false, true} {
				name := deployments[kind].name + "-" + e.name + "-generated database password"
				if typed {
					name = deployments[kind].name + "-" + e.name + "-typed database password"
				}
				t.Run("prompts "+name, func(t *testing.T) {
					steps := interactiveScript(deployments[kind], e)
					if !typed {
						for i := range steps {
							if strings.HasPrefix(steps[i].prompt, "Database password [generated]") {
								steps[i].answer = ""
							}
						}
					}
					w, in, out, _ := testWizard(t, &CLIFlags{}, steps)
					if err := w.setup(); err != nil {
						t.Fatalf("setup: %v\n%s", err, out)
					}
					in.assertConsumed()
					assertNoSecretShown(t, w, strings.Join(in.prompts, "\n")+"\n"+out.String())
				})
			}
		}
	}
}

// Each password step says whether the password was generated or set, and where it is stored: the
// one file holding the secrets, or for Kubernetes the Secret in it (#396 decision 17).
func TestWizard_SaysWhereEachPasswordIsStored(t *testing.T) {
	for _, kind := range []deploymentType{deploymentLocal, deploymentProduction, deploymentKubernetes, deploymentNative} {
		for _, given := range []bool{false, true} {
			how := "generated"
			if given {
				how = "set"
			}
			t.Run(deployments[kind].name+" "+how, func(t *testing.T) {
				w, _, out, _ := testWizard(t, nonInteractiveFlags(kind, testEngine("postgres"), given), nil)
				if err := w.setup(); err != nil {
					t.Fatalf("setup: %v\n%s", err, out)
				}
				stored := w.paths.secrets
				if kind == deploymentKubernetes {
					stored = "the goiabada-secrets Secret in " + w.paths.secrets
				}
				for _, want := range []string{
					"Admin password: " + how + ", stored in " + stored + "\n",
					"Database password: " + how + ", stored in " + stored + "\n",
				} {
					if !strings.Contains(out.String(), want) {
						t.Errorf("output lacks %q:\n%s", want, out)
					}
				}
			})
		}
	}
}

// The summary says whether each password was set or generated, where it showed the admin
// password's first and last two characters (#396 decision 17).
func TestWizard_TheSummaryShowsWhetherEachPasswordWasSetOrGenerated(t *testing.T) {
	for _, tc := range []struct {
		name               string
		typedDatabase      bool
		wantAdmin, wantDB  string
		deployment, engine string
	}{
		{"generated database password", false, "(set)", "(generated)", "production", "postgres"},
		{"typed database password", true, "(set)", "(set)", "production", "postgres"},
		{"external database, generated", false, "(set)", "(generated)", "kubernetes", "postgres"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d, _ := resolveDeployment(tc.deployment)
			steps := interactiveScript(d, testEngine(tc.engine))
			if !tc.typedDatabase {
				for i := range steps {
					if strings.HasPrefix(steps[i].prompt, "Database password [generated]") {
						steps[i].answer = ""
					}
				}
			}
			w, in, out, _ := testWizard(t, &CLIFlags{}, steps)
			if err := w.setup(); err != nil {
				t.Fatalf("setup: %v\n%s", err, out)
			}
			in.assertConsumed()
			for _, want := range []string{
				"  Admin Password:   " + tc.wantAdmin + "\n",
				"  DB Password:      " + tc.wantDB + "\n",
			} {
				if !strings.Contains(out.String(), want) {
					t.Errorf("the summary lacks %q:\n%s", want, out)
				}
			}
		})
	}

	t.Run("SQLite has no database password", func(t *testing.T) {
		w, in, out, _ := testWizard(t, &CLIFlags{}, interactiveScript(deployments[deploymentLocal], testEngine("sqlite")))
		if err := w.setup(); err != nil {
			t.Fatalf("setup: %v\n%s", err, out)
		}
		in.assertConsumed()
		if strings.Contains(out.String(), "DB Password:") {
			t.Errorf("the summary reports a database password SQLite does not have:\n%s", out)
		}
	})
}

// The completion message says where the admin password is: the variable in the secrets file, or for
// Kubernetes the command that reads it back out of the cluster, in the namespace configured.
func TestWizard_TheCompletionMessageSaysWhereTheAdminPasswordIs(t *testing.T) {
	for _, kind := range []deploymentType{deploymentLocal, deploymentProduction, deploymentKubernetes, deploymentNative} {
		t.Run(deployments[kind].name, func(t *testing.T) {
			flags := nonInteractiveFlags(kind, testEngine("postgres"), false)
			flags.Namespace = "identity"
			w, _, out, _ := testWizard(t, flags, nil)
			if err := w.setup(); err != nil {
				t.Fatalf("setup: %v\n%s", err, out)
			}
			completion := out.String()[strings.Index(out.String(), "SETUP COMPLETE!"):]
			want := "Sign in as " + w.config.AdminEmail + " with the admin password, GOIABADA_ADMIN_PASSWORD in " + filepath.Base(w.paths.secrets) + ".\n"
			if kind == deploymentKubernetes {
				want = "Sign in as " + w.config.AdminEmail + " with the admin password, which this reads back out of the cluster:\n" +
					"    kubectl get secret goiabada-secrets -n identity -o jsonpath='{.data.admin-password}' | base64 -d\n"
			}
			if !strings.Contains(completion, want) {
				t.Errorf("the completion message lacks %q:\n%s", want, completion)
			}
			if strings.Contains(completion, "Login with") {
				t.Errorf("the completion message still prints the login line:\n%s", completion)
			}
		})
	}
}
