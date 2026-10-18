package main

import (
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// The prompts of the database connection's TLS, asked by Kubernetes and native binaries after the
// database password: the mode, prefer by default, and for verify-ca and verify-full the CA file,
// blank for the system's roots (#502 decision 7).
const (
	tlsModePrompt    = "Select TLS mode [1-5] [2]: "
	caFilePrompt     = "CA file the database's certificate chains to (PEM), blank for the system's roots: "
	clientCertPrompt = "Client certificate the auth server presents to the database (PEM), blank for none: "
	clientKeyPrompt  = "Client certificate's private key (PEM), blank to name the certificate again: "
	serverNamePrompt = "Host name verify-full checks the certificate against when the address dialed is not the name certified, blank for the host dialed: "
)

// testCAFile is a CA certificate, the PEM of a self-signed test authority.
const testCAFile = "testdata/db-ca.pem"

// uncheckedWarning is what the wizard says when the mode it writes checks no certificate.
const uncheckedWarning = "which checks no certificate"

func readTestCA(t *testing.T) string {
	t.Helper()
	content, err := os.ReadFile(testCAFile)
	if err != nil {
		t.Fatal(err)
	}
	return string(content)
}

// writeFile writes content into a file of its own in a fresh directory and returns its path.
func writeFile(t *testing.T, name, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// withTLSAnswers is the interactive script of a deployment on PostgreSQL with the TLS mode
// answered as given, followed by the CA file's answers, each one read in turn.
func withTLSAnswers(t *testing.T, kind deploymentType, mode string, caAnswers ...string) []scriptedStep {
	t.Helper()
	return withTLSAnswersOn(t, kind, "postgres", mode, caAnswers...)
}

// withTLSAnswersOn is withTLSAnswers on the engine named, which is offered the client certificate
// pair only when its driver reads one (#546).
func withTLSAnswersOn(t *testing.T, kind deploymentType, engineName, mode string, caAnswers ...string) []scriptedStep {
	t.Helper()
	e := testEngine(engineName)
	steps := interactiveScript(deployments[kind], e)
	for i := range steps {
		if steps[i].prompt == tlsModePrompt {
			steps[i].answer = mode
			var ca []scriptedStep
			for _, answer := range caAnswers {
				ca = append(ca, scriptedStep{prompt: caFilePrompt, answer: answer})
			}
			// The pair is offered to the three modes that carry one, answered blank for none, and
			// the host name override to verify-full alone (#546).
			switch mode {
			case "3", "4", "5":
				if e.takesClientCertificate {
					ca = append(ca, scriptedStep{prompt: clientCertPrompt, answer: ""})
				}
			}
			if mode == "5" {
				ca = append(ca, scriptedStep{prompt: serverNamePrompt, answer: ""})
			}
			return slices.Concat(steps[:i+1], ca, steps[i+1:])
		}
	}
	t.Fatalf("the %s script never asks the TLS mode", deployments[kind].name)
	return nil
}

// The two Compose types run the database as a service on the file's own network and ask nothing:
// they write prefer, what the auth server does unset, and say so in a warning worded for that
// network. The TLS flags are read only by the types that ask, as --db-host is, and SQLite has no
// connection to protect (#502 decision 7).
func TestWizard_ComposeWritesPreferAndWarns(t *testing.T) {
	for _, tc := range []struct {
		flags CLIFlags
		tls   bool
	}{
		{CLIFlags{DeploymentType: "local", DBType: "mysql"}, true},
		{CLIFlags{DeploymentType: "production", DBType: "mssql", AuthServerURL: "https://auth.example.org"}, true},
		{CLIFlags{DeploymentType: "production", DBType: "sqlite", AuthServerURL: "https://auth.example.org"}, false},
	} {
		t.Run(tc.flags.DeploymentType+"-"+tc.flags.DBType, func(t *testing.T) {
			flags := tc.flags
			flags.DBTLSMode, flags.DBTLSCAFile = "verify-full", testCAFile
			w, _, out, _ := testWizard(t, &flags, nil)
			if err := w.setup(); err != nil {
				t.Fatalf("setup: %v\n%s", err, out)
			}
			written, err := os.ReadFile(w.paths.description)
			if err != nil {
				t.Fatal(err)
			}
			wrote := strings.Contains(string(written), "\n      - \"GOIABADA_DB_TLS_MODE=prefer\"\n")
			if wrote != tc.tls {
				t.Errorf("the Compose file writes GOIABADA_DB_TLS_MODE=prefer: %v, want %v", wrote, tc.tls)
			}
			if strings.Contains(string(written), "GOIABADA_DB_TLS_CA_FILE=") || strings.Contains(string(written), "GOIABADA_DB_TLS_MODE=verify-full") {
				t.Errorf("the Compose file carries what the TLS flags gave, which it does not read")
			}
			warned := strings.Contains(out.String(), uncheckedWarning)
			if warned != tc.tls {
				t.Errorf("warned that no certificate is checked: %v, want %v\n%s", warned, tc.tls, out)
			}
			if tc.tls && !strings.Contains(out.String(), "this Compose file's own network") {
				t.Errorf("the warning does not speak of the Compose file's network:\n%s", out)
			}
		})
	}
}

// Kubernetes and native binaries ask the mode from a menu of the five, prefer by default, warning
// when the mode kept checks no certificate, and for verify-ca and verify-full ask the CA file,
// blank for the system's roots. The connection check dials with what was answered (#502 decision 7).
func TestWizard_AsksTheTLSMode(t *testing.T) {
	ca := readTestCA(t)
	caPath := writeFile(t, "db-ca.pem", ca)
	cases := map[string]struct {
		kind      deploymentType
		mode      string
		ca        []string
		wantMode  string
		wantCA    string
		wantPEM   string
		wantAlarm bool
	}{
		"native, the default":        {kind: deploymentNative, mode: "", wantMode: "prefer", wantAlarm: true},
		"kubernetes, the default":    {kind: deploymentKubernetes, mode: "", wantMode: "prefer", wantAlarm: true},
		"native, disable":            {kind: deploymentNative, mode: "1", wantMode: "disable", wantAlarm: true},
		"native, require":            {kind: deploymentNative, mode: "3", wantMode: "require", wantAlarm: true},
		"native, verify-ca":          {kind: deploymentNative, mode: "4", ca: []string{caPath}, wantMode: "verify-ca", wantCA: caPath, wantPEM: ca},
		"kubernetes, verify-full":    {kind: deploymentKubernetes, mode: "5", ca: []string{caPath}, wantMode: "verify-full", wantCA: caPath, wantPEM: ca},
		"native, the system's roots": {kind: deploymentNative, mode: "5", ca: []string{""}, wantMode: "verify-full"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			w, in, out, calls := testWizard(t, &CLIFlags{}, withTLSAnswers(t, tc.kind, tc.mode, tc.ca...))
			if err := w.setup(); err != nil {
				t.Fatalf("setup: %v\n%s", err, out)
			}
			in.assertConsumed()
			c := w.config
			if c.DBTLSMode != tc.wantMode || c.DBTLSCAFile != tc.wantCA || c.DBTLSCA != tc.wantPEM {
				t.Errorf("mode %q, CA file %q and %d bytes of PEM; want %q, %q and %d bytes",
					c.DBTLSMode, c.DBTLSCAFile, len(c.DBTLSCA), tc.wantMode, tc.wantCA, len(tc.wantPEM))
			}
			if len(*calls) != 1 || (*calls)[0].tlsMode != tc.wantMode || (*calls)[0].caFile != tc.wantCA {
				t.Errorf("connection checks %+v, want one with mode %q and CA file %q", *calls, tc.wantMode, tc.wantCA)
			}
			if warned := strings.Contains(out.String(), uncheckedWarning); warned != tc.wantAlarm {
				t.Errorf("warned that no certificate is checked: %v, want %v\n%s", warned, tc.wantAlarm, out)
			}
			for _, mode := range []string{"disable", "prefer", "require", "verify-ca", "verify-full"} {
				if !strings.Contains(out.String(), ". "+mode+": ") {
					t.Errorf("the menu offers no %s:\n%s", mode, out)
				}
			}
			// verify-full's line says the certificate may name the host name asked after it (#546).
			if !strings.Contains(out.String(), ". verify-full: "+tlsModeDescription("verify-full", "postgres")+verifyFullOverrideMenuNote+"\n") {
				t.Errorf("the menu's verify-full line does not mention the host name override:\n%s", out)
			}
		})
	}
}

// A CA file the auth server would refuse is asked again, as each of the server's refusals says:
// one that cannot be read, and one holding no PEM certificate (#502 decisions 4 and 7).
func TestWizard_ACAFileTheServerRefusesIsAskedAgain(t *testing.T) {
	ca := readTestCA(t)
	good := writeFile(t, "db-ca.pem", ca)
	noCertificate := writeFile(t, "notes.txt", "not a certificate\n")
	missing := filepath.Join(t.TempDir(), "absent.pem")

	steps := withTLSAnswers(t, deploymentNative, "5", missing, noCertificate, good)
	w, in, out, _ := testWizard(t, &CLIFlags{}, steps)
	if err := w.setup(); err != nil {
		t.Fatalf("setup: %v\n%s", err, out)
	}
	in.assertConsumed()
	for _, said := range []string{"cannot be read", "holds no PEM certificate"} {
		if !strings.Contains(out.String(), said) {
			t.Errorf("no refusal says %q:\n%s", said, out)
		}
	}
	if w.config.DBTLSCAFile != good {
		t.Errorf("CA file is %q, want %q", w.config.DBTLSCAFile, good)
	}
}

// A CA file is written as the certificates in it and nothing else, so a private key that sits in
// the same file never reaches a ConfigMap; a relative path is written absolute, since the auth
// server is started from wherever its service runs (#502 decision 7).
func TestReadCAFile_KeepsTheCertificatesAlone(t *testing.T) {
	ca := readTestCA(t)
	key := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("not a real key")}))
	path := writeFile(t, "bundle.pem", key+ca+"trailing words\n")

	absolute, certificates, err := readCAFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if certificates != ca {
		t.Errorf("the certificates read are\n%s\nwant\n%s", certificates, ca)
	}
	if absolute != path {
		t.Errorf("the path is %q, want %q", absolute, path)
	}

	t.Chdir(filepath.Dir(path))
	absolute, _, err = readCAFile("bundle.pem")
	if err != nil {
		t.Fatal(err)
	}
	if !filepath.IsAbs(absolute) || filepath.Base(absolute) != "bundle.pem" {
		t.Errorf("a relative path reads as %q, want it absolute", absolute)
	}
}

// --db-tls-mode and --db-tls-ca-file answer the two questions; left out, the mode is prefer and is
// warned about. Each refusal is the auth server's: a mode outside the five, a CA file beside a mode
// that checks no certificate, one that cannot be read and one holding no PEM certificate (#502
// decisions 4 and 7).
func TestWizard_TheTLSFlagsAnswerTheQuestions(t *testing.T) {
	ca := readTestCA(t)
	caPath := writeFile(t, "db-ca.pem", ca)
	noCertificate := writeFile(t, "notes.txt", "not a certificate\n")
	flags := func(kind, mode, caFile string) *CLIFlags {
		return &CLIFlags{DeploymentType: kind, DBType: "postgres", AuthServerURL: "https://auth.example.org",
			DBHost: "pg.internal", DBTLSMode: mode, DBTLSCAFile: caFile}
	}

	t.Run("accepted", func(t *testing.T) {
		for _, tc := range []struct {
			name     string
			flags    *CLIFlags
			mode, ca string
			pem      string
			warned   bool
		}{
			{"left out", flags("native", "", ""), "prefer", "", "", true},
			{"disable", flags("native", "disable", ""), "disable", "", "", true},
			{"require", flags("kubernetes", "require", ""), "require", "", "", true},
			{"verify-ca with the system's roots", flags("native", "verify-ca", ""), "verify-ca", "", "", false},
			{"verify-full with a CA file", flags("kubernetes", "verify-full", caPath), "verify-full", caPath, ca, false},
		} {
			t.Run(tc.name, func(t *testing.T) {
				w, _, out, calls := testWizard(t, tc.flags, nil)
				if err := w.setup(); err != nil {
					t.Fatalf("setup: %v\n%s", err, out)
				}
				c := w.config
				if c.DBTLSMode != tc.mode || c.DBTLSCAFile != tc.ca || c.DBTLSCA != tc.pem {
					t.Errorf("mode %q, CA file %q; want %q, %q", c.DBTLSMode, c.DBTLSCAFile, tc.mode, tc.ca)
				}
				if len(*calls) != 1 || (*calls)[0].tlsMode != tc.mode || (*calls)[0].caFile != tc.ca {
					t.Errorf("connection checks %+v, want one with mode %q and CA file %q", *calls, tc.mode, tc.ca)
				}
				if warned := strings.Contains(out.String(), uncheckedWarning); warned != tc.warned {
					t.Errorf("warned that no certificate is checked: %v, want %v\n%s", warned, tc.warned, out)
				}
			})
		}
	})

	t.Run("refused", func(t *testing.T) {
		for _, tc := range []struct {
			name  string
			flags *CLIFlags
			says  string
		}{
			{"a mode outside the five", flags("native", "VERIFY_IDENTITY", ""), "--db-tls-mode"},
			{"a mode in another case", flags("native", "Verify-Full", ""), "--db-tls-mode"},
			{"a CA file beside prefer", flags("native", "", caPath), "checks no certificate"},
			{"a CA file beside require", flags("kubernetes", "require", caPath), "checks no certificate"},
			{"a CA file that cannot be read", flags("native", "verify-full", filepath.Join(t.TempDir(), "absent.pem")), "cannot be read"},
			{"a CA file with no certificate", flags("native", "verify-ca", noCertificate), "holds no PEM certificate"},
		} {
			t.Run(tc.name, func(t *testing.T) {
				w, _, out, _ := testWizard(t, tc.flags, nil)
				err := w.setup()
				if err == nil || !strings.Contains(err.Error(), tc.says) {
					t.Fatalf("setup: %v, want a refusal saying %q\n%s", err, tc.says, out)
				}
				assertNothingWritten(t, w.flags.Output)
			})
		}
	})
}

// A failed test asks the TLS mode and the CA file again with the rest of the details, and the
// check dials with the new answers (#502 decision 7).
func TestWizard_AFailedTestAsksTheTLSModeAgain(t *testing.T) {
	ca := readTestCA(t)
	caPath := writeFile(t, "db-ca.pem", ca)
	full := withTLSAnswers(t, deploymentNative, "")
	// full ends with the seven database reads and the confirmation.
	before, database, confirmation := full[:len(full)-8], full[len(full)-8:len(full)-1], full[len(full)-1]
	again := slices.Clone(database)
	again[5].answer = "5"
	again = slices.Insert(again, 6,
		scriptedStep{prompt: caFilePrompt, answer: caPath},
		scriptedStep{prompt: clientCertPrompt, answer: ""},
		scriptedStep{prompt: serverNamePrompt, answer: ""})
	steps := slices.Concat(before, database, []scriptedStep{{prompt: "Select option [1-3] [1]: ", answer: "1"}}, again, []scriptedStep{confirmation})

	w, in, out, calls := testWizard(t, &CLIFlags{}, steps, false, true)
	if err := w.setup(); err != nil {
		t.Fatalf("setup: %v\n%s", err, out)
	}
	in.assertConsumed()
	if len(*calls) != 2 || (*calls)[0].tlsMode != "prefer" || (*calls)[1].tlsMode != "verify-full" || (*calls)[1].caFile != caPath {
		t.Errorf("connection checks %+v, want prefer and then verify-full with %s", *calls, caPath)
	}
	if w.config.DBTLSMode != "verify-full" || w.config.DBTLSCA != ca {
		t.Errorf("kept mode %q with %d bytes of PEM", w.config.DBTLSMode, len(w.config.DBTLSCA))
	}
}

// testClientPair is the pair of the test certificate, which the auth server's own tests read.
func testClientPair(t *testing.T) (cert, key string) {
	t.Helper()
	certFile, err := os.ReadFile("testdata/db-client-cert.pem")
	if err != nil {
		t.Fatal(err)
	}
	keyFile, err := os.ReadFile("testdata/db-client-key.pem")
	if err != nil {
		t.Fatal(err)
	}
	return string(certFile), string(keyFile)
}

// The pair and the host name override are asked after the CA file, for verify-full, and reach the
// configuration as the generated files write them: the two paths made absolute, the two files'
// contents, and the name. The key beside a certificate the wizard cannot pair is asked again
// (#546).
func TestWizard_AsksTheClientCertificateAndTheHostName(t *testing.T) {
	cert, key := testClientPair(t)
	certPath := writeFile(t, "client-cert.pem", cert)
	keyPath := writeFile(t, "client-key.pem", key)
	caPath := writeFile(t, "db-ca.pem", readTestCA(t))

	steps := withTLSAnswers(t, deploymentNative, "5", caPath)
	certAt, nameAt := -1, -1
	for i, s := range steps {
		switch s.prompt {
		case clientCertPrompt:
			certAt = i
		case serverNamePrompt:
			nameAt = i
		}
	}
	if certAt < 0 || nameAt < 0 {
		t.Fatal("the script never asks for the client certificate or the host name")
	}
	steps[certAt].answer = certPath
	// The CA file is a certificate, not a private key: the pair is refused, as the auth server
	// refuses two files that do not pair, and the key is asked again (#546).
	steps = slices.Insert(steps, certAt+1, scriptedStep{prompt: clientKeyPrompt, answer: caPath},
		scriptedStep{prompt: clientKeyPrompt, answer: keyPath})
	if nameAt > certAt {
		nameAt += 2
	}
	steps[nameAt].answer = "db.internal.example.com"

	w, in, out, _ := testWizard(t, &CLIFlags{}, steps)
	if err := w.setup(); err != nil {
		t.Fatalf("setup: %v\n%s", err, out)
	}
	in.assertConsumed()
	if !strings.Contains(out.String(), "do not pair") {
		t.Errorf("a key that pairs with nothing is not refused:\n%s", out)
	}
	c := w.config
	if c.DBTLSClientCertFile != certPath || c.DBTLSClientKeyFile != keyPath {
		t.Errorf("pair is %q and %q, want %q and %q", c.DBTLSClientCertFile, c.DBTLSClientKeyFile, certPath, keyPath)
	}
	if c.DBTLSClientCert != cert || c.DBTLSClientKey != key {
		t.Error("the configuration holds what the two files hold")
	}
	if c.DBTLSServerName != "db.internal.example.com" {
		t.Errorf("host name is %q, want db.internal.example.com", c.DBTLSServerName)
	}
	env, err := os.ReadFile(w.paths.description)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"GOIABADA_DB_TLS_CLIENT_CERT_FILE=\"" + certPath + "\"",
		"GOIABADA_DB_TLS_CLIENT_KEY_FILE=\"" + keyPath + "\"",
		"GOIABADA_DB_TLS_SERVER_NAME=\"db.internal.example.com\"",
	} {
		if !strings.Contains(string(env), want) {
			t.Errorf("the env file omits %s:\n%s", want, env)
		}
	}
}

// The TLS flags are refused as the auth server refuses the settings they write: half a pair, a
// pair on SQL Server, whose driver takes none, a pair beside a mode that may send no TLS, and a
// host name override beside a mode that checks no host name (#546).
func TestWizard_RefusesTheTLSFlagsTheServerRefuses(t *testing.T) {
	cert, key := testClientPair(t)
	certPath := writeFile(t, "client-cert.pem", cert)
	keyPath := writeFile(t, "client-key.pem", key)
	native := CLIFlags{DeploymentType: "native", DBType: "postgres", AuthServerURL: "https://auth.example.org",
		DBHost: "pg.internal", SkipDBTest: true}
	for _, tc := range []struct {
		name  string
		flags CLIFlags
		want  string
	}{
		{"half a pair", func() CLIFlags {
			f := native
			f.DBTLSMode, f.DBTLSClientCertFile = "require", certPath
			return f
		}(), `without --db-tls-client-key-file: name both or neither`},
		{"a pair on SQL Server", func() CLIFlags {
			f := native
			f.DBType, f.DBTLSMode = "mssql", "require"
			f.DBTLSClientCertFile, f.DBTLSClientKeyFile = certPath, keyPath
			return f
		}(), "while --db is mssql, whose driver takes no client certificate"},
		{"a pair beside prefer", func() CLIFlags {
			f := native
			f.DBTLSClientCertFile, f.DBTLSClientKeyFile = certPath, keyPath
			return f
		}(), "while --db-tls-mode is left out, so prefer, which may send no TLS"},
		{"a host name beside verify-ca", func() CLIFlags {
			f := native
			f.DBTLSMode, f.DBTLSServerName = "verify-ca", "db.internal.example.com"
			return f
		}(), "while --db-tls-mode is verify-ca, which checks no host name"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w, _, out, _ := testWizard(t, &tc.flags, nil)
			err := w.setup()
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("setup refused with %v, want it to say %q\n%s", err, tc.want, out)
			}
		})
	}
}

// Native binaries write the mode and the CA file's absolute path into the env file, the CA file
// only for a mode that reads one (#502 decision 7).
func TestEnvFile_WritesTheTLSModeAndTheCAFile(t *testing.T) {
	for _, tc := range []struct {
		mode, caFile string
	}{
		{"prefer", ""},
		{"verify-ca", ""},
		{"verify-full", "/etc/ssl/goiabada/db-ca.pem"},
	} {
		t.Run(tc.mode+"-"+tc.caFile, func(t *testing.T) {
			config := goldenConfig(deploymentNative, "mysql")
			config.DBTLSMode, config.DBTLSCAFile = tc.mode, tc.caFile
			env, _, err := systemdEnvironmentFile(descriptionOf(config))
			if err != nil {
				t.Fatal(err)
			}
			if got := env["GOIABADA_DB_TLS_MODE"]; got != tc.mode {
				t.Errorf("GOIABADA_DB_TLS_MODE is %q, want %q", got, tc.mode)
			}
			got, written := env["GOIABADA_DB_TLS_CA_FILE"]
			if written != (tc.caFile != "") || got != tc.caFile {
				t.Errorf("GOIABADA_DB_TLS_CA_FILE is %q (written %v), want %q", got, written, tc.caFile)
			}
		})
	}
}

// On Kubernetes the CA travels in the manifest: a goiabada-db-ca ConfigMap holding its PEM, mounted
// read-only into the auth server's pod, at the path the auth server's ConfigMap names as
// GOIABADA_DB_TLS_CA_FILE. Without a CA file the manifest gains nothing (#502 decision 8).
func TestKubernetesManifest_CarriesTheDatabaseCA(t *testing.T) {
	ca := readTestCA(t)

	t.Run("with a CA file", func(t *testing.T) {
		config := kubernetesConfig()
		config.DBTLSMode, config.DBTLSCAFile, config.DBTLSCA = "verify-full", "/home/operator/db-ca.pem", ca
		docs := kubernetesDocuments(t, config)

		caMap := docs["ConfigMap"]["goiabada-db-ca"]
		if caMap == nil {
			t.Fatalf("no goiabada-db-ca ConfigMap among %v", docs["ConfigMap"])
		}
		if got := at[string](t, caMap, "metadata", "namespace"); got != config.K8sNamespace {
			t.Errorf("goiabada-db-ca is in namespace %q, want %q", got, config.K8sNamespace)
		}
		files := at[map[string]any](t, caMap, "data")
		if len(files) != 1 {
			t.Errorf("goiabada-db-ca holds %d files, want 1", len(files))
		}

		settings := at[map[string]any](t, docs["ConfigMap"]["goiabada-authserver-config"], "data")
		if got := at[string](t, settings, "GOIABADA_DB_TLS_MODE"); got != "verify-full" {
			t.Errorf("GOIABADA_DB_TLS_MODE is %q, want verify-full", got)
		}
		caFile := at[string](t, settings, "GOIABADA_DB_TLS_CA_FILE")

		podSpec := at[map[string]any](t, deploymentNamed(t, docs, "goiabada-authserver"), "spec", "template", "spec")
		volume := only[map[string]any](t, at[[]any](t, podSpec, "volumes"), "the auth server's volumes")
		if got := at[string](t, volume, "configMap", "name"); got != "goiabada-db-ca" {
			t.Errorf("the auth server's volume is ConfigMap %q, want goiabada-db-ca", got)
		}
		container := only[map[string]any](t, at[[]any](t, podSpec, "containers"), "the auth server's containers")
		mount := only[map[string]any](t, at[[]any](t, container, "volumeMounts"), "the auth server's volume mounts")
		if at[string](t, mount, "name") != at[string](t, volume, "name") {
			t.Errorf("the mount %v names another volume than %v", mount, volume)
		}
		if readOnly, _ := mount["readOnly"].(bool); !readOnly {
			t.Errorf("the CA is mounted writable: %v", mount)
		}
		mountPath := at[string](t, mount, "mountPath")
		dir, file := filepath.Split(caFile)
		if filepath.Clean(dir) != mountPath {
			t.Errorf("GOIABADA_DB_TLS_CA_FILE is %q, not a file under the mount %q", caFile, mountPath)
		}
		if got := at[string](t, files, file); got != ca {
			t.Errorf("the ConfigMap's %s is\n%s\nwant the CA's PEM\n%s", file, got, ca)
		}
		if strings.Contains(at[string](t, settings, "GOIABADA_DB_TLS_CA_FILE"), "operator") {
			t.Errorf("the manifest names the wizard's machine's path, which no pod has")
		}

		admin := at[map[string]any](t, deploymentNamed(t, docs, "goiabada-adminconsole"), "spec", "template", "spec")
		if _, mounted := admin["volumes"]; mounted {
			t.Errorf("the admin console mounts a volume: %v", admin["volumes"])
		}
	})

	t.Run("without one", func(t *testing.T) {
		for _, mode := range []string{"prefer", "verify-ca"} {
			config := kubernetesConfig()
			config.DBTLSMode = mode
			docs := kubernetesDocuments(t, config)
			if _, written := docs["ConfigMap"]["goiabada-db-ca"]; written {
				t.Errorf("%s: a goiabada-db-ca ConfigMap with no CA file", mode)
			}
			settings := at[map[string]any](t, docs["ConfigMap"]["goiabada-authserver-config"], "data")
			if got := at[string](t, settings, "GOIABADA_DB_TLS_MODE"); got != mode {
				t.Errorf("GOIABADA_DB_TLS_MODE is %q, want %q", got, mode)
			}
			if _, written := settings["GOIABADA_DB_TLS_CA_FILE"]; written {
				t.Errorf("%s: GOIABADA_DB_TLS_CA_FILE with no CA file", mode)
			}
			podSpec := at[map[string]any](t, deploymentNamed(t, docs, "goiabada-authserver"), "spec", "template", "spec")
			if _, mounted := podSpec["volumes"]; mounted {
				t.Errorf("%s: the auth server mounts a volume with no CA file", mode)
			}
		}
	})
}

// The check dials each of its two connections with the mode and the CA file's authorities, as the
// auth server's builders do, on every server engine: the roots handed to the driver, and on
// verify-ca the chain alone checked (#502 decision 7).
func TestCheckDatabase_DialsWithTheModeAndTheCA(t *testing.T) {
	ca := readTestCA(t)
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM([]byte(ca)) {
		t.Fatal("the test CA holds no certificate")
	}
	for _, name := range []string{"mysql", "postgres", "mssql"} {
		for _, mode := range []string{"verify-ca", "verify-full"} {
			t.Run(name+"/"+mode, func(t *testing.T) {
				config := goldenConfig(deploymentNative, name)
				config.DBHost = "db.example.com"
				config.DBTLSMode, config.DBTLSCAFile, config.DBTLSCA = mode, "/etc/ssl/db-ca.pem", ca
				var opened []dbConnection
				open := func(c dbConnection) (dbConn, error) {
					opened = append(opened, c)
					return &fakeConn{db: &fakeDatabase{}, dsn: connectionKey(c)}, nil
				}
				var out strings.Builder
				checkConfiguredDatabase(&console{w: &out}, open, config)
				if len(opened) == 0 {
					t.Fatalf("nothing was opened:\n%s", out.String())
				}
				for i, c := range opened {
					tlsConfig := connectionTLS(t, c)
					if tlsConfig == nil {
						t.Fatalf("connection %d has no TLS configuration", i)
					}
					if tlsConfig.RootCAs == nil || !tlsConfig.RootCAs.Equal(roots) {
						t.Errorf("connection %d trusts other roots than the CA file's", i)
					}
					if tlsConfig.ServerName != "db.example.com" {
						t.Errorf("connection %d names server %q", i, tlsConfig.ServerName)
					}
					chainOnly := tlsConfig.InsecureSkipVerify && (tlsConfig.VerifyConnection != nil || tlsConfig.VerifyPeerCertificate != nil)
					if chainOnly != (mode == "verify-ca") {
						t.Errorf("connection %d checks the chain alone: %v, under %s", i, chainOnly, mode)
					}
					if tlsConfig.InsecureSkipVerify && !chainOnly {
						t.Errorf("connection %d checks nothing under %s", i, mode)
					}
				}
			})
		}
	}
}

// connectionTLS is the TLS configuration a connection the check opens is dialled with, whichever
// driver opens it.
func connectionTLS(t *testing.T, c dbConnection) *tls.Config {
	t.Helper()
	switch {
	case c.mysql != nil:
		return c.mysql.TLS
	case c.postgres != nil:
		return c.postgres.TLSConfig
	case c.mssql != nil:
		return c.mssql.TLSConfig
	}
	t.Fatalf("connection %+v carries no driver configuration", c)
	return nil
}

// The check dials each of its two connections with the client certificate pair and the host name
// override, as the auth server's builders do: the pair presented on MySQL and PostgreSQL in the
// three modes that carry one, and the override what verify-full checks the certificate against on
// all three engines, so a certificate naming it is accepted and one naming the host dialled is
// refused. require still checks nothing with a pair, accepting a certificate no authority it trusts
// signed for another host (#546).
func TestCheckDatabase_DialsWithTheClientPairAndTheNamedHost(t *testing.T) {
	const host, override = "db.example.com", "db-1.internal.example"
	cert, key := testClientPair(t)
	pair, err := tls.X509KeyPair([]byte(cert), []byte(key))
	if err != nil {
		t.Fatal(err)
	}
	ours := newTestAuthority(t, "ours")
	theirs := newTestAuthority(t, "theirs")
	oursPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ours.cert.Raw}))
	forOverride := ours.issue(t, override)
	forDialled := ours.issue(t, host)
	untrustedForAnother := theirs.issue(t, "other.example.com")

	for _, name := range []string{"mysql", "postgres", "mssql"} {
		e := testEngine(name)
		for _, mode := range []string{"require", "verify-ca", "verify-full"} {
			if !e.takesClientCertificate && mode != "verify-full" {
				continue
			}
			t.Run(name+"/"+mode, func(t *testing.T) {
				config := goldenConfig(deploymentNative, name)
				config.DBHost, config.DBTLSMode = host, mode
				if checksCertificate(mode) {
					config.DBTLSCAFile, config.DBTLSCA = "/etc/ssl/db-ca.pem", oursPEM
				}
				if e.takesClientCertificate {
					config.DBTLSClientCertFile, config.DBTLSClientKeyFile = "/etc/ssl/client-cert.pem", "/etc/ssl/client-key.pem"
					config.DBTLSClientCert, config.DBTLSClientKey = cert, key
				}
				if checksHostName(mode) {
					config.DBTLSServerName = override
				}
				db := &fakeDatabase{counts: map[string]int{e.existenceQuery: 1}}
				var opened []dbConnection
				open := func(c dbConnection) (dbConn, error) {
					opened = append(opened, c)
					return &fakeConn{db: db, dsn: connectionKey(c)}, nil
				}
				var out strings.Builder
				if !checkConfiguredDatabase(&console{w: &out}, open, config) {
					t.Fatalf("the check failed:\n%s", out.String())
				}
				if len(opened) != 2 {
					t.Fatalf("opened %d connections, want the maintenance one and the application database's", len(opened))
				}
				for i, c := range opened {
					tlsConfig := connectionTLS(t, c)
					if tlsConfig == nil {
						t.Fatalf("connection %d has no TLS configuration", i)
					}
					presented := len(tlsConfig.Certificates) == 1 && samePair(tlsConfig.Certificates[0], pair)
					if presented != e.takesClientCertificate {
						t.Errorf("connection %d presents the pair: %v, want %v", i, presented, e.takesClientCertificate)
					}
					switch mode {
					case "require":
						if err := testHandshake(t, tlsConfig, untrustedForAnother); err != nil {
							t.Errorf("connection %d refuses, under require, a certificate it was never to check: %v", i, err)
						}
					case "verify-full":
						if tlsConfig.ServerName != override {
							t.Errorf("connection %d names server %q, want the override %q", i, tlsConfig.ServerName, override)
						}
						if c.mssql != nil && !c.mssql.HostInCertificateProvided {
							t.Errorf("connection %d carries no hostNameInCertificate", i)
						}
						if err := testHandshake(t, tlsConfig, forOverride); err != nil {
							t.Errorf("connection %d refuses a certificate naming the override: %v", i, err)
						}
						if testHandshake(t, tlsConfig, forDialled) == nil {
							t.Errorf("connection %d accepts a certificate naming only the host dialled", i)
						}
					}
				}
			})
		}
	}
}

// samePair reports whether got is the pair want is: the same certificate chain and the same
// private key, which is what signs the handshake a database checking client certificates asks for.
// A chain without its key is no pair (#546).
func samePair(got, want tls.Certificate) bool {
	if !slices.EqualFunc(got.Certificate, want.Certificate, slices.Equal[[]byte]) {
		return false
	}
	key, ok := want.PrivateKey.(interface{ Equal(crypto.PrivateKey) bool })
	return ok && got.PrivateKey != nil && key.Equal(got.PrivateKey)
}

// A certificate and key that do not pair fail the check before anything is dialled, as the auth
// server refuses them before it connects (#546).
func TestCheckDatabase_AClientPairThatDoesNotPairOpensNothing(t *testing.T) {
	cert, _ := testClientPair(t)
	der, err := x509.MarshalPKCS8PrivateKey(testKey(t))
	if err != nil {
		t.Fatal(err)
	}
	otherKey := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
	for _, name := range []string{"mysql", "postgres"} {
		t.Run(name, func(t *testing.T) {
			config := goldenConfig(deploymentNative, name)
			config.DBTLSMode = "require"
			config.DBTLSClientCertFile, config.DBTLSClientKeyFile = "/etc/ssl/client-cert.pem", "/etc/ssl/client-key.pem"
			config.DBTLSClientCert, config.DBTLSClientKey = cert, otherKey
			opened := 0
			open := func(dbConnection) (dbConn, error) {
				opened++
				return &fakeConn{db: &fakeDatabase{}}, nil
			}
			var out strings.Builder
			if checkConfiguredDatabase(&console{w: &out}, open, config) {
				t.Errorf("the check passed a pair that does not pair:\n%s", out.String())
			}
			if opened != 0 {
				t.Errorf("opened %d connections, want none", opened)
			}
			if !strings.Contains(out.String(), "do not pair") {
				t.Errorf("the failure does not say the two do not pair:\n%s", out.String())
			}
		})
	}
}

// The three new flags answer their questions: the pair read from the two files and written as their
// absolute paths, the override written beside it, and the generated file's comment naming the
// override as what the certificate must name (#546).
func TestWizard_TheClientCertificateAndHostNameFlagsAnswerTheQuestions(t *testing.T) {
	cert, key := testClientPair(t)
	certPath := writeFile(t, "client-cert.pem", cert)
	keyPath := writeFile(t, "client-key.pem", key)
	caPath := writeFile(t, "db-ca.pem", readTestCA(t))
	flags := &CLIFlags{DeploymentType: "native", DBType: "postgres", AuthServerURL: "https://auth.example.org",
		DBHost: "10.0.0.5", DBTLSMode: "verify-full", DBTLSCAFile: caPath,
		DBTLSClientCertFile: certPath, DBTLSClientKeyFile: keyPath, DBTLSServerName: "db.internal.example.com"}

	w, _, out, calls := testWizard(t, flags, nil)
	if err := w.setup(); err != nil {
		t.Fatalf("setup: %v\n%s", err, out)
	}
	c := w.config
	if c.DBTLSClientCertFile != certPath || c.DBTLSClientKeyFile != keyPath || c.DBTLSClientCert != cert || c.DBTLSClientKey != key {
		t.Errorf("pair is %q and %q, want %q and %q with their contents", c.DBTLSClientCertFile, c.DBTLSClientKeyFile, certPath, keyPath)
	}
	if c.DBTLSServerName != "db.internal.example.com" {
		t.Errorf("host name is %q, want db.internal.example.com", c.DBTLSServerName)
	}
	if len(*calls) != 1 {
		t.Errorf("connection checks %+v, want one", *calls)
	}
	env, _, err := systemdEnvironmentFile(descriptionOf(c))
	if err != nil {
		t.Fatal(err)
	}
	for variable, want := range map[string]string{
		"GOIABADA_DB_TLS_MODE":             "verify-full",
		"GOIABADA_DB_TLS_CLIENT_CERT_FILE": certPath,
		"GOIABADA_DB_TLS_CLIENT_KEY_FILE":  keyPath,
		"GOIABADA_DB_TLS_SERVER_NAME":      "db.internal.example.com",
	} {
		if got := env[variable]; got != want {
			t.Errorf("%s is %q, want %q", variable, got, want)
		}
	}
	written, err := os.ReadFile(w.paths.description)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(written), "# verify-full: "+verifyFullOverrideDescription+".\n") {
		t.Errorf("the env file's comment does not say the certificate must name the override:\n%s", written)
	}
	for _, said := range []string{"Database client certificate: " + certPath + " and " + keyPath, "Database certificate host name: db.internal.example.com"} {
		if !strings.Contains(out.String(), said) {
			t.Errorf("the wizard does not say %q:\n%s", said, out)
		}
	}
}

// A certificate named and its key left blank returns to the certificate question, where a blank
// answer means none, as it did the first time: the connection presents no pair, the key is not
// asked again, and verify-full goes on to the host name (#546).
func TestWizard_ABlankCertificateAfterABlankKeyMeansNone(t *testing.T) {
	cert, _ := testClientPair(t)
	certPath := writeFile(t, "client-cert.pem", cert)

	steps := withTLSAnswers(t, deploymentNative, "5", "")
	certAt := slices.IndexFunc(steps, func(s scriptedStep) bool { return s.prompt == clientCertPrompt })
	if certAt < 0 || steps[certAt+1].prompt != serverNamePrompt {
		t.Fatal("the script does not ask the host name right after the client certificate")
	}
	steps[certAt].answer = certPath
	steps = slices.Insert(steps, certAt+1,
		scriptedStep{prompt: clientKeyPrompt, answer: ""},
		scriptedStep{prompt: clientCertPrompt, answer: ""})

	w, in, out, _ := testWizard(t, &CLIFlags{}, steps)
	if err := w.setup(); err != nil {
		t.Fatalf("setup: %v\n%s", err, out)
	}
	in.assertConsumed()
	c := w.config
	if c.DBTLSClientCertFile != "" || c.DBTLSClientKeyFile != "" || c.DBTLSClientCert != "" || c.DBTLSClientKey != "" {
		t.Errorf("a blank certificate left a pair: %q and %q", c.DBTLSClientCertFile, c.DBTLSClientKeyFile)
	}
	asked := 0
	for _, prompt := range in.prompts {
		if prompt == clientKeyPrompt {
			asked++
		}
	}
	if asked != 1 {
		t.Errorf("the key was asked %d times, want once", asked)
	}
	env, err := os.ReadFile(w.paths.description)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(env), "GOIABADA_DB_TLS_CLIENT_") {
		t.Errorf("the env file names a client certificate:\n%s", env)
	}
}

// SQL Server's driver takes no client certificate, and the auth server refuses one there, so the
// interactive wizard never offers it: in each of the three modes that would carry one, the CA file
// and the host name are asked as on the other engines, with no certificate between them (#546).
func TestWizard_NeverOffersSQLServerAClientCertificate(t *testing.T) {
	for _, kind := range []deploymentType{deploymentNative, deploymentKubernetes} {
		for mode, ca := range map[string][]string{"3": nil, "4": {""}, "5": {""}} {
			t.Run(deployments[kind].name+"/"+tlsModes[mode[0]-'1'].name, func(t *testing.T) {
				w, in, out, _ := testWizard(t, &CLIFlags{}, withTLSAnswersOn(t, kind, "mssql", mode, ca...))
				if err := w.setup(); err != nil {
					t.Fatalf("setup: %v\n%s", err, out)
				}
				in.assertConsumed()
				for _, prompt := range in.prompts {
					if strings.HasPrefix(prompt, "Client certificate") {
						t.Errorf("SQL Server was asked %q", prompt)
					}
				}
				if w.config.DBTLSClientCertFile != "" || w.config.DBTLSClientCert != "" {
					t.Error("SQL Server's configuration carries a client certificate")
				}
			})
		}
	}
}

// The CA line names the system's roots only for a mode that checks the certificate against them:
// disable, prefer and require check none, which the warning beside them says (#546).
func TestWizard_TheTLSFlagsNameTheSystemsRootsOnlyForAModeThatChecks(t *testing.T) {
	for mode, named := range map[string]bool{"disable": false, "": false, "require": false, "verify-ca": true, "verify-full": true} {
		t.Run("mode "+mode, func(t *testing.T) {
			flags := &CLIFlags{DeploymentType: "native", DBType: "postgres", AuthServerURL: "https://auth.example.org",
				DBHost: "pg.internal", DBTLSMode: mode}
			w, _, out, _ := testWizard(t, flags, nil)
			if err := w.setup(); err != nil {
				t.Fatalf("setup: %v\n%s", err, out)
			}
			if said := strings.Contains(out.String(), "Database CA: the system's roots"); said != named {
				t.Errorf("names the system's roots: %v, want %v\n%s", said, named, out)
			}
		})
	}
}
