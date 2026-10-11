package main

import (
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
	tlsModePrompt = "Select TLS mode [1-5] [2]: "
	caFilePrompt  = "CA file the database's certificate chains to (PEM), blank for the system's roots: "
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
	steps := interactiveScript(deployments[kind], testEngine("postgres"))
	for i := range steps {
		if steps[i].prompt == tlsModePrompt {
			steps[i].answer = mode
			var ca []scriptedStep
			for _, answer := range caAnswers {
				ca = append(ca, scriptedStep{prompt: caFilePrompt, answer: answer})
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
	again = slices.Insert(again, 6, scriptedStep{prompt: caFilePrompt, answer: caPath})
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
