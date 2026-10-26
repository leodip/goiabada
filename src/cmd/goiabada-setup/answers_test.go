package main

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// writeDeployment writes the files a run with config writes into dir, and a secrets file holding
// keptSecrets in place of the generated one, the way a deployment's directory holds its own: it
// returns where they are.
func writeDeployment(t *testing.T, config *Config, dir string) outputPaths {
	t.Helper()
	paths := resolveOutputPaths(config.Deployment, dir)
	description, _ := writtenConfiguration(config, paths)
	for path, content := range map[string]string{
		paths.description: description.content,
		paths.answers:     generateAnswers(config, paths),
		paths.secrets:     keptSecrets,
	} {
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return paths
}

// keptSecrets stands for a deployment's own secrets file, which no generator writes.
const keptSecrets = "# the deployment's own secrets\n"

func readFile(t *testing.T, path string) string {
	t.Helper()
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(content)
}

// runWithAnswers runs the wizard as the command line args would, the answers file they name read
// first.
func runWithAnswers(t *testing.T, args ...string) (*wizard, string, error) {
	t.Helper()
	flags, err := parseFlags(args, &strings.Builder{})
	if err != nil {
		t.Fatalf("parseFlags(%q): %v", args, err)
	}
	if flags, err = loadAnswers(args, flags.Answers); err != nil {
		return nil, "", err
	}
	w, _, out, _ := testWizard(t, flags, nil)
	err = w.setup()
	return w, out.String(), err
}

// Every golden configuration that has an answers file is written again from it by a run under
// --keep-secrets, byte for byte, with the answers file itself, and its secrets file is left as it
// was; a run without --keep-secrets, in an empty directory, writes the same description from the
// answers alone. This is section 4's "done when": a manifest regenerated from its saved answers is
// the one it was generated as (#686 section 4).
func TestAnswers_RegenerateEveryGoldenConfigurationByteForByte(t *testing.T) {
	for _, tc := range goldenCases() {
		config := tc.config()
		if config.Deployment.defaultPaths().answers == "" {
			continue
		}
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			paths := writeDeployment(t, config, dir)
			description, answers := readFile(t, paths.description), readFile(t, paths.answers)

			_, out, err := runWithAnswers(t, "--answers", paths.answers, "--keep-secrets", "--output", dir)
			if err != nil {
				t.Fatalf("a run under --keep-secrets: %v\n%s", err, out)
			}
			if got := readFile(t, paths.description); got != description {
				t.Errorf("%s differs once written again. First difference at %s", filepath.Base(paths.description), firstDifference(description, got))
			}
			if got := readFile(t, paths.answers); got != answers {
				t.Errorf("%s differs once written again. First difference at %s", filepath.Base(paths.answers), firstDifference(answers, got))
			}
			if got := readFile(t, paths.secrets); got != keptSecrets {
				t.Errorf("--keep-secrets wrote %s:\n%s", filepath.Base(paths.secrets), got)
			}

			if config.presentsClientCertificate() {
				// A full run writes the pair into the secrets file, so it needs the files: refused below.
				return
			}
			fresh := t.TempDir()
			answersCopy := filepath.Join(fresh, filepath.Base(paths.answers))
			if writeErr := os.WriteFile(answersCopy, []byte(answers), 0o600); writeErr != nil {
				t.Fatal(writeErr)
			}
			w, out, err := runWithAnswers(t, "--answers", answersCopy, "--skip-db-test", "--output", fresh)
			if err != nil {
				t.Fatalf("a run writing every file: %v\n%s", err, out)
			}
			if got := readFile(t, w.paths.description); got != description {
				t.Errorf("a run writing every file writes another %s. First difference at %s", filepath.Base(paths.description), firstDifference(description, got))
			}
			if got := readFile(t, w.paths.secrets); got == keptSecrets || got == "" {
				t.Errorf("a run writing every file wrote no secrets file")
			}
		})
	}
}

// A flag given beside --answers replaces the answer of its name, whatever their order on the line,
// and the CA file replaces the certificates the answers hold for it.
func TestAnswers_AFlagReplacesTheAnswerOfItsName(t *testing.T) {
	dir := t.TempDir()
	config := goldenConfig(deploymentKubernetes, "postgres")
	paths := writeDeployment(t, config, dir)

	w, out, err := runWithAnswers(t, "--routing=ingress", "--answers", paths.answers, "--keep-secrets",
		"--tls-issuer=internal-ca", "--namespace=identity", "--output", dir)
	if err != nil {
		t.Fatalf("setup: %v\n%s", err, out)
	}
	if w.config.Routing != routingIngress || w.config.TLSIssuer != "internal-ca" || w.config.K8sNamespace != "identity" {
		t.Errorf("routing %q, issuer %q, namespace %q; want the flags' ingress, internal-ca and identity", w.config.Routing, w.config.TLSIssuer, w.config.K8sNamespace)
	}
	if w.config.AuthServerURL != config.AuthServerURL || w.config.DBHost != config.DBHost {
		t.Errorf("the answers no flag replaced changed: auth URL %q, database host %q", w.config.AuthServerURL, w.config.DBHost)
	}
	answers := readFile(t, paths.answers)
	for _, want := range []string{`routing: "ingress"`, `tls-issuer: "internal-ca"`, `namespace: "identity"`} {
		if !strings.Contains(answers, want+"\n") {
			t.Errorf("the answers file written holds no %s", want)
		}
	}

	ca, err := filepath.Abs(testCAFile)
	if err != nil {
		t.Fatal(err)
	}
	flags, err := loadAnswers([]string{"--answers", paths.answers, "--db-tls-ca-file", ca}, paths.answers)
	if err != nil {
		t.Fatal(err)
	}
	if flags.DBTLSCAFile != ca || flags.DBTLSCA != "" {
		t.Errorf("with --db-tls-ca-file given, the CA file is %q and the answers' certificates %q; want the file alone", flags.DBTLSCAFile, flags.DBTLSCA)
	}
}

// An answers file is refused, naming the file, the line and what is wrong, when the wizard could
// misread it: another version or none, a key it doesn't know, one given twice or holding more than
// one value, an answer its flag refuses, no type, and a secret, which only the secrets file holds.
func TestAnswers_RefusesAFileItCouldMisread(t *testing.T) {
	cases := []struct {
		name, content, want string
	}{
		{"no version", "type: kubernetes\n", "has no version"},
		{"another version", "version: 2\ntype: kubernetes\n", "is version 2, and this wizard reads version 1 alone"},
		{"an unknown key", "version: 1\ntype: kubernetes\nrouteing: ingress\n", "line 3: routeing is no answer the wizard knows"},
		{"a key given twice", "version: 1\ntype: kubernetes\nnamespace: a\nnamespace: b\n", "line 4: namespace is answered twice, first on line 3"},
		{"a list", "version: 1\ntype: kubernetes\nnamespace: [a, b]\n", "line 3: namespace is not a single value"},
		{"an answer its flag refuses", "version: 1\ntype: kubernetes\nrouting: mesh\n", "line 3: invalid routing \"mesh\""},
		{"no type", "version: 1\ndb: postgres\n", "has no type"},
		{"a password", "version: 1\ntype: kubernetes\nadmin-password: hunter2hunter2hunter2\n", "line 3: admin-password is a secret, which an answers file never holds"},
		{"a client key's file", "version: 1\ntype: kubernetes\ndb-tls-client-key-file: key.pem\n", "line 3: db-tls-client-key-file names a secret's file"},
		{"a run option", "version: 1\ntype: kubernetes\noverwrite: true\n", "line 3: overwrite says how one run writes"},
		{"certificates that are none", "version: 1\ntype: kubernetes\ndb-tls-ca: nothing\n", "line 3: db-tls-ca holds no PEM certificate"},
		{"no mapping", "- type\n", "holds no mapping of answers"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), answersFile)
			if err := os.WriteFile(path, []byte(tc.content), 0o600); err != nil {
				t.Fatal(err)
			}
			_, err := loadAnswers([]string{"--answers", path}, path)
			if err == nil || !strings.Contains(err.Error(), tc.want) || !strings.Contains(err.Error(), path) {
				t.Errorf("loadAnswers: %v, want an error naming %s and saying %q", err, path, tc.want)
			}
		})
	}
}

// --keep-secrets generates no secret, so a password given beside it, which would be dropped, is
// refused; native binaries, whose one file holds every secret, take neither it nor an answers file;
// and a client certificate the answers say is presented needs its files on a run that writes the
// secrets file (#686 section 4).
func TestKeepSecrets_RefusesWhatItCannotHonour(t *testing.T) {
	t.Run("a password", func(t *testing.T) {
		flags := kubernetesFlags()
		flags.KeepSecrets, flags.DBPassword = true, "db-secret"
		w, _, out, _ := testWizard(t, flags, nil)
		if err := w.setup(); err == nil || !strings.Contains(err.Error(), "--db-password is given with --keep-secrets") {
			t.Errorf("setup: %v, want the password refused\n%s", err, out)
		}
	})
	t.Run("a client certificate's files", func(t *testing.T) {
		flags := kubernetesFlags()
		flags.KeepSecrets, flags.DBTLSMode = true, "verify-full"
		flags.DBTLSClientCertFile, flags.DBTLSClientKeyFile = "client.crt", "client.key"
		w, _, out, _ := testWizard(t, flags, nil)
		if err := w.setup(); err == nil || !strings.Contains(err.Error(), "--db-tls-client-cert-file is given with --keep-secrets") {
			t.Errorf("setup: %v, want the pair refused before it is read\n%s", err, out)
		}
	})
	t.Run("native binaries", func(t *testing.T) {
		flags := &CLIFlags{DeploymentType: "native", DBType: "sqlite", AuthServerURL: "https://auth.example.org", KeepSecrets: true}
		w, _, out, _ := testWizard(t, flags, nil)
		if err := w.setup(); err == nil || !strings.Contains(err.Error(), "--keep-secrets is for local, production, or kubernetes") {
			t.Errorf("setup: %v, want native binaries refused\n%s", err, out)
		}
	})
	t.Run("a client certificate without its files", func(t *testing.T) {
		config := goldenConfig(deploymentKubernetes, "postgres")
		config.DBTLSMode = "verify-full"
		config.DBTLSClientCert, config.DBTLSClientKey = goldenClientCertificate()
		dir := t.TempDir()
		paths := writeDeployment(t, config, dir)
		if _, out, err := runWithAnswers(t, "--answers", paths.answers, "--skip-db-test", "--overwrite", "--output", dir); err == nil ||
			!strings.Contains(err.Error(), "answers that the auth server presents a client certificate") {
			t.Errorf("setup: %v, want the run refused until the pair's files are named\n%s", err, out)
		}
	})
}

// An interactive run under --keep-secrets asks every question that shapes the description and no
// password, tests no connection, and writes the description a run asking everything writes, leaving
// the secrets file as it was.
func TestKeepSecrets_AnInteractiveRunAsksNoSecret(t *testing.T) {
	for _, kind := range []deploymentType{deploymentKubernetes, deploymentProduction} {
		d := deployments[kind]
		e := testEngine("postgres")
		t.Run(d.name, func(t *testing.T) {
			full, _, out, _ := testWizard(t, &CLIFlags{}, interactiveScript(d, e))
			if err := full.setup(); err != nil {
				t.Fatalf("a run asking everything: %v\n%s", err, out)
			}
			want := readFile(t, full.paths.description)

			var steps []scriptedStep
			for _, step := range interactiveScript(d, e) {
				if !step.hidden && step.prompt != "Test database connection? [Y/n]: " {
					steps = append(steps, step)
				}
			}
			dir := t.TempDir()
			secrets := resolveOutputPaths(d, dir).secrets
			if err := os.WriteFile(secrets, []byte(keptSecrets), 0o600); err != nil {
				t.Fatal(err)
			}
			kept, _, out, calls := testWizard(t, &CLIFlags{KeepSecrets: true, Output: dir}, steps)
			if err := kept.setup(); err != nil {
				t.Fatalf("a run under --keep-secrets: %v\n%s", err, out)
			}
			if len(*calls) != 0 {
				t.Errorf("a run under --keep-secrets tested the connection %d times", len(*calls))
			}
			if got := readFile(t, kept.paths.description); got != want {
				t.Errorf("the description differs from a run asking everything. First difference at %s", firstDifference(want, got))
			}
			if got := readFile(t, secrets); got != keptSecrets {
				t.Errorf("--keep-secrets wrote the secrets file:\n%s", got)
			}
			if !strings.Contains(out.String(), "CONFIGURATION REGENERATED") || strings.Contains(out.String(), "Generating credentials") {
				t.Errorf("the run's output does not read as a regeneration:\n%s", out)
			}
			entries, err := os.ReadDir(dir)
			if err != nil {
				t.Fatal(err)
			}
			if names := entryNames(entries); !slices.Contains(names, answersFile) {
				t.Errorf("the directory holds %v, no %s", names, answersFile)
			}
		})
	}
}

// An empty flag beside --answers replaces the answer too: --db-tls-ca-file= returns to the system's
// roots, dropping the certificates and their ConfigMap, and empty client certificate files stop
// presenting the pair, dropping its mount.
func TestAnswers_AnEmptyFlagReplacesTheAnswer(t *testing.T) {
	config := goldenConfig(deploymentKubernetes, "postgres")
	config.DBTLSMode, config.DBTLSCA = "verify-full", goldenCA()
	config.DBTLSClientCert, config.DBTLSClientKey = goldenClientCertificate()
	dir := t.TempDir()
	paths := writeDeployment(t, config, dir)

	w, out, err := runWithAnswers(t, "--answers", paths.answers, "--keep-secrets", "--output", dir,
		"--db-tls-ca-file=", "--db-tls-client-cert-file=", "--db-tls-client-key-file=")
	if err != nil {
		t.Fatalf("setup: %v\n%s", err, out)
	}
	if w.config.DBTLSCA != "" || w.config.presentsClientCertificate() {
		t.Errorf("the CA's certificates %q, a client certificate presented %t; want neither", w.config.DBTLSCA, w.config.presentsClientCertificate())
	}
	manifest := readFile(t, paths.description)
	for _, gone := range []string{dbCAConfigMap, dbClientTLSSecret} {
		if strings.Contains(manifest, gone) {
			t.Errorf("the manifest still names %s", gone)
		}
	}
}
