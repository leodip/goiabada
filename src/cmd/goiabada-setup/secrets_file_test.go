package main

import (
	"encoding/base64"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// secretConfig is a golden case's answers with every secret set to a value nothing else in a
// generated file spells, not a Secret's key nor a variable's name, so a test can find each one
// wherever it was written.
func secretConfig(testCase goldenCase) *Config {
	config := testCase.config()
	config.AdminPassword = "Zq7AdminPassValue"
	if config.DBPassword != "" {
		config.DBPassword = "Zq7DatabasePassValue"
	}
	config.AuthSessionAuthKey = "a1b2c3authsessionauth"
	config.AuthSessionEncKey = "a1b2c3authsessionenc"
	config.AdminSessionAuthKey = "a1b2c3adminsessionauth"
	config.AdminSessionEncKey = "a1b2c3adminsessionenc"
	config.AESEncryptionKey = "a1b2c3dataencryption"
	config.OAuthClientSecret = "Zq7ClientSecretValue"
	return config
}

// secretValues is every secret a configuration carries, by what it is.
func secretValues(config *Config) map[string]string {
	values := map[string]string{
		"admin password":               config.AdminPassword,
		"auth server session auth key": config.AuthSessionAuthKey,
		"auth server session enc key":  config.AuthSessionEncKey,
		"admin session auth key":       config.AdminSessionAuthKey,
		"admin session enc key":        config.AdminSessionEncKey,
		"AES key":                      config.AESEncryptionKey,
		"OAuth client secret":          config.OAuthClientSecret,
	}
	if config.DBPassword != "" {
		values["database password"] = config.DBPassword
	}
	return values
}

// The Kubernetes and Compose outputs are two files each: the description of the deployment, which
// holds no secret and can be committed, and the file beside it holding every secret, the
// manifest's Secrets in goiabada-secrets.yaml and Compose's in docker-compose.override.yml. The
// native env file stays one file, being the secret material itself (#396 decision 14).
func TestEveryConfiguration_KeepsItsSecretsInAFileOfTheirOwn(t *testing.T) {
	wantNames := map[deploymentType][2]string{
		deploymentLocal:      {"docker-compose.yml", "docker-compose.override.yml"},
		deploymentProduction: {"docker-compose.yml", "docker-compose.override.yml"},
		deploymentKubernetes: {"goiabada-k8s.yaml", "goiabada-secrets.yaml"},
		deploymentNative:     {"goiabada.env", "goiabada.env"},
	}
	for _, testCase := range goldenCases() {
		if testCase.hostile {
			continue
		}
		t.Run(testCase.name, func(t *testing.T) {
			config := secretConfig(testCase)
			description, secrets := generatedConfiguration(config)
			want := wantNames[testCase.deployment]
			if description.name != want[0] || secrets.name != want[1] {
				t.Fatalf("the files are %q and %q, want %q and %q", description.name, secrets.name, want[0], want[1])
			}
			if testCase.deployment == deploymentNative {
				if secrets != description {
					t.Errorf("the env file's secrets are not the env file itself")
				}
			}
			for what, value := range secretValues(config) {
				written := value
				if testCase.deployment == deploymentKubernetes {
					written = base64Encode(value)
				}
				if !strings.Contains(secrets.content, written) {
					t.Errorf("%s does not carry the %s", secrets.name, what)
				}
				if secrets == description {
					continue
				}
				if strings.Contains(description.content, value) || strings.Contains(description.content, base64Encode(value)) {
					t.Errorf("%s carries the %s", description.name, what)
				}
			}
		})
	}
}

// secretRef is a Secret's name and one of its keys.
type secretRef struct {
	secret, key string
}

// The secrets file holds two Secrets and nothing else: the AES key alone in goiabada-encryption-key,
// so RBAC can restrict get on it by resourceNames and a secret manager can own it alone, and every
// other secret in goiabada-secrets. Each container's secret references name a key one of them holds,
// the admin console's none of the AES key's, but for the previous keys a rotation fills, which are
// optional, so a rotation edits the Secrets alone, and the manifest holds no Secret (#396 decisions
// 14 and 16).
func TestKubernetesSecretsFile_HoldsTheSecretsEachContainerReads(t *testing.T) {
	config := kubernetesConfig()
	description, secrets := generatedConfiguration(config)

	for _, doc := range yamlDocuments(t, description.content) {
		if kind := at[string](t, doc, "kind"); kind == "Secret" {
			t.Errorf("%s holds the Secret %s", description.name, at[string](t, doc, "metadata", "name"))
		}
	}

	wantData := map[string]map[string]string{
		"goiabada-secrets": {
			"db-password":            config.DBPassword,
			"admin-password":         config.AdminPassword,
			"auth-session-auth-key":  config.AuthSessionAuthKey,
			"auth-session-enc-key":   config.AuthSessionEncKey,
			"admin-session-auth-key": config.AdminSessionAuthKey,
			"admin-session-enc-key":  config.AdminSessionEncKey,
			"oauth-client-secret":    config.OAuthClientSecret,
		},
		"goiabada-encryption-key": {
			"aes-encryption-key": config.AESEncryptionKey,
		},
	}
	held := map[secretRef]bool{}
	docs := yamlDocuments(t, secrets.content)
	if len(docs) != len(wantData) {
		t.Errorf("%s holds %d documents, want the two Secrets", secrets.name, len(docs))
	}
	for _, doc := range docs {
		name := at[string](t, doc, "metadata", "name")
		if kind := at[string](t, doc, "kind"); kind != "Secret" {
			t.Errorf("%s holds the %s %s, want Secrets alone", secrets.name, kind, name)
			continue
		}
		if got := at[string](t, doc, "metadata", "namespace"); got != config.K8sNamespace {
			t.Errorf("the Secret %s is in namespace %q, want %q", name, got, config.K8sNamespace)
		}
		want, ok := wantData[name]
		if !ok {
			t.Errorf("%s holds a Secret named %s", secrets.name, name)
			continue
		}
		data := at[map[string]any](t, doc, "data")
		if got := slices.Sorted(maps.Keys(data)); !slices.Equal(got, slices.Sorted(maps.Keys(want))) {
			t.Errorf("the Secret %s holds %v, want %v", name, got, slices.Sorted(maps.Keys(want)))
		}
		for key, value := range want {
			decoded, err := base64.StdEncoding.DecodeString(at[string](t, data, key))
			if err != nil || string(decoded) != value {
				t.Errorf("the Secret %s's %s decodes to %q (%v), want %q", name, key, decoded, err, value)
			}
			held[secretRef{name, key}] = true
		}
	}

	wantRefs := map[string]map[string]secretRef{
		"goiabada-authserver": {
			"GOIABADA_ADMIN_PASSWORD":                        {"goiabada-secrets", "admin-password"},
			"GOIABADA_DB_PASSWORD":                           {"goiabada-secrets", "db-password"},
			"GOIABADA_AUTHSERVER_SESSION_AUTHENTICATION_KEY": {"goiabada-secrets", "auth-session-auth-key"},
			"GOIABADA_AUTHSERVER_SESSION_ENCRYPTION_KEY":     {"goiabada-secrets", "auth-session-enc-key"},
			"GOIABADA_AES_ENCRYPTION_KEY":                    {"goiabada-encryption-key", "aes-encryption-key"},
			"GOIABADA_ADMINCONSOLE_OAUTH_CLIENT_SECRET":      {"goiabada-secrets", "oauth-client-secret"},

			"GOIABADA_AUTHSERVER_SESSION_AUTHENTICATION_KEY_PREVIOUS": {"goiabada-secrets", "auth-session-auth-key-previous"},
			"GOIABADA_AUTHSERVER_SESSION_ENCRYPTION_KEY_PREVIOUS":     {"goiabada-secrets", "auth-session-enc-key-previous"},
			"GOIABADA_AES_ENCRYPTION_KEY_PREVIOUS":                    {"goiabada-encryption-key", "aes-encryption-key-previous"},
		},
		"goiabada-adminconsole": {
			"GOIABADA_ADMINCONSOLE_OAUTH_CLIENT_SECRET":        {"goiabada-secrets", "oauth-client-secret"},
			"GOIABADA_ADMINCONSOLE_SESSION_AUTHENTICATION_KEY": {"goiabada-secrets", "admin-session-auth-key"},
			"GOIABADA_ADMINCONSOLE_SESSION_ENCRYPTION_KEY":     {"goiabada-secrets", "admin-session-enc-key"},

			"GOIABADA_ADMINCONSOLE_SESSION_AUTHENTICATION_KEY_PREVIOUS": {"goiabada-secrets", "admin-session-auth-key-previous"},
			"GOIABADA_ADMINCONSOLE_SESSION_ENCRYPTION_KEY_PREVIOUS":     {"goiabada-secrets", "admin-session-enc-key-previous"},
		},
	}
	manifest := kubernetesDocuments(t, config)
	for deployment, want := range wantRefs {
		t.Run(deployment, func(t *testing.T) {
			podSpec := at[map[string]any](t, deploymentNamed(t, manifest, deployment), "spec", "template", "spec")
			container := only[map[string]any](t, at[[]any](t, podSpec, "containers"), deployment+"'s containers")
			got, optional := map[string]secretRef{}, map[string]bool{}
			for _, e := range at[[]any](t, container, "env") {
				entry := e.(map[string]any)
				ref := at[map[string]any](t, entry, "valueFrom", "secretKeyRef")
				name := at[string](t, entry, "name")
				got[name] = secretRef{at[string](t, ref, "name"), at[string](t, ref, "key")}
				optional[name] = ref["optional"] == true
			}
			if !maps.Equal(got, want) {
				t.Errorf("the container's secret references are %v, want %v", got, want)
			}
			for name, ref := range got {
				current, previous := strings.CutSuffix(name, "_PREVIOUS")
				if !previous {
					if optional[name] {
						t.Errorf("%s is optional, and a pod with it unset would start without it", name)
					}
					if !held[ref] {
						t.Errorf("%s reads %v, which the secrets file does not hold", name, ref)
					}
					continue
				}
				// A previous key is read only while a rotation fills it, so it is optional and no
				// generated file holds one. It sits in its current key's Secret, so the one change
				// that adds both halves of a previous session pair reaches the pods whole, since a
				// server refuses to start with one half (sessionstore.ParseKeys).
				if !optional[name] {
					t.Errorf("%s is not optional, so no pod starts until a rotation fills it", name)
				}
				if held[ref] {
					t.Errorf("%s reads %v, which the secrets file holds, so a rotation is already under way", name, ref)
				}
				if wantRef := (secretRef{got[current].secret, got[current].key + "-previous"}); ref != wantRef {
					t.Errorf("%s reads %v, want %v beside %s", name, ref, wantRef, current)
				}
			}
		})
	}
}

// composeEnvironmentOf reads the environment a file gives a service, in either of Compose's two
// forms, through the interpolation rule: none when the file does not name the service or gives it
// no environment.
func composeEnvironmentOf(t *testing.T, doc map[string]any, service string) map[string]string {
	t.Helper()
	services := at[map[string]any](t, doc, "services")
	entry, ok := services[service].(map[string]any)
	if !ok {
		return map[string]string{}
	}
	switch environment := entry["environment"].(type) {
	case nil:
		return map[string]string{}
	case []any:
		return composeListEnvironment(t, entry)
	case map[string]any:
		env := map[string]string{}
		for name, value := range environment {
			interpolated, ok := composeInterpolate(value.(string))
			if !ok {
				t.Fatalf("%s's %s holds a variable reference", service, name)
			}
			env[name] = interpolated
		}
		return env
	default:
		t.Fatalf("%s's environment is %T", service, environment)
		return nil
	}
}

// composeMergedEnvironment is the environment Compose gives a service from the Compose file and its
// override: the override's entries win by name (probe/compose-override, Compose v5.5).
func composeMergedEnvironment(t *testing.T, base, override map[string]any, service string) map[string]string {
	t.Helper()
	env := composeEnvironmentOf(t, base, service)
	maps.Copy(env, composeEnvironmentOf(t, override, service))
	return env
}

// The override names only services the Compose file runs, and gives each nothing but the secrets it
// reads, as environment entries Compose merges by name into the file's own, so `docker compose up
// -d` is unchanged; the Compose file sets none of them (#396 decision 14).
func TestComposeOverride_CarriesEachSecretUnderTheServiceThatReadsIt(t *testing.T) {
	for _, testCase := range composeCases(t) {
		if testCase.hostile {
			continue
		}
		t.Run(testCase.name, func(t *testing.T) {
			config := secretConfig(testCase)
			description, secrets := generatedConfiguration(config)
			base := only[map[string]any](t, toAny(yamlDocuments(t, description.content)), "the Compose file's documents")
			override := only[map[string]any](t, toAny(yamlDocuments(t, secrets.content)), "the override's documents")
			if got := slices.Sorted(maps.Keys(override)); !slices.Equal(got, []string{"services"}) {
				t.Errorf("the override sets %v, want services alone", got)
			}

			want := map[string]map[string]string{
				"goiabada-authserver": {
					"GOIABADA_ADMIN_PASSWORD":                        config.AdminPassword,
					"GOIABADA_AUTHSERVER_SESSION_AUTHENTICATION_KEY": config.AuthSessionAuthKey,
					"GOIABADA_AUTHSERVER_SESSION_ENCRYPTION_KEY":     config.AuthSessionEncKey,
					"GOIABADA_AES_ENCRYPTION_KEY":                    config.AESEncryptionKey,
					"GOIABADA_ADMINCONSOLE_OAUTH_CLIENT_SECRET":      config.OAuthClientSecret,
				},
				"goiabada-adminconsole": {
					"GOIABADA_ADMINCONSOLE_OAUTH_CLIENT_SECRET":        config.OAuthClientSecret,
					"GOIABADA_ADMINCONSOLE_SESSION_AUTHENTICATION_KEY": config.AdminSessionAuthKey,
					"GOIABADA_ADMINCONSOLE_SESSION_ENCRYPTION_KEY":     config.AdminSessionEncKey,
				},
			}
			if config.Engine.hasServer {
				want["goiabada-authserver"]["GOIABADA_DB_PASSWORD"] = config.DBPassword
				passwordVariable := map[string]string{"mysql": "MYSQL_ROOT_PASSWORD", "postgres": "POSTGRES_PASSWORD", "mssql": "MSSQL_SA_PASSWORD"}[testCase.engine]
				want[config.Engine.composeService] = map[string]string{passwordVariable: config.DBPassword}
			}

			overrideServices := at[map[string]any](t, override, "services")
			if got := slices.Sorted(maps.Keys(overrideServices)); !slices.Equal(got, slices.Sorted(maps.Keys(want))) {
				t.Errorf("the override names the services %v, want %v", got, slices.Sorted(maps.Keys(want)))
			}
			for service, secretEnv := range want {
				if _, ok := at[map[string]any](t, base, "services")[service]; !ok {
					t.Errorf("the override names %s, which the Compose file does not run", service)
				}
				if entry, ok := overrideServices[service].(map[string]any); ok {
					if got := slices.Sorted(maps.Keys(entry)); !slices.Equal(got, []string{"environment"}) {
						t.Errorf("the override sets %v on %s, want its environment alone", got, service)
					}
				}
				if got := composeEnvironmentOf(t, override, service); !maps.Equal(got, secretEnv) {
					t.Errorf("the override gives %s %v, want %v", service, slices.Sorted(maps.Keys(got)), slices.Sorted(maps.Keys(secretEnv)))
				}
				merged := composeMergedEnvironment(t, base, override, service)
				for name, value := range secretEnv {
					if merged[name] != value {
						t.Errorf("%s reads %s as %q, want %q", service, name, merged[name], value)
					}
					if _, set := composeEnvironmentOf(t, base, service)[name]; set {
						t.Errorf("the Compose file sets %s on %s", name, service)
					}
				}
			}
		})
	}
}

// aesWarning is what every word about the AES key must say: back it up apart from the database,
// since without it what the database holds encrypted cannot be read (#396 decision 16).
var aesWarning = []string{"Back it up separately from the database", "cannot be recovered"}

// Each output says beside the AES key that it is backed up apart from the database and why: the
// manifest's secrets file above the goiabada-encryption-key Secret, the Compose override and the env
// file above the variable (#396 decision 16).
func TestEveryOutput_WarnsBesideTheAESKey(t *testing.T) {
	for _, testCase := range goldenCases() {
		t.Run(testCase.name, func(t *testing.T) {
			_, secrets := generatedConfiguration(testCase.config())
			var comment string
			if testCase.deployment == deploymentKubernetes {
				comment = secretDocumentComment(t, secrets.content, "goiabada-encryption-key")
			} else {
				lines := strings.Split(secrets.content, "\n")
				found := 0
				for i, line := range lines {
					if strings.Contains(line, "GOIABADA_AES_ENCRYPTION_KEY=") {
						comment = commentAbove(lines, i)
						found++
					}
				}
				if found != 1 {
					t.Fatalf("%s sets the AES key on %d lines, want 1", secrets.name, found)
				}
			}
			for _, want := range aesWarning {
				if !strings.Contains(comment, want) {
					t.Errorf("the comment beside the AES key does not say %q: %q", want, comment)
				}
			}
		})
	}
}

// secretDocumentComment is the comment block of the Secret document named name, between its `---`
// and its apiVersion.
func secretDocumentComment(t *testing.T, content, name string) string {
	t.Helper()
	for _, doc := range strings.Split(content, "---\n") {
		if !strings.Contains(doc, "\nkind: Secret\n") || !strings.Contains(doc, "\n  name: "+name+"\n") {
			continue
		}
		var comment []string
		for _, line := range strings.Split(doc, "\n") {
			if !strings.HasPrefix(line, "#") {
				break
			}
			comment = append(comment, strings.TrimSpace(strings.TrimPrefix(line, "#")))
		}
		return strings.Join(comment, " ")
	}
	t.Fatalf("no Secret document named %s", name)
	return ""
}

// flagsFor is a non-interactive run of the deployment type, writing to output.
func flagsFor(kind deploymentType, output string) *CLIFlags {
	switch kind {
	case deploymentKubernetes:
		flags := kubernetesFlags()
		flags.Output = output
		return flags
	case deploymentNative:
		return &CLIFlags{DeploymentType: "native", DBType: "postgres", AuthServerURL: "https://auth.example.org",
			DBHost: "pg.internal", SkipDBTest: true, Output: output}
	case deploymentProduction:
		return &CLIFlags{DeploymentType: "production", DBType: "postgres", AuthServerURL: "https://auth.example.org", Output: output}
	default:
		return &CLIFlags{DeploymentType: "local", DBType: "mysql", Output: output}
	}
}

// The wizard writes both files of a configuration, each 0600 whatever it holds, so no mode depends
// on content and a later change that moves a value back cannot leak it (#426). Under their default
// names in the directory --output names; when --output names a file, the description takes that
// name and the secrets file is named from it: Kubernetes' with -secrets before its extension, and
// Compose's as Compose names an override, .override before its extension, so a compose.yaml's
// override is the compose.override.yaml Compose merges by itself (#396 decision 14).
func TestWizard_WritesTheSecretsFileBesideTheDescription(t *testing.T) {
	cases := []struct {
		name                 string
		kind                 deploymentType
		output               string
		description, secrets string
	}{
		{"kubernetes into a directory", deploymentKubernetes, "", "goiabada-k8s.yaml", "goiabada-secrets.yaml"},
		{"kubernetes named", deploymentKubernetes, "prod.yaml", "prod.yaml", "prod-secrets.yaml"},
		{"production into a directory", deploymentProduction, "", "docker-compose.yml", "docker-compose.override.yml"},
		{"production named", deploymentProduction, "compose.yaml", "compose.yaml", "compose.override.yaml"},
		{"local into a directory", deploymentLocal, "", "docker-compose.yml", "docker-compose.override.yml"},
		{"native into a directory", deploymentNative, "", "goiabada.env", "goiabada.env"},
		{"native named", deploymentNative, "prod.env", "prod.env", "prod.env"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			output := dir
			if tc.output != "" {
				output = filepath.Join(dir, tc.output)
			}
			w, _, out, _ := testWizard(t, flagsFor(tc.kind, output), nil)
			if err := w.setup(); err != nil {
				t.Fatalf("setup: %v\n%s", err, out)
			}
			entries, err := os.ReadDir(dir)
			if err != nil {
				t.Fatal(err)
			}
			want := slices.Compact(slices.Sorted(slices.Values([]string{tc.description, tc.secrets})))
			if got := entryNames(entries); !slices.Equal(got, want) {
				t.Fatalf("the directory holds %v, want %v", got, want)
			}
			description, secrets := writtenConfiguration(w.config, w.paths)
			for name, want := range map[string]string{tc.description: description.content, tc.secrets: secrets.content} {
				path := filepath.Join(dir, name)
				info, err := os.Stat(path)
				if err != nil {
					t.Fatal(err)
				}
				if got := info.Mode().Perm(); got != 0600 {
					t.Errorf("%s is %v, want -rw-------", name, got)
				}
				written, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				if string(written) != want {
					t.Errorf("%s is not the generator's output for it", name)
				}
			}
		})
	}
}

// completionLine is the one line of the wizard's output holding command, trimmed.
func completionLine(t *testing.T, output, command string) string {
	t.Helper()
	var found []string
	for _, line := range strings.Split(output, "\n") {
		if strings.Contains(line, command) {
			found = append(found, strings.TrimSpace(line))
		}
	}
	if len(found) != 1 {
		t.Fatalf("%d lines hold %q, want 1:\n%s", len(found), command, output)
	}
	return found[0]
}

// The completion message prints one kubectl apply naming both files, the manifest first: the
// Secrets are namespaced and the manifest creates their Namespace, and kubectl applies its files in
// the order given, so the command works on an empty cluster. Checked by walking its files in that
// order, every namespaced object after the Namespace that holds it (#396 decision 14).
func TestWizard_PrintsOneApplyThatWorksOnAnEmptyCluster(t *testing.T) {
	for _, tc := range []struct{ output, manifest, want string }{
		{"", "goiabada-k8s.yaml", "kubectl apply -f goiabada-k8s.yaml -f goiabada-secrets.yaml"},
		{"identity.yaml", "identity.yaml", "kubectl apply -f identity.yaml -f identity-secrets.yaml"},
	} {
		t.Run(tc.want, func(t *testing.T) {
			dir := t.TempDir()
			output := dir
			if tc.output != "" {
				output = filepath.Join(dir, tc.output)
			}
			w, _, out, _ := testWizard(t, flagsFor(deploymentKubernetes, output), nil)
			if err := w.setup(); err != nil {
				t.Fatalf("setup: %v\n%s", err, out)
			}
			command := completionLine(t, out.String(), "kubectl apply -f "+tc.manifest)
			if command != tc.want {
				t.Fatalf("the message applies with %q, want %q", command, tc.want)
			}

			created := map[string]bool{}
			objects := 0
			fields := strings.Fields(command)
			for i := 0; i < len(fields); i++ {
				if fields[i] != "-f" {
					continue
				}
				i++
				content, err := os.ReadFile(filepath.Join(dir, fields[i]))
				if err != nil {
					t.Fatal(err)
				}
				for _, doc := range yamlDocuments(t, string(content)) {
					objects++
					kind, name := at[string](t, doc, "kind"), at[string](t, doc, "metadata", "name")
					if kind == "Namespace" {
						created[name] = true
						continue
					}
					if namespace := at[string](t, doc, "metadata", "namespace"); !created[namespace] {
						t.Errorf("%s %s in %s is applied before its namespace %s is created", kind, name, fields[i], namespace)
					}
				}
			}
			if !created[w.config.K8sNamespace] || objects < 3 {
				t.Errorf("the command applied %d objects, creating the namespaces %v", objects, created)
			}
		})
	}
}

// Compose merges docker-compose.override.yml into docker-compose.yml by itself, as it does for any
// of its default names, so docker compose up -d is unchanged; a name Compose does not look for is
// started with both files named, the Compose file first.
func TestWizard_PrintsTheComposeCommandForBothFiles(t *testing.T) {
	for _, tc := range []struct{ output, want string }{
		{"", "docker compose up -d"},
		{"compose.yaml", "docker compose up -d"},
		{"identity.yml", "docker compose -f identity.yml -f identity.override.yml up -d"},
	} {
		t.Run(tc.want, func(t *testing.T) {
			dir := t.TempDir()
			output := dir
			if tc.output != "" {
				output = filepath.Join(dir, tc.output)
			}
			w, _, out, _ := testWizard(t, flagsFor(deploymentProduction, output), nil)
			if err := w.setup(); err != nil {
				t.Fatalf("setup: %v\n%s", err, out)
			}
			if got := completionLine(t, out.String(), "docker compose "); got != tc.want {
				t.Errorf("the message starts Goiabada with %q, want %q", got, tc.want)
			}
		})
	}
}

// The completion message names the one file holding the secrets and says to keep it out of version
// control, for every type; inside a git working tree, found by a .git entry in the output directory
// or above it, a directory or a worktree's file, it warns and gives the exact line to add to the
// tree's .gitignore, and outside one it does not (#396 decision 15).
func TestWizard_SaysWhichFileToKeepOutOfVersionControl(t *testing.T) {
	cases := []struct {
		name     string
		kind     deploymentType
		output   string
		git      string
		secrets  string
		ignoring string
	}{
		{"kubernetes outside a tree", deploymentKubernetes, "", "", "goiabada-secrets.yaml", ""},
		{"production outside a tree", deploymentProduction, "", "", "docker-compose.override.yml", ""},
		{"native outside a tree", deploymentNative, "", "", "goiabada.env", ""},
		{"kubernetes in a repository", deploymentKubernetes, "", "dir", "goiabada-secrets.yaml", "/generated/goiabada-secrets.yaml"},
		{"production in a worktree", deploymentProduction, "", "file", "docker-compose.override.yml", "/generated/docker-compose.override.yml"},
		{"native in a repository", deploymentNative, "", "dir", "goiabada.env", "/generated/goiabada.env"},
		{"a name gitignore reads as a pattern", deploymentKubernetes, "id [1]*?.yaml", "dir", "id [1]*?-secrets.yaml", `/generated/id \[1\]\*\?-secrets.yaml`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			switch tc.git {
			case "dir":
				if err := os.Mkdir(filepath.Join(root, ".git"), 0o700); err != nil {
					t.Fatal(err)
				}
			case "file":
				if err := os.WriteFile(filepath.Join(root, ".git"), []byte("gitdir: /elsewhere/.git/worktrees/x\n"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			dir := filepath.Join(root, "generated")
			if err := os.Mkdir(dir, 0o700); err != nil {
				t.Fatal(err)
			}
			output := dir
			if tc.output != "" {
				output = filepath.Join(dir, tc.output)
			}
			w, _, out, _ := testWizard(t, flagsFor(tc.kind, output), nil)
			if err := w.setup(); err != nil {
				t.Fatalf("setup: %v\n%s", err, out)
			}
			message := out.String()[strings.Index(out.String(), "SETUP COMPLETE!"):]

			advice := completionLine(t, message, "out of version control")
			if !strings.Contains(advice, tc.secrets) {
				t.Errorf("the advice %q does not name %s", advice, tc.secrets)
			}
			if tc.ignoring == "" {
				if strings.Contains(message, "git working tree") || strings.Contains(message, ".gitignore") {
					t.Errorf("outside a working tree, the message warns about one:\n%s", message)
				}
				return
			}
			if !strings.Contains(message, "git working tree") {
				t.Errorf("the message does not warn that %s is in a git working tree:\n%s", dir, message)
			}
			if got := completionLine(t, message, "/generated/"); got != tc.ignoring {
				t.Errorf("the line to add to .gitignore is %q, want %q", got, tc.ignoring)
			}
		})
	}
}

// The credential step warns beside the AES key's generation that it must be backed up apart from
// the database, naming where it is stored, and never prints it: the moment of generation is the one
// at which a backup can still be made (#396 decision 16).
func TestWizard_WarnsWhenItGeneratesTheAESKey(t *testing.T) {
	for _, tc := range []struct {
		kind   deploymentType
		output string
		stored []string
	}{
		{deploymentKubernetes, "", []string{"goiabada-encryption-key", "goiabada-secrets.yaml"}},
		{deploymentKubernetes, "identity.yaml", []string{"goiabada-encryption-key", "identity-secrets.yaml"}},
		{deploymentProduction, "", []string{"docker-compose.override.yml"}},
		{deploymentNative, "", []string{"goiabada.env"}},
	} {
		t.Run(deployments[tc.kind].name+" "+tc.output, func(t *testing.T) {
			dir := t.TempDir()
			output := dir
			if tc.output != "" {
				output = filepath.Join(dir, tc.output)
			}
			w, _, out, _ := testWizard(t, flagsFor(tc.kind, output), nil)
			if err := w.setup(); err != nil {
				t.Fatalf("setup: %v\n%s", err, out)
			}
			all := out.String()
			start := strings.Index(all, "Generating credentials")
			end := strings.Index(all, "Generating configuration")
			if start < 0 || end < start {
				t.Fatalf("no credential step in:\n%s", all)
			}
			step := all[start:end]
			for _, want := range append([]string{"Back up the AES encryption key separately from the database"}, tc.stored...) {
				if !strings.Contains(step, want) {
					t.Errorf("the credential step does not say %q:\n%s", want, step)
				}
			}
			if strings.Contains(all, w.config.AESEncryptionKey) {
				t.Errorf("the wizard printed the AES key")
			}
		})
	}
}
