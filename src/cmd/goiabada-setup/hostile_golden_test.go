package main

import (
	"encoding/base64"
	"errors"
	"io"
	"maps"
	"slices"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

// hostileCase is the hostile golden case that has name.
func hostileCase(t *testing.T, name string) goldenCase {
	t.Helper()
	for _, c := range hostileCases {
		if c.name == name {
			return c
		}
	}
	t.Fatalf("no hostile case is named %s", name)
	return goldenCase{}
}

// yamlDocuments decodes every document of a YAML stream as yaml.v3 reads it.
func yamlDocuments(t *testing.T, content string) []map[string]any {
	t.Helper()
	var docs []map[string]any
	decoder := yaml.NewDecoder(strings.NewReader(content))
	for {
		var doc map[string]any
		err := decoder.Decode(&doc)
		if errors.Is(err, io.EOF) {
			return docs
		}
		if err != nil {
			t.Fatalf("yaml.v3 refuses the file: %v\n%s", err, content)
		}
		if doc != nil {
			docs = append(docs, doc)
		}
	}
}

// at walks a decoded YAML document by keys, failing the test where a key is missing.
func at[T any](t *testing.T, node any, keys ...string) T {
	t.Helper()
	for _, key := range keys {
		m, ok := node.(map[string]any)
		if !ok {
			t.Fatalf("%v is not a mapping at %q", node, key)
		}
		if node, ok = m[key]; !ok {
			t.Fatalf("no %q in %v", key, slices.Sorted(maps.Keys(m)))
		}
	}
	value, ok := node.(T)
	if !ok {
		t.Fatalf("%v at %v is %T", node, keys, node)
	}
	return value
}

// everyString calls visit on every string scalar of a decoded document, keys included.
func everyString(node any, visit func(string)) {
	switch n := node.(type) {
	case string:
		visit(n)
	case map[string]any:
		for key, value := range n {
			visit(key)
			everyString(value, visit)
		}
	case []any:
		for _, value := range n {
			everyString(value, visit)
		}
	}
}

// composeListEnvironment reads a service's list-form environment the way Compose does: YAML, then
// the interpolation rule, then the split at the first `=`.
func composeListEnvironment(t *testing.T, service map[string]any) map[string]string {
	t.Helper()
	env := map[string]string{}
	for _, entry := range at[[]any](t, service, "environment") {
		line, ok := entry.(string)
		if !ok {
			t.Fatalf("environment entry %v is %T, want a string", entry, entry)
		}
		interpolated, ok := composeInterpolate(line)
		if !ok {
			t.Fatalf("environment entry %q holds a variable reference", line)
		}
		name, value, _ := strings.Cut(interpolated, "=")
		env[name] = value
	}
	return env
}

// The Compose file and its override of hostile answers are read back by YAML, the interpolation
// rule and Compose's merge with every answer exactly as given, and no string anywhere in either
// holds a `$` Compose would substitute.
func TestHostileGolden_ComposeReadsBackEveryAnswer(t *testing.T) {
	config := hostileCase(t, "hostile-compose").config()
	description, secrets := generatedConfiguration(config)
	var files []map[string]any
	for _, file := range []generatedFile{description, secrets} {
		docs := yamlDocuments(t, file.content)
		if len(docs) != 1 {
			t.Fatalf("%s has %d documents, want 1", file.name, len(docs))
		}
		everyString(docs[0], func(s string) {
			if _, ok := composeInterpolate(s); !ok {
				t.Errorf("%q holds a variable reference Compose would substitute", s)
			}
		})
		files = append(files, docs[0])
	}
	base, override := files[0], files[1]

	services := at[map[string]any](t, base, "services")
	auth := composeMergedEnvironment(t, base, override, "goiabada-authserver")
	for name, want := range map[string]string{
		"GOIABADA_ADMIN_EMAIL":          config.AdminEmail,
		"GOIABADA_ADMIN_PASSWORD":       config.AdminPassword,
		"GOIABADA_AUTHSERVER_BASEURL":   config.AuthServerURL,
		"GOIABADA_ADMINCONSOLE_BASEURL": config.AdminConsoleURL,
		"GOIABADA_DB_PASSWORD":          config.DBPassword,
	} {
		if auth[name] != want {
			t.Errorf("auth server %s reads back as %q, want %q", name, auth[name], want)
		}
	}
	admin := composeMergedEnvironment(t, base, override, "goiabada-adminconsole")
	for name, want := range map[string]string{
		"GOIABADA_AUTHSERVER_BASEURL":   config.AuthServerURL,
		"GOIABADA_ADMINCONSOLE_BASEURL": config.AdminConsoleURL,
	} {
		if admin[name] != want {
			t.Errorf("admin console %s reads back as %q, want %q", name, admin[name], want)
		}
	}

	db := at[map[string]any](t, services, config.Engine.composeService)
	if got := composeMergedEnvironment(t, base, override, config.Engine.composeService)["MSSQL_SA_PASSWORD"]; got != config.DBPassword {
		t.Errorf("MSSQL_SA_PASSWORD reads back as %q, want %q", got, config.DBPassword)
	}
	test := at[[]any](t, db, "healthcheck", "test")
	if len(test) != 2 || test[0] != "CMD-SHELL" {
		t.Fatalf("healthcheck test is %q, want CMD-SHELL and a command", test)
	}
	command, _ := composeInterpolate(test[1].(string))
	if command != config.Engine.healthcheck {
		t.Errorf("the container's shell is handed %q, want %q", command, config.Engine.healthcheck)
	}
}

// The Kubernetes manifests of hostile answers are read back by YAML with every answer exactly as
// given, the passwords through the Secret's base64.
func TestHostileGolden_KubernetesReadsBackEveryAnswer(t *testing.T) {
	config := hostileCase(t, "hostile-kubernetes").config()
	description, secrets := generatedConfiguration(config)
	docs := append(yamlDocuments(t, description.content), yamlDocuments(t, secrets.content)...)

	// The ConfigMaps and Secrets, by kind/name.
	documents := map[string]map[string]any{}
	for _, doc := range docs {
		kind := at[string](t, doc, "kind")
		if kind == "Namespace" {
			if name := at[string](t, doc, "metadata", "name"); name != config.K8sNamespace {
				t.Errorf("the namespace is %q, want %q", name, config.K8sNamespace)
			}
		} else if namespace := at[string](t, doc, "metadata", "namespace"); namespace != config.K8sNamespace {
			t.Errorf("%s is in namespace %q, want %q", kind, namespace, config.K8sNamespace)
		}
		if kind == "ConfigMap" || kind == "Secret" {
			documents[kind+"/"+at[string](t, doc, "metadata", "name")] = doc
		}
	}

	for configMap, wants := range map[string]map[string]string{
		"goiabada-authserver-config": {
			"GOIABADA_ADMIN_EMAIL":          config.AdminEmail,
			"GOIABADA_AUTHSERVER_BASEURL":   config.AuthServerURL,
			"GOIABADA_ADMINCONSOLE_BASEURL": config.AdminConsoleURL,
			"GOIABADA_DB_HOST":              config.DBHost,
			"GOIABADA_DB_PORT":              config.DBPort,
			"GOIABADA_DB_NAME":              config.DBName,
			"GOIABADA_DB_USERNAME":          config.DBUsername,
		},
		"goiabada-adminconsole-config": {
			"GOIABADA_AUTHSERVER_BASEURL":   config.AuthServerURL,
			"GOIABADA_ADMINCONSOLE_BASEURL": config.AdminConsoleURL,
		},
	} {
		data := at[map[string]any](t, documents["ConfigMap/"+configMap], "data")
		for name, want := range wants {
			if got := at[string](t, data, name); got != want {
				t.Errorf("ConfigMap %s's %s reads back as %q, want %q", configMap, name, got, want)
			}
		}
	}

	secret := at[map[string]any](t, documents["Secret/goiabada-secrets"], "data")
	for name, want := range map[string]string{
		"admin-password": config.AdminPassword,
		"db-password":    config.DBPassword,
	} {
		decoded, err := base64.StdEncoding.DecodeString(at[string](t, secret, name))
		if err != nil || string(decoded) != want {
			t.Errorf("Secret %s decodes to %q (%v), want %q", name, decoded, err, want)
		}
	}
}

// hostileEnvWant is every interpolated assignment of the env file with the answer it must carry.
func hostileEnvWant(config *Config) map[string]string {
	return map[string]string{
		"GOIABADA_ADMIN_EMAIL":                config.AdminEmail,
		"GOIABADA_ADMIN_PASSWORD":             config.AdminPassword,
		"GOIABADA_DB_TYPE":                    config.Engine.name,
		"GOIABADA_DB_HOST":                    config.DBHost,
		"GOIABADA_DB_PORT":                    config.DBPort,
		"GOIABADA_DB_NAME":                    config.DBName,
		"GOIABADA_DB_USERNAME":                config.DBUsername,
		"GOIABADA_DB_PASSWORD":                config.DBPassword,
		"GOIABADA_AUTHSERVER_BASEURL":         config.AuthServerURL,
		"GOIABADA_AUTHSERVER_INTERNALBASEURL": config.AuthServerURL,
		"GOIABADA_ADMINCONSOLE_BASEURL":       config.AdminConsoleURL,
	}
}

// goiabadaVariables is the GOIABADA_ variables of an environment, which is all the env file sets.
func goiabadaVariables(env map[string]string) map[string]string {
	vars := map[string]string{}
	for name, value := range env {
		if strings.HasPrefix(name, "GOIABADA_") {
			vars[name] = value
		}
	}
	return vars
}

// The env file of hostile answers, handed to a child the way its header says, gives that child
// every answer exactly as given, under bash and under POSIX sh.
func TestHostileGolden_EnvFileReadsBackEveryAnswerThroughAShell(t *testing.T) {
	config := hostileCase(t, "hostile-env").config()
	content := descriptionOf(config)
	for _, shell := range posixShells(t) {
		t.Run(shell, func(t *testing.T) {
			env := sourceWithSetA(t, shell, content)
			for name, want := range hostileEnvWant(config) {
				if env[name] != want {
					t.Errorf("%s reads back as %q, want %q", name, env[name], want)
				}
			}
			// What the shell hands on and what systemd reads must be the same set, so neither
			// reader is shown a file the other reads differently.
			fromSystemd, _, err := systemdEnvironmentFile(content)
			if err != nil {
				t.Fatalf("the systemd emulation cannot read the file: %v", err)
			}
			if got := goiabadaVariables(env); !maps.Equal(got, fromSystemd) {
				t.Errorf("the shell hands on %d variables and the systemd rule reads %d, or their values differ",
					len(got), len(fromSystemd))
			}
		})
	}
}

// The same file read by the emulation of systemd.exec(5)'s EnvironmentFile= rule: every answer
// exactly as given, and not one assignment dropped.
func TestHostileGolden_EnvFileReadsBackEveryAnswerThroughTheSystemdRule(t *testing.T) {
	config := hostileCase(t, "hostile-env").config()
	content := descriptionOf(config)
	env, dropped, err := systemdEnvironmentFile(content)
	if err != nil {
		t.Fatalf("the systemd emulation cannot read the file: %v", err)
	}
	if len(dropped) != 0 {
		t.Errorf("systemd would drop %q", dropped)
	}
	for name, want := range hostileEnvWant(config) {
		if env[name] != want {
			t.Errorf("%s reads back as %q, want %q", name, env[name], want)
		}
	}
}

// Every env file the wizard writes is one systemd reads whole: an assignment per line that sets a
// variable, none dropped. Each line was `export KEY="value"`, which systemd reads as the key
// `export KEY` and drops, so the header's EnvironmentFile= line described a file that set nothing
// (#430).
func TestEnvFile_SystemdReadsEveryAssignment(t *testing.T) {
	for _, testCase := range goldenCases() {
		// The hostile file's values span lines, and the two tests above read it whole.
		if deployments[testCase.deployment].outputFile != "goiabada.env" || testCase.hostile {
			continue
		}
		t.Run(testCase.name, func(t *testing.T) {
			content := descriptionOf(testCase.config())
			env, dropped, err := systemdEnvironmentFile(content)
			if err != nil {
				t.Fatalf("the systemd emulation cannot read the file: %v", err)
			}
			if len(dropped) != 0 {
				t.Errorf("systemd would drop %q", dropped)
			}
			// No ordinary answer spans lines, so every line that is neither blank nor a comment
			// is one assignment.
			assignments := 0
			for _, line := range strings.Split(content, "\n") {
				if line != "" && !strings.HasPrefix(line, "#") {
					assignments++
				}
			}
			if assignments == 0 || len(env) != assignments {
				t.Errorf("systemd reads %d variables from %d assignment lines", len(env), assignments)
			}
		})
	}
}
