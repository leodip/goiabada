package main

import (
	"os"
	"strings"
	"testing"
)

// reverseProxySample is the hand-written Compose sample for a deployment behind a reverse proxy,
// which the docs point at beside the wizard's own output.
const reverseProxySample = "../../build/docker-compose-reverse-proxy.yml"

// trustedOutput is one configuration an operator deploys from, with what each server reads from it.
type trustedOutput struct {
	name    string
	content string
	// env is each server's environment, by its variables' prefix, AUTHSERVER or ADMINCONSOLE.
	env map[string]map[string]string
	// trust is the value both servers' TRUST_PROXY_HEADERS must have, and proxies the
	// TRUSTED_PROXIES that must sit beside it when trust is "true".
	trust, proxies string
}

// wantedTrust is what each generated output must tell both servers about forwarded headers, read
// from the agreement rather than from the generators: one hop behind the gateway or the proxy on
// the host, with an explicit empty list (#396 decisions 3 and 6); 127.0.0.1 behind a reverse proxy
// on the same machine, and no trust at all with none (decision 7); and local testing, which no
// proxy fronts, trusting nothing.
func wantedTrust(t *testing.T, config *Config) (trust, proxies string) {
	t.Helper()
	switch config.Deployment.kind {
	case deploymentLocal:
		return "false", ""
	case deploymentProduction, deploymentKubernetes:
		return "true", ""
	case deploymentNative:
		if config.LocalProxy {
			return "true", "127.0.0.1"
		}
		return "false", ""
	}
	t.Fatalf("no trust is wanted for %s", config.Deployment.name)
	return "", ""
}

// serverEnvironments reads what each server is handed from a generated output, the way its reader
// does: the server's own ConfigMap, its Compose service's environment, or the one env file both
// servers load.
func serverEnvironments(t *testing.T, config *Config, content string) map[string]map[string]string {
	t.Helper()
	switch config.Deployment.outputFile {
	case "goiabada-k8s.yaml":
		envs := map[string]map[string]string{}
		for _, doc := range yamlDocuments(t, content) {
			if at[string](t, doc, "kind") != "ConfigMap" {
				continue
			}
			data := map[string]string{}
			for name, value := range at[map[string]any](t, doc, "data") {
				data[name], _ = value.(string)
			}
			switch at[string](t, doc, "metadata", "name") {
			case "goiabada-authserver-config":
				envs["AUTHSERVER"] = data
			case "goiabada-adminconsole-config":
				envs["ADMINCONSOLE"] = data
			}
		}
		return envs
	case "docker-compose.yml":
		return composeServerEnvironments(t, content)
	case "goiabada.env":
		env, _, err := systemdEnvironmentFile(content)
		if err != nil {
			t.Fatalf("the systemd emulation cannot read the file: %v", err)
		}
		return map[string]map[string]string{"AUTHSERVER": env, "ADMINCONSOLE": env}
	}
	t.Fatalf("no reader for %s", config.Deployment.outputFile)
	return nil
}

func composeServerEnvironments(t *testing.T, content string) map[string]map[string]string {
	t.Helper()
	docs := yamlDocuments(t, content)
	if len(docs) != 1 {
		t.Fatalf("%d documents, want 1", len(docs))
	}
	services := at[map[string]any](t, docs[0], "services")
	return map[string]map[string]string{
		"AUTHSERVER":   composeListEnvironment(t, at[map[string]any](t, services, "goiabada-authserver")),
		"ADMINCONSOLE": composeListEnvironment(t, at[map[string]any](t, services, "goiabada-adminconsole")),
	}
}

// trustedOutputs is every generated output, each deployment type on each engine it accepts and each
// answer to the native question, plus the hand-written reverse-proxy sample.
func trustedOutputs(t *testing.T) []trustedOutput {
	t.Helper()
	var outputs []trustedOutput
	for _, testCase := range goldenCases() {
		config := testCase.config()
		content := descriptionOf(config)
		trust, proxies := wantedTrust(t, config)
		outputs = append(outputs, trustedOutput{
			name: testCase.name, content: content, env: serverEnvironments(t, config, content),
			trust: trust, proxies: proxies,
		})
	}
	sample, err := os.ReadFile(reverseProxySample)
	if err != nil {
		t.Fatal(err)
	}
	return append(outputs, trustedOutput{
		name: reverseProxySample, content: string(sample), env: composeServerEnvironments(t, string(sample)),
		trust: "true", proxies: "",
	})
}

// Every output that trusts forwarded headers says whom it trusts: each server's
// TRUST_PROXY_HEADERS set to true has its TRUSTED_PROXIES on the next line, under a comment saying
// how the client is read from X-Forwarded-For, so the one can never be emitted without the other,
// and each output trusts what is correct for its topology (#396 decisions 3, 6 and 7).
func TestEveryOutput_PairsTrustWithTheProxiesItTrusts(t *testing.T) {
	outputs := trustedOutputs(t)
	paired := 0
	for _, output := range outputs {
		t.Run(output.name, func(t *testing.T) {
			lines := strings.Split(output.content, "\n")
			for _, server := range []string{"AUTHSERVER", "ADMINCONSOLE"} {
				trustName := "GOIABADA_" + server + "_TRUST_PROXY_HEADERS"
				proxiesName := "GOIABADA_" + server + "_TRUSTED_PROXIES"
				env := output.env[server]
				if env == nil {
					t.Fatalf("no environment for the %s", server)
				}
				if got, ok := env[trustName]; !ok || got != output.trust {
					t.Errorf("%s is %q (set: %v), want %q", trustName, got, ok, output.trust)
				}
				if output.trust != "true" {
					continue
				}
				if got, ok := env[proxiesName]; !ok || got != output.proxies {
					t.Errorf("%s is %q (set: %v), want %q beside %s", proxiesName, got, ok, output.proxies, trustName)
				}

				named := 0
				for i, line := range lines {
					if !strings.Contains(line, trustName) {
						continue
					}
					named++
					if i+1 >= len(lines) || !strings.Contains(lines[i+1], proxiesName) {
						t.Errorf("line %d sets %s and the next line does not set %s", i+1, trustName, proxiesName)
					}
					if comment := commentAbove(lines, i); !strings.Contains(comment, "X-Forwarded-For") {
						t.Errorf("line %d sets %s under no comment saying how the client is read from X-Forwarded-For: %q",
							i+1, trustName, comment)
					}
				}
				if named == 0 {
					t.Errorf("no line names %s", trustName)
				}
				paired++
			}
		})
	}
	if len(outputs) == 0 || paired == 0 {
		t.Fatalf("%d outputs and %d pairs, so this checked nothing", len(outputs), paired)
	}
}

// Behind a reverse proxy on the same machine both servers listen on 127.0.0.1 alone, the address
// the native docs proxy to, so nothing past the proxy reaches the plain HTTP it serves; with none
// they listen on every interface, and a comment names the settings that serve HTTPS directly
// (#396 decision 7).
func TestEnvFile_ListensOnLoopbackOnlyBehindALocalProxy(t *testing.T) {
	checked := map[bool]int{}
	for _, testCase := range goldenCases() {
		config := testCase.config()
		if config.Deployment.kind != deploymentNative || testCase.hostile {
			continue
		}
		t.Run(testCase.name, func(t *testing.T) {
			content := descriptionOf(config)
			env, _, err := systemdEnvironmentFile(content)
			if err != nil {
				t.Fatalf("the systemd emulation cannot read the file: %v", err)
			}
			want := "0.0.0.0"
			if config.LocalProxy {
				want = "127.0.0.1"
			}
			for _, server := range []string{"AUTHSERVER", "ADMINCONSOLE"} {
				name := "GOIABADA_" + server + "_LISTEN_HOST_HTTP"
				if env[name] != want {
					t.Errorf("%s is %q, want %q", name, env[name], want)
				}
				if config.LocalProxy {
					continue
				}
				for _, setting := range []string{"GOIABADA_" + server + "_CERTFILE", "GOIABADA_" + server + "_KEYFILE"} {
					if !commentNames(content, setting) {
						t.Errorf("no comment names %s, which serves HTTPS directly", setting)
					}
				}
			}
			checked[config.LocalProxy]++
		})
	}
	if checked[true] == 0 || checked[false] == 0 {
		t.Fatalf("checked %d files behind a local proxy and %d without one; want both answers", checked[true], checked[false])
	}
}

// commentAbove is the block of comment lines directly above line i, joined by spaces.
func commentAbove(lines []string, i int) string {
	var block []string
	for j := i - 1; j >= 0 && strings.HasPrefix(strings.TrimSpace(lines[j]), "#"); j-- {
		block = append([]string{strings.TrimSpace(lines[j])}, block...)
	}
	return strings.Join(block, " ")
}

// commentNames says whether a comment line of the file names the setting.
func commentNames(content, setting string) bool {
	for _, line := range strings.Split(content, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "#") && strings.Contains(line, setting) {
			return true
		}
	}
	return false
}
