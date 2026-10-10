package main

import (
	"strings"
	"testing"
)

// Every generated Compose file and Kubernetes manifest points the admin console at the auth server
// over plain HTTP, and says so on the line above each GOIABADA_AUTHSERVER_INTERNALBASEURL it writes:
// what crosses that hop and what it assumes of the network (#505). The env file of native binaries
// carries no such line: with a reverse proxy on the machine it writes the auth server's loopback
// listener, under a line saying the hop never leaves the machine, and without one the public URL,
// under a line saying the admin console waits for its HTTPS (#542).
func TestGeneratedFiles_SayTheInternalHopIsPlainHTTP(t *testing.T) {
	const comment = "# Plain HTTP: the admin console's secret and tokens cross this hop unencrypted, so it assumes a network you trust."

	checked := 0
	for _, testCase := range goldenCases() {
		t.Run(testCase.name, func(t *testing.T) {
			lines := strings.Split(descriptionOf(testCase.config()), "\n")
			if testCase.deployment == deploymentNative {
				checkNativeInternalURL(t, lines, testCase.config())
				return
			}
			found := 0
			for i, line := range lines {
				if !strings.Contains(line, "GOIABADA_AUTHSERVER_INTERNALBASEURL") {
					continue
				}
				found++
				if !strings.Contains(line, "http://goiabada-authserver:9090") {
					t.Errorf("line %d sets the internal URL as %q, which the comment does not describe", i+1, line)
				}
				if i == 0 || strings.TrimSpace(lines[i-1]) != comment {
					t.Errorf("line %d, %q, is not under the comment saying the hop is plain HTTP", i+1, strings.TrimSpace(line))
				}
			}
			// Both services of a Compose file, both ConfigMaps of a manifest.
			if found != 2 {
				t.Errorf("found the internal URL %d times, want 2", found)
			}
		})
		checked++
	}
	if checked == 0 {
		t.Fatal("no golden case, so this checked nothing")
	}
}

// checkNativeInternalURL holds an env file's one GOIABADA_AUTHSERVER_INTERNALBASEURL to the address the
// admin console can reach before the reverse proxy exists: the loopback listener with a local proxy,
// since the admin console waits for the auth server before it listens, and the public URL without
// one, where the auth server serves HTTPS itself. Each sits under the line saying which.
func checkNativeInternalURL(t *testing.T, lines []string, config *Config) {
	t.Helper()
	want, above := `GOIABADA_AUTHSERVER_INTERNALBASEURL="http://127.0.0.1:9090"`, "plain HTTP that never leaves"
	if !config.LocalProxy {
		want, above = "GOIABADA_AUTHSERVER_INTERNALBASEURL="+envQuote(config.AuthServerURL), "until the auth server serves HTTPS there."
	}
	found := 0
	for i, line := range lines {
		if strings.TrimSpace(line) == "# Plain HTTP: the admin console's secret and tokens cross this hop unencrypted, so it assumes a network you trust." {
			t.Errorf("line %d: the env file carries the Compose file's plain HTTP line", i+1)
		}
		if !strings.HasPrefix(line, "GOIABADA_AUTHSERVER_INTERNALBASEURL=") {
			continue
		}
		found++
		if line != want {
			t.Errorf("line %d sets %q, want %q", i+1, line, want)
		}
		if i < 2 || !strings.Contains(lines[i-2]+lines[i-1], above) {
			t.Errorf("line %d is not under the line saying %q", i+1, above)
		}
	}
	if found != 1 {
		t.Errorf("found the internal URL %d times, want 1", found)
	}
}
