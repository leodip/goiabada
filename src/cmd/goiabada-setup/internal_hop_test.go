package main

import (
	"strings"
	"testing"
)

// Every generated Compose file and Kubernetes manifest points the admin console at the auth server
// over plain HTTP, and says so on the line above each GOIABADA_AUTHSERVER_INTERNALBASEURL it writes:
// what crosses that hop and what it assumes of the network (#505). The env file of native binaries
// writes the public URL instead, whatever its scheme, and carries no such line.
func TestGeneratedFiles_SayTheInternalHopIsPlainHTTP(t *testing.T) {
	const comment = "# Plain HTTP: the admin console's secret and tokens cross this hop unencrypted, so it assumes a network you trust."

	checked := 0
	for _, testCase := range goldenCases() {
		t.Run(testCase.name, func(t *testing.T) {
			lines := strings.Split(descriptionOf(testCase.config()), "\n")
			if testCase.deployment == deploymentNative {
				for _, line := range lines {
					if strings.TrimSpace(line) == comment {
						t.Errorf("the env file says the internal hop is plain HTTP, but it writes the public URL")
					}
				}
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
