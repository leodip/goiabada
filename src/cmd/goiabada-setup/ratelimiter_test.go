package main

import (
	"strings"
	"testing"
)

// rateLimiterVariable is the auth server's switch for its built-in rate limiter, off in the server
// by default.
const rateLimiterVariable = "GOIABADA_AUTHSERVER_RATELIMITER_ENABLED"

// rateLimitsDocs is where the limits the switch turns on are listed.
const rateLimitsDocs = "https://goiabada.dev/reference/environment-variables/#rate-limits"

// Production Compose, native binaries and Kubernetes write the rate limiter's switch explicitly,
// on or off as answered, to the auth server alone, under a comment saying what it turns on and where
// the limits are documented. Local testing never asks, and leaves the server's own default, off
// (#396 decision 9).
func TestEveryAskingOutput_WritesTheRateLimiterExplicitly(t *testing.T) {
	checked := map[deploymentType]map[bool]int{}
	for _, testCase := range goldenCases() {
		config := testCase.config()
		t.Run(testCase.name, func(t *testing.T) {
			content := descriptionOf(config)
			env := serverEnvironments(t, config, content)
			kind := config.Deployment.kind

			if kind == deploymentLocal {
				if strings.Contains(content, rateLimiterVariable) {
					t.Errorf("local testing names %s, which it never asks about", rateLimiterVariable)
				}
				return
			}

			want := map[bool]string{true: "true", false: "false"}[config.RateLimiter]
			if got, ok := env["AUTHSERVER"][rateLimiterVariable]; !ok || got != want {
				t.Errorf("the auth server's %s is %q (set: %v), want %q", rateLimiterVariable, got, ok, want)
			}
			// The native binaries load one env file between them, so only the outputs that hand each
			// server its own environment can keep the switch from the admin console.
			if kind != deploymentNative {
				if _, ok := env["ADMINCONSOLE"][rateLimiterVariable]; ok {
					t.Errorf("the admin console is handed %s, which it does not read", rateLimiterVariable)
				}
			}

			lines := strings.Split(content, "\n")
			named := 0
			for i, line := range lines {
				if strings.HasPrefix(strings.TrimSpace(line), "#") || !strings.Contains(line, rateLimiterVariable) {
					continue
				}
				named++
				comment := commentAbove(lines, i)
				for _, said := range []string{"rate limit", rateLimitsDocs} {
					if !strings.Contains(comment, said) {
						t.Errorf("line %d sets %s under a comment that does not say %q: %q", i+1, rateLimiterVariable, said, comment)
					}
				}
			}
			if named != 1 {
				t.Errorf("%d lines set %s, want 1", named, rateLimiterVariable)
			}

			if checked[kind] == nil {
				checked[kind] = map[bool]int{}
			}
			checked[kind][config.RateLimiter]++
		})
	}
	for _, kind := range []deploymentType{deploymentProduction, deploymentNative, deploymentKubernetes} {
		if checked[kind][true] == 0 || checked[kind][false] == 0 {
			t.Errorf("%s was checked %d times on and %d off; want both answers", deployments[kind].name, checked[kind][true], checked[kind][false])
		}
	}
}
