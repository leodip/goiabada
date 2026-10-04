package main

import "testing"

// Every generated Compose file gives both servers 60 seconds to stop, where Compose's default of 10
// cut the auth server's 50-second stop short: one value for both, since a grace period is a
// ceiling and the admin console exits once its own drain is done (#390 decision 4).
func TestComposeFile_GivesEachServerTimeToStop(t *testing.T) {
	checked := 0
	for _, testCase := range goldenCases() {
		if testCase.deployment != deploymentLocal && testCase.deployment != deploymentProduction {
			continue
		}
		t.Run(testCase.name, func(t *testing.T) {
			_, content := generatedConfiguration(testCase.config())
			doc := only[map[string]any](t, toAny(yamlDocuments(t, content)), "the Compose file's documents")
			for _, name := range []string{"goiabada-authserver", "goiabada-adminconsole"} {
				if got := at[string](t, doc, "services", name, "stop_grace_period"); got != "60s" {
					t.Errorf("service %s has stop_grace_period %q, want 60s", name, got)
				}
			}
		})
		checked++
	}
	if checked == 0 {
		t.Fatal("no golden case is a Compose file, so this checked nothing")
	}
}

func toAny(docs []map[string]any) []any {
	list := make([]any, len(docs))
	for i, doc := range docs {
		list[i] = doc
	}
	return list
}

// Every generated Compose file gives the auth server five minutes to start before a failed
// healthcheck counts, where its 10-second start period and three failures 10 seconds apart turned a
// seeding or migrating start unhealthy at about 40 seconds and left the admin console, which waits
// for it to be healthy, never started. The interval stays 10 seconds, so the admin console starts
// within one of the auth server answering (#390 decision 5).
func TestComposeFile_GivesTheAuthServerTimeToStart(t *testing.T) {
	checked := 0
	for _, testCase := range goldenCases() {
		if testCase.deployment != deploymentLocal && testCase.deployment != deploymentProduction {
			continue
		}
		t.Run(testCase.name, func(t *testing.T) {
			_, content := generatedConfiguration(testCase.config())
			doc := only[map[string]any](t, toAny(yamlDocuments(t, content)), "the Compose file's documents")
			healthcheck := at[map[string]any](t, doc, "services", "goiabada-authserver", "healthcheck")
			if got := at[string](t, healthcheck, "start_period"); got != "300s" {
				t.Errorf("the auth server's healthcheck has start_period %q, want 300s", got)
			}
			if got := at[string](t, healthcheck, "interval"); got != "10s" {
				t.Errorf("the auth server's healthcheck has interval %q, want 10s", got)
			}
			if _, ok := healthcheck["start_interval"]; ok {
				t.Errorf("the auth server's healthcheck sets start_interval, which Docker Engine before 25 refuses")
			}
			if got := at[string](t, doc, "services", "goiabada-adminconsole", "depends_on", "goiabada-authserver", "condition"); got != "service_healthy" {
				t.Errorf("the admin console waits for the auth server's condition %q, want service_healthy", got)
			}
		})
		checked++
	}
	if checked == 0 {
		t.Fatal("no golden case is a Compose file, so this checked nothing")
	}
}
