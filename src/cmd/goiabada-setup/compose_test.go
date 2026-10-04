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
