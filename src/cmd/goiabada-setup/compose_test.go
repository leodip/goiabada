package main

import (
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

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

// composeCases are the golden cases whose output is a Compose file, failing the test when there
// are none, so a renamed deployment type cannot leave a Compose property checking nothing.
func composeCases(t *testing.T) []goldenCase {
	t.Helper()
	var cases []goldenCase
	for _, testCase := range goldenCases() {
		if testCase.deployment == deploymentLocal || testCase.deployment == deploymentProduction {
			cases = append(cases, testCase)
		}
	}
	if len(cases) == 0 {
		t.Fatal("no golden case is a Compose file, so this checks nothing")
	}
	return cases
}

// Each of our two services runs as the images' uid and gid 10001, drops every capability, cannot
// gain privileges through a setuid binary, and runs on a read-only root with /tmp on tmpfs, where
// SQLite writes the temporary files of large sorts and VACUUM: the Compose counterpart of the
// manifest's restricted securityContext, in the local file as in the production one (#396
// decisions 1 and 2).
func TestComposeFile_RunsEachServerHardened(t *testing.T) {
	for _, testCase := range composeCases(t) {
		t.Run(testCase.name, func(t *testing.T) {
			_, content := generatedConfiguration(testCase.config())
			doc := only[map[string]any](t, toAny(yamlDocuments(t, content)), "the Compose file's documents")
			for _, name := range []string{"goiabada-authserver", "goiabada-adminconsole"} {
				service := at[map[string]any](t, doc, "services", name)
				if got := at[string](t, service, "user"); got != "10001:10001" {
					t.Errorf("service %s runs as user %q, want 10001:10001", name, got)
				}
				if got := only[string](t, at[[]any](t, service, "cap_drop"), name+"'s dropped capabilities"); got != "ALL" {
					t.Errorf("service %s drops %q, want ALL", name, got)
				}
				if got := only[string](t, at[[]any](t, service, "security_opt"), name+"'s security options"); got != "no-new-privileges:true" {
					t.Errorf("service %s has security option %q, want no-new-privileges:true", name, got)
				}
				if got := at[bool](t, service, "read_only"); !got {
					t.Errorf("service %s has read_only %v, want true", name, got)
				}
				if got := only[string](t, at[[]any](t, service, "tmpfs"), name+"'s tmpfs mounts"); got != "/tmp" {
					t.Errorf("service %s mounts tmpfs at %q, want /tmp", name, got)
				}
				for _, widening := range []string{"cap_add", "privileged"} {
					if value, ok := service[widening]; ok {
						t.Errorf("service %s sets %s: %v", name, widening, value)
					}
				}
			}
		})
	}
}

// The MySQL and PostgreSQL services name the major their latest tag resolved to on 2026-10-04,
// mysql:26 and postgres:18, under a comment saying a major upgrade is not a tag edit: a database
// container on an existing data volume refuses to start once latest moves a major. SQL Server's
// 2022-latest already names its line (#396 decision 11).
func TestComposeFile_PinsTheDatabaseMajor(t *testing.T) {
	want := map[string]string{
		"mysql":    "mysql:26",
		"postgres": "postgres:18",
		"mssql":    "mcr.microsoft.com/mssql/server:2022-latest",
	}
	checked := 0
	for _, testCase := range composeCases(t) {
		config := testCase.config()
		if !config.Engine.hasServer {
			continue
		}
		t.Run(testCase.name, func(t *testing.T) {
			_, content := generatedConfiguration(config)
			doc := only[map[string]any](t, toAny(yamlDocuments(t, content)), "the Compose file's documents")
			service := config.Engine.composeService
			if got := at[string](t, doc, "services", service, "image"); got != want[testCase.engine] {
				t.Errorf("service %s runs %q, want %q", service, got, want[testCase.engine])
			}
			if testCase.engine == "mssql" {
				return
			}
			comment := imageComment(t, content, service)
			if !strings.Contains(comment, "not a tag edit") {
				t.Errorf("service %s's image has no comment saying a major upgrade is not a tag edit: %q", service, comment)
			}
		})
		checked++
	}
	if checked == 0 {
		t.Fatal("no Compose golden case runs a database server, so this checked nothing")
	}
}

// imageComment is the comment written above a service's image key.
func imageComment(t *testing.T, content, service string) string {
	t.Helper()
	var root yaml.Node
	if err := yaml.Unmarshal([]byte(content), &root); err != nil {
		t.Fatalf("yaml.v3 refuses the file: %v", err)
	}
	node := &root
	if node.Kind == yaml.DocumentNode {
		node = node.Content[0]
	}
	for _, key := range []string{"services", service, "image"} {
		found := false
		for i := 0; i+1 < len(node.Content); i += 2 {
			if node.Content[i].Value == key {
				if key == "image" {
					return node.Content[i].HeadComment
				}
				node, found = node.Content[i+1], true
				break
			}
		}
		if !found {
			t.Fatalf("no %q on the way to service %s's image", key, service)
		}
	}
	return ""
}
