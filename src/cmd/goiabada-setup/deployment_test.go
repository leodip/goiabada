package main

import (
	"slices"
	"strconv"
	"strings"
	"testing"
)

// deployments is indexed by deploymentType, so a row out of place would answer for another type.
func TestDeployments_EachRowSitsAtItsKind(t *testing.T) {
	kinds := []deploymentType{deploymentLocal, deploymentProduction, deploymentKubernetes, deploymentNative}
	if len(deployments) != len(kinds) {
		t.Fatalf("%d rows for %d deployment types", len(deployments), len(kinds))
	}
	for _, kind := range kinds {
		if got := deployments[kind].kind; got != kind {
			t.Errorf("row %d is kind %d", kind, got)
		}
	}
}

func TestDeployments_EveryRowIsComplete(t *testing.T) {
	for i, d := range deployments {
		t.Run(d.name, func(t *testing.T) {
			if want := strconv.Itoa(i + 1); d.number != want {
				t.Errorf("number is %s at menu position %s", d.number, want)
			}
			for field, value := range map[string]string{
				"name": d.name, "menuLabel": d.menuLabel, "displayName": d.displayName, "outputFile": d.outputFile,
			} {
				if value == "" {
					t.Errorf("%s is empty", field)
				}
			}
			if d.generate == nil {
				t.Errorf("generate is nil")
			}
			if d.printInstructions == nil {
				t.Errorf("printInstructions is nil")
			}
		})
	}
}

// The --type values and menu numbers operators type today, each resolving to its type in any case.
func TestDeployments_EveryNameAliasAndNumberResolvesToItsRow(t *testing.T) {
	want := map[deploymentType][]string{
		deploymentLocal:      {"local", "1"},
		deploymentProduction: {"production", "2"},
		deploymentKubernetes: {"kubernetes", "k8s", "3"},
		deploymentNative:     {"native", "binaries", "4"},
	}

	owner := map[string]string{}
	for _, d := range deployments {
		values := append([]string{d.name, d.number}, d.aliases...)
		if len(values) != len(want[d.kind]) {
			t.Errorf("%s answers to %v, want %v", d.name, values, want[d.kind])
		}
		for _, value := range values {
			if other, taken := owner[value]; taken {
				t.Errorf("%q names both %s and %s", value, other, d.name)
			}
			owner[value] = d.name
		}
	}

	for kind, values := range want {
		for _, value := range values {
			for _, spelling := range []string{value, strings.ToUpper(value)} {
				got, ok := resolveDeployment(spelling)
				if !ok || got.kind != kind {
					t.Errorf("resolveDeployment(%q) = %v, %v, want %s", spelling, got, ok, deployments[kind].name)
				}
			}
		}
	}

	for _, value := range []string{"", "5", "0", "docker", "kube"} {
		if got, ok := resolveDeployment(value); ok {
			t.Errorf("resolveDeployment(%q) = %s, want no type", value, got.name)
		}
	}
}

// What each type asks and how its Compose services listen, as main read it from "1" to "4" before
// the table: only local testing skips the URLs, only Kubernetes asks for a namespace, Kubernetes
// and native binaries reach the operator's own database, and production sits behind a proxy.
func TestDeployments_StepFacts(t *testing.T) {
	facts := func(d *deployment) map[string]bool {
		return map[string]bool{
			"asksURLs": d.asksURLs, "asksNamespace": d.asksNamespace,
			"externalDatabase": d.externalDatabase, "behindProxy": d.behindProxy,
			"asksLocalProxy": d.asksLocalProxy,
		}
	}
	want := map[deploymentType][]string{
		deploymentLocal:      nil,
		deploymentProduction: {"asksURLs", "behindProxy"},
		deploymentKubernetes: {"asksURLs", "asksNamespace", "externalDatabase"},
		deploymentNative:     {"asksURLs", "externalDatabase", "asksLocalProxy"},
	}
	for kind, wantTrue := range want {
		d := deployments[kind]
		for fact, got := range facts(d) {
			if expected := slices.Contains(wantTrue, fact); got != expected {
				t.Errorf("%s: %s is %v, want %v", d.name, fact, got, expected)
			}
		}
	}
}

// A pod's filesystem is not where an auth server's only copy of its data can live, so Kubernetes
// takes every engine with a server and refuses SQLite; every other type takes all four.
func TestDeployments_KubernetesRefusesSQLite(t *testing.T) {
	for _, d := range deployments {
		for _, e := range engines {
			want := d.kind != deploymentKubernetes || e.name != "sqlite"
			if got := d.accepts(e); got != want {
				t.Errorf("%s accepts %s: %v, want %v", d.name, e.name, got, want)
			}
			if got := slices.Contains(d.acceptedEngines(), e); got != want {
				t.Errorf("%s's database menu offers %s: %v, want %v", d.name, e.name, got, want)
			}
		}
	}
}

// The database prompt reads "Select database [1-n]" and accepts the numbers it lists, so a type's
// menu is numbered 1 to n with no gap: leaving SQLite out must not leave a hole.
func TestDeployments_EachEngineMenuIsNumberedWithoutAGap(t *testing.T) {
	for _, d := range deployments {
		for i, e := range d.acceptedEngines() {
			if want := strconv.Itoa(i + 1); e.number != want {
				t.Errorf("%s's database menu lists %s as %s at position %s", d.name, e.name, e.number, want)
			}
		}
	}
}
