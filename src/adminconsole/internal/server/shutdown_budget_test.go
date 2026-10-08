package server

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/leodip/goiabada/core/guard"
	"go.yaml.in/yaml/v3"
)

// adminConsoleImage is the image reference every deployment file running this binary names, the
// generator's `adminconsole-<tag>` and the samples' `adminconsole-latest` alike.
const adminConsoleImage = "leodip/goiabada:adminconsole-"

// deploymentSources are the deployment files a platform runs this binary from, relative to the
// source root: the setup wizard's goldens, which are its generator's output held to it byte for
// byte, and the sample Compose files under src/build. Each must hold at least one file running the
// binary, so a source moved or emptied fails the test rather than leaving it nothing to read.
var deploymentSources = []string{
	"cmd/goiabada-setup/testdata/*.golden",
	"build/docker-compose-*.yml",
}

// The platform's own grace periods, which a file that sets none gets: Compose's stop_grace_period
// and Kubernetes' terminationGracePeriodSeconds.
const (
	composeDefaultGrace    = 10 * time.Second
	kubernetesDefaultGrace = 30 * time.Second
)

// headroom is what every deployment file gives over the budget, for the signal's delivery and the
// last records: the "plus 10s of headroom" the generator's two grace-period constants, the comment
// each golden and sample file carries and the Kubernetes Probes and shutdown page all state. It is
// a floor here so that a raised shutdown constant cannot spend it with every one of those still
// saying 10s.
const headroom = 10 * time.Second

// Every deployment file running the admin console gives it the time its stop can take, which is
// its listeners' drain, and the headroom over it: Compose's stop_grace_period, and in Kubernetes
// the pod's grace period less the preStop pause, which counts against it. Raising
// httpShutdownTimeout by any amount fails here until the generator, its goldens and the sample
// files follow (#390 decision 3). The auth server holds the same files to its own budget from its
// own tier, and since every file gives both binaries the auth server's ceiling (decision 4), it is
// that tier a small raise fails first; this one is the floor the admin console's own stop owes.
func TestDeploymentFiles_GracePeriodsCoverTheShutdownBudget(t *testing.T) {
	assertGracePeriodsCover(t, guard.SourceRoot(t), adminConsoleImage, httpShutdownTimeout)
}

func TestDeploymentFiles_AShortGracePeriodFailsNamingTheFile(t *testing.T) {
	root := t.TempDir()
	writeDeploymentFixture(t, root, "build/docker-compose-short.yml", `
services:
  console:
    image: leodip/goiabada:adminconsole-latest
    stop_grace_period: 14s
  unrelated:
    image: postgres:18
`)
	writeDeploymentFixture(t, root, "build/docker-compose-default.yml", `
services:
  console:
    image: leodip/goiabada:adminconsole-latest
`)
	// 20 covers the budget, and not the headroom over it.
	writeDeploymentFixture(t, root, "build/docker-compose-budget-only.yml", `
services:
  console:
    image: leodip/goiabada:adminconsole-latest
    stop_grace_period: 20s
`)
	writeDeploymentFixture(t, root, "build/docker-compose-enough.yml", `
services:
  console:
    image: leodip/goiabada:adminconsole-latest
    stop_grace_period: 25s
`)
	// 40 covers the budget and the headroom alone, and not once the 20-second pause is taken from it.
	writeDeploymentFixture(t, root, "cmd/goiabada-setup/testdata/kubernetes-pause.golden", `
apiVersion: v1
kind: Namespace
metadata:
  name: goiabada
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: console
spec:
  template:
    spec:
      terminationGracePeriodSeconds: 40
      containers:
      - name: adminconsole
        image: leodip/goiabada:adminconsole-1.0
        lifecycle:
          preStop:
            sleep:
              seconds: 20
`)
	writeDeploymentFixture(t, root, "cmd/goiabada-setup/testdata/local-env.golden", "NOT_YAML=\"a: b: c\"\n")

	report := guard.Run(func(r guard.Reporter) {
		assertGracePeriodsCover(r, root, adminConsoleImage, 15*time.Second)
	})

	if report.Stopped {
		t.Fatalf("the walk stopped rather than reporting: %s", report.Fatal)
	}
	text := report.Text()
	for _, want := range []string{
		"build/docker-compose-short.yml",
		"build/docker-compose-budget-only.yml",
		"build/docker-compose-default.yml",
		"cmd/goiabada-setup/testdata/kubernetes-pause.golden",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("no failure names %s:\n%s", want, text)
		}
	}
	for _, unwanted := range []string{"docker-compose-enough.yml", "local-env.golden", "unrelated"} {
		if strings.Contains(text, unwanted) {
			t.Errorf("a failure names %s, which covers the budget and the headroom or runs no admin console:\n%s", unwanted, text)
		}
	}
	if len(report.Errors) != 4 {
		t.Errorf("%d failures, want 4:\n%s", len(report.Errors), text)
	}
}

func TestDeploymentFiles_AWalkFindingNothingFails(t *testing.T) {
	root := t.TempDir()
	// The goldens are there; the sample files are not.
	writeDeploymentFixture(t, root, "cmd/goiabada-setup/testdata/production-sqlite.golden", `
services:
  console:
    image: leodip/goiabada:adminconsole-latest
    stop_grace_period: 20s
`)

	report := guard.Run(func(r guard.Reporter) {
		assertGracePeriodsCover(r, root, adminConsoleImage, 15*time.Second)
	})

	if !report.Stopped || !strings.Contains(report.Fatal, "build/docker-compose-*.yml") {
		t.Errorf("a source holding no deployment file did not stop the walk naming it: %+v", report)
	}
}

func writeDeploymentFixture(t *testing.T, root, path, content string) {
	t.Helper()
	full := filepath.Join(root, filepath.FromSlash(path))
	if err := os.MkdirAll(filepath.Dir(full), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(full, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

// assertGracePeriodsCover is the reporting half: one failure per file falling short, and a stop
// when a source holds no file running the binary.
func assertGracePeriodsCover(r guard.Reporter, root, image string, budget time.Duration) {
	r.Helper()
	for _, source := range deploymentSources {
		shortfalls, examined, err := gracePeriodShortfalls(root, source, image, budget)
		if err != nil {
			r.Fatalf("%v", err)
		}
		if examined == 0 {
			r.Fatalf("no file matching %s runs %s, so this test read nothing there", source, image)
		}
		for _, shortfall := range shortfalls {
			r.Errorf("%s", shortfall)
		}
	}
}

// gracePeriodShortfalls reads every file matching pattern under root that names image, and returns
// one line per service or Deployment running it whose grace period does not cover budget plus the headroom, with
// how many files it read.
func gracePeriodShortfalls(root, pattern, image string, budget time.Duration) ([]string, int, error) {
	paths, err := filepath.Glob(filepath.Join(root, filepath.FromSlash(pattern)))
	if err != nil {
		return nil, 0, err
	}
	var shortfalls []string
	examined := 0
	for _, path := range paths {
		content, err := os.ReadFile(path)
		if err != nil {
			return nil, 0, err
		}
		// The env file the wizard writes for native runs names no image and sets no grace period.
		if !bytes.Contains(content, []byte(image)) {
			continue
		}
		examined++
		rel, _ := filepath.Rel(root, path)
		rel = filepath.ToSlash(rel)

		short, running, err := shortfallsIn(content, image, budget)
		if err != nil {
			return nil, 0, fmt.Errorf("%s: %w", rel, err)
		}
		if running == 0 {
			return nil, 0, fmt.Errorf("%s names %s and no service or container runs it", rel, image)
		}
		for _, s := range short {
			shortfalls = append(shortfalls, rel+": "+s)
		}
	}
	return shortfalls, examined, nil
}

// shortfallsIn reads one deployment file, Compose or a Kubernetes manifest, as the documents it
// holds, and returns its shortfalls with how many services or containers in it run image.
func shortfallsIn(content []byte, image string, budget time.Duration) ([]string, int, error) {
	var shortfalls []string
	running := 0
	decoder := yaml.NewDecoder(bytes.NewReader(content))
	for {
		var doc map[string]any
		err := decoder.Decode(&doc)
		if errors.Is(err, io.EOF) {
			return shortfalls, running, nil
		}
		if err != nil {
			return nil, 0, err
		}
		if services, ok := doc["services"].(map[string]any); ok {
			for name, s := range services {
				service, _ := s.(map[string]any)
				if !imageIs(service, image) {
					continue
				}
				running++
				grace := composeDefaultGrace
				if value, ok := service["stop_grace_period"]; ok {
					if grace, err = time.ParseDuration(fmt.Sprint(value)); err != nil {
						return nil, 0, fmt.Errorf("service %s: stop_grace_period %v: %w", name, value, err)
					}
				}
				if grace < budget+headroom {
					shortfalls = append(shortfalls, fmt.Sprintf(
						"service %s stops within stop_grace_period %s, short of the %s its shutdown can take "+
							"plus %s of headroom",
						name, grace, budget, headroom))
				}
			}
		}
		if doc["kind"] == "Deployment" {
			podSpec := mapAt(doc, "spec", "template", "spec")
			containers, _ := podSpec["containers"].([]any)
			for _, c := range containers {
				container, _ := c.(map[string]any)
				if !imageIs(container, image) {
					continue
				}
				running++
				grace := kubernetesDefaultGrace
				if value, ok := podSpec["terminationGracePeriodSeconds"]; ok {
					seconds, isInt := value.(int)
					if !isInt {
						return nil, 0, fmt.Errorf("the Deployment %v: terminationGracePeriodSeconds %v is no number of seconds",
							mapAt(doc, "metadata")["name"], value)
					}
					grace = time.Duration(seconds) * time.Second
				}
				pause, err := preStopPause(container)
				if err != nil {
					return nil, 0, fmt.Errorf("the Deployment %v: %w", mapAt(doc, "metadata")["name"], err)
				}
				if grace < budget+headroom+pause {
					shortfalls = append(shortfalls, fmt.Sprintf(
						"Deployment %v gives its pod terminationGracePeriodSeconds %s, short of the %s preStop pause "+
							"plus the %s its shutdown can take plus %s of headroom",
						mapAt(doc, "metadata")["name"], grace, pause, budget, headroom))
				}
			}
		}
	}
}

// preStopPause is how long a container's preStop hook holds the signal back, which Kubernetes counts
// against the pod's grace period. Only the sleep action states its length, so any other hook is
// refused rather than read as no pause.
func preStopPause(container map[string]any) (time.Duration, error) {
	preStop, ok := mapAt(container, "lifecycle")["preStop"].(map[string]any)
	if !ok {
		return 0, nil
	}
	seconds, ok := mapAt(preStop, "sleep")["seconds"].(int)
	if !ok {
		return 0, fmt.Errorf("a preStop hook other than a sleep, whose length this test cannot read: %v", preStop)
	}
	return time.Duration(seconds) * time.Second, nil
}

func imageIs(node map[string]any, image string) bool {
	value, _ := node["image"].(string)
	return strings.HasPrefix(value, image)
}

// mapAt walks a decoded document by keys, an empty mapping where a key is missing.
func mapAt(node map[string]any, keys ...string) map[string]any {
	for _, key := range keys {
		node, _ = node[key].(map[string]any)
	}
	return node
}
