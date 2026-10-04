package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/leodip/goiabada/core/guard"
	"go.yaml.in/yaml/v3"
)

// adminConsoleImage is the image reference every manifest running this binary names.
const adminConsoleImage = "leodip/goiabada:adminconsole-"

// kubernetesManifests are the setup wizard's goldens, its generator's output held to it byte for
// byte, relative to the source root. The Compose goldens and the env file among them run no
// Deployment and are passed over.
const kubernetesManifests = "cmd/goiabada-setup/testdata/*.golden"

// The variables each Kubernetes container running the admin console receives, from its ConfigMap or
// its Secret references, are variables this server reads: configVariables, which
// TestConfigSource_EveryVariableAndFlagHasARow holds to every name config.go spells. The manifest
// once handed this process the database's type, host, port, name and username, the admin email,
// the app name and the auth server's proxy settings, none of which it reads (#396 decision 13).
func TestKubernetesManifests_HandThisServerOnlyWhatItReads(t *testing.T) {
	assertContainersReceiveOnlyWhatTheyRead(t, guard.SourceRoot(t), adminConsoleImage, readVariables())
}

func TestKubernetesManifests_AnUnreadVariableFailsNamingTheFile(t *testing.T) {
	root := t.TempDir()
	writeManifestFixture(t, root, "cmd/goiabada-setup/testdata/kubernetes-shared.golden", `
apiVersion: v1
kind: ConfigMap
metadata:
  name: shared
data:
  GOIABADA_ADMINCONSOLE_BASEURL: "Goiabada"
  GOIABADA_UNREAD_FROM_MAP: "x"
---
apiVersion: v1
kind: Secret
metadata:
  name: secrets
data:
  UNREAD_FROM_SECRET: eA==
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: console
spec:
  template:
    spec:
      containers:
      - name: adminconsole
        image: leodip/goiabada:adminconsole-1.0
        envFrom:
        - configMapRef:
            name: shared
        - secretRef:
            name: secrets
          prefix: GOIABADA_
        env:
        - name: GOIABADA_ADMINCONSOLE_OAUTH_CLIENT_SECRET
          value: x
        - name: GOIABADA_UNREAD_INLINE
          value: x
      - name: unrelated
        image: busybox
        env:
        - name: GOIABADA_UNREAD_ELSEWHERE
          value: x
`)
	writeManifestFixture(t, root, "cmd/goiabada-setup/testdata/kubernetes-own.golden", `
apiVersion: v1
kind: ConfigMap
metadata:
  name: own
data:
  GOIABADA_ADMINCONSOLE_BASEURL: "Goiabada"
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: console
spec:
  template:
    spec:
      containers:
      - name: adminconsole
        image: leodip/goiabada:adminconsole-1.0
        envFrom:
        - configMapRef:
            name: own
`)
	writeManifestFixture(t, root, "cmd/goiabada-setup/testdata/production-compose.golden", `
services:
  console:
    image: leodip/goiabada:adminconsole-latest
    environment:
      - GOIABADA_UNREAD_IN_COMPOSE=x
`)
	writeManifestFixture(t, root, "cmd/goiabada-setup/testdata/native-env.golden", "NOT_YAML=\"a: b: c\"\n")

	report := guard.Run(func(r guard.Reporter) {
		assertContainersReceiveOnlyWhatTheyRead(r, root, adminConsoleImage,
			map[string]bool{"GOIABADA_ADMINCONSOLE_BASEURL": true, "GOIABADA_ADMINCONSOLE_OAUTH_CLIENT_SECRET": true})
	})

	if report.Stopped {
		t.Fatalf("the walk stopped rather than reporting: %s", report.Fatal)
	}
	text := report.Text()
	for _, want := range []string{"GOIABADA_UNREAD_FROM_MAP", "GOIABADA_UNREAD_FROM_SECRET", "GOIABADA_UNREAD_INLINE"} {
		if !strings.Contains(text, "cmd/goiabada-setup/testdata/kubernetes-shared.golden") || !strings.Contains(text, want) {
			t.Errorf("no failure names %s in kubernetes-shared.golden:\n%s", want, text)
		}
	}
	for _, unwanted := range []string{"kubernetes-own.golden", "GOIABADA_UNREAD_ELSEWHERE", "GOIABADA_UNREAD_IN_COMPOSE", "native-env.golden"} {
		if strings.Contains(text, unwanted) {
			t.Errorf("a failure names %s, which hands this server nothing it does not read:\n%s", unwanted, text)
		}
	}
	if len(report.Errors) != 3 {
		t.Errorf("%d failures, want 3:\n%s", len(report.Errors), text)
	}
}

func TestKubernetesManifests_AReferenceToAMissingConfigMapStops(t *testing.T) {
	root := t.TempDir()
	writeManifestFixture(t, root, "cmd/goiabada-setup/testdata/kubernetes-dangling.golden", `
apiVersion: apps/v1
kind: Deployment
metadata:
  name: console
spec:
  template:
    spec:
      containers:
      - name: adminconsole
        image: leodip/goiabada:adminconsole-1.0
        envFrom:
        - configMapRef:
            name: absent
`)

	report := guard.Run(func(r guard.Reporter) {
		assertContainersReceiveOnlyWhatTheyRead(r, root, adminConsoleImage, map[string]bool{})
	})

	if !report.Stopped || !strings.Contains(report.Fatal, "absent") {
		t.Errorf("a reference to a ConfigMap the manifest lacks did not stop the walk naming it: %+v", report)
	}
}

func TestKubernetesManifests_AWalkFindingNothingFails(t *testing.T) {
	root := t.TempDir()
	// A Compose golden runs the image, and no manifest does.
	writeManifestFixture(t, root, "cmd/goiabada-setup/testdata/production-sqlite.golden", `
services:
  console:
    image: leodip/goiabada:adminconsole-latest
`)

	report := guard.Run(func(r guard.Reporter) {
		assertContainersReceiveOnlyWhatTheyRead(r, root, adminConsoleImage, map[string]bool{})
	})

	if !report.Stopped || !strings.Contains(report.Fatal, kubernetesManifests) {
		t.Errorf("a source holding no manifest running the image did not stop the walk naming it: %+v", report)
	}
}

// readVariables is every GOIABADA_* variable this server loads.
func readVariables() map[string]bool {
	read := map[string]bool{}
	for _, v := range configVariables {
		read[v.env] = true
	}
	return read
}

func writeManifestFixture(t *testing.T, root, path, content string) {
	t.Helper()
	full := filepath.Join(root, filepath.FromSlash(path))
	if err := os.MkdirAll(filepath.Dir(full), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(full, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

// assertContainersReceiveOnlyWhatTheyRead is the reporting half: one failure per variable a
// container running image receives and read does not hold, and a stop when no manifest runs image.
func assertContainersReceiveOnlyWhatTheyRead(r guard.Reporter, root, image string, read map[string]bool) {
	r.Helper()
	unread, examined, err := unreadVariables(root, image, read)
	if err != nil {
		r.Fatalf("%v", err)
	}
	if examined == 0 {
		r.Fatalf("no Deployment in a file matching %s runs %s, so this test read nothing", kubernetesManifests, image)
	}
	for _, finding := range unread {
		r.Errorf("%s", finding)
	}
}

// unreadVariables reads every manifest under root and returns one line per variable a container
// running image receives that read does not hold, with how many containers it examined.
func unreadVariables(root, image string, read map[string]bool) ([]string, int, error) {
	paths, err := filepath.Glob(filepath.Join(root, filepath.FromSlash(kubernetesManifests)))
	if err != nil {
		return nil, 0, err
	}
	var unread []string
	examined := 0
	for _, path := range paths {
		content, err := os.ReadFile(path)
		if err != nil {
			return nil, 0, err
		}
		if !bytes.Contains(content, []byte(image)) {
			continue
		}
		rel, _ := filepath.Rel(root, path)
		rel = filepath.ToSlash(rel)

		received, err := receivedVariables(content, image)
		if err != nil {
			return nil, 0, fmt.Errorf("%s: %w", rel, err)
		}
		for container, names := range received {
			examined++
			for _, name := range names {
				if !read[name] {
					unread = append(unread, fmt.Sprintf("%s: the container %s receives %s, which this server does not read", rel, container, name))
				}
			}
		}
	}
	sort.Strings(unread)
	return unread, examined, nil
}

// receivedVariables reads one file as the documents it holds and returns, for each Deployment's
// container running image, every variable it receives: its env entries, and every key of each
// ConfigMap and Secret its envFrom names, under that source's prefix. Compose files hold no
// Deployment and answer nothing.
func receivedVariables(content []byte, image string) (map[string][]string, error) {
	var docs []map[string]any
	decoder := yaml.NewDecoder(bytes.NewReader(content))
	for {
		var doc map[string]any
		err := decoder.Decode(&doc)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			// The env file the wizard writes for native runs is no YAML, and names no image.
			return nil, err
		}
		docs = append(docs, doc)
	}

	keys := map[string]map[string][]string{"ConfigMap": {}, "Secret": {}}
	for _, doc := range docs {
		kind, _ := doc["kind"].(string)
		if keys[kind] == nil {
			continue
		}
		name, _ := mapAt(doc, "metadata")["name"].(string)
		keys[kind][name] = []string{}
		for _, field := range []string{"data", "stringData"} {
			for key := range mapAt(doc, field) {
				keys[kind][name] = append(keys[kind][name], key)
			}
		}
	}

	received := map[string][]string{}
	for _, doc := range docs {
		if doc["kind"] != "Deployment" {
			continue
		}
		containers, _ := mapAt(doc, "spec", "template", "spec")["containers"].([]any)
		for _, c := range containers {
			container, _ := c.(map[string]any)
			if value, _ := container["image"].(string); !strings.HasPrefix(value, image) {
				continue
			}
			label := fmt.Sprintf("%v of Deployment %v", container["name"], mapAt(doc, "metadata")["name"])
			names := []string{}
			env, _ := container["env"].([]any)
			for _, e := range env {
				entry, _ := e.(map[string]any)
				names = append(names, fmt.Sprint(entry["name"]))
			}
			sources, _ := container["envFrom"].([]any)
			for _, s := range sources {
				source, _ := s.(map[string]any)
				prefix, _ := source["prefix"].(string)
				for kind, field := range map[string]string{"ConfigMap": "configMapRef", "Secret": "secretRef"} {
					ref, ok := source[field].(map[string]any)
					if !ok {
						continue
					}
					name, _ := ref["name"].(string)
					sourceKeys, found := keys[kind][name]
					if !found {
						return nil, fmt.Errorf("the container %s reads the %s %q, which the manifest does not define", label, kind, name)
					}
					for _, key := range sourceKeys {
						names = append(names, prefix+key)
					}
				}
			}
			received[label] = names
		}
	}
	return received, nil
}

// mapAt walks a decoded document by keys, an empty mapping where a key is missing.
func mapAt(node map[string]any, keys ...string) map[string]any {
	for _, key := range keys {
		node, _ = node[key].(map[string]any)
	}
	return node
}
