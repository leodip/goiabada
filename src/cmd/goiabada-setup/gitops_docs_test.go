package main

import (
	"fmt"
	"maps"
	"os"
	"path"
	"slices"
	"strings"
	"testing"

	"github.com/leodip/goiabada/core/docsreader"
	"go.yaml.in/yaml/v3"
	"sigs.k8s.io/kustomize/api/krusty"
	"sigs.k8s.io/kustomize/kyaml/filesys"
)

// The GitOps page keeps each environment's settings as a kustomization over the manifest the
// wizard generated for it, with a component every environment shares. Its patches select their
// target by kind and name, and Kustomize builds a target-selected patch that matches nothing
// without complaint, so a manifest change that renamed the Deployment or its container would
// leave a patch doing nothing on an operator's cluster. So the page's own blocks are built here
// against every Kubernetes golden, and every patch is held to changing what it builds (#686
// section 10).
const (
	gitOpsPage      = "../../../site/src/content/docs/deploy/kubernetes/gitops.mdx"
	gitOpsSetUp     = "## Set up the repository"
	gitOpsArgoCD    = "## Argo CD"
	gitOpsFlux      = "## Flux"
	gitOpsComponent = "components/common/kustomization.yaml"
	variablesPage   = "../../../site/src/content/docs/reference/environment-variables.mdx"
)

// serverOf is the server each container of the manifest runs, as the environment variables page
// names it in a variable's "Read by".
var serverOf = map[string]string{"authserver": "auth server", "adminconsole": "admin console"}

// gitOpsGuide is what the page has an operator commit, by the path it saves each file under, and
// the objects it has them apply for Argo CD and Flux.
type gitOpsGuide struct {
	files       map[string]string
	environment string
	tools       []object
}

// readGitOpsGuide reads the files the page saves and the objects of its Argo CD and Flux sections.
// It saves the component and one environment's kustomization, whose directory is the environment.
func readGitOpsGuide(page string) (gitOpsGuide, error) {
	guide := gitOpsGuide{}
	setUp, found := docsreader.SectionText(page, gitOpsSetUp)
	if !found {
		return guide, fmt.Errorf("no %q section", gitOpsSetUp)
	}
	var patches []string
	var err error
	if guide.files, patches, err = savedBlocks(setUp); err != nil {
		return guide, fmt.Errorf("%s: %w", gitOpsSetUp, err)
	}
	if len(patches) > 0 {
		return guide, fmt.Errorf("%s adds to a kustomization's patches outside a saved file", gitOpsSetUp)
	}
	if _, ok := guide.files[gitOpsComponent]; !ok {
		return guide, fmt.Errorf("%s saves no %s", gitOpsSetUp, gitOpsComponent)
	}
	for name := range guide.files {
		if name != gitOpsComponent && path.Base(name) == "kustomization.yaml" {
			if guide.environment != "" {
				return guide, fmt.Errorf("%s saves two environments' kustomizations, %s and %s", gitOpsSetUp, guide.environment, path.Dir(name))
			}
			guide.environment = path.Dir(name)
		}
	}
	if guide.environment == "" {
		return guide, fmt.Errorf("%s saves no environment's kustomization", gitOpsSetUp)
	}
	for _, heading := range []string{gitOpsArgoCD, gitOpsFlux} {
		section, found := docsreader.SectionText(page, heading)
		if !found {
			return guide, fmt.Errorf("no %q section", heading)
		}
		for _, m := range yamlBlock.FindAllStringSubmatch(section, -1) {
			objects, err := decodeObjects(dedent(m[2], m[1]))
			if err != nil {
				return guide, fmt.Errorf("%s: a block is not YAML: %w", heading, err)
			}
			guide.tools = append(guide.tools, objects...)
		}
	}
	return guide, nil
}

func readGitOpsPage(t *testing.T) gitOpsGuide {
	t.Helper()
	page, err := os.ReadFile(gitOpsPage)
	if err != nil {
		t.Fatalf("unable to read the GitOps page: %v", err)
	}
	guide, err := readGitOpsGuide(string(page))
	if err != nil {
		t.Fatalf("%s: %v", gitOpsPage, err)
	}
	return guide
}

// buildGitOps builds the environment's kustomization over manifest, as the repository the page
// lays out holds it, with drop removed from the patches of the kustomization saved under its path,
// when given. A resource the page lists but doesn't save, such as a sealed file, is a SealedSecret
// named after the file: what it holds is the controller's business, not the build's.
func buildGitOps(guide gitOpsGuide, manifest, drop string, patch int) (string, error) {
	fs := filesys.MakeFsInMemory()
	write := func(name, content string) error { return fs.WriteFile("/repo/"+name, []byte(content)) }
	for name, content := range guide.files {
		if name == drop {
			var kustomization map[string]any
			if err := yaml.Unmarshal([]byte(content), &kustomization); err != nil {
				return "", fmt.Errorf("%s: %w", name, err)
			}
			patches, _ := kustomization["patches"].([]any)
			kustomization["patches"] = slices.Delete(slices.Clone(patches), patch, patch+1)
			dropped, err := yaml.Marshal(kustomization)
			if err != nil {
				return "", err
			}
			content = string(dropped)
		}
		if err := write(name, content); err != nil {
			return "", err
		}
	}
	if err := write(path.Join(guide.environment, "goiabada-k8s.yaml"), manifest); err != nil {
		return "", err
	}
	var kustomization struct{ Resources []string }
	if err := yaml.Unmarshal([]byte(guide.files[path.Join(guide.environment, "kustomization.yaml")]), &kustomization); err != nil {
		return "", err
	}
	for _, resource := range kustomization.Resources {
		name := path.Join(guide.environment, resource)
		if _, saved := guide.files[name]; saved || resource == "goiabada-k8s.yaml" {
			continue
		}
		stub := fmt.Sprintf("apiVersion: bitnami.com/v1alpha1\nkind: SealedSecret\nmetadata:\n  name: %s\n  namespace: goiabada\n",
			strings.TrimSuffix(resource, ".sealed.yaml"))
		if err := write(name, stub); err != nil {
			return "", err
		}
	}
	built, err := krusty.MakeKustomizer(krusty.MakeDefaultOptions()).Run(fs, "/repo/"+guide.environment)
	if err != nil {
		return "", fmt.Errorf("kustomize refuses the kustomization: %w", err)
	}
	content, err := built.AsYaml()
	return string(content), err
}

// patchCounts is the number of patches in each kustomization the page saves, by its path.
func patchCounts(guide gitOpsGuide) (map[string]int, error) {
	counts := map[string]int{}
	for name, content := range guide.files {
		if path.Base(name) != "kustomization.yaml" {
			continue
		}
		var kustomization struct{ Patches []any }
		if err := yaml.Unmarshal([]byte(content), &kustomization); err != nil {
			return nil, fmt.Errorf("%s: %w", name, err)
		}
		counts[name] = len(kustomization.Patches)
	}
	return counts, nil
}

// gitOpsFindings says what in the build of the page's environment over manifest differs from what
// its patches set out to do: a value a patch sets that the build lacks, a Deployment whose
// containers changed, or a variable a patch sets that the container's server doesn't read. A
// container patch that names no container the manifest writes adds one with no image beside it,
// and a misspelt variable is one more the server ignores: each leaves the build changed but the
// intended setting as it was. variables is the environment variables page.
func gitOpsFindings(guide gitOpsGuide, manifest, built, variables string) ([]string, error) {
	base, err := decodeObjects(manifest)
	if err != nil {
		return nil, err
	}
	result, err := decodeObjects(built)
	if err != nil {
		return nil, err
	}
	var findings []string
	for _, name := range slices.Sorted(maps.Keys(guide.files)) {
		if path.Base(name) != "kustomization.yaml" {
			continue
		}
		var kustomization struct{ Patches []struct{ Patch string } }
		if err := yaml.Unmarshal([]byte(guide.files[name]), &kustomization); err != nil {
			return nil, fmt.Errorf("%s: %w", name, err)
		}
		for i, p := range kustomization.Patches {
			patches, err := decodeObjects(p.Patch)
			if err != nil {
				return nil, fmt.Errorf("patch %d of %s: %w", i+1, name, err)
			}
			for _, patch := range patches {
				o, ok := objectNamed(result, patch.kind, patch.name)
				if !ok {
					findings = append(findings, fmt.Sprintf("patch %d of %s: the build has no %s", i+1, name, patch))
					continue
				}
				for _, missing := range uncovered(patch.doc, o.doc, "") {
					findings = append(findings, fmt.Sprintf("patch %d of %s sets %s, which the build lacks", i+1, name, missing))
				}
				for _, c := range listAt(patch.doc, "spec", "template", "spec", "containers") {
					container, _ := c.(map[string]any)
					for _, e := range listAt(container, "env") {
						variable, _ := atPath(e, "name").(string)
						if !readBy(variables, variable, serverOf[fmt.Sprint(container["name"])]) {
							findings = append(findings, fmt.Sprintf("patch %d of %s sets %s, which the environment variables page doesn't list as read by the container %v",
								i+1, name, variable, container["name"]))
						}
					}
				}
			}
		}
	}
	for _, o := range base {
		if o.kind != "Deployment" {
			continue
		}
		r, _ := objectNamed(result, o.kind, o.name)
		if before, after := containerNames(o.doc), containerNames(r.doc); !slices.Equal(before, after) {
			findings = append(findings, fmt.Sprintf("%s runs containers %v after the patches, %v before", o, after, before))
		}
	}
	return findings, nil
}

// buildOverEveryGolden builds guide's kustomizations over every Kubernetes golden, and fails on
// each finding, and on each of the patches counts gives, by kustomization, whose removal leaves
// the build as it was.
func buildOverEveryGolden(t *testing.T, guide gitOpsGuide, variables string, counts map[string]int) {
	t.Helper()
	built := 0
	for _, c := range goldenCases() {
		if c.deployment != deploymentKubernetes {
			continue
		}
		manifest := descriptionOf(c.config())
		whole, err := buildGitOps(guide, manifest, "", 0)
		if err != nil {
			t.Errorf("%s: %v", c.name, err)
			continue
		}
		built++
		findings, err := gitOpsFindings(guide, manifest, whole, variables)
		if err != nil {
			t.Errorf("%s: %v", c.name, err)
		}
		for _, finding := range findings {
			t.Errorf("%s: %s", c.name, finding)
		}
		for name, count := range counts {
			for i := range count {
				without, err := buildGitOps(guide, manifest, name, i)
				if err != nil {
					t.Errorf("%s, without patch %d of %s: %v", c.name, i+1, name, err)
					continue
				}
				if without == whole {
					t.Errorf("%s: patch %d of %s changes nothing: its target matches no object, or it sets what the manifest already has", c.name, i+1, name)
				}
			}
		}
	}
	if built == 0 {
		t.Error("no Kubernetes golden was built")
	}
}

// readBy says whether the environment variables page lists variable as read by server, or by both.
func readBy(variables, variable, server string) bool {
	for _, line := range strings.Split(variables, "\n") {
		if strings.HasPrefix(line, "| `"+variable+"`") {
			return server != "" && (strings.Contains(line, "Read by: "+server) || strings.Contains(line, "Read by: both"))
		}
	}
	return false
}

func readVariablesPage(t *testing.T) string {
	t.Helper()
	page, err := os.ReadFile(variablesPage)
	if err != nil {
		t.Fatalf("unable to read the environment variables page: %v", err)
	}
	return string(page)
}

// Every Kubernetes golden builds under the page's environment, component included, with every
// value the patches set in the container it names, and every variable one read by that server. Every patch of either changes what it builds:
// one that matched nothing would leave the build as it was without it.
func TestGitOpsDocs_EveryPatchChangesEveryGeneratedManifest(t *testing.T) {
	guide := readGitOpsPage(t)
	variables := readVariablesPage(t)
	counts, err := patchCounts(guide)
	if err != nil {
		t.Fatal(err)
	}
	if counts[gitOpsComponent] == 0 {
		t.Fatalf("%s has no patches, so the page shares nothing between environments", gitOpsComponent)
	}
	buildOverEveryGolden(t, guide, variables, counts)
}

// The Argo CD Application and the Flux Kustomization apply the environment's directory the page
// saves, and prune, which its text relies on to delete what leaves the manifest. Flux's
// Kustomization reads the page's GitRepository.
func TestGitOpsDocs_TheToolsApplyTheEnvironmentsDirectory(t *testing.T) {
	guide := readGitOpsPage(t)
	field := func(o object, keys ...string) any { return atPath(o.doc, keys...) }
	applications, kustomizations, repositories := 0, 0, map[string]bool{}
	for _, o := range guide.tools {
		if o.kind == "GitRepository" {
			repositories[o.name] = true
		}
	}
	for _, o := range guide.tools {
		switch o.kind {
		case "Application":
			applications++
			if got, _ := field(o, "spec", "source", "path").(string); path.Clean(got) != guide.environment {
				t.Errorf("the Application %s applies %q, not the environment's directory %s", o.name, got, guide.environment)
			}
			if field(o, "spec", "syncPolicy", "automated", "prune") != true {
				t.Errorf("the Application %s does not prune", o.name)
			}
		case "Kustomization":
			kustomizations++
			if got, _ := field(o, "spec", "path").(string); path.Clean(got) != guide.environment {
				t.Errorf("the Kustomization %s applies %q, not the environment's directory %s", o.name, got, guide.environment)
			}
			if field(o, "spec", "prune") != true {
				t.Errorf("the Kustomization %s does not prune", o.name)
			}
			if source, _ := field(o, "spec", "sourceRef", "name").(string); !repositories[source] {
				t.Errorf("the Kustomization %s reads the GitRepository %q, which the page does not define", o.name, source)
			}
		}
	}
	if applications != 1 || kustomizations != 1 {
		t.Errorf("the page shows %d Applications and %d Flux Kustomizations, want one of each", applications, kustomizations)
	}
}

// A patch that selects no object is a finding, the failure the first test exists to catch: a
// renamed Deployment leaves the component's patch with nothing to change.
func TestGitOpsFindings_FindAPatchThatMatchesNothing(t *testing.T) {
	guide := readGitOpsPage(t)
	manifest := descriptionOf(goldenConfig(deploymentKubernetes, "postgres"))
	renamed := strings.ReplaceAll(manifest, "name: goiabada-authserver\n", "name: goiabada-auth\n")
	whole, err := buildGitOps(guide, renamed, "", 0)
	if err != nil {
		t.Fatal(err)
	}
	without, err := buildGitOps(guide, renamed, gitOpsComponent, 0)
	if err != nil {
		t.Fatal(err)
	}
	if whole != without {
		t.Error("over a manifest whose auth server Deployment is renamed, the component's patch still changed the build")
	}
}

// A container patch whose container name is misspelt is a finding: it changes the build, and every
// value it sets is in the build, in the container of that name it adds beside the auth server's.
func TestGitOpsFindings_FindAPatchOfAContainerTheManifestDoesNotRun(t *testing.T) {
	guide := readGitOpsPage(t)
	misspelt := strings.Replace(guide.files[gitOpsComponent], "- name: authserver\n", "- name: authserer\n", 1)
	if misspelt == guide.files[gitOpsComponent] {
		t.Fatalf("%s patches no container named authserver", gitOpsComponent)
	}
	guide.files[gitOpsComponent] = misspelt
	manifest := descriptionOf(goldenConfig(deploymentKubernetes, "postgres"))
	built, err := buildGitOps(guide, manifest, "", 0)
	if err != nil {
		t.Fatal(err)
	}
	findings, err := gitOpsFindings(guide, manifest, built, readVariablesPage(t))
	if err != nil {
		t.Fatal(err)
	}
	if !slices.ContainsFunc(findings, func(f string) bool { return strings.Contains(f, "runs containers [authserver authserer]") }) {
		t.Errorf("no finding of the added container, in %q", findings)
	}
}

// A patch setting a variable whose name is misspelt is a finding: the auth server reads no such
// variable, so the setting stays at its default.
func TestGitOpsFindings_FindAVariableTheServerDoesNotRead(t *testing.T) {
	guide := readGitOpsPage(t)
	environment := path.Join(guide.environment, "kustomization.yaml")
	misspelt := strings.Replace(guide.files[environment], "GOIABADA_DB_MAX_OPEN_CONNS", "GOIABADA_DB_MAX_OPEN_CONN", 1)
	if misspelt == guide.files[environment] {
		t.Fatalf("%s sets no GOIABADA_DB_MAX_OPEN_CONNS", environment)
	}
	guide.files[environment] = misspelt
	manifest := descriptionOf(goldenConfig(deploymentKubernetes, "postgres"))
	built, err := buildGitOps(guide, manifest, "", 0)
	if err != nil {
		t.Fatal(err)
	}
	findings, err := gitOpsFindings(guide, manifest, built, readVariablesPage(t))
	if err != nil {
		t.Fatal(err)
	}
	if !slices.ContainsFunc(findings, func(f string) bool { return strings.Contains(f, "sets GOIABADA_DB_MAX_OPEN_CONN,") }) {
		t.Errorf("no finding of the misspelt variable, in %q", findings)
	}
}

// A variable the page lists as read by both servers may be set on either container, and one read
// by a single server on that server's alone.
func TestGitOpsFindings_AVariableIsReadByTheServersThePageNames(t *testing.T) {
	variables := readVariablesPage(t)
	tests := []struct {
		variable, server string
		want             bool
	}{
		{"GOIABADA_AUTHSERVER_INTERNALBASEURL", "auth server", true},
		{"GOIABADA_AUTHSERVER_INTERNALBASEURL", "admin console", true},
		{"GOIABADA_DB_MAX_OPEN_CONNS", "auth server", true},
		{"GOIABADA_DB_MAX_OPEN_CONNS", "admin console", false},
		{"GOIABADA_DB_MAX_OPEN_CONN", "auth server", false},
	}
	for _, tt := range tests {
		if got := readBy(variables, tt.variable, tt.server); got != tt.want {
			t.Errorf("readBy(%s, %s) = %v, want %v", tt.variable, tt.server, got, tt.want)
		}
	}
}
