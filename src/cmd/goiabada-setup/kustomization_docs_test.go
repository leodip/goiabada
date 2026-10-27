package main

import (
	"os"
	"path"
	"testing"
)

// kustomizationPages are pages whose kustomizations keep a setting over the manifest the wizard
// writes again on every run: the database pool's limit, the admin console's replicas, and a long
// migration's startup budget. Their patches select their target by kind and name, as the GitOps
// page's do, so each is held to the same: it changes every golden's build, and every value it sets
// lands in the container it names (#686).
var kustomizationPages = []string{
	"../../../site/src/content/docs/deploy/kubernetes/high-availability.mdx",
	"../../../site/src/content/docs/deploy/kubernetes/probes-and-shutdown.mdx",
}

// pageKustomizations are a page's YAML blocks that are kustomizations, each as an environment
// directory of its own holding it.
func pageKustomizations(t *testing.T, page string) []gitOpsGuide {
	t.Helper()
	content, err := os.ReadFile(page)
	if err != nil {
		t.Fatalf("unable to read %s: %v", page, err)
	}
	var guides []gitOpsGuide
	for _, m := range yamlBlock.FindAllStringSubmatch(string(content), -1) {
		block := dedent(m[2], m[1])
		objects, err := decodeObjects(block)
		if err != nil {
			t.Fatalf("%s: a block is not YAML: %v", page, err)
		}
		if len(objects) == 1 && objects[0].kind == "Kustomization" {
			guides = append(guides, gitOpsGuide{files: map[string]string{"deploy/kustomization.yaml": block}, environment: "deploy"})
		}
	}
	return guides
}

func TestKustomizationDocs_EveryPatchChangesEveryGeneratedManifest(t *testing.T) {
	variables := readVariablesPage(t)
	for _, page := range kustomizationPages {
		t.Run(path.Base(page), func(t *testing.T) {
			guides := pageKustomizations(t, page)
			patches := 0
			for _, guide := range guides {
				counts, err := patchCounts(guide)
				if err != nil {
					t.Fatal(err)
				}
				patches += counts["deploy/kustomization.yaml"]
				buildOverEveryGolden(t, guide, variables, counts)
			}
			if patches == 0 {
				t.Errorf("%s shows no kustomization with a patch", page)
			}
		})
	}
}
