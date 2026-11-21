package main

import (
	"os"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/leodip/goiabada/core/docsreader"
)

// A GitOps tool applying the manifest puts back whatever a rotation changed in it, so the
// Kubernetes Secrets page tells such an operator what to suspend from what the rotations change.
// Every rotation but the one off the published sample key changes the Secrets and restarts the
// pods, and the pods read each key a rotation adds through the manifest's optional references, so
// the manifest is left as it is; the sample key's rotation alone scales the auth server to zero
// (#492 decisions 1 and 2). These guards hold the rotate page's commands and the page's GitOps
// paragraph to that, and to the manifest the wizard generates.
const (
	rotatePage            = "../../../site/src/content/docs/deploy/rotate-secrets.mdx"
	kubernetesSecretsPage = "../../../site/src/content/docs/deploy/kubernetes/secrets.mdx"
	sampleKeyRotation     = "### Off the published sample key"
	gitOpsParagraphStart  = "**When a GitOps tool applies the manifest,**"
)

// kubectlVerb is a kubectl command and what it acts on, such as `rollout restart` or `patch secret`.
var kubectlVerb = regexp.MustCompile(`kubectl ([a-z]+) ([a-z/-]+)`)

// writtenPreviousKey is a -previous key a rotation's patch writes or removes.
var writtenPreviousKey = regexp.MustCompile(`"(?:/data/)?([a-z-]+-previous)"`)

// rotationKubectl is every kubectl command a rotation runs that changes nothing the manifest sets:
// it changes a Secret, reads one, reads the ReplicaSets to find a rollout's revision, restarts the
// pods, waits for the pods of earlier revisions to stop, or runs a command in one.
var rotationKubectl = []string{"patch secret", "get secret", "get rs", "rollout restart", "rollout status", "wait -n", "exec -n"}

// TestRotateSecretsPage_OnlyTheSampleKeyRotationChangesWhatTheManifestSets: outside the sample
// key's rotation, every kubectl command on the rotate page changes a Secret, reads one, reads the
// ReplicaSets, waits for the pods, restarts them or runs a command in one, and each -previous key a rotation writes is one the generated
// manifest reads through an optional reference, so a pod starts with it present or absent and no
// Deployment edit is made. The sample key's rotation is the one that scales the auth server.
func TestRotateSecretsPage_OnlyTheSampleKeyRotationChangesWhatTheManifestSets(t *testing.T) {
	body, err := os.ReadFile(rotatePage)
	if err != nil {
		t.Fatal(err)
	}
	page := string(body)
	sample, found := docsreader.SectionText(page, sampleKeyRotation)
	if !found {
		t.Fatalf("rotate-secrets.mdx has no section headed %s", sampleKeyRotation)
	}
	stopFree := strings.Replace(page, sample, "", 1)

	for _, match := range kubectlVerb.FindAllStringSubmatch(stopFree, -1) {
		command := match[1] + " " + match[2]
		if !slices.ContainsFunc(rotationKubectl, func(allowed string) bool { return strings.HasPrefix(command, allowed) }) {
			t.Errorf("rotate-secrets.mdx: `kubectl %s` outside the sample key's rotation changes what the manifest sets, or isn't a rotation's", command)
		}
	}
	scales := false
	for _, match := range kubectlVerb.FindAllStringSubmatch(sample, -1) {
		if match[1] == "scale" && match[2] == "deployment" {
			scales = true
		}
	}
	if !scales {
		t.Errorf("rotate-secrets.mdx: the sample key's rotation scales the auth server's Deployment")
	}

	optional := map[string]bool{}
	docs := kubernetesDocuments(t, kubernetesConfig())
	for _, w := range workloads {
		containers := at[[]any](t, deploymentNamed(t, docs, w.deployment), "spec", "template", "spec", "containers")
		for _, c := range containers {
			env, _ := c.(map[string]any)["env"].([]any)
			for _, e := range env {
				valueFrom, _ := e.(map[string]any)["valueFrom"].(map[string]any)
				ref, ok := valueFrom["secretKeyRef"].(map[string]any)
				if ok && ref["optional"] == true {
					optional[ref["key"].(string)] = true
				}
			}
		}
	}
	written := writtenPreviousKey.FindAllStringSubmatch(page, -1)
	if len(written) == 0 {
		t.Fatal("rotate-secrets.mdx writes no -previous key, so this check read nothing")
	}
	for _, match := range written {
		if !optional[match[1]] {
			t.Errorf("rotate-secrets.mdx writes %s, which the generated manifest does not read through an optional reference", match[1])
		}
	}
}

// TestKubernetesSecretsPage_TheGitOpsParagraphSuspendsOnlyForTheSampleKey: the paragraph for a
// GitOps tool names replicas only for the sample key's rotation, and links to it, so an operator
// suspends the tool's sync for that rotation alone.
func TestKubernetesSecretsPage_TheGitOpsParagraphSuspendsOnlyForTheSampleKey(t *testing.T) {
	body, err := os.ReadFile(kubernetesSecretsPage)
	if err != nil {
		t.Fatal(err)
	}
	var paragraph string
	for _, line := range strings.Split(string(body), "\n") {
		if strings.HasPrefix(line, gitOpsParagraphStart) {
			paragraph = line
		}
	}
	if paragraph == "" {
		t.Fatalf("kubernetes/secrets.mdx has no paragraph starting %s", gitOpsParagraphStart)
	}
	if !strings.Contains(paragraph, "(/deploy/rotate-secrets/#off-the-published-sample-key)") {
		t.Errorf("kubernetes/secrets.mdx: the GitOps paragraph links to the sample key's rotation:\n%s", paragraph)
	}
	for _, sentence := range strings.Split(paragraph, ". ") {
		if strings.Contains(sentence, "replicas") && !strings.Contains(sentence, "sample key") {
			t.Errorf("kubernetes/secrets.mdx: the GitOps paragraph says a rotation other than the sample key's changes replicas: %q", sentence)
		}
	}
}
