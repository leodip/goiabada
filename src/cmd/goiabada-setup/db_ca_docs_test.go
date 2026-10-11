package main

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// The Kubernetes pages tell an operator where the manifest keeps the database's CA and how to
// change it, held here to the manifest the wizard writes, so a renamed ConfigMap, a moved mount or
// another restart command fails until the pages say so (#502 decision 8).
const (
	kubernetesSecurityPage = "../../../site/src/content/docs/deploy/kubernetes/security.mdx"
	kubernetesOverviewPage = "../../../site/src/content/docs/deploy/kubernetes/overview.mdx"
	databaseCAHeading      = "## Check the database's certificate"
)

// restartInManifest is the restart command the CA ConfigMap's comment gives.
var restartInManifest = regexp.MustCompile(`(?m)^#\s+(kubectl rollout restart .+)$`)

func TestKubernetesDocs_SayWhereTheDatabaseCALivesAndHowToChangeIt(t *testing.T) {
	config := goldenConfig(deploymentKubernetes, "postgres")
	config.DBTLSMode, config.DBTLSCAFile, config.DBTLSCA = "verify-full", "/home/operator/db-ca.pem", goldenCA()
	manifest := generateKubernetesManifests(config, deployments[deploymentKubernetes].defaultPaths())

	restart := restartInManifest.FindStringSubmatch(manifest)
	if restart == nil {
		t.Fatal("the CA ConfigMap's comment gives no restart command")
	}
	named := []string{
		"name: " + dbCAConfigMap,
		"mountPath: " + dbCAMountDir,
		"GOIABADA_DB_TLS_CA_FILE: " + yamlQuote(dbCAFileInPod),
		"  " + dbCAFileName + ": |",
	}
	for _, line := range named {
		if !strings.Contains(manifest, line) {
			t.Fatalf("the manifest no longer writes %q, which this test reads the page against", line)
		}
	}

	page, err := os.ReadFile(kubernetesSecurityPage)
	if err != nil {
		t.Fatalf("unable to read the Kubernetes security page: %v", err)
	}
	section, found := sectionText(page, databaseCAHeading)
	if !found {
		t.Fatalf("%s has no %q section", kubernetesSecurityPage, databaseCAHeading)
	}
	for _, want := range []string{
		"`" + dbCAConfigMap + "`",
		"`" + dbCAFileInPod + "`",
		"`" + dbCAMountDir + "`",
		"`" + dbCAFileName + "`",
		"`GOIABADA_DB_TLS_CA_FILE`",
		"`GOIABADA_DB_TLS_MODE`",
		"`goiabada-authserver-config`",
		restart[1],
	} {
		if !strings.Contains(section, want) {
			t.Errorf("%s, %s: does not name %s, which the manifest writes", kubernetesSecurityPage, databaseCAHeading, want)
		}
	}

	overview, err := os.ReadFile(kubernetesOverviewPage)
	if err != nil {
		t.Fatalf("unable to read the Kubernetes overview: %v", err)
	}
	generated, found := sectionText(overview, "## What the wizard generates")
	if !found {
		t.Fatalf("%s has no section listing what the wizard generates", kubernetesOverviewPage)
	}
	if !strings.Contains(generated, "`"+dbCAConfigMap+"`") {
		t.Errorf("%s: what the wizard generates leaves out the %s ConfigMap", kubernetesOverviewPage, dbCAConfigMap)
	}
}

// sectionText is the text of the section heading opens, up to the next heading of its level or
// above, a line in a fenced code block being no heading.
func sectionText(page []byte, heading string) (string, bool) {
	level := strings.Index(heading, " ")
	var b strings.Builder
	inSection, inFence, found := false, false, false
	for _, line := range strings.Split(string(page), "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "```") {
			inFence = !inFence
		}
		if hashes := headingLevel(line); !inFence && hashes > 0 {
			if inSection && hashes <= level {
				break
			}
			if strings.TrimSpace(line) == heading {
				inSection, found = true, true
				continue
			}
		}
		if inSection {
			b.WriteString(line)
			b.WriteByte('\n')
		}
	}
	return b.String(), found
}
