package main

import (
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/leodip/goiabada/core/docsreader"
)

// The Kubernetes pages tell an operator where the manifest keeps the database's CA and how to
// change it, held here to the manifest the wizard writes, so a renamed ConfigMap, a moved mount or
// another way to change it fails until the pages say so (#502 decision 8). The way is the wizard's
// flag, since the answers file holds the certificates and the next run writes them back over an
// edit of the ConfigMap (#686).
const (
	kubernetesSecurityPage = "../../../site/src/content/docs/deploy/kubernetes/security.mdx"
	kubernetesOverviewPage = "../../../site/src/content/docs/deploy/kubernetes/overview.mdx"
	databaseCAHeading      = "## Check the database's certificate"
)

// changeInManifest is the flag the CA ConfigMap's comment changes the authorities with.
var changeInManifest = regexp.MustCompile(`(?m)^#.* with (--[a-z-]+) and apply`)

func TestKubernetesDocs_SayWhereTheDatabaseCALivesAndHowToChangeIt(t *testing.T) {
	config := goldenConfig(deploymentKubernetes, "postgres")
	config.DBTLSMode, config.DBTLSCAFile, config.DBTLSCA = "verify-full", "/home/operator/db-ca.pem", goldenCA()
	manifest := generateKubernetesManifests(config, deployments[deploymentKubernetes].defaultPaths())

	change := changeInManifest.FindStringSubmatch(manifest)
	if change == nil {
		t.Fatal("the CA ConfigMap's comment gives no flag to change the authorities with")
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
	section, found := docsreader.SectionText(string(page), databaseCAHeading)
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
		change[1] + "=",
	} {
		if !strings.Contains(section, want) {
			t.Errorf("%s, %s: does not name %s, which the manifest writes", kubernetesSecurityPage, databaseCAHeading, want)
		}
	}

	if strings.Contains(section, "kubectl edit") {
		t.Errorf("%s, %s: edits the ConfigMap in place, which the wizard's next run writes over", kubernetesSecurityPage, databaseCAHeading)
	}

	overview, err := os.ReadFile(kubernetesOverviewPage)
	if err != nil {
		t.Fatalf("unable to read the Kubernetes overview: %v", err)
	}
	generated, found := docsreader.SectionText(string(overview), "## What the wizard generates")
	if !found {
		t.Fatalf("%s has no section listing what the wizard generates", kubernetesOverviewPage)
	}
	if !strings.Contains(generated, "`"+dbCAConfigMap+"`") {
		t.Errorf("%s: what the wizard generates leaves out the %s ConfigMap", kubernetesOverviewPage, dbCAConfigMap)
	}
}
