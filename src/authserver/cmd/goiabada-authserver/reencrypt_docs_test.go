package main

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/leodip/goiabada/core/docsreader"
	"github.com/leodip/goiabada/core/guard"
)

// The data key's rotation is a procedure an operator copies command by command, and its order is
// what keeps every auth server able to open what every other one seals (#492 decisions 2 and 3).
// These guards hold the pages that tell it to the reencrypt command as the usage spells it, to the
// order the agreement settles, and to the one rotation that still stops the auth servers.

const (
	rotateSecretsPage     = "site/src/content/docs/deploy/rotate-secrets.mdx"
	kubernetesSecretsPage = "site/src/content/docs/deploy/kubernetes/secrets.mdx"
	aesKeySection         = "## The AES key"
	sampleKeySection      = "### Off the published sample key"
)

// reencryptUsageCommand is the subcommand as the usage's first line spells it.
var reencryptUsageCommand = regexp.MustCompile(`(?m)^  (goiabada-authserver \S+) \[--db-\* flags\]$`)

// docsPage reads a page of the docs site, from the repository root.
func docsPage(t *testing.T, page string) string {
	t.Helper()
	body, err := os.ReadFile(filepath.Join(filepath.Dir(guard.SourceRoot(t)), page))
	require.NoError(t, err)
	return string(body)
}

// docsSection reads one section of a page, failing when the page has none.
func docsSection(t *testing.T, page, heading string) string {
	t.Helper()
	section, found := docsreader.SectionText(docsPage(t, page), heading)
	require.Truef(t, found, "%s has no section headed %s", page, heading)
	return section
}

// platformTabs is every tab of one platform in text, joined in the order they appear.
func platformTabs(t *testing.T, text, platform string) string {
	t.Helper()
	tabs := regexp.MustCompile(`(?s)<TabItem label="`+regexp.QuoteMeta(platform)+`"[^>]*>(.*?)</TabItem>`).
		FindAllStringSubmatch(text, -1)
	require.NotEmptyf(t, tabs, "the text holds no %s tab", platform)
	var joined strings.Builder
	for _, tab := range tabs {
		joined.WriteString(tab[1])
		joined.WriteString("\n")
	}
	return joined.String()
}

// nativeCommand is how the Native binaries page's unit runs the auth server's binary with args:
// as its user, from its working directory and with its environment file, as the rollback and
// recover commands run it.
func nativeCommand(t *testing.T, args string) string {
	t.Helper()
	native := docsPage(t, "site/src/content/docs/deploy/native-binaries.mdx")
	unit := map[string]string{}
	for _, key := range []string{"User", "WorkingDirectory", "EnvironmentFile", "ExecStart"} {
		match := regexp.MustCompile(`(?m)^\s*` + key + `=(\S+)$`).FindStringSubmatch(native)
		require.NotNilf(t, match, "native-binaries.mdx: the auth server's unit sets %s", key)
		unit[key] = match[1]
	}
	return "sudo -u " + unit["User"] + " sh -c 'cd " + unit["WorkingDirectory"] + " && set -a && . " +
		unit["EnvironmentFile"] + " && set +a && exec " + unit["ExecStart"] + " " + args + "'"
}

// reencryptCommands is the reencrypt command as each platform's tab runs it: as recover runs on
// Compose and natively, and in a pod of the auth server's Deployment on Kubernetes, which reads
// the Secret as the pods that serve read it (#492 assumptions).
func reencryptCommands(t *testing.T) map[string]string {
	t.Helper()
	usage := reencryptUsageCommand.FindStringSubmatch(reencryptUsage)
	require.NotNil(t, usage, "the usage spells the reencrypt subcommand on its first line")
	subcommand := strings.TrimPrefix(usage[1], "goiabada-authserver ")
	return map[string]string{
		"Docker Compose":  "docker compose run --rm -T goiabada-authserver " + subcommand,
		"Native binaries": nativeCommand(t, subcommand),
		"Kubernetes":      "kubectl exec -n goiabada deployment/goiabada-authserver -- /app/goiabada-authserver " + subcommand,
	}
}

// assertInOrder holds text to holding each needle after the one before it, naming the first that
// is missing or out of place.
func assertInOrder(t *testing.T, text, what string, needles ...string) {
	t.Helper()
	at := 0
	for i, needle := range needles {
		found := strings.Index(text[at:], needle)
		if found < 0 {
			if i == 0 {
				t.Errorf("%s: %q is missing", what, needle)
			} else {
				t.Errorf("%s: %q is missing after %q", what, needle, needles[i-1])
			}
			return
		}
		at += found + len(needle)
	}
}

// TestRotateSecretsPage_TheAESKeyRunsReencryptInEachDeploymentShape: each platform's tabs of the
// AES key's rotation run the reencrypt command the usage spells, in the way that platform runs
// the auth server's binary, so an operator copying the step runs the sweep against the database
// the servers use and with the keys they hold.
func TestRotateSecretsPage_TheAESKeyRunsReencryptInEachDeploymentShape(t *testing.T) {
	section := docsSection(t, rotateSecretsPage, aesKeySection)
	for platform, command := range reencryptCommands(t) {
		assert.Containsf(t, platformTabs(t, section, platform), command,
			"%s: the %s tabs of the AES key's rotation run reencrypt", rotateSecretsPage, platform)
	}
	assert.Containsf(t, section, "exits 0",
		"%s: the AES key's rotation removes the previous key only once reencrypt exits 0, the proof the sweep reached its end", rotateSecretsPage)
}

// TestRotateSecretsPage_TheAESKeyRotatesThroughRestartsAlone: outside the sample key's rotation,
// the AES key rotates through restarts that never change the auth server's replica count, in the
// order that keeps every pod opening what every other one seals: on Kubernetes the new key goes in
// as the previous key and rolls out, the keys are swapped and roll out, reencrypt runs, and only
// then is the previous key removed and rolled out; on Compose and natively the swap is the first
// restart (#492 decision 2). Each of the two Kubernetes rollouts before reencrypt waits, after
// `rollout status`, for the pods listed before its restart to stop: `rollout status` ends once the
// new pods are ready, while old ones still drain, and one of those on the earlier keys could seal
// under a key the next step leaves.
func TestRotateSecretsPage_TheAESKeyRotatesThroughRestartsAlone(t *testing.T) {
	section := docsSection(t, rotateSecretsPage, aesKeySection)
	sample, found := docsreader.SectionText(section, sampleKeySection)
	require.Truef(t, found, "%s: the AES key's section has a subsection headed %s", rotateSecretsPage, sampleKeySection)
	stopFree := strings.Replace(section, sample, "", 1)
	assert.NotContainsf(t, stopFree, "kubectl scale",
		"%s: only the sample key's rotation scales the auth server", rotateSecretsPage)
	assert.NotContainsf(t, stopFree, "--replicas",
		"%s: only the sample key's rotation changes the auth server's replicas", rotateSecretsPage)

	commands := reencryptCommands(t)
	const (
		restart = "kubectl rollout restart deployment/goiabada-authserver -n goiabada"
		listed  = "old=$(kubectl get pods -n goiabada -l app=goiabada-authserver -o name)"
		status  = "kubectl rollout status deployment/goiabada-authserver -n goiabada"
		stopped = "kubectl wait -n goiabada $old --for=delete"
	)
	kubernetes := platformTabs(t, stopFree, "Kubernetes")
	assertInOrder(t, kubernetes, rotateSecretsPage+": the Kubernetes rotation",
		`"aes-encryption-key-previous": "$(openssl rand -hex 32)"`, listed, restart, status, stopped,
		`"aes-encryption-key": "$(aes aes-encryption-key-previous)"`, listed, restart, status, stopped,
		commands["Kubernetes"],
		`"/data/aes-encryption-key-previous"`, restart)
	assert.Containsf(t, kubernetes, `"aes-encryption-key-previous": "$(aes aes-encryption-key)"`,
		"%s: the Kubernetes swap makes the old key the previous key in the same patch", rotateSecretsPage)

	for platform, restart := range map[string]string{
		"Docker Compose":  "docker compose up -d --wait goiabada-authserver",
		"Native binaries": "sudo systemctl restart goiabada-authserver",
	} {
		assertInOrder(t, platformTabs(t, stopFree, platform), rotateSecretsPage+": the "+platform+" rotation",
			"GOIABADA_AES_ENCRYPTION_KEY_PREVIOUS=", restart,
			commands[platform],
			"Delete the `GOIABADA_AES_ENCRYPTION_KEY_PREVIOUS` line", restart)
	}
}

// TestRotateSecretsPage_TheSampleKeyRotationStopsEveryAuthServerFirst: the auth server refuses the
// published sample key as the current key, so no server runs it beside the new key as previous,
// and the servers still on it are a release holding one key. Its rotation is the one that stops
// them first, inside the section the refusal links to, and on Kubernetes scales to zero before the
// keys change and back after (#492 decision on the sample key).
func TestRotateSecretsPage_TheSampleKeyRotationStopsEveryAuthServerFirst(t *testing.T) {
	section := docsSection(t, rotateSecretsPage, aesKeySection)
	sample, found := docsreader.SectionText(section, sampleKeySection)
	require.Truef(t, found, "%s: the AES key's section has a subsection headed %s", rotateSecretsPage, sampleKeySection)

	assert.Containsf(t, sample, "GOIABADA_AES_ENCRYPTION_KEY_PREVIOUS",
		"%s: the sample key's rotation keeps the sample key as the previous key", rotateSecretsPage)
	assertInOrder(t, platformTabs(t, sample, "Kubernetes"), rotateSecretsPage+": the sample key's Kubernetes rotation",
		"kubectl scale deployment goiabada-authserver -n goiabada --replicas=0",
		"kubectl wait pod -n goiabada -l app=goiabada-authserver --for=delete",
		`"aes-encryption-key-previous": "$(kubectl get secret goiabada-encryption-key -n goiabada -o jsonpath='{.data.aes-encryption-key}')"`,
		`"aes-encryption-key": "$(openssl rand -hex 32)"`,
		"--replicas=<n>",
		reencryptCommands(t)["Kubernetes"])
	for _, platform := range []string{"Docker Compose", "Native binaries"} {
		assert.Containsf(t, platformTabs(t, sample, platform), reencryptCommands(t)[platform],
			"%s: the sample key's %s rotation runs reencrypt", rotateSecretsPage, platform)
	}
}

// TestKubernetesSecretsPage_TheSealedAESKeyGoesInAsThePreviousKeyBeforeTheSwap: with SealedSecrets
// the AES key's rotation is staged as the rotate page stages it: a new key sealed as the previous
// key alone, and once that is unsealed, the two swapped in one sealed file. A new key sealed
// straight in as the current key is the stop the procedure no longer needs.
func TestKubernetesSecretsPage_TheSealedAESKeyGoesInAsThePreviousKeyBeforeTheSwap(t *testing.T) {
	section := docsSection(t, kubernetesSecretsPage, "## Rotating Secrets something else owns")
	assertInOrder(t, section, kubernetesSecretsPage+": the sealed AES key's rotation",
		"seal_aes --from-file=aes-encryption-key-previous=<(openssl rand -hex 32 | tr -d '\\n')",
		"seal_aes --from-file=aes-encryption-key=<(aes aes-encryption-key-previous)",
		"--from-file=aes-encryption-key-previous=<(aes aes-encryption-key)")
	assert.NotContainsf(t, section, "--from-file=aes-encryption-key=<(openssl",
		"%s: no rotation seals a new key straight in as the current key", kubernetesSecretsPage)
	assert.Equalf(t, 2, strings.Count(section, "waiting for the pods listed before the restart to stop"),
		"%s: the External Secrets Operator's and SealedSecrets' AES key rotations each wait, after a rollout, "+
			"for the pods listed before it to stop, as the rotate page does", kubernetesSecretsPage)
}

// dataKeyDocs is every section outside the rotate page that tells an operator to move stored data
// between data keys: each names the reencrypt command, since a start no longer re-encrypts.
var dataKeyDocs = []struct{ page, heading string }{
	{"site/src/content/docs/reference/environment-variables.mdx", "## The data encryption key"},
	{"site/src/content/docs/deploy/secrets.mdx", "## Back up the AES key"},
	{"site/src/content/docs/deploy/secrets.mdx", "## When a secret changes"},
	{"site/src/content/docs/deploy/upgrade-goiabada.mdx", "## Roll back to an earlier release"},
	{"site/src/content/docs/troubleshooting/crashloopbackoff-or-unable-to-create-the-database-connection.mdx", "## When it isn't the database"},
	{kubernetesSecretsPage, "## Rotating Secrets something else owns"},
}

// TestDataKeyDocs_EveryPageMovingTheDataNamesReencrypt: the pages that restore a backup under an
// older key, roll back, answer the start's refusal, or rotate a Secret something else owns name
// the reencrypt command, and none quotes the start-up record a start no longer writes, which a
// reader would wait for in vain (#492 decision 3).
func TestDataKeyDocs_EveryPageMovingTheDataNamesReencrypt(t *testing.T) {
	for _, doc := range dataKeyDocs {
		assert.Containsf(t, docsSection(t, doc.page, doc.heading), "reencrypt`",
			"%s: %s names the reencrypt command", doc.page, doc.heading)
	}
	for _, page := range []string{rotateSecretsPage, kubernetesSecretsPage, "site/src/content/docs/deploy/secrets.mdx",
		"site/src/content/docs/reference/environment-variables.mdx", "site/src/content/docs/deploy/upgrade-goiabada.mdx"} {
		assert.NotContainsf(t, docsPage(t, page), "rotated data-at-rest encryption",
			"%s quotes a record no start writes", page)
	}
}
