package main

import (
	"os"
	"path/filepath"
	"regexp"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/leodip/goiabada/core/docsreader"
	"github.com/leodip/goiabada/core/guard"
)

// recoverEmailFlag is the --email spelling the usage gives beside the subcommand itself.
var recoverEmailFlag = regexp.MustCompile(`(?m)^  goiabada-authserver recover (--email <\S+>)`)

// recoverActionFlags are the action flags the usage spells one per line, each with the operand
// it takes.
var recoverActionFlags = regexp.MustCompile(`(?m)^  (--\S+(?: <\S+>)?)\s`)

// recoverDocsPage is the Troubleshooting page an operator locked out of the admin console reads,
// whose last-administrator section holds the recovery command (#498).
const recoverDocsPage = "site/src/content/docs/troubleshooting/locked-out-of-the-admin-console.mdx"

// TestLockedOutPage_TheRecoveryNamesTheFlagsTheUsageSpells: the page names the recover
// subcommand's flags as the usage spells them, so a renamed flag or a changed operand fails this
// tier until the page says the new one, and an operator copying the page runs a command the
// binary accepts (#498).
func TestLockedOutPage_TheRecoveryNamesTheFlagsTheUsageSpells(t *testing.T) {
	body, err := os.ReadFile(filepath.Join(filepath.Dir(guard.SourceRoot(t)), recoverDocsPage))
	require.NoError(t, err)
	section, found := docsreader.SectionText(string(body), "## The last administrator can't sign in")
	require.Truef(t, found, "%s has no section headed ## The last administrator can't sign in", recoverDocsPage)

	email := recoverEmailFlag.FindStringSubmatch(recoverUsage)
	require.NotNilf(t, email, "the usage spells recover's --email flag")
	assert.Containsf(t, section, "`"+email[1]+"`",
		"%s: the recovery names %q as the usage spells it", recoverDocsPage, email[1])
	for _, match := range recoverActionFlags.FindAllStringSubmatch(recoverUsage, -1) {
		assert.Containsf(t, section, "`"+match[1]+"`",
			"%s: the recovery names %q as the usage spells it", recoverDocsPage, match[1])
	}
}

// TestDeployPages_TheRecoveryRunsInEachDeploymentShape: each deployment page documents the
// recover command for the shape it installs, so an operator follows the page their deployment
// came from rather than translating a command between shapes (#498). The Native binaries command
// is held to the unit the page installs, as the rollback command is, so a changed user, working
// directory, environment file or binary path fails here until the command follows.
func TestDeployPages_TheRecoveryRunsInEachDeploymentShape(t *testing.T) {
	root := filepath.Dir(guard.SourceRoot(t))

	shapes := []struct{ page, command string }{
		{"site/src/content/docs/deploy/docker-compose.mdx",
			"docker compose run --rm goiabada-authserver recover --email admin@example.com"},
		{"site/src/content/docs/deploy/native-binaries.mdx", ""},
		{"site/src/content/docs/deploy/kubernetes/overview.mdx",
			"kubectl exec -n goiabada deployment/goiabada-authserver -- /app/goiabada-authserver recover --email admin@example.com"},
	}

	for _, shape := range shapes {
		body, err := os.ReadFile(filepath.Join(root, shape.page))
		require.NoError(t, err)
		section, found := docsreader.SectionText(string(body), "## Recover a locked-out administrator")
		require.Truef(t, found, "%s has no section headed ## Recover a locked-out administrator", shape.page)

		command := shape.command
		if shape.page == "site/src/content/docs/deploy/native-binaries.mdx" {
			unit := map[string]string{}
			for _, key := range []string{"User", "WorkingDirectory", "EnvironmentFile", "ExecStart"} {
				match := regexp.MustCompile(`(?m)^\s*` + key + `=(\S+)$`).
					FindStringSubmatch(string(body))
				require.NotNilf(t, match, "%s: the auth server's unit sets %s", shape.page, key)
				unit[key] = match[1]
			}
			command = "sudo -u " + unit["User"] + " sh -c 'cd " + unit["WorkingDirectory"] +
				" && set -a && . " + unit["EnvironmentFile"] + " && set +a && exec " +
				unit["ExecStart"] + " recover --email admin@example.com"
		}
		assert.Containsf(t, section, command,
			"%s: the recovery runs the command for the shape the page installs", shape.page)
	}
}
