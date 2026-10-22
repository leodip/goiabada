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

// passwordArgument is a documented command giving the new password as --password's argument,
// which every documented form must not: the argument reaches the shell's history, the process
// list, sudo's log and the Kubernetes API server's audit log, and inside the native form's
// `sh -c '...'` the inner shell rewrote a password holding `$`, a backtick or a backslash into one
// the operator never typed (#498 review F3 and F4).
var passwordArgument = regexp.MustCompile(`--password[ =]`)

// recoverPasswordPrompt is the line that asks for the new password before each documented command.
// IFS= keeps the spaces and tabs a plain read strips from either end of the line.
const recoverPasswordPrompt = `printf 'New password: ' && IFS= read -rs RECOVERY_PASSWORD && echo`

// TestDeployPages_TheRecoveryRunsInEachDeploymentShape: each deployment page documents the
// recover command for the shape it installs, so an operator follows the page their deployment
// came from rather than translating a command between shapes, and the troubleshooting page's tabs
// hold the same command (#498). The Native binaries command is held to the unit the page installs,
// as the rollback command is, so a changed user, working directory, environment file or binary path
// fails here until the command follows. Every documented command reads the password from stdin,
// the shape's own way of handing a pipe to the command: -T for Compose, -i for kubectl, and
// sudo's own stdin for the native form. The line before each reads the password with IFS= read,
// since a plain read strips spaces and tabs from either end of what is typed, and the password the
// command stored would then refuse the one the operator signs in with (#498 round 2 F1).
func TestDeployPages_TheRecoveryRunsInEachDeploymentShape(t *testing.T) {
	root := filepath.Dir(guard.SourceRoot(t))

	troubleshooting, err := os.ReadFile(filepath.Join(root, recoverDocsPage))
	require.NoError(t, err)
	tabs, found := docsreader.SectionText(string(troubleshooting), "## The last administrator can't sign in")
	require.Truef(t, found, "%s has no section headed ## The last administrator can't sign in", recoverDocsPage)

	shapes := []struct{ page, command string }{
		{"site/src/content/docs/deploy/docker-compose.mdx",
			"docker compose run --rm -T goiabada-authserver recover --email admin@example.com"},
		{"site/src/content/docs/deploy/native-binaries.mdx", ""},
		{"site/src/content/docs/deploy/kubernetes/overview.mdx",
			"kubectl exec -i -n goiabada deployment/goiabada-authserver -- /app/goiabada-authserver recover --email admin@example.com"},
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
		assert.Containsf(t, tabs, command,
			"%s: the troubleshooting page's tab runs the command %s does", recoverDocsPage, shape.page)

		for _, text := range []struct{ page, section string }{{shape.page, section}, {recoverDocsPage, tabs}} {
			lines := strings.Split(text.section, "\n")
			for i, line := range lines {
				if !strings.Contains(line, command) {
					continue
				}
				require.Positivef(t, i, "%s: the documented command has a line before it", text.page)
				assert.Equalf(t, recoverPasswordPrompt, strings.TrimSpace(lines[i-1]),
					"%s: the line before the command reads the password whole", text.page)
				assert.Containsf(t, line, "--password-stdin",
					"%s: the documented command reads the new password from stdin", text.page)
				assert.Falsef(t, passwordArgument.MatchString(line),
					"%s: the documented command gives the password on the command line: %s", text.page, line)
				assert.Containsf(t, line, `printf '%s\n' "$RECOVERY_PASSWORD" | `+command,
					"%s: the password is piped to the command by the shell's own printf", text.page)
			}
		}
	}
}
