package main

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/leodip/goiabada/core/guard"
)

// usageCommand is a subcommand as the usage spells it, with its operand when it takes one.
var usageCommand = regexp.MustCompile(`(?m)^  goiabada-authserver migrate (?:\S+ <\S+>|\S+)`)

// TestUpgradePage_TheRollbackIsWhatMigrateDoes: the page an operator rolls back from names the two
// migrate subcommands as the usage spells them, and the floor below which `migrate to` refuses, so
// a reader planning a rollback learns before starting that it cannot go further back (#522
// decision 15).
func TestUpgradePage_TheRollbackIsWhatMigrateDoes(t *testing.T) {
	const page = "site/src/content/docs/deploy/upgrade-goiabada.mdx"
	body, err := os.ReadFile(filepath.Join(filepath.Dir(guard.SourceRoot(t)), page))
	require.NoError(t, err)
	_, section, found := strings.Cut(string(body), "\n## Roll back to an earlier release\n")
	require.Truef(t, found, "%s has no section headed ## Roll back to an earlier release", page)
	if next := strings.Index(section, "\n## "); next >= 0 {
		section = section[:next]
	}

	commands := usageCommand.FindAllString(migrateUsage, -1)
	require.Len(t, commands, 2, "the usage spells out the two subcommands")
	for _, command := range commands {
		command = strings.TrimSpace(command)
		assert.Containsf(t, section, "`"+command+"`", "%s: the rollback section names %q as the usage spells it", page, command)
	}

	assert.Containsf(t, section, fmt.Sprintf("`%06d`", rollbackFloor), "%s: the rollback section names the floor `migrate to` refuses below", page)
}
