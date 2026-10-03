package api

import (
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestPackageFiles_OneFilePerResource holds the package to its layout: one file per resource the
// admin and account APIs serve, each declaring that resource's requests beside its responses, and
// no file per direction. It was requests.go and responses.go until #441, which put every request a
// file away from its response and split the #266 session types across both. A new file is a new
// resource, so it is added here.
func TestPackageFiles_OneFilePerResource(t *testing.T) {
	entries, err := os.ReadDir(".")
	require.NoError(t, err)

	var files []string
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		files = append(files, name)
	}

	assert.ElementsMatch(t, []string{
		"account.go",
		"audit.go",
		"clients.go",
		"doc.go",
		"errors.go",
		"groups.go",
		"pictures.go",
		"resources.go",
		"sessions.go",
		"settings.go",
		"users.go",
	}, files)
}
