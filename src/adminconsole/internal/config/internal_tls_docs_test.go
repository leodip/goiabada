package config

import (
	"path/filepath"
	"testing"

	"github.com/leodip/goiabada/core/guard"
)

// The Internal TLS page, which has the console trust the auth server's certificate authority in a
// ConfigMap patch.
var internalTLSDocs = []docSection{
	{"site/src/content/docs/deploy/kubernetes/internal-tls.mdx", ""},
}

// The Internal TLS page names only admin console variables this console reads. A misspelt CA file
// setting is ignored, so the console checks the auth server's certificate against the system's
// roots alone and cannot connect. Every other GOIABADA_ variable is the auth server's tier to check
// (#686 section 10).
func TestInternalTLSDocs_NameOnlyVariablesTheConsoleReads(t *testing.T) {
	assertDocsNameOnlyReadVariables(t, filepath.Dir(guard.SourceRoot(t)), internalTLSDocs, readVariables())
}
