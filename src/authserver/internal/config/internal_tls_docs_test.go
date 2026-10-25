package config

import (
	"path/filepath"
	"testing"

	"github.com/leodip/goiabada/core/guard"
)

// The Internal TLS page, which turns the HTTPS listener on in a ConfigMap patch.
var internalTLSDocs = []docSection{
	{"site/src/content/docs/deploy/kubernetes/internal-tls.mdx", ""},
}

// The Internal TLS page names only variables this server reads. A misspelt certificate or listener
// setting is ignored, so the HTTPS listener never starts and the admin console, sent to it, cannot
// connect. The admin console's own variables are its tier to check (#686 section 10).
func TestInternalTLSDocs_NameOnlyVariablesTheServerReads(t *testing.T) {
	assertDocsNameOnlyReadVariables(t, filepath.Dir(guard.SourceRoot(t)), internalTLSDocs, readVariables())
}
