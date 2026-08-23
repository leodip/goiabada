package server

import (
	"testing"

	"github.com/leodip/goiabada/core/testutil"
)

// TestGoSourcesAreGofmted fails the admin console unit tier when any Go file in
// the repository is not gofmt'd, which is what CI's Lint job checks per module
// before it runs vet, unparam or golangci-lint. testutil.AssertGofmted carries
// the reasoning, including why the scope is the whole tree rather than this
// module. Core and the auth server call it from their own tiers.
func TestGoSourcesAreGofmted(t *testing.T) {
	testutil.AssertGofmted(t)
}
