package adminresourcehandlers

import (
	"os"
	"testing"

	"github.com/leodip/goiabada/core/config"
	"github.com/leodip/goiabada/core/i18n"
)

// The bundle is loaded because the validate-permission cases assert on the message a refusal
// carries. Without it, i18n renders the catalog key instead and every one of those assertions
// would hold against the key rather than against the text an administrator reads.
func TestMain(m *testing.M) {
	config.Init()
	if _, err := i18n.LoadBundle(); err != nil {
		panic(err)
	}
	code := m.Run()
	os.Exit(code)
}
