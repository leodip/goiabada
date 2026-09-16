package accountvalidation

import (
	"fmt"
	"os"
	"testing"

	"github.com/leodip/goiabada/core/i18n"
)

func TestMain(m *testing.M) {
	// Without the bundle, EnglishFallback() returns the message id rather than the sentence
	// (i18n's visible-miss policy), so every assertion on a LocalizedError's rendered text
	// would compare a key against prose and pass only by being rewritten to expect the key.
	// All five tables here assert the sentence beside the code, which is what pins the English
	// catalog to what the user reads (#230).
	//
	// No data cipher: none of these five validators encrypts. core/validators keeps one for
	// token_validator_test.go, which does.
	if _, err := i18n.LoadBundle(); err != nil {
		fmt.Fprintf(os.Stderr, "i18n.LoadBundle in TestMain: %v\n", err)
		os.Exit(1)
	}
	os.Exit(m.Run())
}
