package validators

import (
	"fmt"
	"os"
	"testing"

	"github.com/leodip/goiabada/core/encryption"
	"github.com/leodip/goiabada/core/i18n"
)

func TestMain(m *testing.M) {
	if err := encryption.InitDataCipher([]byte("0123456789abcdef0123456789abcdef")); err != nil {
		panic(err)
	}
	// Without the bundle, EnglishFallback() returns the message id rather than the sentence
	// (i18n's visible-miss policy), so every assertion on a LocalizedError's rendered text
	// would compare a key against prose and pass only by being rewritten to expect the key.
	// The authorize tests assert the sentence deliberately: it is what pins the English
	// catalog value to the text the refusal page has always shown (#213).
	if _, err := i18n.LoadBundle(); err != nil {
		fmt.Fprintf(os.Stderr, "i18n.LoadBundle in TestMain: %v\n", err)
		os.Exit(1)
	}
	os.Exit(m.Run())
}
