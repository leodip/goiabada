package protocolvalidation

import (
	"os"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/encryption"
)

func TestMain(m *testing.M) {
	// token_validator_test.go encrypts, so the process cipher is installed once here (#344). The
	// message bundle the authorize tests' sentences are read from needs no setup: core/i18n serves
	// its embedded catalogs without any (#431).
	if err := encryption.InitDataCipher([]byte("0123456789abcdef0123456789abcdef")); err != nil {
		panic(err)
	}
	os.Exit(m.Run())
}
