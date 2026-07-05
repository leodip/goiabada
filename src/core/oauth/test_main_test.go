package oauth

import (
	"os"
	"testing"

	"github.com/leodip/goiabada/core/config"
	"github.com/leodip/goiabada/core/encryption"
)

func TestMain(m *testing.M) {
	if err := encryption.InitDataCipher([]byte("0123456789abcdef0123456789abcdef")); err != nil {
		panic(err)
	}
	config.Init()
	code := m.Run()
	os.Exit(code)
}
