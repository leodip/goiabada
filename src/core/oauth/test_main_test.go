package oauth

import (
	"os"
	"testing"

	"github.com/leodip/goiabada/core/config"
)

func TestMain(m *testing.M) {
	config.Init("AuthServer")
	code := m.Run()
	os.Exit(code)
}
