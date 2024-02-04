package integrationtests

import (
	"testing"

	"github.com/leodip/goiabada/internal/datav2"
	"github.com/leodip/goiabada/internal/initialization"
)

func TestDatabase(t *testing.T) {
	initialization.InitViper()
	database, err := datav2.NewDatabase()
	if err != nil {
		t.Fatal(err)
	}
	if database == nil {
		t.Fatal("database is nil")
	}
}
