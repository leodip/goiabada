package integrationtests

import (
	"net/http"
	"os"
	"testing"

	"github.com/PuerkitoBio/goquery"
	"github.com/leodip/goiabada/internal/data"
	"github.com/leodip/goiabada/internal/initialization"
	"github.com/leodip/goiabada/internal/lib"
	"github.com/stretchr/testify/assert"
	"golang.org/x/exp/slog"
)

var database *data.Database

func setup() {
	if database == nil {
		initialization.Viper()
		db, err := data.NewDatabase()
		if err != nil {
			slog.Error(err.Error())
			os.Exit(1)
		}
		database = db
	}
}

func TestClientIdIsMissing(t *testing.T) {
	setup()
	url := lib.GetBaseUrl() + "/auth/authorize/"

	client := createHttpClient(t, true, true)

	resp, err := client.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	doc, err := goquery.NewDocumentFromReader(resp.Body)
	if err != nil {
		t.Fatal(err)
	}

	title := doc.Find("p#errorMsg").Text()
	assert.Equal(t, "The client_id parameter is missing.", title)
}
