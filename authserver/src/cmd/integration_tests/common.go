package integrationtests

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"net/http/cookiejar"
	"os"
	"testing"

	"github.com/leodip/goiabada/internal/data"
	"github.com/leodip/goiabada/internal/initialization"
	"github.com/pkg/errors"
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
		seedTestData(database)
	}
}

type createHttpClientInput struct {
	T               *testing.T
	FollowRedirects bool
	IgnoreTLSErrors bool
}

func createHttpClient(input *createHttpClientInput) *http.Client {
	jar, err := cookiejar.New(nil)
	if err != nil {
		input.T.Fatal(err)
	}
	client := &http.Client{
		Jar: jar,
	}

	if !input.FollowRedirects {
		client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}
	}

	if input.IgnoreTLSErrors {
		tr := &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
		client.Transport = tr
	}
	return client
}

func clientSetEnabled(clientIdentifier string, enabled bool) error {
	c, err := database.GetClientByClientIdentifier(clientIdentifier)
	if err != nil {
		return err
	}
	if c == nil {
		return fmt.Errorf("can't disable client %v because it does not exist", clientIdentifier)
	}
	c.Enabled = enabled
	result := database.DB.Save(c)

	if result.Error != nil {
		return errors.Wrap(result.Error, "unable to update client in database")
	}

	return nil
}
