package integrationtests

import (
	"crypto/tls"
	"net/http"
	"net/http/cookiejar"
	"testing"
)

func createHttpClient(t *testing.T, followRedirects bool, ignoreTLSErrors bool) *http.Client {
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{
		Jar: jar,
	}

	if !followRedirects {
		client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}
	}

	if ignoreTLSErrors {
		tr := &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
		client.Transport = tr
	}
	return client
}
