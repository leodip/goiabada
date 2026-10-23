package integration

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/PuerkitoBio/goquery"
	"github.com/leodip/goiabada/core/i18n"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func assertWithinLastXSeconds(t *testing.T, timeToCheck time.Time, seconds float64) {
	now := time.Now().UTC()
	xSecondsAgo := now.Add(-time.Duration(seconds * float64(time.Second)))

	assert.True(t, timeToCheck.After(xSecondsAgo) && timeToCheck.Before(now),
		"Expected time to be within the last %.2f seconds", seconds)
}

// parseHTMLResponse reads the response body and returns a goquery document
// while preserving the response body for potential re-reading
func parseHTMLResponse(t *testing.T, response *http.Response) *goquery.Document {
	byteArr, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	response.Body = io.NopCloser(bytes.NewReader(byteArr))

	doc, err := goquery.NewDocumentFromReader(strings.NewReader(string(byteArr)))
	if err != nil {
		t.Fatal(err)
	}
	return doc
}

// assertClientNameInHTML verifies the client name is displayed: <p class="auth-client-name">, which
// the auth layout and the consent page both write.
func assertClientNameInHTML(t *testing.T, doc *goquery.Document, expectedName string) {
	var names []string
	doc.Find("p.auth-client-name").Each(func(i int, s *goquery.Selection) {
		names = append(names, strings.TrimSpace(s.Text()))
	})
	if !slices.Contains(names, expectedName) {
		dumpResponseBody(t, &http.Response{Body: io.NopCloser(strings.NewReader(doc.Text()))})
	}
	assert.Contains(t, names, expectedName, "Client name '%s' should be displayed in HTML", expectedName)
}

// assertClientLogoInHTML verifies logo image is present/absent as expected
func assertClientLogoInHTML(t *testing.T, doc *goquery.Document, clientIdentifier string, expectLogo bool) {
	expectedSrc := "/client/logo/" + clientIdentifier
	var logoFound bool

	doc.Find("img").Each(func(i int, s *goquery.Selection) {
		src, exists := s.Attr("src")
		if exists && src == expectedSrc {
			logoFound = true
		}
	})

	if expectLogo {
		assert.True(t, logoFound,
			"Logo image with src '%s' should be present when ShowLogo=true and logo exists", expectedSrc)
	} else {
		assert.False(t, logoFound,
			"Logo image with src '%s' should not be present when ShowLogo=false or no logo uploaded", expectedSrc)
	}
}

// assertClientDescriptionInHTML verifies the description is present or absent as expected:
// <p class="auth-client-description">, which the auth layout and the consent page both write.
func assertClientDescriptionInHTML(t *testing.T, doc *goquery.Document, expectedDescription string, expectPresent bool) {
	var descriptions []string
	doc.Find("p.auth-client-description").Each(func(i int, s *goquery.Selection) {
		descriptions = append(descriptions, strings.TrimSpace(s.Text()))
	})
	if !expectPresent {
		if expectedDescription != "" {
			assert.NotContains(t, descriptions, expectedDescription,
				"Description should not be visible when ShowDescription=false or description empty")
		}
		return
	}
	assert.Contains(t, descriptions, expectedDescription,
		"Description '%s' should be visible when ShowDescription=true and description not empty", expectedDescription)
}

// assertClientWebsiteUrlInHTML verifies website URL link is present/absent as expected
func assertClientWebsiteUrlInHTML(t *testing.T, doc *goquery.Document, expectedURL string, expectPresent bool) {
	if expectedURL == "" && !expectPresent {
		return
	}

	var linkFound bool
	doc.Find("a").Each(func(i int, s *goquery.Selection) {
		href, exists := s.Attr("href")
		if exists && href == expectedURL {
			linkFound = true

			if expectPresent {
				// Verify link attributes
				target, _ := s.Attr("target")
				assert.Equal(t, "_blank", target, "Website link should open in new tab")

				rel, _ := s.Attr("rel")
				assert.Equal(t, "noopener noreferrer", rel, "Website link should have security attributes")
			}
		}
	})

	if expectPresent {
		assert.True(t, linkFound,
			"Website URL link with href '%s' should be present when ShowWebsiteURL=true and URL not empty", expectedURL)
	} else {
		assert.False(t, linkFound,
			"Website URL link with href '%s' should not be present when ShowWebsiteURL=false or URL empty", expectedURL)
	}
}

// assertStateMismatchPage reads the page a state mismatch renders and holds it to the catalog
// entry that belongs to the condition, not merely to "some error page".
//
// The distinction is the point. The ceremony-mismatch page beside it says the sign-in can no longer
// continue, which is a different diagnosis and a different remedy from "you went
// back to a step the server has finished with", and a check that accepted either would let the
// two be confused (#279 decision 21).
func assertStateMismatchPage(t *testing.T, resp *http.Response) {
	t.Helper()

	doc, err := goquery.NewDocumentFromReader(resp.Body)
	require.NoError(t, err)

	body := doc.Text()
	assert.Contains(t, body, i18n.T(context.Background(), "auth_error.state_mismatch.title"))
	assert.Contains(t, body, i18n.T(context.Background(), "auth_error.state_mismatch.message"))
	assert.NotContains(t, body, i18n.T(context.Background(), "auth_error.ceremony_mismatch.message"),
		"a state mismatch is not a ceremony mismatch, and the pages must not be interchangeable")
}
