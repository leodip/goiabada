package logging

import (
	"fmt"
	"os"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The Logs page lists the query parameters whose value a request record keeps, on the one line
// that carries keptValuesMarker. An operator reads it to know what the log can hold, so a name the
// page lists that RequestTargetForLog redacts, or one it keeps that the page leaves out, is a
// promise about the log the code does not keep.
const (
	logsPage         = "../../../site/src/content/docs/deploy/logs.mdx"
	keptValuesMarker = "whose value is kept:"
)

var docCodeSpan = regexp.MustCompile("`([^`]+)`")

func TestLogsPage_ListsExactlyTheQueryParametersWhoseValueIsKept(t *testing.T) {
	page, err := os.ReadFile(logsPage)
	require.NoError(t, err, "unable to read the Logs page")

	listed, err := keptQueryParamsOnPage(string(page))
	require.NoError(t, err, logsPage)

	var kept []string
	for name := range loggableQueryParams {
		kept = append(kept, name)
	}
	slices.Sort(kept)
	slices.Sort(listed)
	assert.Equal(t, kept, listed, "%s lists the query parameters whose value is kept as %q; RequestTargetForLog keeps %q", logsPage, listed, kept)
}

func TestKeptQueryParamsOnPage_ReadsTheMarkedLineAlone(t *testing.T) {
	page := "Values like `code` are redacted.\n\n" +
		"Every value is redacted, apart from those of these names, whose value is kept: `scope`, `page` and `size`.\n\n" +
		"A value under `scope` can be long.\n"

	listed, err := keptQueryParamsOnPage(page)

	require.NoError(t, err)
	assert.Equal(t, []string{"scope", "page", "size"}, listed)
}

func TestKeptQueryParamsOnPage_AMissingLineIsAnError(t *testing.T) {
	_, err := keptQueryParamsOnPage("Every value is redacted, apart from `scope`.\n")

	require.Error(t, err)
	assert.Contains(t, err.Error(), keptValuesMarker)
}

// keptQueryParamsOnPage returns the code spans after keptValuesMarker on the page's one line that
// carries it, and an error when no line or more than one does, so the check never passes having
// read nothing.
func keptQueryParamsOnPage(page string) ([]string, error) {
	var listed []string
	found := 0
	for _, line := range strings.Split(page, "\n") {
		_, after, ok := strings.Cut(line, keptValuesMarker)
		if !ok {
			continue
		}
		found++
		for _, m := range docCodeSpan.FindAllStringSubmatch(after, -1) {
			listed = append(listed, m[1])
		}
	}
	if found != 1 {
		return nil, fmt.Errorf("want exactly one line carrying %q, found %d", keptValuesMarker, found)
	}
	return listed, nil
}
