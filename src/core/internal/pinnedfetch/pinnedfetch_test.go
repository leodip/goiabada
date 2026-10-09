package pinnedfetch

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/leodip/goiabada/core/boundedread"
)

const testURL = "https://example.test/data.csv"

// fakeDoer answers every request with one canned status and body, and records the request it was
// handed so a test can assert on what Get sent.
type fakeDoer struct {
	status int
	body   string
	err    error
	got    *http.Request
}

func (f *fakeDoer) do(req *http.Request) (*http.Response, error) {
	f.got = req
	if f.err != nil {
		return nil, f.err
	}
	return &http.Response{
		StatusCode: f.status,
		Body:       io.NopCloser(strings.NewReader(f.body)),
		Header:     make(http.Header),
	}, nil
}

func TestGet(t *testing.T) {
	t.Run("a 200 returns the body", func(t *testing.T) {
		d := &fakeDoer{status: http.StatusOK, body: "col\nval\n"}

		body, err := Get(d.do, testURL, "test-agent", 1024)

		require.NoError(t, err)
		assert.Equal(t, "col\nval\n", string(body))
	})

	t.Run("the request is a GET of the url carrying the user agent", func(t *testing.T) {
		d := &fakeDoer{status: http.StatusOK, body: "x"}

		_, err := Get(d.do, testURL, "test-agent", 1024)

		require.NoError(t, err)
		require.NotNil(t, d.got)
		assert.Equal(t, http.MethodGet, d.got.Method)
		assert.Equal(t, testURL, d.got.URL.String())
		assert.Equal(t, "test-agent", d.got.Header.Get("User-Agent"))
	})

	t.Run("a non-200 is refused, naming the url and the status", func(t *testing.T) {
		d := &fakeDoer{status: http.StatusForbidden, body: "denied"}

		body, err := Get(d.do, testURL, "test-agent", 1024)

		require.Error(t, err)
		assert.Nil(t, body)
		assert.Contains(t, err.Error(), testURL)
		assert.Contains(t, err.Error(), "403")
	})

	t.Run("a doer error is refused and stays matchable", func(t *testing.T) {
		sentinel := errors.New("connection refused")
		d := &fakeDoer{err: sentinel}

		body, err := Get(d.do, testURL, "test-agent", 1024)

		assert.Nil(t, body)
		assert.ErrorIs(t, err, sentinel, "got %v", err)
	})

	// The boundary cases of the ceiling belong to boundedread's own tests; what is here is that Get
	// reads through it at the limit it is given.
	t.Run("a body of exactly the limit is returned whole", func(t *testing.T) {
		d := &fakeDoer{status: http.StatusOK, body: "abc"}

		body, err := Get(d.do, testURL, "test-agent", 3)

		require.NoError(t, err)
		assert.Equal(t, "abc", string(body))
	})

	t.Run("one byte over the limit is refused", func(t *testing.T) {
		d := &fakeDoer{status: http.StatusOK, body: "abcd"}

		body, err := Get(d.do, testURL, "test-agent", 3)

		require.ErrorIs(t, err, boundedread.ErrResponseTooLarge, "got %v", err)
		assert.Nil(t, body)
	})
}

func TestCheckSHA256(t *testing.T) {
	body := []byte("the pinned bytes")
	sum := sha256.Sum256(body)
	digest := hex.EncodeToString(sum[:])
	other := strings.Repeat("0", 64)

	t.Run("a matching pin passes and returns the digest", func(t *testing.T) {
		got, err := CheckSHA256(body, digest)

		require.NoError(t, err)
		assert.Equal(t, digest, got)
	})

	t.Run("a mismatch is refused, naming the pinned and the received digest", func(t *testing.T) {
		got, err := CheckSHA256(body, other)

		require.Error(t, err)
		assert.Empty(t, got)
		assert.Contains(t, err.Error(), "pinned "+other)
		assert.Contains(t, err.Error(), "received "+digest)
	})

	t.Run("the right digest in upper case is refused, since pins compare exactly", func(t *testing.T) {
		_, err := CheckSHA256(body, strings.ToUpper(digest))

		require.Error(t, err)
	})
}
