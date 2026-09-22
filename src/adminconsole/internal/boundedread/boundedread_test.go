package boundedread

import (
	"errors"
	"io"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The rule itself, owned once. The six sites that read through Read each own their own accepted
// and refused pair against their own ceiling; what is here is that the boundary is where it says
// it is, that the overrun hands nothing back, and that a read which fails partway is a different
// outcome from an overrun (#386 decision 4).

// countingReader serves a fixed body and records how much of it was actually read, which is what
// makes "one byte past the ceiling, and no more" assertable rather than merely stated.
type countingReader struct {
	remaining []byte
	read      atomic.Int64
}

func (r *countingReader) Read(p []byte) (int, error) {
	if len(r.remaining) == 0 {
		return 0, io.EOF
	}
	n := copy(p, r.remaining)
	r.remaining = r.remaining[n:]
	r.read.Add(int64(n))
	return n, nil
}

func TestRead_AcceptsABodyUnderTheCeiling(t *testing.T) {
	body, err := Read(strings.NewReader("abc"), 16)

	require.NoError(t, err)
	assert.Equal(t, []byte("abc"), body)
}

func TestRead_AcceptsABodyOfExactlyTheCeiling(t *testing.T) {
	exact := strings.Repeat("x", 16)

	body, err := Read(strings.NewReader(exact), 16)

	require.NoError(t, err)
	assert.Equal(t, []byte(exact), body, "the ceiling is the largest accepted answer, not the first refused one")
}

func TestRead_RefusesABodyOneByteOverTheCeiling(t *testing.T) {
	over := &countingReader{remaining: []byte(strings.Repeat("x", 17))}

	body, err := Read(over, 16)

	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrResponseTooLarge), "got %v", err)
	assert.Nil(t, body, "nothing is handed back, so no prefix can reach a decoder")
	assert.Equal(t, int64(17), over.read.Load(), "one byte past the ceiling is read, and no more")
}

// The far-past case is the one the ceiling exists for: a peer answering with vastly more than the
// ceiling still costs one byte past it, not the whole body.
func TestRead_ReadsOnlyOneBytePastTheCeilingOfAMuchLargerBody(t *testing.T) {
	huge := &countingReader{remaining: []byte(strings.Repeat("x", 4096))}

	_, err := Read(huge, 16)

	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrResponseTooLarge), "got %v", err)
	assert.Equal(t, int64(17), huge.read.Load())
}

// failingReader delivers some bytes and then fails, which is the transport dropping partway
// through an answer that was never oversized.
type failingReader struct {
	delivered bool
}

func (r *failingReader) Read(p []byte) (int, error) {
	if r.delivered {
		return 0, errConnectionDropped
	}
	r.delivered = true
	n := copy(p, "partial")
	return n, nil
}

var errConnectionDropped = errors.New("the connection dropped")

func TestRead_ReturnsWhatArrivedWhenTheReadFailsPartway(t *testing.T) {
	body, err := Read(&failingReader{}, 16)

	require.Error(t, err)
	assert.False(t, errors.Is(err, ErrResponseTooLarge), "a dropped read is not an overrun")
	assert.True(t, errors.Is(err, errConnectionDropped))
	assert.Equal(t, []byte("partial"), body,
		"the partial body is handed back, for the callers that treat a failed read as a success")
}
