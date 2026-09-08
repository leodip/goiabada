package commondb

import (
	"fmt"
	"math"
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// PageOffset is the multiplication every paginated read passes through on its
// way to a SQL OFFSET. It used to be written out at each of the seven sites,
// guarded only by "page < 1", so a page near math.MaxInt wrapped the product
// negative and the query failed -- which the admin API answered 500 to, for a
// request that only asked for a page past the end (#305).
//
// The cases below are the whole of it: the ordinary arithmetic, the
// normalisation, and the saturation at the top, where the answer stops being
// the product and becomes the largest offset that fits.

func TestPageOffset_Table(t *testing.T) {
	testCases := []struct {
		page, pageSize, want int
		why                  string
	}{
		// The ordinary arithmetic.
		{1, 10, 0, "the first page skips nothing"},
		{2, 10, 10, "the second page skips one page"},
		{3, 10, 20, "the third"},
		{9, 10, 80, "a page well inside"},
		{1, 20, 0, "the audit log's page size"},
		{4, 20, 60, "the audit log's page size, page 4"},
		{2, 1, 1, "a page of one row"},
		{7, 200, 1200, "the largest page size the API accepts"},

		// A page past the end is arithmetic like any other: the offset simply
		// lands beyond the last row, and the query returns nothing.
		{1000, 10, 9990, "past the end of any small table"},

		// Normalisation. Callers guard these already; PageOffset guards them
		// again so it is correct wherever it is called from.
		{0, 10, 0, "page 0 is page 1"},
		{-1, 10, 0, "a negative page is page 1"},
		{math.MinInt, 10, 0, "the most negative page is page 1"},
		{3, 0, 2, "a page size of 0 counts as 1"},
		{3, -5, 2, "a negative page size counts as 1"},

		// Saturation. Every row here overflowed before: the product wrapped
		// negative, and a negative offset is not a query any engine will run.
		{math.MaxInt, 10, math.MaxInt / 10 * 10, "the largest page"},
		{math.MaxInt, 20, math.MaxInt / 20 * 20, "the largest page, at the audit log's size"},
		{math.MaxInt, 200, math.MaxInt / 200 * 200, "the largest page, at the largest size"},
		{math.MaxInt/10 + 2, 10, math.MaxInt / 10 * 10, "the first page whose product wraps"},

		// The boundary itself, either side of it. One page below saturation the
		// answer is still the exact product.
		{math.MaxInt/10 + 1, 10, math.MaxInt / 10 * 10, "the last page that fits, exactly"},
		{math.MaxInt / 10, 10, (math.MaxInt/10 - 1) * 10, "one below it, still the product"},

		// A page size of 1 makes every page number an offset, so nothing
		// saturates short of the largest int itself.
		{math.MaxInt, 1, math.MaxInt - 1, "at a page size of 1 the product always fits"},
	}

	for _, tc := range testCases {
		t.Run(fmt.Sprintf("page=%d_size=%d", tc.page, tc.pageSize), func(t *testing.T) {
			assert.Equal(t, tc.want, PageOffset(tc.page, tc.pageSize), tc.why)
		})
	}
}

// TestPageOffset_IsNeverNegative is the property the fix exists for, swept
// rather than sampled: a negative offset is the failure, whatever produced it.
// Every page a browser can send, at every page size that can reach the
// database.
func TestPageOffset_IsNeverNegative(t *testing.T) {
	pages := []int{
		math.MinInt, math.MinInt + 1, -1000, -1, 0, 1, 2, 10, 1000,
		1 << 20, 1 << 40, 1 << 62,
		math.MaxInt / 200, math.MaxInt/200 + 1,
		math.MaxInt / 20, math.MaxInt/20 + 1,
		math.MaxInt / 10, math.MaxInt/10 + 1, math.MaxInt/10 + 2,
		math.MaxInt / 2, math.MaxInt - 1, math.MaxInt,
	}
	// 10, 20 and 50 are the defaults the six endpoints use; 200 and 100 are
	// their caps; 1 is what a bad size normalises to.
	sizes := []int{1, 10, 20, 50, 100, 200}

	for _, size := range sizes {
		for _, page := range pages {
			offset := PageOffset(page, size)
			require.GreaterOrEqual(t, offset, 0,
				"PageOffset(%d, %d) = %d, which no engine will run", page, size, offset)
		}
	}
}

// TestPageOffset_IsTheProductUntilItCannotBe pins both halves against exact
// arithmetic done in big.Int: below the boundary the answer is the real
// product, and at or above it the answer is the largest multiple of pageSize an
// int can hold. Comparing against big.Int rather than against the same int
// expression is the point -- an int expression that overflows agrees with
// another int expression that overflows.
func TestPageOffset_IsTheProductUntilItCannotBe(t *testing.T) {
	for _, size := range []int{1, 10, 20, 50, 100, 200} {
		maxOffset := big.NewInt(math.MaxInt)
		maxOffset.Div(maxOffset, big.NewInt(int64(size)))
		maxOffset.Mul(maxOffset, big.NewInt(int64(size)))

		for _, page := range []int{1, 2, 3, 1000, 1 << 30, 1 << 50,
			math.MaxInt/size - 1, math.MaxInt / size, math.MaxInt/size + 1,
			math.MaxInt/size + 2, math.MaxInt / 2, math.MaxInt} {

			if page < 1 {
				continue // a size of 1 makes some of these wrap into negatives
			}

			exact := new(big.Int).Mul(big.NewInt(int64(page)-1), big.NewInt(int64(size)))
			got := big.NewInt(int64(PageOffset(page, size)))

			if exact.Cmp(maxOffset) <= 0 {
				assert.Equal(t, exact.String(), got.String(),
					"PageOffset(%d, %d) should be the exact product", page, size)
			} else {
				assert.Equal(t, maxOffset.String(), got.String(),
					"PageOffset(%d, %d) should saturate at the largest offset that fits", page, size)
			}
		}
	}
}

// TestPageOffset_SaturationIsPastTheEndOfAnyTable is why saturating is a
// truthful answer rather than a convenient one. The caller asked for a page
// past the end; the offset it gets is also past the end, so the query returns
// no rows -- the same answer every other page past the end already gets, rather
// than the error a negative offset produced.
func TestPageOffset_SaturationIsPastTheEndOfAnyTable(t *testing.T) {
	for _, size := range []int{10, 20, 200} {
		offset := PageOffset(math.MaxInt, size)

		// A row count no deployment will reach: a billion billion rows.
		assert.Greater(t, offset, 1_000_000_000_000_000,
			"size=%d: the saturated offset must still be past the end of any table", size)

		// And it is a whole number of pages, the way an offset derived from a
		// page always is.
		assert.Zero(t, offset%size, "size=%d: the saturated offset is not a whole number of pages", size)
	}
}
