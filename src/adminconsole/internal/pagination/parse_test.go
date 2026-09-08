package pagination

import (
	"fmt"
	"math"
	"math/big"
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestParsePage_Table is the whole of ParsePage: every shape a "?page=" can
// arrive in, and the page number it becomes.
//
// The five paginated admin lists used to disagree about most of these rows.
// Three answered 500 to "abc" and to "0" while two clamped to 1, so the same
// typed URL was an error screen on one page and the first page on another.
// Every one of them now reads the parameter through this function, which is
// what the rows below are pinning (#305).
func TestParsePage_Table(t *testing.T) {
	testCases := []struct {
		raw  string
		want int
		why  string
	}{
		// The ordinary cases.
		{"1", 1, "the first page"},
		{"2", 2, "a page"},
		{"99", 99, "a page past the end is not this function's to judge; ClampPage is"},
		{"2147483648", 2147483648, "past a 32-bit int, still an int here"},

		// Absent, empty, blank. A link that builds "?page=" with nothing after
		// it is the same request as no parameter at all.
		{"", 1, "absent or empty"},
		{" ", 1, "a space is not a number to strconv.Atoi"},
		{" 2 ", 1, "Atoi does not trim, so this is not a number either"},

		// Not a number.
		{"abc", 1, "a word"},
		{"1.5", 1, "a decimal"},
		{"1e3", 1, "scientific notation"},
		{"0x10", 1, "hex"},
		{"1,000", 1, "a thousands separator"},
		{"2 OR 1=1", 1, "an injection attempt is just an unparseable page"},

		// A number, but not a page.
		{"0", 1, "pages are one-based"},
		{"-1", 1, "negative"},
		{"-9223372036854775808", 1, "the most negative int"},
		{"+2", 2, "Atoi accepts a leading plus"},
		{"007", 7, "leading zeros"},

		// Out of int range. Atoi returns ErrRange here *and* hands back MaxInt,
		// so a caller keeping the value on a non-nil error would page at MaxInt
		// -- which is exactly the value that overflowed a slice offset and
		// panicked the groups-with-permission page. Returning 1 on any error is
		// what stops that; these rows are the ones that would fail if the error
		// check were narrowed to a syntax error.
		{"9223372036854775808", 1, "one past the largest int"},
		{"99999999999999999999999999", 1, "far past it"},
		{"-99999999999999999999999999", 1, "far below it"},

		// Above maxPage. These parse, so they are pages rather than errors, but
		// they come back bounded: an offset built from math.MaxInt wraps
		// negative, and the wrapped value is what panicked a slice here and what
		// made the auth server return the first page's rows, or refuse outright,
		// for a page far past the end. They stay past the end themselves, so
		// ClampPage still brings them to the last page.
		{strconv.Itoa(math.MaxInt), maxPage, "the largest int, bounded"},
		{strconv.Itoa(math.MaxInt - 1), maxPage, "one below it, bounded"},
		{strconv.Itoa(maxPage + 1), maxPage, "one above the bound"},
		{strconv.Itoa(maxPage), maxPage, "the bound itself is a page"},
		{strconv.Itoa(maxPage - 1), maxPage - 1, "one below the bound is untouched"},
	}

	for _, tc := range testCases {
		t.Run(fmt.Sprintf("%q", tc.raw), func(t *testing.T) {
			assert.Equal(t, tc.want, ParsePage(tc.raw), tc.why)
		})
	}
}

// TestParsePage_NeverReturnsBelowOne sweeps a wide range of raw values, valid
// and not, and holds the one property every caller depends on: whatever comes
// back is a usable page number. A caller that trusted a zero or a negative
// would ask an API for page 0, or compute a negative offset.
func TestParsePage_NeverReturnsBelowOne(t *testing.T) {
	raws := []string{"", " ", "abc", "0", "-1", "-0", "+0", "0.0", "null", "NaN",
		"Infinity", "1/0", "%20", "true", "[]", "9223372036854775808"}
	for i := -3000; i <= 3000; i++ {
		raws = append(raws, strconv.Itoa(i))
	}

	for _, raw := range raws {
		if got := ParsePage(raw); got < 1 {
			t.Fatalf("ParsePage(%q) = %d, which is not a page", raw, got)
		}
	}
}

// TestClampPage_Table pins the answer for a page number against a known total:
// the page itself while it is inside the list, the last page once it is past
// the end, and page 1 for a list with nothing in it.
func TestClampPage_Table(t *testing.T) {
	testCases := []struct {
		total, pageSize, page, want int
		why                         string
	}{
		// An empty list still has a page, holding a lone "[1]", so every page
		// number lands on it. This is the arm the users-with-permission page
		// takes when no permission is selected.
		{0, 10, 1, 1, "empty list, first page"},
		{0, 10, 2, 1, "empty list, any page"},
		{0, 10, math.MaxInt, 1, "empty list, the largest page"},

		// One page, partly full.
		{1, 10, 1, 1, "one row"},
		{1, 10, 2, 1, "one row, page 2"},
		{10, 10, 1, 1, "exactly one full page"},
		{10, 10, 2, 1, "exactly one full page, page 2"},

		// Inside the list: untouched, which is the case that must not cost a
		// second query.
		{73, 10, 1, 1, "first of eight"},
		{73, 10, 4, 4, "middle of eight"},
		{73, 10, 8, 8, "last of eight"},
		{80, 10, 8, 8, "an exact multiple: eight pages, not nine"},

		// Past the end: the last page. "?page=99" over three pages is the
		// report's own example.
		{73, 10, 9, 8, "one past the last"},
		{73, 10, 99, 8, "far past the last"},
		{25, 10, 99, 3, "the reported case: page 99 over three pages"},
		{73, 10, math.MaxInt, 8, "the largest page"},
		{73, 10, maxPage, 8, "the bound ParsePage stops at"},

		// Below the first: page 1. ParsePage should already have caught these,
		// so this is the second of the two guards rather than the first.
		{73, 10, 0, 1, "zero"},
		{73, 10, -1, 1, "negative"},
		{73, 10, math.MinInt, 1, "the most negative int"},

		// The audit log viewer's page size, which is the one that is not 10.
		{20, 20, 2, 1, "one page of twenty"},
		{21, 20, 2, 2, "two pages of twenty"},
		{21, 20, 3, 2, "past two pages of twenty"},

		// A pageSize a caller should never pass, normalised the way New does
		// rather than dividing by zero.
		{5, 0, 3, 3, "pageSize 0 counts as 1, so five pages"},
		{5, 0, 9, 5, "pageSize 0, past the end"},
		{5, -1, 9, 5, "a negative pageSize likewise"},
	}

	for _, tc := range testCases {
		t.Run(fmt.Sprintf("total=%d_size=%d_page=%d", tc.total, tc.pageSize, tc.page), func(t *testing.T) {
			assert.Equal(t, tc.want, ClampPage(tc.total, tc.pageSize, tc.page), tc.why)
		})
	}
}

// TestClampPage_AgreesWithTheBar is the property that matters more than any
// single row: the page a handler settles on is the page the bar draws as
// current. They are computed by two functions, and if those two ever count
// pages differently the list renders one page while the bar highlights
// another -- which is the bug being fixed, in a new place.
//
// The sweep covers every total from 0 to 200 at both page sizes the handlers
// use, against pages from below the first to well past the last.
func TestClampPage_AgreesWithTheBar(t *testing.T) {
	for _, pageSize := range []int{10, 20} {
		for total := 0; total <= 200; total++ {
			for page := -2; page <= total/pageSize+4; page++ {
				clamped := ClampPage(total, pageSize, page)

				require.GreaterOrEqual(t, clamped, 1,
					"total=%d size=%d page=%d", total, pageSize, page)

				// The bar's own idea of the current page, for the page the
				// handler settled on: New clamps internally too, so feeding it
				// the clamped page must leave the same page current.
				var current int
				for _, p := range New(total, pageSize, clamped, 5).Pages {
					if p.IsCurrent {
						current = p.Num
					}
				}
				assert.Equal(t, clamped, current,
					"total=%d size=%d page=%d: the handler shows %d, the bar highlights %d",
					total, pageSize, page, clamped, current)

				// And the clamped page holds rows: it is the last page at worst,
				// never one beyond it. An offset built from it stays inside the
				// list, which is what keeps the hand-rolled slice on the
				// groups-with-permission page in range.
				if total > 0 {
					assert.Less(t, (clamped-1)*pageSize, total,
						"total=%d size=%d page=%d: offset past the end", total, pageSize, page)
				}
			}
		}
	}
}

// TestClampPage_HugePageDoesNotOverflowAnOffset is the arithmetic behind the
// panic. handler_admin_resource_groups_with_permission.go slices its list with
// "(page-1)*pageSize", and the page arrives from a URL. At math.MaxInt that
// product wraps negative and the slice panics; the guards around it only
// bounded from above, so they never saw it.
//
// The clamp is what makes the product safe, so this pins the product and not
// just the page: positive, and within the list.
func TestClampPage_HugePageDoesNotOverflowAnOffset(t *testing.T) {
	const pageSize = 10

	for _, total := range []int{0, 1, 9, 10, 11, 73, 1000} {
		for _, page := range []int{math.MaxInt, math.MaxInt - 1, math.MaxInt / pageSize, maxPage, 1 << 40} {
			clamped := ClampPage(total, pageSize, page)

			start := (clamped - 1) * pageSize
			assert.GreaterOrEqual(t, start, 0,
				"total=%d page=%d: offset %d wrapped", total, page, start)
			assert.LessOrEqual(t, start, total,
				"total=%d page=%d: offset %d past the end", total, page, start)

			// The slice the handler then takes, run for real: this line is the
			// one that panicked.
			list := make([]int, total)
			end := start + pageSize
			if end > total {
				end = total
			}
			assert.NotPanics(t, func() { _ = list[start:end] },
				"total=%d page=%d", total, page)
		}
	}
}

// TestParsePage_ThenClampPage walks the whole path a page number takes, from
// the raw query value to the page the handler asks for, because the two
// functions are only ever used one after the other and the panic needed both
// to miss it.
func TestParsePage_ThenClampPage(t *testing.T) {
	const total, pageSize = 25, 10 // three pages

	testCases := []struct {
		raw  string
		want int
	}{
		{"", 1},
		{"abc", 1},
		{"0", 1},
		{"-5", 1},
		{"2", 2},
		{"3", 3},
		{"4", 3},
		{"99", 3},
		{"9223372036854775807", 3},  // parses, bounds, then clamps
		{"9223372036854775808", 1},  // does not parse
		{"-9223372036854775808", 1}, // parses, below the first
	}

	for _, tc := range testCases {
		t.Run(fmt.Sprintf("%q", tc.raw), func(t *testing.T) {
			assert.Equal(t, tc.want, ClampPage(total, pageSize, ParsePage(tc.raw)))
		})
	}
}

// TestParsePage_OffsetNeverOverflows is the property the bound exists for, and
// it is about the *first* query rather than the clamped one.
//
// A handler cannot clamp before it knows the total, and it only learns the
// total by asking, so the page ParsePage returns goes to the auth server API as
// it stands. There it becomes "OFFSET (page-1)*size" in SQL. Unbounded,
// math.MaxInt wrapped that product negative, and the clamp below never got a
// usable answer to work from: the query either came back with the first page's
// rows, because sqlbuilder drops a negative OFFSET clause, or failed outright
// on the one read that formats the offset into SQL itself, which the handler
// then answered 500 to. On the groups-with-permission page the same product is
// a slice offset, and there it panicked (#305).
//
// So: whatever a browser puts in "?page=", the offset built from the result is
// non-negative, at every page size that can reach the database.
func TestParsePage_OffsetNeverOverflows(t *testing.T) {
	raws := []string{
		"9223372036854775807", // math.MaxInt
		"9223372036854775806",
		"9223372036854775808", // one past it, so ErrRange
		"99999999999999999999999999",
		"4611686018427387904",
		"1000000000000000000",
		"2147483647",
		"1099511627776",
		"99",
		"1",
		"",
		"abc",
		"-1",
		strconv.Itoa(maxPage),
		strconv.Itoa(maxPage + 1),
	}

	// 10 and 20 are the console's own; 200 is the largest the API will accept,
	// and the size maxPage is derived from. 1 catches a caller that normalises
	// a bad size the way New does.
	for _, size := range []int{1, 10, 20, 200} {
		for _, raw := range raws {
			page := ParsePage(raw)
			require.GreaterOrEqual(t, page, 1, "ParsePage(%q)", raw)

			offset := (page - 1) * size
			assert.GreaterOrEqual(t, offset, 0,
				"ParsePage(%q)=%d at size %d gives offset %d, which wrapped", raw, page, size, offset)

			// Not just non-negative: the product is the one the arithmetic
			// actually did, rather than a wrapped value that happens to land
			// back above zero.
			assert.Equal(t, big.NewInt(int64(page-1)).Mul(big.NewInt(int64(page-1)), big.NewInt(int64(size))).String(),
				strconv.Itoa(offset),
				"ParsePage(%q)=%d at size %d", raw, page, size)
		}
	}
}

// TestMaxPage_IsTheLargestSafeBound keeps the bound honest in both directions.
// Too large and the offset it permits wraps, which is the bug; too small and it
// is not the bound it is documented as.
//
// Every assertion here is about the offset a page produces, (page-1)*pageSize,
// and not about page*pageSize. That distinction is the whole of it: checking
// the product of the page itself is off by one page, and an earlier version of
// this test did exactly that, so it passed while the bound was a page tighter
// than the arithmetic required.
func TestMaxPage_IsTheLargestSafeBound(t *testing.T) {
	assert.Equal(t, math.MaxInt/maxApiPageSize+1, maxPage)

	// offsetOf is the offset a page produces, computed exactly, so an int
	// expression that overflows cannot agree with another that overflows.
	offsetOf := func(page int) *big.Int {
		return new(big.Int).Mul(big.NewInt(int64(page)-1), big.NewInt(int64(maxApiPageSize)))
	}

	// The bound itself fits: the int arithmetic gives the exact answer, and
	// that answer is not negative.
	assert.Equal(t, offsetOf(maxPage).String(), strconv.Itoa((maxPage-1)*maxApiPageSize),
		"the bound overflows the offset it was chosen for")
	assert.GreaterOrEqual(t, (maxPage-1)*maxApiPageSize, 0, "the bound wraps its own offset")

	// One page further does not fit, which is what makes this bound the largest
	// rather than merely a safe one. If this assertion ever fails, the bound can
	// be raised.
	assert.NotEqual(t, offsetOf(maxPage+1).String(), strconv.Itoa(maxPage*maxApiPageSize),
		"the page above the bound still fits at size %d, so the bound is tighter than it needs to be",
		maxApiPageSize)

	// And it is far beyond anything the console can page through: at its own
	// page size, a list of this many pages is more rows than any deployment
	// will hold.
	assert.Greater(t, maxPage, 1_000_000_000, "the bound cuts off pages a real list could reach")
}
