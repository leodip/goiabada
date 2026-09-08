package pagination

import (
	"math"
	"strconv"
)

// maxApiPageSize is the largest page size the auth server API accepts, from the
// "s > 0 && s <= 200" its list endpoints validate with. The admin console never
// asks for more than 20, but the bound below is only honest if it holds for the
// largest page size that could reach the database.
const maxApiPageSize = 200

// maxPage is the largest page number ParsePage will return.
//
// A page number does not stay in the admin console: it reaches the database as
// an offset of (page-1)*pageSize, in the auth server's SQL and once, on the
// groups-with-permission page, in a slice expression here. A page large enough
// to overflow that product is not a page at all -- it is the value that
// panicked the slice, and that turns a SQL OFFSET negative, where it went two
// ways: sqlbuilder drops a negative OFFSET clause, so the query came back with
// the FIRST page's rows labelled as the page asked for, and the one read that
// formats the offset into SQL itself got the engine's refusal and a 500 (#305).
//
// commondb.PageOffset now saturates the offset on the far side of that call, so
// neither half can happen any more. Bounding the page here is still this
// package's own business: the console should not send a page it knows is
// nonsense, and the bound is what keeps the offset in range at both ends of the
// call, so the clamp that follows has a total to work from.
//
// The bound is math.MaxInt/maxApiPageSize, so the product is in range on any
// platform's int rather than only on a 64-bit one. That is a page number no
// list will ever reach: at the console's page size of 10 it is a list of
// 4.6e17 rows.
var maxPage = math.MaxInt / maxApiPageSize

// ParsePage turns the raw value of a "?page=" query parameter into a page
// number. Anything a browser can put there and this package cannot use -- an
// absent parameter, an empty one, a word, a decimal, a negative, zero, or a
// number too large for an int -- becomes page 1 rather than an error, because
// the parameter is part of a URL a person can type, edit or keep in a bookmark
// after the list behind it has shrunk, and the first page is always a truthful
// answer to a request for a page that is not there.
//
// Every handler that reads "?page=" uses this, so the five paginated admin
// lists no longer disagree: three of them used to answer 500 to "page=abc" and
// to "page=0" while two clamped to 1 (#305).
//
// A page above maxPage becomes maxPage rather than 1, so it stays a page past
// the end and ClampPage brings it back to the last page like any other, instead
// of the request quietly landing on the first page.
//
// The out-of-int-range case is the one worth naming: strconv.Atoi reports
// ErrRange for "9223372036854775808" and hands back math.MaxInt along with it,
// so a caller that keeps the value on a non-nil error would page at MaxInt.
// Returning 1 on any error, rather than on a syntax error alone, is what stops
// that.
func ParsePage(raw string) int {
	page, err := strconv.Atoi(raw)
	if err != nil || page < 1 {
		return 1
	}
	if page > maxPage {
		return maxPage
	}
	return page
}

// ClampPage returns the page a caller should show, given the total number of
// items the query at page reported. It is page itself while page is within the
// list, the last page once page is past the end, and 1 for an empty list.
//
// It exists because the bar clamps and the query does not: New draws page 3 of
// 3 as the current page for a "?page=99", while the handler asks the API for
// page 99 and gets nothing, so the list renders empty under a bar that says it
// should be full. A handler calls this after it learns the total, and asks
// again when the answer moved (#305).
//
// It shares pageCount with New rather than counting pages itself, so the page
// the handler settles on and the page the bar highlights cannot drift apart.
func ClampPage(total, pageSize, page int) int {
	if page < 1 {
		return 1
	}
	if last := pageCount(total, pageSize); page > last {
		return last
	}
	return page
}
