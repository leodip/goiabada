// Package pagination computes the page bar rendered by the admin console's
// "paginator" template partial: the previous and next arrows, and the run of
// page numbers around the current page.
//
// A Page whose Num is -1 is an ellipsis rather than a page: the partial renders
// it as "..." and does not link it. Everything the partial reads is an exported
// field of Paginator or Page, because a Go template resolves a field and a
// niladic method alike and fields keep this package free of one-line accessors.
package pagination

// Page is one entry in the bar. Num is -1 for an ellipsis standing in for two
// or more pages that are not shown; any other value is a page number.
type Page struct {
	Num       int
	IsCurrent bool
}

// Paginator is everything the partial needs to draw the bar. Previous and Next
// hold the current page itself when the matching arrow is disabled, so the
// links they build are never out of range.
type Paginator struct {
	HasPrevious bool
	Previous    int
	HasNext     bool
	Next        int
	Pages       []Page
}

// New builds the bar for a result set of total items shown pageSize at a time,
// with current selected, showing at most numPages consecutive page numbers plus
// an ellipsis at either end. Callers pass a numPages of 5.
//
// Out-of-range arguments are clamped rather than rejected, because current
// comes from a "?page=" query parameter that anybody can type.
func New(total, pageSize, current, numPages int) *Paginator {
	if pageSize <= 0 {
		pageSize = 1
	}
	if current <= 0 {
		current = 1
	}

	totalPages := (total + pageSize - 1) / pageSize
	if totalPages < 1 {
		totalPages = 1
	}
	if current > totalPages {
		current = totalPages
	}

	p := &Paginator{
		HasPrevious: current > 1,
		Previous:    current,
		HasNext:     total > current*pageSize,
		Next:        current,
	}
	if p.HasPrevious {
		p.Previous = current - 1
	}
	if p.HasNext {
		p.Next = current + 1
	}

	if numPages <= 0 {
		return p
	}

	// The window of numPages consecutive pages holding current, with current
	// just left of the middle when numPages is even. Slide it back inside the
	// range when it runs off either end, so the bar shows numPages numbers
	// whenever there are that many pages.
	first := current - (numPages-1)/2
	last := first + numPages - 1
	if last > totalPages {
		first -= last - totalPages
		last = totalPages
	}
	if first < 1 {
		first = 1
		last = first + numPages - 1
		if last > totalPages {
			last = totalPages
		}
	}

	// Each end shows the pages outside the window as a single "...", except
	// when exactly one page is outside: an ellipsis occupies the slot that page
	// could have used and is not a link, so hiding one page behind it makes
	// that page reachable only through an arrow. Showing the number instead
	// costs nothing and the dots then always stand for two or more pages.
	// Replacing either arm with an unconditional "..." reverses the behaviour
	// #271 shipped.
	switch {
	case first == 2:
		p.Pages = append(p.Pages, Page{Num: 1})
	case first > 2:
		p.Pages = append(p.Pages, Page{Num: -1})
	}
	for n := first; n <= last; n++ {
		p.Pages = append(p.Pages, Page{Num: n, IsCurrent: n == current})
	}
	switch {
	case last == totalPages-1:
		p.Pages = append(p.Pages, Page{Num: totalPages})
	case last < totalPages-1:
		p.Pages = append(p.Pages, Page{Num: -1})
	}

	return p
}
