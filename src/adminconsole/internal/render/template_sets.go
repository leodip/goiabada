package render

import (
	"html/template"
	"sync"
)

// templateSets holds every template set the renderer draws, a page's or the "settings unavailable"
// page's, parsed the first time it is drawn and kept: the built-in templates cannot change while the
// console runs, so a request only executes its set (#819 decisions 5 and 6). A set that does not
// parse is not kept, and is an error at each draw. Concurrent requests share the sets.
type templateSets struct {
	mu   sync.RWMutex
	sets map[string]*templateSet
}

// templateSet is a parsed set, with what a draw reads off its parse trees, read once as it is
// parsed: html/template rewrites the trees as it first executes the set, so reading them at each draw
// would race a concurrent first draw.
type templateSet struct {
	templ *template.Template
	// page is the data-page the set names, stylingcontract.PageName's answer.
	page string
	// adminPage is whether the set draws the admin menu, drawsAdminMenu's answer.
	adminPage bool
}

func newTemplateSets() *templateSets {
	return &templateSets{sets: map[string]*templateSet{}}
}

// get answers the set kept under key, parsing it with parse the first time. A page's key is its
// layout and its template joined by a NUL, and the "settings unavailable" page's is its file name,
// which holds none.
func (s *templateSets) get(key string, parse func() (*templateSet, error)) (*templateSet, error) {
	s.mu.RLock()
	set, ok := s.sets[key]
	s.mu.RUnlock()
	if ok {
		return set, nil
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if set, ok = s.sets[key]; ok {
		return set, nil
	}
	set, err := parse()
	if err != nil {
		return nil, err
	}
	s.sets[key] = set
	return set, nil
}
