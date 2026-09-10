package migrator

import (
	"io/fs"
	"regexp"
	"sort"
	"strconv"

	"github.com/leodip/goiabada/core/errs"
)

// migrationFileRe reads a filename exactly the way golang-migrate's source parser read it, from
// its source/parse.go: the version is the LEADING INTEGER with no fixed width, which is what
// keeps SQLite's five-digit 00001_initial_create counted as version 1 rather than as absent. The
// extension is captured but unconstrained, again as the library had it.
//
// src/core/data/migration_rules_test.go carries the same reading in its own migrationFileRe, and
// deliberately so: that lint is a check ON the migration directories and has to keep working if
// this parser ever drifts, so the two are twins by intent rather than one importing the other
// (#268).
var migrationFileRe = regexp.MustCompile(`^([0-9]+)_(.*)\.(down|up)\.(.*)$`)

// source is the set of migration files a binary carries for one engine, parsed once at
// construction. Nothing here reads a file body until a step asks for it.
type source struct {
	fsys fs.FS
	dir  string

	// versions is every version the set carries, sorted ascending, each appearing once. Gaps are
	// normal and differ per engine, so stepping walks this list rather than counting.
	versions []int
	ups      map[int]string
	downs    map[int]string
}

// newSource parses dir in fsys eagerly. A filename that does not match is skipped, as the library
// skipped it, so a README or a stray file in the directory is not a startup failure. Two files at
// one version and direction are refused, naming both, because there is no defensible way to
// choose between them.
func newSource(fsys fs.FS, dir string) (*source, error) {
	entries, err := fs.ReadDir(fsys, dir)
	if err != nil {
		return nil, errs.Errorf("unable to read the migrations directory %q: %w", dir, err)
	}

	s := &source{
		fsys:  fsys,
		dir:   dir,
		ups:   map[int]string{},
		downs: map[int]string{},
	}

	seen := map[int]bool{}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		m := migrationFileRe.FindStringSubmatch(e.Name())
		if m == nil {
			continue
		}
		version, err := strconv.Atoi(m[1])
		if err != nil {
			// Only reachable for a number too large for an int, since the pattern already
			// admitted nothing but digits.
			return nil, errs.Errorf("migration file %q carries an unreadable version number: %w", e.Name(), err)
		}

		half := s.ups
		if m[3] == "down" {
			half = s.downs
		}
		if existing, dup := half[version]; dup {
			return nil, errs.Errorf("two %s migrations are numbered %s: %q and %q; one number means one change",
				m[3], formatVersion(version), existing, e.Name())
		}
		half[version] = e.Name()

		if !seen[version] {
			seen[version] = true
			s.versions = append(s.versions, version)
		}
	}

	sort.Ints(s.versions)
	return s, nil
}

// first is the lowest version the set carries, or NilVersion when it is empty.
func (s *source) first() int {
	if len(s.versions) == 0 {
		return NilVersion
	}
	return s.versions[0]
}

// head is the highest version the set carries, and so the version a binary migrates up to.
func (s *source) head() int {
	if len(s.versions) == 0 {
		return NilVersion
	}
	return s.versions[len(s.versions)-1]
}

// exists reports whether the set carries a version in either direction, which is what the
// library's versionExists accepted: a version with only a down file still counts, because the
// database can legitimately record it.
func (s *source) exists(v int) bool {
	_, up := s.ups[v]
	_, down := s.downs[v]
	return up || down
}

// next is the lowest version above v, or NilVersion when v is at or above the head.
func (s *source) next(v int) int {
	i := sort.SearchInts(s.versions, v+1)
	if i == len(s.versions) {
		return NilVersion
	}
	return s.versions[i]
}

// prev is the highest version below v, or NilVersion when there is none, which is also what the
// floor of a full step down looks like.
func (s *source) prev(v int) int {
	i := sort.SearchInts(s.versions, v)
	if i == 0 {
		return NilVersion
	}
	return s.versions[i-1]
}

// neighbours are the nearest carried versions either side of v, each NilVersion when absent. They
// are what an unknown-version refusal offers an operator instead of the number they typed.
func (s *source) neighbours(v int) (below, above int) {
	return s.prev(v), s.next(v)
}

// readUp and readDown answer the file body for a version and direction, and (false) when the set
// carries no file there. A missing file is not an error: the library ran nothing and still moved
// the marker, which is how a version present in one direction only behaves, and the four
// migration sets rely on it.
func (s *source) readUp(v int) ([]byte, string, bool, error) {
	return s.read(s.ups, v)
}

func (s *source) readDown(v int) ([]byte, string, bool, error) {
	return s.read(s.downs, v)
}

func (s *source) read(half map[int]string, v int) ([]byte, string, bool, error) {
	name, ok := half[v]
	if !ok {
		return nil, "", false, nil
	}
	body, err := fs.ReadFile(s.fsys, s.dir+"/"+name)
	if err != nil {
		return nil, name, true, errs.Errorf("unable to read migration file %q: %w", name, err)
	}
	return body, name, true, nil
}
