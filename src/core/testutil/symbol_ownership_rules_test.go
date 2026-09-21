package testutil

// Seam 1: the fifth table, src/core/OWNERSHIP.md, over fixture trees written into a temp directory
// and read through the same census the real caller and ownershipdump use.
//
// The synthetic half exists for the reason architecture_rules_test.go sets out, and this rule needs
// it more than any of the other seven. The table was generated from the tree, so the real tree
// satisfies it by construction and a passing run against it proves only that nothing crashed. Every
// direction the rule refuses therefore gets a fixture that must be caught, and every deliberate
// leniency — a test file, a same-spelled local, a package naming its own siblings from a justified
// declaration — gets one that must survive.

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---- fixture helpers -----------------------------------------------------------------------

// symbolBaselineFiles is a tree that resolves all four computed justifications and leaves exactly
// three symbols for a human to assert, one per asserted word. Every case below starts from it, so
// a fixture says only what it is about.
//
//	Widget     both-apps    both applications name it
//	New        both-apps    both applications name it
//	Colour     both-apps    both applications name it
//	Kernelled  kernel       another core package names it
//	Limit      own-package  New's body names it and New is justified
//	Cog        reachable    Widget's declaration names it
//	ColourRed  reachable    a const spelling the justified type Colour
//	ColourBlue reachable    a const inheriting Colour from the spec above it
//	Stable     none         only the auth server names it
//	Departing  none         only the admin console names it
//	Helper     none         no production file anywhere names it; one test does
func symbolBaselineFiles() map[string]string {
	return map[string]string{
		"core/shared/shared.go": `package shared

type Widget struct {
	Part Cog
}

type Cog struct{}

const Limit = 5

type Colour string

const (
	ColourRed Colour = "red"
	ColourBlue
)

type Kernelled struct{}

type Stable struct{}

type Departing struct{}

type Helper struct{}

func New() *Widget {
	if Limit > 0 {
		return &Widget{}
	}
	return nil
}
`,
		"core/other/other.go": `package other

import "example.test/core/shared"

var _ = shared.Kernelled{}
`,
		"authserver/main.go": `package main

import "example.test/core/shared"

var (
	_ = shared.Widget{}
	_ = shared.Colour("")
	_ = shared.New()
	_ = shared.Stable{}
)
`,
		"authserver/main_test.go": `package main

import "example.test/core/shared"

var _ = shared.Helper{}
`,
		"adminconsole/main.go": `package main

import "example.test/core/shared"

var (
	_ = shared.Widget{}
	_ = shared.Colour("")
	_ = shared.New()
	_ = shared.Departing{}
)
`,
	}
}

// symbolBaselineRows is the table that describes symbolBaselineFiles exactly.
func symbolBaselineRows() []string {
	return []string{
		"core/shared Cog reachable —",
		"core/shared Colour both-apps —",
		"core/shared ColourBlue reachable —",
		"core/shared ColourRed reachable —",
		"core/shared Departing moving #385 carries it to the admin console.",
		"core/shared Helper test-support Only a test names it.",
		"core/shared Kernelled kernel —",
		"core/shared Limit own-package —",
		"core/shared New both-apps —",
		"core/shared Stable contract A value the two processes agree on.",
		"core/shared Widget both-apps —",
	}
}

// withSymbolBaseline overlays a fixture onto the baseline tree.
func withSymbolBaseline(files map[string]string) map[string]string {
	out := symbolBaselineFiles()
	for rel, src := range files {
		out[rel] = src
	}
	return out
}

// symbolRows builds the table from "<package> <symbol> <justification> <note...>" lines. The note
// is the rest of the line, because it is prose.
func symbolRows(rows ...string) []symbolRow {
	out := make([]symbolRow, 0, len(rows))
	for i, r := range rows {
		f := strings.SplitN(r, " ", 4)
		note := ""
		if len(f) == 4 {
			note = f[3]
		}
		out = append(out, symbolRow{pkg: f[0], symbol: f[1], justification: f[2], note: note, line: i + 1})
	}
	return out
}

// checkSymbols runs the census and the checks over a fixture tree, sorted the way
// assertSymbolOwnership sorts findings.
func checkSymbols(t *testing.T, files map[string]string, rows []string) []string {
	t.Helper()

	root := writeTree(t, files)
	graph, err := buildImportGraph(root)
	require.NoError(t, err)
	census, err := buildSymbolCensus(root, graph)
	require.NoError(t, err)

	findings := checkSymbolOwnership(symbolRows(rows...), census)
	sort.Strings(findings)
	return findings
}

// computedOver returns what the resolver makes of a fixture tree, keyed by "package.Symbol".
func computedOver(t *testing.T, files map[string]string) map[string]string {
	t.Helper()

	root := writeTree(t, files)
	graph, err := buildImportGraph(root)
	require.NoError(t, err)
	census, err := buildSymbolCensus(root, graph)
	require.NoError(t, err)

	out := map[string]string{}
	for key, word := range census.computeJustifications() {
		out[key.String()] = word
	}
	for _, key := range census.declared {
		if _, ok := out[key.String()]; !ok {
			out[key.String()] = ""
		}
	}
	return out
}

// symbolOwnershipDoc renders a whole OWNERSHIP.md around a table, which is what the reporting half
// reads off disk.
func symbolOwnershipDoc(rows ...string) string {
	var b strings.Builder
	b.WriteString("# Core symbol ownership\n\nPreamble prose the parser never reads.\n\n")
	b.WriteString(symbolOwnershipHeading + "\n\n")
	b.WriteString("| package | symbol | justification | note |\n|---|---|---|---|\n")
	for _, r := range rows {
		f := strings.SplitN(r, " ", 4)
		note := "—"
		if len(f) == 4 {
			note = f[3]
		}
		b.WriteString("| `" + f[0] + "` | `" + f[1] + "` | " + f[2] + " | " + note + " |\n")
	}
	return b.String()
}

// ---- the seven justifications --------------------------------------------------------------

// TestSymbolOwnership_TheBaselineTreeResolves is the tree that must pass, and it is also the
// resolver's table: every computed word reached the symbol it belongs to, and the three the tree
// cannot justify reached none.
func TestSymbolOwnership_TheBaselineTreeResolves(t *testing.T) {
	computed := computedOver(t, symbolBaselineFiles())

	assert.Equal(t, map[string]string{
		"core/shared.Widget":     justificationBothApps,
		"core/shared.New":        justificationBothApps,
		"core/shared.Colour":     justificationBothApps,
		"core/shared.Kernelled":  justificationKernel,
		"core/shared.Limit":      justificationOwnPackage,
		"core/shared.Cog":        justificationReachable,
		"core/shared.ColourRed":  justificationReachable,
		"core/shared.ColourBlue": justificationReachable,
		"core/shared.Stable":     "",
		"core/shared.Departing":  "",
		"core/shared.Helper":     "",
	}, computed)

	assert.Empty(t, checkSymbols(t, symbolBaselineFiles(), symbolBaselineRows()))
}

// TestSymbolOwnership_AConstInheritsItsType pins the half of the reachable arm that reads the Go
// spec rather than the syntax. ColourBlue spells no type at all, and reading each ValueSpec on its
// own is what made probe/census2.out call the three Gender constants test-only while Gender itself
// was both-apps.
func TestSymbolOwnership_AConstInheritsItsType(t *testing.T) {
	computed := computedOver(t, symbolBaselineFiles())

	assert.Equal(t, justificationReachable, computed["core/shared.ColourRed"])
	assert.Equal(t, justificationReachable, computed["core/shared.ColourBlue"])
}

// TestSymbolOwnership_AConstTypedByConversionIsReachable is the same arm where the type is in the
// expression rather than the type slot. `TintRed = Tint("red")` and `TintRed Tint = "red"` declare
// the same constant, and a reader choosing the first spelling should not be handed an asserted
// escape hatch for a symbol the tree justifies. Final review round 1, finding 3.
func TestSymbolOwnership_AConstTypedByConversionIsReachable(t *testing.T) {
	files := withSymbolBaseline(map[string]string{
		"core/shared/tint.go": `package shared

type Tint string

const (
	TintRed = Tint("red")
	TintBlue
)
`,
		"authserver/main.go": `package main

import "example.test/core/shared"

var (
	_ = shared.Widget{}
	_ = shared.Colour("")
	_ = shared.New()
	_ = shared.Stable{}
	_ = shared.Tint("")
)
`,
		"adminconsole/main.go": `package main

import "example.test/core/shared"

var (
	_ = shared.Widget{}
	_ = shared.Colour("")
	_ = shared.New()
	_ = shared.Departing{}
	_ = shared.Tint("")
)
`,
	})

	computed := computedOver(t, files)

	assert.Equal(t, justificationBothApps, computed["core/shared.Tint"])
	assert.Equal(t, justificationReachable, computed["core/shared.TintRed"],
		"a const whose type comes from a conversion is a const of that type")
	assert.Equal(t, justificationReachable, computed["core/shared.TintBlue"],
		"and so is the one repeating that expression")
}

// TestSymbolOwnership_AConversionInAnInitializerIsTheDeclaredType is the other half of that, and
// the half the circular fixture cannot reach: `LevelLow = Level("low")` puts the declared type in
// the expression, where it would otherwise read as an ordinary reference and let the constant
// vouch for the type it enumerates. Describe's signature is the only honest evidence for Level
// here, so Level is reachable and must not be promoted to own-package by its own member.
func TestSymbolOwnership_AConversionInAnInitializerIsTheDeclaredType(t *testing.T) {
	files := withSymbolBaseline(map[string]string{
		"core/ring/ring.go": `package ring

type Level string

const LevelLow = Level("low")

func Describe() Level {
	return ""
}
`,
		"authserver/main.go": `package main

import (
	"example.test/core/ring"
	"example.test/core/shared"
)

var (
	_ = shared.Widget{}
	_ = shared.Colour("")
	_ = shared.New()
	_ = shared.Stable{}
	_ = ring.Describe()
)
`,
		"adminconsole/main.go": `package main

import (
	"example.test/core/ring"
	"example.test/core/shared"
)

var (
	_ = shared.Widget{}
	_ = shared.Colour("")
	_ = shared.New()
	_ = shared.Departing{}
	_ = ring.Describe()
)
`,
	})

	computed := computedOver(t, files)

	assert.Equal(t, justificationBothApps, computed["core/ring.Describe"])
	assert.Equal(t, justificationReachable, computed["core/ring.Level"],
		"Describe's signature is the evidence; LevelLow's own conversion is not")
	assert.Equal(t, justificationReachable, computed["core/ring.LevelLow"])
}

// ---- both directions: the symbol and the row -----------------------------------------------

// TestSymbolOwnership_ASymbolWithNoRow is the direction that makes adding an exported symbol to
// core a decision. Without it the table only ever describes what somebody remembered to write down.
func TestSymbolOwnership_ASymbolWithNoRow(t *testing.T) {
	rows := symbolBaselineRows()
	rows = append(rows[:1], rows[2:]...) // drop the Colour row

	findings := checkSymbols(t, symbolBaselineFiles(), rows)

	assertFindings(t, findings, "holds no row for core/shared.Colour")
}

// TestSymbolOwnership_ARowForASymbolThatIsGone is the other direction, and it is what stops the
// table outliving what it describes: the stage that moves a symbol has to delete its row.
func TestSymbolOwnership_ARowForASymbolThatIsGone(t *testing.T) {
	rows := append(symbolBaselineRows(), "core/shared Vanished kernel —")

	findings := checkSymbols(t, symbolBaselineFiles(), rows)

	assertFindings(t, findings, "records core/shared.Vanished, which the tree no longer declares")
}

// TestSymbolOwnership_ADuplicateRow keeps two rows for one symbol from disagreeing quietly, with
// whichever the parser read last deciding.
func TestSymbolOwnership_ADuplicateRow(t *testing.T) {
	rows := append(symbolBaselineRows(), "core/shared Widget contract A second opinion.")

	findings := checkSymbols(t, symbolBaselineFiles(), rows)

	assertFindings(t, findings, "gives core/shared.Widget a second row")
}

// ---- a row must state the strongest claim the tree backs -------------------------------------

// TestSymbolOwnership_ARowClaimingLessThanTheTreeBacks is what keeps the weaker words honest. A
// both-apps symbol recorded as reachable is true and useless: it hides that removing one
// application's caller would change the answer.
func TestSymbolOwnership_ARowClaimingLessThanTheTreeBacks(t *testing.T) {
	rows := symbolBaselineRows()
	for i, r := range rows {
		if strings.HasPrefix(r, "core/shared Widget ") {
			rows[i] = "core/shared Widget reachable —"
		}
	}

	findings := checkSymbols(t, symbolBaselineFiles(), rows)

	assertFindings(t, findings, "records core/shared.Widget as reachable, but the tree backs both-apps")
}

// TestSymbolOwnership_AnAssertedRowForASymbolTheTreeJustifies refuses an escape hatch used where
// the tree already has an answer, which is the direction that would let the vocabulary rot.
func TestSymbolOwnership_AnAssertedRowForASymbolTheTreeJustifies(t *testing.T) {
	rows := symbolBaselineRows()
	for i, r := range rows {
		if strings.HasPrefix(r, "core/shared Limit ") {
			rows[i] = "core/shared Limit contract Asserted where the tree already answered."
		}
	}

	findings := checkSymbols(t, symbolBaselineFiles(), rows)

	assertFindings(t, findings, "records core/shared.Limit as contract, but the tree backs own-package")
}

// TestSymbolOwnership_AComputedRowTheTreeDoesNotBack is the same check from the other side: a word
// the reference graph cannot produce is not available just because it reads well.
func TestSymbolOwnership_AComputedRowTheTreeDoesNotBack(t *testing.T) {
	rows := symbolBaselineRows()
	for i, r := range rows {
		if strings.HasPrefix(r, "core/shared Stable ") {
			rows[i] = "core/shared Stable both-apps —"
		}
	}

	findings := checkSymbols(t, symbolBaselineFiles(), rows)

	assertFindings(t, findings, "records core/shared.Stable as both-apps, but nothing in the tree backs a computed justification for it")
}

// TestSymbolOwnership_AWordThatIsNoneOfTheSeven catches a typo before it reads as a claim.
func TestSymbolOwnership_AWordThatIsNoneOfTheSeven(t *testing.T) {
	rows := symbolBaselineRows()
	for i, r := range rows {
		if strings.HasPrefix(r, "core/shared Stable ") {
			rows[i] = "core/shared Stable contractual A value the two processes agree on."
		}
	}

	findings := checkSymbols(t, symbolBaselineFiles(), rows)

	assertFindings(t, findings, `gives core/shared.Stable the justification "contractual", which is none of the seven`)
}

// ---- circular evidence is not evidence -------------------------------------------------------

// circularPackage is the shape that made this rule necessary: an exported type, its constructor,
// a method and typed constants, with nothing outside the package naming any of them. Read naively
// every one of them justifies another, and core/enums — the package #385 deletes — is exactly this.
const circularPackage = `package ring

type Level string

const (
	LevelLow  Level = "low"
	LevelHigh Level = "high"
)

func NewLevel(s string) Level {
	return Level(s)
}

func (l Level) IsHigherThan(other Level) bool {
	return l == LevelHigh && other == LevelLow
}
`

// TestSymbolOwnership_CircularEvidenceJustifiesNothing is plan review round 2's finding 6. Without
// the two excluded references — a method's receiver, and the declared type of a const the same
// package writes — every symbol here resolves and the guard is blind to the package it was built
// to see.
func TestSymbolOwnership_CircularEvidenceJustifiesNothing(t *testing.T) {
	files := withSymbolBaseline(map[string]string{"core/ring/ring.go": circularPackage})

	computed := computedOver(t, files)

	for _, name := range []string{"core/ring.Level", "core/ring.LevelLow", "core/ring.LevelHigh", "core/ring.NewLevel"} {
		assert.Equal(t, "", computed[name], "%s has no evidence outside its own package", name)
	}
}

// TestSymbolOwnership_ACircularPackageAcceptsMovingRows is the other half of the same fixture: the
// words a human may write there, and that the table is satisfied once they are written.
func TestSymbolOwnership_ACircularPackageAcceptsMovingRows(t *testing.T) {
	files := withSymbolBaseline(map[string]string{"core/ring/ring.go": circularPackage})
	rows := append(symbolBaselineRows(),
		"core/ring Level moving #385 carries it to the auth server.",
		"core/ring LevelLow moving #385 carries it to the auth server.",
		"core/ring LevelHigh moving #385 carries it to the auth server.",
		"core/ring NewLevel moving #385 carries it to the auth server.",
	)

	assert.Empty(t, checkSymbols(t, files, rows))
}

// TestSymbolOwnership_OneReferenceFromEachApplicationEndsTheAssertion is the burn-down direction.
// The same package, given a caller in each application, resolves to both-apps and refuses the
// moving rows that were legal a moment ago — which is what makes a moving row expire rather than
// settle.
func TestSymbolOwnership_OneReferenceFromEachApplicationEndsTheAssertion(t *testing.T) {
	files := withSymbolBaseline(map[string]string{
		"core/ring/ring.go": circularPackage,
		"authserver/main.go": `package main

import (
	"example.test/core/ring"
	"example.test/core/shared"
)

var (
	_ = shared.Widget{}
	_ = shared.Colour("")
	_ = shared.New()
	_ = shared.Stable{}
	_ = ring.Level("")
)
`,
		"adminconsole/main.go": `package main

import (
	"example.test/core/ring"
	"example.test/core/shared"
)

var (
	_ = shared.Widget{}
	_ = shared.Colour("")
	_ = shared.New()
	_ = shared.Departing{}
	_ = ring.Level("")
)
`,
	})

	computed := computedOver(t, files)
	assert.Equal(t, justificationBothApps, computed["core/ring.Level"])
	// The two constants follow, now that the type whose method names them has a seed. The
	// constructor does not: NewLevel names Level, which is the arrow pointing the other way, and
	// nothing in production calls it. So it still owes a written word, which is the rule working
	// rather than a gap in it.
	assert.Equal(t, justificationOwnPackage, computed["core/ring.LevelLow"])
	assert.Equal(t, justificationOwnPackage, computed["core/ring.LevelHigh"])
	assert.Equal(t, "", computed["core/ring.NewLevel"])

	rows := append(symbolBaselineRows(),
		"core/ring Level moving #385 carries it to the auth server.",
		"core/ring LevelLow own-package —",
		"core/ring LevelHigh own-package —",
		"core/ring NewLevel moving #385 carries it to the auth server.",
	)

	findings := checkSymbols(t, files, rows)
	assertFindings(t, findings, "records core/ring.Level as moving, but the tree backs both-apps")
}

// ---- a method rides with its receiver, however the receiver is spelled -----------------------

// TestSymbolOwnership_AGenericMethodRidesWithItsReceiver is the attribution half of the same rule,
// at the two shapes the parser keeps for a generic receiver: `Box[T]` is an IndexExpr and
// `Pair[K, V]` an IndexListExpr, so each is a separate arm of the walk that finds the base name.
// Fail to unwrap one and the method is discarded rather than attributed, which is the quiet
// direction: everything only that method reaches loses its evidence, and the table then asks a
// human to assert a symbol the tree does in fact justify. Before these two receivers existed,
// replacing either arm on its own left the whole core tier green. Final review round 5, finding 3
// (#385).
func TestSymbolOwnership_AGenericMethodRidesWithItsReceiver(t *testing.T) {
	files := withSymbolBaseline(map[string]string{
		"core/ring/ring.go": `package ring

type Crank struct{}

type Flange struct{}

type Sprocket struct{}

type Bearing struct{}

type Box[T any] struct {
	V T
}

func (b Box[T]) Build() *Crank {
	_ = Flange{}
	return nil
}

type Pair[K, V any] struct {
	Key   K
	Value V
}

func (p Pair[K, V]) Build() *Sprocket {
	_ = Bearing{}
	return nil
}
`,
		"authserver/main.go": `package main

import (
	"example.test/core/ring"
	"example.test/core/shared"
)

var (
	_ = shared.Widget{}
	_ = shared.Colour("")
	_ = shared.New()
	_ = shared.Stable{}
	_ = ring.Box[int]{}
	_ = ring.Pair[int, string]{}
)
`,
		"adminconsole/main.go": `package main

import (
	"example.test/core/ring"
	"example.test/core/shared"
)

var (
	_ = shared.Widget{}
	_ = shared.Colour("")
	_ = shared.New()
	_ = shared.Departing{}
	_ = ring.Box[int]{}
	_ = ring.Pair[int, string]{}
)
`,
	})

	computed := computedOver(t, files)

	assert.Equal(t, justificationBothApps, computed["core/ring.Box"])
	assert.Equal(t, justificationBothApps, computed["core/ring.Pair"])
	assert.Equal(t, justificationReachable, computed["core/ring.Crank"],
		"a one-parameter generic method's signature is its receiver's declaration")
	assert.Equal(t, justificationOwnPackage, computed["core/ring.Flange"],
		"and its body is its receiver's body")
	assert.Equal(t, justificationReachable, computed["core/ring.Sprocket"],
		"which holds for a receiver carrying more than one type parameter too")
	assert.Equal(t, justificationOwnPackage, computed["core/ring.Bearing"],
		"in the body as in the signature")
}

// TestSymbolOwnership_AParenthesizedReceiverStillNamesItsType is the receiver form the walk did not
// know. Go accepts `func (l *(Level)) Build()` and gofmt preserves parentheses between the pointer
// and its base, so the form survives every formatting check this repository runs and a reader has
// no hint it is unusual. The walk stripped pointers and type arguments but not parentheses, so it
// returned "" and the method was dropped rather than attributed to Level -- a symbol only that
// method reaches would then be asked to justify itself in writing. The second receiver is the
// composition, `*(Box[T])`, which is a pointer, parentheses and an instantiation at once. Final
// review round 5, finding 4 (#385).
func TestSymbolOwnership_AParenthesizedReceiverStillNamesItsType(t *testing.T) {
	files := withSymbolBaseline(map[string]string{
		"core/ring/ring.go": `package ring

type Level struct{}

type Orphan struct{}

type Cotter struct{}

type Gasket struct{}

type Spindle struct{}

type Box[T any] struct {
	V T
}

func (l *(Level)) Build() *Orphan {
	_ = Cotter{}
	return nil
}

func (b *(Box[T])) Peek() *Gasket {
	_ = Spindle{}
	return nil
}
`,
		"authserver/main.go": `package main

import (
	"example.test/core/ring"
	"example.test/core/shared"
)

var (
	_ = shared.Widget{}
	_ = shared.Colour("")
	_ = shared.New()
	_ = shared.Stable{}
	_ = ring.Level{}
	_ = ring.Box[int]{}
)
`,
		"adminconsole/main.go": `package main

import (
	"example.test/core/ring"
	"example.test/core/shared"
)

var (
	_ = shared.Widget{}
	_ = shared.Colour("")
	_ = shared.New()
	_ = shared.Departing{}
	_ = ring.Level{}
	_ = ring.Box[int]{}
)
`,
	})

	computed := computedOver(t, files)

	assert.Equal(t, justificationBothApps, computed["core/ring.Level"])
	assert.Equal(t, justificationBothApps, computed["core/ring.Box"])
	assert.Equal(t, justificationReachable, computed["core/ring.Orphan"],
		"a parenthesized pointer receiver names its type as surely as a bare one")
	assert.Equal(t, justificationOwnPackage, computed["core/ring.Cotter"],
		"so the method's body is its receiver's body")
	assert.Equal(t, justificationReachable, computed["core/ring.Gasket"],
		"and parentheses compose with the pointer and the type arguments")
	assert.Equal(t, justificationOwnPackage, computed["core/ring.Spindle"],
		"in the body as in the signature")
}

// ---- a name is not a reference ---------------------------------------------------------------

// TestSymbolOwnership_ASameSpelledNameIsNotAReference is why the own-package arm resolves objects
// rather than matching spellings. This tree already has the shape: core/testutil declares a type
// Address and a field named Address, and addr.Address matches the type's spelling without
// referring to it.
func TestSymbolOwnership_ASameSpelledNameIsNotAReference(t *testing.T) {
	files := withSymbolBaseline(map[string]string{
		"core/shared/shadow.go": `package shared

type Envelope struct {
	// A field whose name is the type's, which resolves to the field and not to Cog.
	Cog string
}

func Sort(list []string) string {
	// A local, a parameter and a selector member, all spelled like exported symbols.
	Limit := len(list)
	e := Envelope{Cog: "x"}
	if Limit > 0 {
		return e.Cog
	}
	return ""
}
`,
	})

	computed := computedOver(t, files)

	// Sort has no consumer, so nothing it names could be justified through it either way. What
	// matters is that Cog is still reachable through Widget alone and Limit still own-package
	// through New alone: the shadowing file added no evidence.
	assert.Equal(t, justificationReachable, computed["core/shared.Cog"])
	assert.Equal(t, justificationOwnPackage, computed["core/shared.Limit"])
	assert.Equal(t, "", computed["core/shared.Envelope"])
	assert.Equal(t, "", computed["core/shared.Sort"])
}

// TestSymbolOwnership_AShadowedNameDoesNotJustifyItsNamesake is the same rule where it could
// actually mislead: a justified function whose body declares a local spelled like an unreferenced
// exported symbol must not justify it.
func TestSymbolOwnership_AShadowedNameDoesNotJustifyItsNamesake(t *testing.T) {
	files := withSymbolBaseline(map[string]string{
		"core/shared/shadow.go": `package shared

type Orphan struct{}

func Reset() {
	Orphan := 1
	_ = Orphan
}
`,
		"authserver/main.go": `package main

import "example.test/core/shared"

var (
	_ = shared.Widget{}
	_ = shared.Colour("")
	_ = shared.New()
	_ = shared.Stable{}
	_ = shared.Reset
)
`,
		"adminconsole/main.go": `package main

import "example.test/core/shared"

var (
	_ = shared.Widget{}
	_ = shared.Colour("")
	_ = shared.New()
	_ = shared.Departing{}
	_ = shared.Reset
)
`,
	})

	computed := computedOver(t, files)

	assert.Equal(t, justificationBothApps, computed["core/shared.Reset"])
	assert.Equal(t, "", computed["core/shared.Orphan"], "the local spelled Orphan is not a reference to the type")
}

// TestSymbolOwnership_OneNameInAValueSpecDoesNotVouchForItsSiblings: `var Ready, discarded = true,
// Orphan{}` declares two independent values that happen to share a line, and only the second names
// Orphan. Attributing every expression to every name let a justified first name carry an
// unjustified sibling's references, which is a false edge in the graph the whole table rests on.
// Final review round 1, finding 2.
func TestSymbolOwnership_OneNameInAValueSpecDoesNotVouchForItsSiblings(t *testing.T) {
	files := withSymbolBaseline(map[string]string{
		"core/shared/pair.go": `package shared

type Orphan struct{}

var Ready, discarded = true, Orphan{}
`,
		"authserver/main.go": `package main

import "example.test/core/shared"

var (
	_ = shared.Widget{}
	_ = shared.Colour("")
	_ = shared.New()
	_ = shared.Stable{}
	_ = shared.Ready
)
`,
		"adminconsole/main.go": `package main

import "example.test/core/shared"

var (
	_ = shared.Widget{}
	_ = shared.Colour("")
	_ = shared.New()
	_ = shared.Departing{}
	_ = shared.Ready
)
`,
	})

	computed := computedOver(t, files)

	assert.Equal(t, justificationBothApps, computed["core/shared.Ready"])
	assert.Equal(t, "", computed["core/shared.Orphan"],
		"only discarded's initializer names Orphan, and nothing justifies discarded")
}

// TestSymbolOwnership_ATupleValuedSpecReachesThroughItsOneCall is the leniency the rule above must
// not take with it. `var ignored, Loaded = pair()` has one expression for two names, so that
// expression really does initialise both, and pairing by position would leave the justified name
// with nothing — or reach past the end of the list.
func TestSymbolOwnership_ATupleValuedSpecReachesThroughItsOneCall(t *testing.T) {
	files := withSymbolBaseline(map[string]string{
		"core/shared/tuple.go": `package shared

type Tupled struct{}

func pair() (bool, *Tupled) {
	return true, nil
}

var ignored, Loaded = pair()
`,
		"authserver/main.go": `package main

import "example.test/core/shared"

var (
	_ = shared.Widget{}
	_ = shared.Colour("")
	_ = shared.New()
	_ = shared.Stable{}
	_ = shared.Loaded
)
`,
		"adminconsole/main.go": `package main

import "example.test/core/shared"

var (
	_ = shared.Widget{}
	_ = shared.Colour("")
	_ = shared.New()
	_ = shared.Departing{}
	_ = shared.Loaded
)
`,
	})

	computed := computedOver(t, files)

	assert.Equal(t, justificationBothApps, computed["core/shared.Loaded"])
	assert.Equal(t, justificationReachable, computed["core/shared.Tupled"],
		"Loaded reaches pair, whose signature names Tupled")
}

// TestSymbolOwnership_AnOmittedConstSpecRepeatsTheExpressionAboveIt: Go defines an omitted
// expression list inside a parenthesized const declaration as the textual repetition of the
// nearest preceding non-empty one, so `const ( discarded = int(Tick(1)); Rearmed )` makes Rearmed's
// own declaration name Tick. Reading only the spec's own Values left that edge out of the graph, so
// a symbol the tree justifies would have been offered an asserted escape hatch instead, which is
// the one thing this table exists to refuse. Final review round 2, finding 1.
func TestSymbolOwnership_AnOmittedConstSpecRepeatsTheExpressionAboveIt(t *testing.T) {
	files := withSymbolBaseline(map[string]string{
		"core/shared/repeat.go": `package shared

type Tick int

const (
	discarded = int(Tick(1))
	Rearmed
)
`,
		"authserver/main.go": `package main

import "example.test/core/shared"

var (
	_ = shared.Widget{}
	_ = shared.Colour("")
	_ = shared.New()
	_ = shared.Stable{}
	_ = shared.Rearmed
)
`,
		"adminconsole/main.go": `package main

import "example.test/core/shared"

var (
	_ = shared.Widget{}
	_ = shared.Colour("")
	_ = shared.New()
	_ = shared.Departing{}
	_ = shared.Rearmed
)
`,
	})

	computed := computedOver(t, files)

	assert.Equal(t, justificationBothApps, computed["core/shared.Rearmed"])
	assert.Equal(t, justificationOwnPackage, computed["core/shared.Tick"],
		"Rearmed repeats the expression above it, and that expression names Tick")
}

// TestSymbolOwnership_AnInheritedExpressionListIsStillPositional is the leniency the rule above
// must not take with it: what an omitted spec inherits is the whole list, and the list is still
// paired name by name. `Repeated` repeats the `1`, not the sibling expression that names Tick, so
// attributing the inherited list wholesale would resurrect exactly the false edge round 1 removed.
func TestSymbolOwnership_AnInheritedExpressionListIsStillPositional(t *testing.T) {
	files := withSymbolBaseline(map[string]string{
		"core/shared/repeat.go": `package shared

type Tick int

const (
	Kept, discarded       = 1, int(Tick(1))
	Repeated, alsoDiscarded
)
`,
		"authserver/main.go": `package main

import "example.test/core/shared"

var (
	_ = shared.Widget{}
	_ = shared.Colour("")
	_ = shared.New()
	_ = shared.Stable{}
	_ = shared.Repeated
)
`,
		"adminconsole/main.go": `package main

import "example.test/core/shared"

var (
	_ = shared.Widget{}
	_ = shared.Colour("")
	_ = shared.New()
	_ = shared.Departing{}
	_ = shared.Repeated
)
`,
	})

	computed := computedOver(t, files)

	assert.Equal(t, justificationBothApps, computed["core/shared.Repeated"])
	assert.Equal(t, "", computed["core/shared.Tick"],
		"Repeated inherits the 1; only alsoDiscarded inherits the expression naming Tick")
}

// TestSymbolOwnership_AVarOmittingItsValuesInheritsNothing is the other half of the const
// repetition rule, and the half that says where it stops. A var with no expression list takes its
// declared type's zero value rather than repeating the list above it, so nothing the preceding
// initializer names is evidence for it. Without this case the rule reads the same with the const
// test removed from it: a mutation widening `case d.Tok == token.CONST` to every kind of value
// declaration left the whole core tier green. Final review round 3, finding 1.
func TestSymbolOwnership_AVarOmittingItsValuesInheritsNothing(t *testing.T) {
	files := withSymbolBaseline(map[string]string{
		"core/shared/zero.go": `package shared

type Tick int

var (
	discarded = int(Tick(1))
	Reset     int
)
`,
		"authserver/main.go": `package main

import "example.test/core/shared"

var (
	_ = shared.Widget{}
	_ = shared.Colour("")
	_ = shared.New()
	_ = shared.Stable{}
	_ = shared.Reset
)
`,
		"adminconsole/main.go": `package main

import "example.test/core/shared"

var (
	_ = shared.Widget{}
	_ = shared.Colour("")
	_ = shared.New()
	_ = shared.Departing{}
	_ = shared.Reset
)
`,
	})

	computed := computedOver(t, files)

	assert.Equal(t, justificationBothApps, computed["core/shared.Reset"])
	assert.Equal(t, "", computed["core/shared.Tick"],
		"Reset is its type's zero value; it repeats nothing and names nothing")
}

// TestSymbolOwnership_AnOmittedConstSpecInheritsItsTypeSlotToo: what Go substitutes into an
// omitted ConstSpec is the preceding expression list *and its type if any*, so `const ( discarded
// Tick = 1; Rearmed )` declares Rearmed exactly as `Rearmed Tick = 1` does. Carrying only the
// expressions left the type out of the inheriting spec's declaration, and a type slot is the one
// reference a package makes to an alias standing in front of a predeclared type. Final review
// round 3, finding 2.
func TestSymbolOwnership_AnOmittedConstSpecInheritsItsTypeSlotToo(t *testing.T) {
	files := withSymbolBaseline(map[string]string{
		"core/shared/alias.go": `package shared

type Tick = int

const (
	discarded Tick = 1
	Rearmed
)
`,
		"authserver/main.go": `package main

import "example.test/core/shared"

var (
	_ = shared.Widget{}
	_ = shared.Colour("")
	_ = shared.New()
	_ = shared.Stable{}
	_ = shared.Rearmed
)
`,
		"adminconsole/main.go": `package main

import "example.test/core/shared"

var (
	_ = shared.Widget{}
	_ = shared.Colour("")
	_ = shared.New()
	_ = shared.Departing{}
	_ = shared.Rearmed
)
`,
	})

	computed := computedOver(t, files)

	assert.Equal(t, justificationBothApps, computed["core/shared.Rearmed"])
	assert.Equal(t, justificationReachable, computed["core/shared.Tick"],
		"Rearmed inherits the type slot as well as the expression, and a type slot is a declaration")
}

// TestSymbolOwnership_AnInheritedTypeSlotIsResetByTheNextList is the leniency that one must not
// take with it. The substitution is of the *nearest preceding* non-empty list, so a later untyped
// list resets the type to nothing at all, and a const inheriting `2` inherits no type with it.
// Carrying the last type seen would hand every const below an untyped list a declaration edge to a
// type it does not have.
func TestSymbolOwnership_AnInheritedTypeSlotIsResetByTheNextList(t *testing.T) {
	files := withSymbolBaseline(map[string]string{
		"core/shared/alias.go": `package shared

type Tick = int

const (
	discarded Tick = 1
	alsoDiscarded
	second = 2
	Reset
)
`,
		"authserver/main.go": `package main

import "example.test/core/shared"

var (
	_ = shared.Widget{}
	_ = shared.Colour("")
	_ = shared.New()
	_ = shared.Stable{}
	_ = shared.Reset
)
`,
		"adminconsole/main.go": `package main

import "example.test/core/shared"

var (
	_ = shared.Widget{}
	_ = shared.Colour("")
	_ = shared.New()
	_ = shared.Departing{}
	_ = shared.Reset
)
`,
	})

	computed := computedOver(t, files)

	assert.Equal(t, justificationBothApps, computed["core/shared.Reset"])
	assert.Equal(t, "", computed["core/shared.Tick"],
		"Reset inherits the untyped 2 above it, which carries no type slot with it")
}

// TestSymbolOwnership_AValueSpecTypeSlotIsPartOfItsDeclaration: `var Registry map[string]Slotted`
// names Slotted in the type slot and nowhere else, so reading only the initializer left the one
// reference the package makes out of the graph. The same family as the two the final review
// reported, found by walking the declaration shapes readDecl handles rather than the one it was
// handed.
func TestSymbolOwnership_AValueSpecTypeSlotIsPartOfItsDeclaration(t *testing.T) {
	files := withSymbolBaseline(map[string]string{
		"core/shared/slot.go": `package shared

type Slotted struct{}

var Registry map[string]Slotted
`,
		"authserver/main.go": `package main

import "example.test/core/shared"

var (
	_ = shared.Widget{}
	_ = shared.Colour("")
	_ = shared.New()
	_ = shared.Stable{}
	_ = shared.Registry
)
`,
		"adminconsole/main.go": `package main

import "example.test/core/shared"

var (
	_ = shared.Widget{}
	_ = shared.Colour("")
	_ = shared.New()
	_ = shared.Departing{}
	_ = shared.Registry
)
`,
	})

	computed := computedOver(t, files)

	assert.Equal(t, justificationBothApps, computed["core/shared.Registry"])
	assert.Equal(t, justificationReachable, computed["core/shared.Slotted"],
		"Registry's declared type names Slotted, and a declaration is reachable")
}

// TestSymbolOwnership_AValueDoesNotVouchForItsOwnTypeSlot is the leniency reading the type slot
// must not take with it, and it is the rule the whole table rests on: a const of a type the same
// package declares is exactly how core/enums justified itself, so the value's own named type is
// deleted from what its declaration reaches. The arrow runs the other way -- a const of a
// justified type is reachable -- and Tone is justified by nothing here.
func TestSymbolOwnership_AValueDoesNotVouchForItsOwnTypeSlot(t *testing.T) {
	files := withSymbolBaseline(map[string]string{
		"core/shared/tone.go": `package shared

type Tone string

const ToneWarm Tone = "warm"
`,
		"authserver/main.go": `package main

import "example.test/core/shared"

var (
	_ = shared.Widget{}
	_ = shared.Colour("")
	_ = shared.New()
	_ = shared.Stable{}
	_ = shared.ToneWarm
)
`,
		"adminconsole/main.go": `package main

import "example.test/core/shared"

var (
	_ = shared.Widget{}
	_ = shared.Colour("")
	_ = shared.New()
	_ = shared.Departing{}
	_ = shared.ToneWarm
)
`,
	})

	computed := computedOver(t, files)

	assert.Equal(t, justificationBothApps, computed["core/shared.ToneWarm"])
	assert.Equal(t, "", computed["core/shared.Tone"],
		"a value never justifies the type it is declared with, whichever slot that type is spelled in")
}

// TestSymbolOwnership_AGenericTypeSlotIsStillTheValuesOwnType is the same rule spelled with type
// arguments. Go writes an instantiated named type as an IndexExpr, so the type slot of
// `var Default Box[int]` is not the bare identifier the exclusion was looking for, and Box was
// read as an ordinary reference from a justified value -- the circular evidence the rule above
// exists to refuse, reached by writing the type generically. The type argument is a different
// question and stays an ordinary reference, which is what Knob asserts. Final review round 4,
// finding 1.
func TestSymbolOwnership_AGenericTypeSlotIsStillTheValuesOwnType(t *testing.T) {
	files := withSymbolBaseline(map[string]string{
		"core/shared/box.go": `package shared

type Knob int

type Box[T any] struct{ V T }

var Default Box[Knob]
`,
		"authserver/main.go": `package main

import "example.test/core/shared"

var (
	_ = shared.Widget{}
	_ = shared.Colour("")
	_ = shared.New()
	_ = shared.Stable{}
	_ = shared.Default
)
`,
		"adminconsole/main.go": `package main

import "example.test/core/shared"

var (
	_ = shared.Widget{}
	_ = shared.Colour("")
	_ = shared.New()
	_ = shared.Departing{}
	_ = shared.Default
)
`,
	})

	computed := computedOver(t, files)

	assert.Equal(t, justificationBothApps, computed["core/shared.Default"])
	assert.Equal(t, "", computed["core/shared.Box"],
		"an instantiated generic type slot spells the value's own type as surely as a bare one")
	assert.Equal(t, justificationReachable, computed["core/shared.Knob"],
		"the type argument is not the value's own type, so it stays an ordinary reference")
}

// TestSymbolOwnership_AMultiArgumentGenericTypeSlotIsStillTheValuesOwnType is the same exclusion at
// the other parser shape. Go writes a one-argument instantiation `Box[Knob]` as an IndexExpr and
// every wider one `Pair[Knob, Toggle]` as an IndexListExpr, so a fixture covering the first pins
// nothing about the second: with only the Box case here, replacing the IndexListExpr arm left the
// whole core tier green. Generated is the same instantiation spelled at the head of an initializer
// instead of in the slot, which is where this exclusion and the composite-literal one compose.
// Final review round 5, finding 1 (#385).
func TestSymbolOwnership_AMultiArgumentGenericTypeSlotIsStillTheValuesOwnType(t *testing.T) {
	files := withSymbolBaseline(map[string]string{
		"core/shared/pair.go": `package shared

type Knob int

type Toggle bool

type Ferrule int

type Shim bool

type Pair[K, V any] struct {
	Key   K
	Value V
}

var Default Pair[Knob, Toggle]

var Generated = Pair[Ferrule, Shim]{}
`,
		"authserver/main.go": `package main

import "example.test/core/shared"

var (
	_ = shared.Widget{}
	_ = shared.Colour("")
	_ = shared.New()
	_ = shared.Stable{}
	_ = shared.Default
	_ = shared.Generated
)
`,
		"adminconsole/main.go": `package main

import "example.test/core/shared"

var (
	_ = shared.Widget{}
	_ = shared.Colour("")
	_ = shared.New()
	_ = shared.Departing{}
	_ = shared.Default
	_ = shared.Generated
)
`,
	})

	computed := computedOver(t, files)

	assert.Equal(t, justificationBothApps, computed["core/shared.Default"])
	assert.Equal(t, justificationBothApps, computed["core/shared.Generated"])
	assert.Equal(t, "", computed["core/shared.Pair"],
		"a two-argument instantiation spells the value's own type, in the slot and at the head of an initializer alike")
	assert.Equal(t, justificationReachable, computed["core/shared.Knob"],
		"the first type argument is not the value's own type, so the slot names it as an ordinary reference")
	assert.Equal(t, justificationReachable, computed["core/shared.Toggle"],
		"and neither is the second")
	assert.Equal(t, justificationOwnPackage, computed["core/shared.Ferrule"],
		"the arguments of the instantiation that stands in an initializer are ordinary references too, from the stronger position")
	assert.Equal(t, justificationOwnPackage, computed["core/shared.Shim"],
		"and so is the second of those")
}

// TestSymbolOwnership_ACompositeLiteralHeadIsTheDeclaredType is the second of the three initializer
// heads, and the one no fixture reached: `var Default = Tone{}` spells Tone exactly as the
// conversion `Tone("warm")` and the assertion `source.(Tone)` do, and for the same reason it is not
// a use of Tone. Read as an ordinary reference it let a package's own value promote the type it is
// an instance of, which is the circularity this exclusion exists to refuse. Replacing the arm left
// the whole core tier green before this fixture existed. Final review round 5, finding 2 (#385).
func TestSymbolOwnership_ACompositeLiteralHeadIsTheDeclaredType(t *testing.T) {
	files := withSymbolBaseline(map[string]string{
		"core/shared/tone.go": `package shared

type Tone struct {
	Name string
}

var Default = Tone{Name: "warm"}
`,
		"authserver/main.go": `package main

import "example.test/core/shared"

var (
	_ = shared.Widget{}
	_ = shared.Colour("")
	_ = shared.New()
	_ = shared.Stable{}
	_ = shared.Default
)
`,
		"adminconsole/main.go": `package main

import "example.test/core/shared"

var (
	_ = shared.Widget{}
	_ = shared.Colour("")
	_ = shared.New()
	_ = shared.Departing{}
	_ = shared.Default
)
`,
	})

	computed := computedOver(t, files)

	assert.Equal(t, justificationBothApps, computed["core/shared.Default"])
	assert.Equal(t, "", computed["core/shared.Tone"],
		"a composite literal at the head of an initializer is the value's own type, not a use of it")
}

// TestSymbolOwnership_ATypeAssertionHeadIsTheDeclaredType is the third way an initializer spells
// the type of the value it initializes, after the conversion and the composite literal: a value
// that omits its type slot and asserts one instead. Reading it as an ordinary reference let a
// package's own member promote the type it belongs to all the way to own-package. The comma-ok
// form is the same assertion, and only the first result takes the asserted type -- the bool does
// not, so for it the assertion is an ordinary reference like any other. Final review round 4,
// finding 2.
func TestSymbolOwnership_ATypeAssertionHeadIsTheDeclaredType(t *testing.T) {
	files := withSymbolBaseline(map[string]string{
		"core/shared/tone.go": `package shared

var source any = "warm"

type Tone string

var ToneWarm = source.(Tone)

var ToneCool, ToneCoolOk = source.(Tone)
`,
		"authserver/main.go": `package main

import "example.test/core/shared"

var (
	_ = shared.Widget{}
	_ = shared.Colour("")
	_ = shared.New()
	_ = shared.Stable{}
	_ = shared.ToneWarm
	_ = shared.ToneCool
)
`,
		"adminconsole/main.go": `package main

import "example.test/core/shared"

var (
	_ = shared.Widget{}
	_ = shared.Colour("")
	_ = shared.New()
	_ = shared.Departing{}
	_ = shared.ToneWarm
	_ = shared.ToneCool
)
`,
	})

	computed := computedOver(t, files)

	assert.Equal(t, justificationBothApps, computed["core/shared.ToneWarm"])
	assert.Equal(t, justificationBothApps, computed["core/shared.ToneCool"])
	assert.Equal(t, "", computed["core/shared.Tone"],
		"an asserted type is the value's own type, not a use of it, in either form of the assertion")
}

// TestSymbolOwnership_TheBoolOfACommaOkAssertionStillNamesTheType is how far that exclusion
// reaches, and it is the leniency the per-value rule buys. The exclusion asks what type *this*
// value was declared with, and the bool of a comma-ok assertion was declared with bool, so the
// asserted type is an ordinary reference from where it stands. Excluding it for every name in the
// spec instead would be a per-declaration rule, which is the wide reading
// AnIndependentUseOfTheDeclaredTypeIsStillAReference already refuses. Final review round 4,
// finding 2.
func TestSymbolOwnership_TheBoolOfACommaOkAssertionStillNamesTheType(t *testing.T) {
	files := withSymbolBaseline(map[string]string{
		"core/shared/tone.go": `package shared

var source any = "warm"

type Tone string

var toneCool, ToneCoolOk = source.(Tone)

var _ = toneCool
`,
		"authserver/main.go": `package main

import "example.test/core/shared"

var (
	_ = shared.Widget{}
	_ = shared.Colour("")
	_ = shared.New()
	_ = shared.Stable{}
	_ = shared.ToneCoolOk
)
`,
		"adminconsole/main.go": `package main

import "example.test/core/shared"

var (
	_ = shared.Widget{}
	_ = shared.Colour("")
	_ = shared.New()
	_ = shared.Departing{}
	_ = shared.ToneCoolOk
)
`,
	})

	computed := computedOver(t, files)

	assert.Equal(t, justificationBothApps, computed["core/shared.ToneCoolOk"])
	assert.Equal(t, justificationOwnPackage, computed["core/shared.Tone"],
		"the bool was not declared with Tone, so its declaration names Tone like any other")
}

// TestSymbolOwnership_AnIndependentUseOfTheDeclaredTypeIsStillAReference is how far that
// exclusion reaches, and it is a narrow rule rather than a wide one: what a value may not vouch
// for is the one occurrence that spells its own type, the type slot or the conversion standing in
// for it. Every other occurrence in the initializer is an ordinary reference, and erasing the type
// from the whole declaration by name threw those away -- an initializer that builds a slice of the
// type, or names it in a signature, really is the package using it. Final review round 3,
// finding 3.
func TestSymbolOwnership_AnIndependentUseOfTheDeclaredTypeIsStillAReference(t *testing.T) {
	files := withSymbolBaseline(map[string]string{
		"core/shared/tone.go": `package shared

type Tone string

var ToneWarm Tone = func() Tone {
	tones := []Tone{"warm"}
	return tones[0]
}()
`,
		"authserver/main.go": `package main

import "example.test/core/shared"

var (
	_ = shared.Widget{}
	_ = shared.Colour("")
	_ = shared.New()
	_ = shared.Stable{}
	_ = shared.ToneWarm
)
`,
		"adminconsole/main.go": `package main

import "example.test/core/shared"

var (
	_ = shared.Widget{}
	_ = shared.Colour("")
	_ = shared.New()
	_ = shared.Departing{}
	_ = shared.ToneWarm
)
`,
	})

	computed := computedOver(t, files)

	assert.Equal(t, justificationBothApps, computed["core/shared.ToneWarm"])
	assert.Equal(t, justificationOwnPackage, computed["core/shared.Tone"],
		"the type slot is the excluded occurrence; the slice the initializer builds is a use of Tone")
}

// TestSymbolOwnership_ATypeParameterConstraintIsPartOfTheDeclaration: a constraint is named in the
// type parameter list rather than in the type, and walking only the type left it unreferenced.
// Third member of the same family.
func TestSymbolOwnership_ATypeParameterConstraintIsPartOfTheDeclaration(t *testing.T) {
	files := withSymbolBaseline(map[string]string{
		"core/shared/generic.go": `package shared

type Bounded interface {
	~int | ~string
}

type Box[T Bounded] struct {
	V T
}
`,
		"authserver/main.go": `package main

import "example.test/core/shared"

var (
	_ = shared.Widget{}
	_ = shared.Colour("")
	_ = shared.New()
	_ = shared.Stable{}
	_ = shared.Box[int]{}
)
`,
		"adminconsole/main.go": `package main

import "example.test/core/shared"

var (
	_ = shared.Widget{}
	_ = shared.Colour("")
	_ = shared.New()
	_ = shared.Departing{}
	_ = shared.Box[int]{}
)
`,
	})

	computed := computedOver(t, files)

	assert.Equal(t, justificationBothApps, computed["core/shared.Box"])
	assert.Equal(t, justificationReachable, computed["core/shared.Bounded"],
		"Box's type parameter list names Bounded")
}

// TestSymbolOwnership_ADeclarationWithNoBodyIsWalked is the crash in the same function, found the
// same way. A function declared without a body -- assembly, or a //go:linkname -- carries a typed
// nil that ast.Inspect dereferences, so the walk died on a nil pointer and took every module's
// unit tier with it rather than reporting anything. There are none in core today, which is why
// nothing had met it.
func TestSymbolOwnership_ADeclarationWithNoBodyIsWalked(t *testing.T) {
	files := withSymbolBaseline(map[string]string{
		"core/shared/linked.go": `package shared

import _ "unsafe"

//go:linkname elsewhere example.test/other.elsewhere
func elsewhere() Cog
`,
	})

	computed := computedOver(t, files)

	assert.Equal(t, justificationBothApps, computed["core/shared.Widget"],
		"the walk reached the rest of the package")
}

// ---- the asserted words ----------------------------------------------------------------------

// TestSymbolOwnership_AnAssertedRowWithNoNote is what keeps contract an argument rather than a
// shrug. The guard cannot check the argument, so the least it can do is refuse its absence.
func TestSymbolOwnership_AnAssertedRowWithNoNote(t *testing.T) {
	rows := symbolBaselineRows()
	for i, r := range rows {
		if strings.HasPrefix(r, "core/shared Stable ") {
			rows[i] = "core/shared Stable contract —"
		}
	}

	findings := checkSymbols(t, symbolBaselineFiles(), rows)

	assertFindings(t, findings, "asserts contract for core/shared.Stable with no note")
}

// TestSymbolOwnership_AMovingRowNamingNoIssue: a justification that expires has to say when, or it
// is a contract row that nobody will ever revisit.
func TestSymbolOwnership_AMovingRowNamingNoIssue(t *testing.T) {
	rows := symbolBaselineRows()
	for i, r := range rows {
		if strings.HasPrefix(r, "core/shared Departing ") {
			rows[i] = "core/shared Departing moving It is going to the admin console at some point."
		}
	}

	findings := checkSymbols(t, symbolBaselineFiles(), rows)

	assertFindings(t, findings, "records core/shared.Departing as moving but its note names no issue")
}

// TestSymbolOwnership_ATestSupportRowAProductionReferenceContradicts is the direction that stops
// test-support being a parking space. It is the one asserted word the tree can argue with.
func TestSymbolOwnership_ATestSupportRowAProductionReferenceContradicts(t *testing.T) {
	rows := symbolBaselineRows()
	for i, r := range rows {
		if strings.HasPrefix(r, "core/shared Stable ") {
			rows[i] = "core/shared Stable test-support Parked here rather than moved."
		}
	}

	findings := checkSymbols(t, symbolBaselineFiles(), rows)

	assertFindings(t, findings, "records core/shared.Stable as test-support, but authserver names it in production and a binary links that package")
}

// TestSymbolOwnership_ATestSupportRowNothingNames refuses the word to a symbol that supports
// nothing at all, which is the shape dead code takes here.
func TestSymbolOwnership_ATestSupportRowNothingNames(t *testing.T) {
	files := withSymbolBaseline(map[string]string{
		"core/shared/orphan.go": "package shared\n\ntype Unused struct{}\n",
	})
	rows := append(symbolBaselineRows(), "core/shared Unused test-support Nothing names it.")

	findings := checkSymbols(t, files, rows)

	assertFindings(t, findings, "records core/shared.Unused as test-support, but nothing names it")
}

// TestSymbolOwnership_ALocalInATestSpelledLikeASymbolNamesNothing is the same refusal where the
// spelling is there and the reference is not. test-support is the one asserted word the tree can
// contradict, so evidence for it has to be a reference rather than a matching identifier: a local,
// a parameter or a field spelled like an exported orphan would otherwise park dead code in core
// behind a word the guard believes it checked. Final review round 1, finding 1.
func TestSymbolOwnership_ALocalInATestSpelledLikeASymbolNamesNothing(t *testing.T) {
	files := withSymbolBaseline(map[string]string{
		"core/shared/orphan.go": "package shared\n\ntype Unused struct{}\n",
		"core/shared/orphan_test.go": `package shared

import "testing"

func TestNothingNamesUnused(t *testing.T) {
	Unused := 1
	_ = Unused
}
`,
	})
	rows := append(symbolBaselineRows(), "core/shared Unused test-support Nothing names it.")

	findings := checkSymbols(t, files, rows)

	assertFindings(t, findings, "records core/shared.Unused as test-support, but nothing names it")
}

// TestSymbolOwnership_AnInternalTestNamingASymbolIsEvidence is that rule's leniency: the arm still
// has to see a real unqualified reference from the declaring package's own test, which is how
// core/mocks and core/testutil earn the word at all.
func TestSymbolOwnership_AnInternalTestNamingASymbolIsEvidence(t *testing.T) {
	files := withSymbolBaseline(map[string]string{
		"core/shared/orphan.go": "package shared\n\ntype Unused struct{}\n",
		"core/shared/orphan_test.go": `package shared

import "testing"

func TestUnusedIsNamed(t *testing.T) {
	_ = Unused{}
}
`,
	})
	rows := append(symbolBaselineRows(), "core/shared Unused test-support Only a test names it.")

	assert.Empty(t, checkSymbols(t, files, rows))
}

// TestSymbolOwnership_AnExternalTestNamingASymbolIsEvidence is the second shape a declaring
// package's own test takes. `package shared_test` sits in the same directory but is a different
// package, so it names the symbol through the import like any other file, and the identity pass
// that reads the internal arm cannot see it at all.
func TestSymbolOwnership_AnExternalTestNamingASymbolIsEvidence(t *testing.T) {
	files := withSymbolBaseline(map[string]string{
		"core/shared/orphan.go": "package shared\n\ntype Unused struct{}\n",
		"core/shared/orphan_test.go": `package shared_test

import (
	"testing"

	"example.test/core/shared"
)

func TestUnusedIsNamed(t *testing.T) {
	_ = shared.Unused{}
}
`,
	})
	rows := append(symbolBaselineRows(), "core/shared Unused test-support Only a test names it.")

	assert.Empty(t, checkSymbols(t, files, rows))
}

// TestSymbolOwnership_AnInternalTestOfAPackageNamedLikeATestIsEvidence is the shape the spelling
// heuristic could not read. A production package may legally be named `odd_test`, and then its own
// internal tests carry that same clause: classifying a test file by whether its package name ends
// in `_test` sent them down the external arm, which looks for a self-import no internal test has,
// and the guard then refused genuine evidence for the one asserted word the tree can argue with.
// The declaring package's own name decides it instead. Final review round 2, finding 2.
func TestSymbolOwnership_AnInternalTestOfAPackageNamedLikeATestIsEvidence(t *testing.T) {
	files := withSymbolBaseline(map[string]string{
		"core/odd/odd.go": "package odd_test\n\ntype Unused struct{}\n",
		"core/odd/odd_test.go": `package odd_test

import "testing"

func TestUnusedIsNamed(t *testing.T) {
	_ = Unused{}
}
`,
	})
	rows := append(symbolBaselineRows(), "core/odd Unused test-support Only a test names it.")

	assert.Empty(t, checkSymbols(t, files, rows))
}

// TestSymbolOwnership_ALocalInTheTestOfAPackageNamedLikeATestNamesNothing is that arm's other half:
// reaching the internal pass must not cost it the identity check, so a local spelled like the
// orphan is still not a reference to it.
func TestSymbolOwnership_ALocalInTheTestOfAPackageNamedLikeATestNamesNothing(t *testing.T) {
	files := withSymbolBaseline(map[string]string{
		"core/odd/odd.go": "package odd_test\n\ntype Unused struct{}\n",
		"core/odd/odd_test.go": `package odd_test

import "testing"

func TestNothingNamesUnused(t *testing.T) {
	Unused := 1
	_ = Unused
}
`,
	})
	rows := append(symbolBaselineRows(), "core/odd Unused test-support Nothing names it.")

	findings := checkSymbols(t, files, rows)

	assertFindings(t, findings, "records core/odd.Unused as test-support, but nothing names it")
}

// TestSymbolOwnership_AnExternalTestOfAPackageNamedLikeATestIsEvidence is the external half of the
// same shape, and it turns on what Go binds an unaliased import to: the imported package's
// declared name, not the last segment of its path. An external test of a package named `odd_test`
// living in `core/odd` therefore writes `odd_test.Unused`, and looking for `odd.Unused` refused
// the evidence and with it the one asserted word the tree can argue with. Final review round 3,
// finding 4.
func TestSymbolOwnership_AnExternalTestOfAPackageNamedLikeATestIsEvidence(t *testing.T) {
	files := withSymbolBaseline(map[string]string{
		"core/odd/odd.go": "package odd_test\n\ntype Unused struct{}\n",
		"core/odd/orphan_test.go": `package odd_test_test

import (
	"testing"

	"example.test/core/odd"
)

func TestUnusedIsNamed(t *testing.T) {
	_ = odd_test.Unused{}
}
`,
	})
	rows := append(symbolBaselineRows(), "core/odd Unused test-support Only a test names it.")

	assert.Empty(t, checkSymbols(t, files, rows))
}

// TestSymbolOwnership_APackageNamedForSomethingOtherThanItsDirectory is that same binding rule on
// the production side, where it decides every row rather than one asserted word. Both applications
// import `core/odd` without an alias and name its symbol through the identifier the package
// declares, and reading the path's last segment instead saw no reference at all: a symbol the
// whole tree shares would have been offered an asserted escape hatch, which is the one thing this
// table exists to refuse. Final review round 3, finding 5.
func TestSymbolOwnership_APackageNamedForSomethingOtherThanItsDirectory(t *testing.T) {
	files := withSymbolBaseline(map[string]string{
		"core/odd/odd.go": "package renamed\n\ntype Shared struct{}\n",
		"authserver/main.go": `package main

import (
	"example.test/core/odd"
	"example.test/core/shared"
)

var (
	_ = shared.Widget{}
	_ = shared.Colour("")
	_ = shared.New()
	_ = shared.Stable{}
	_ = renamed.Shared{}
)
`,
		"adminconsole/main.go": `package main

import (
	"example.test/core/odd"
	"example.test/core/shared"
)

var (
	_ = shared.Widget{}
	_ = shared.Colour("")
	_ = shared.New()
	_ = shared.Departing{}
	_ = renamed.Shared{}
)
`,
	})

	computed := computedOver(t, files)

	assert.Equal(t, justificationBothApps, computed["core/odd.Shared"],
		"an unaliased import binds the name the package declares, which is what both applications wrote")
}

// TestSymbolOwnership_AnAliasedImportStillOverridesTheDeclaredName is the negative that binding
// rule must not swallow: an explicit alias is the file's own word on the identifier, and it beats
// both the declared name and the path.
func TestSymbolOwnership_AnAliasedImportStillOverridesTheDeclaredName(t *testing.T) {
	files := withSymbolBaseline(map[string]string{
		"core/odd/odd.go": "package renamed\n\ntype Shared struct{}\n",
		"authserver/main.go": `package main

import (
	odd "example.test/core/odd"
	"example.test/core/shared"
)

var (
	_ = shared.Widget{}
	_ = shared.Colour("")
	_ = shared.New()
	_ = shared.Stable{}
	_ = odd.Shared{}
)
`,
		"adminconsole/main.go": `package main

import (
	odd "example.test/core/odd"
	"example.test/core/shared"
)

var (
	_ = shared.Widget{}
	_ = shared.Colour("")
	_ = shared.New()
	_ = shared.Departing{}
	_ = odd.Shared{}
)
`,
	})

	computed := computedOver(t, files)

	assert.Equal(t, justificationBothApps, computed["core/odd.Shared"],
		"the alias is what the selector names, whatever the package calls itself")
}

// TestSymbolOwnership_ATestSupportRowAnUnlinkedProductionFileNames is the deliberate leniency that
// makes the word usable. Three packages in this repository are test support written in files with
// no _test.go suffix, so a production reference from a package no binary links is not a
// contradiction.
func TestSymbolOwnership_ATestSupportRowAnUnlinkedProductionFileNames(t *testing.T) {
	files := withSymbolBaseline(map[string]string{
		"adminconsole/handlertest/helper.go": `package handlertest

import "example.test/core/shared"

func Build() shared.Helper {
	return shared.Helper{}
}
`,
	})

	assert.Empty(t, checkSymbols(t, files, symbolBaselineRows()))
}

// ---- the reporting half ------------------------------------------------------------------------

// TestSymbolOwnership_ReportingHalfPasses drives assertSymbolOwnership itself over a tree its table
// describes, which is the only thing that exercises the document reader and the fatal guards.
func TestSymbolOwnership_ReportingHalfPasses(t *testing.T) {
	files := withSymbolBaseline(map[string]string{
		"core/OWNERSHIP.md": symbolOwnershipDoc(symbolBaselineRows()...),
	})
	root := writeTree(t, files)

	report := RunGuard(func(r Reporter) { assertSymbolOwnership(r, root) })

	assert.False(t, report.Failed(), "findings:\n%s", report.Text())
}

// TestSymbolOwnership_ReportingHalfReports is the other half: a finding reaches Errorf rather than
// being computed and dropped. Blinding the five lines that report is what disabled
// AssertNoDeadInterfaces across every module with nothing going red.
func TestSymbolOwnership_ReportingHalfReports(t *testing.T) {
	rows := symbolBaselineRows()
	for i, r := range rows {
		if strings.HasPrefix(r, "core/shared Widget ") {
			rows[i] = "core/shared Widget reachable —"
		}
	}
	files := withSymbolBaseline(map[string]string{"core/OWNERSHIP.md": symbolOwnershipDoc(rows...)})
	root := writeTree(t, files)

	report := RunGuard(func(r Reporter) { assertSymbolOwnership(r, root) })

	assert.True(t, report.Failed())
	assert.Contains(t, report.Text(), "but the tree backs both-apps")
}

// TestSymbolOwnership_TheWalkThatReachedNothing is the failure a clean tree cannot be told apart
// from a correct one. A census that read no declaration satisfies "every symbol has a row" over an
// empty set.
func TestSymbolOwnership_TheWalkThatReachedNothing(t *testing.T) {
	root := writeTree(t, map[string]string{
		"core/OWNERSHIP.md": symbolOwnershipDoc(),
		"core/quiet/quiet.go": `package quiet

func helper() int { return 1 }
`,
	})

	report := RunGuard(func(r Reporter) { assertSymbolOwnership(r, root) })

	assert.True(t, report.Stopped)
	assert.Contains(t, report.Fatal, "found no exported declarations in any core package")
}

// TestSymbolOwnership_TheWalkThatFoundNoPackage is the same failure one step earlier, and it is
// the one a mistyped root produces: a guard rooted at the wrong directory passes everything.
func TestSymbolOwnership_TheWalkThatFoundNoPackage(t *testing.T) {
	root := writeTree(t, map[string]string{"core/OWNERSHIP.md": symbolOwnershipDoc()})

	report := RunGuard(func(r Reporter) { assertSymbolOwnership(r, root) })

	assert.True(t, report.Stopped)
	assert.Contains(t, report.Fatal, "found no core packages under")
}

// TestSymbolOwnership_TheWalkThatFoundNoReference is the same failure one step along: declarations
// read, but nothing naming them, which would rest every justification on an empty set.
func TestSymbolOwnership_TheWalkThatFoundNoReference(t *testing.T) {
	root := writeTree(t, map[string]string{
		"core/OWNERSHIP.md":     symbolOwnershipDoc("core/lonely Thing contract Nothing names it."),
		"core/lonely/lonely.go": "package lonely\n\ntype Thing struct{}\n",
	})

	report := RunGuard(func(r Reporter) { assertSymbolOwnership(r, root) })

	assert.True(t, report.Stopped)
	assert.Contains(t, report.Fatal, "found no production reference to any core symbol")
}

// TestSymbolOwnership_ADocumentWithNoTable fails loudly rather than reading an empty table as a
// tree with no symbols in it.
func TestSymbolOwnership_ADocumentWithNoTable(t *testing.T) {
	files := withSymbolBaseline(map[string]string{
		"core/OWNERSHIP.md": "# Core symbol ownership\n\nSomebody deleted the heading.\n",
	})
	root := writeTree(t, files)

	report := RunGuard(func(r Reporter) { assertSymbolOwnership(r, root) })

	assert.True(t, report.Failed())
	assert.Contains(t, report.Text(), `has no "`+symbolOwnershipHeading+`" table`)
}

// ---- the generator ------------------------------------------------------------------------------

// TestRenderSymbolOwnership_WritesTheComputedRowsAndKeepsTheAssertedOnes pins what ownershipdump
// does: the computed words come from the tree, the asserted words and every note come from the
// file, and the prose around the table is untouched.
func TestRenderSymbolOwnership_WritesTheComputedRowsAndKeepsTheAssertedOnes(t *testing.T) {
	// The table on disk is wrong in both available directions: a computed row states the wrong
	// word, and an asserted row carries a note only a human could have written.
	stale := symbolBaselineRows()
	for i, r := range stale {
		if strings.HasPrefix(r, "core/shared Widget ") {
			stale[i] = "core/shared Widget reachable —"
		}
	}
	files := withSymbolBaseline(map[string]string{"core/OWNERSHIP.md": symbolOwnershipDoc(stale...)})
	root := writeTree(t, files)

	doc, unjustified, err := RenderSymbolOwnership(root)
	require.NoError(t, err)

	assert.Empty(t, unjustified)
	assert.Contains(t, doc, "Preamble prose the parser never reads.")
	assert.Contains(t, doc, "| `core/shared` | `Widget` | both-apps | — |")
	assert.Contains(t, doc, "| `core/shared` | `Stable` | contract | A value the two processes agree on. |")
	assert.Contains(t, doc, "| `core/shared` | `Departing` | moving | #385 carries it to the admin console. |")
}

// TestRenderSymbolOwnership_RefusesToInventAJustification is the property that makes the tool safe
// to run unattended: the one cell it must never fill in is the one the table exists to ask about.
func TestRenderSymbolOwnership_RefusesToInventAJustification(t *testing.T) {
	rows := symbolBaselineRows()
	var kept []string
	for _, r := range rows {
		if !strings.HasPrefix(r, "core/shared Stable ") {
			kept = append(kept, r)
		}
	}
	files := withSymbolBaseline(map[string]string{"core/OWNERSHIP.md": symbolOwnershipDoc(kept...)})
	root := writeTree(t, files)

	doc, unjustified, err := RenderSymbolOwnership(root)
	require.NoError(t, err)

	assert.Equal(t, []string{"core/shared.Stable"}, unjustified)
	assert.Contains(t, doc, "| `core/shared` | `Stable` | "+unjustifiedPlaceholder+" | — |")
}

// TestRenderSymbolOwnership_IsIdempotent is what lets the lint tier run the tool and fail on a tree
// it changed. A generator whose output depends on its own last output cannot be checked that way,
// and an earlier draft of the resolver had exactly that defect: seeding the fixpoint from the
// asserted rows made two mutually referring symbols computed on one run and unjustified on the next.
func TestRenderSymbolOwnership_IsIdempotent(t *testing.T) {
	files := withSymbolBaseline(map[string]string{
		"core/ring/ring.go": circularPackage,
		"core/OWNERSHIP.md": symbolOwnershipDoc(append(symbolBaselineRows(),
			"core/ring Level moving #385 carries it to the auth server.",
			"core/ring LevelLow moving #385 carries it to the auth server.",
			"core/ring LevelHigh moving #385 carries it to the auth server.",
			"core/ring NewLevel moving #385 carries it to the auth server.",
		)...),
	})
	root := writeTree(t, files)

	first, unjustified, err := RenderSymbolOwnership(root)
	require.NoError(t, err)
	require.Empty(t, unjustified)

	require.NoError(t, os.WriteFile(filepath.Join(root, "core", "OWNERSHIP.md"), []byte(first), 0o644))
	second, unjustified, err := RenderSymbolOwnership(root)
	require.NoError(t, err)

	assert.Empty(t, unjustified)
	assert.Equal(t, first, second)
}
