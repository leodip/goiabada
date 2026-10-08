package handlers

// The concept pages on how strongly a user signs in, held to the code that decides it (#522).
//
// Two tables there are the answers an integrator writes code against: what a silent request
// (prompt=none) is refused with, in the order the auth server asks, and which acr and amr a sign-in
// with no session ends with for each level. Both are decided here, in decideSilentAuthentication and
// in the step-up rule and decideLevel2Arm, so each table is held to those in both directions: a row
// the code does not answer fails, and so does an answer the table leaves out.
//
// It reads files and nothing else.

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/ceremony"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/core/guard"
)

// The pages, relative to the repository root.
const (
	promptPage    = "site/src/content/docs/concepts/prompt.mdx"
	acrAndAmrPage = "site/src/content/docs/concepts/acr-and-amr.mdx"
)

// conceptSection is one section of a page: the page, and its heading line as written.
type conceptSection struct{ page, heading string }

var (
	silentChecksSection = conceptSection{promptPage, "### The silent checks"}
	signInLevelsSection = conceptSection{acrAndAmrPage, "### A sign-in with no session"}
)

// silentRefusalWorlds is one prompt=none request per refusal, in the order decideSilentAuthentication
// asks. Each world passes every check before its own and fails its own and every one after it, so
// the answer is its own check's only while that check is asked before all the later ones: a check
// moved earlier answers in a world before its own, and the table's order stops matching. The last
// world passes every check.
func silentRefusalWorlds() []silentWorld {
	scope := func(s string) *string { return &s }
	failsEverything := silentWorld{
		valid:           false,
		disabled:        true,
		subject:         "sub-1",
		hint:            "sub-2",
		target:          record.AcrLevel2Mandatory,
		sessionAcr:      record.AcrLevel1,
		sessionOtpGen:   1,
		userOtpGen:      2,
		otpEnabled:      false,
		effectiveScope:  "",
		consentRequired: true,
	}

	noSession := failsEverything
	noSession.noSession = true

	expired := failsEverything

	tooOld := failsEverything
	tooOld.maxAgeRequested = true
	tooOld.validWithoutMaxAge = true

	disabled := failsEverything
	disabled.valid = true

	otherUser := disabled
	otherUser.disabled = false

	lowerLevel := otherUser
	lowerLevel.hint = "sub-1"

	noAuthenticator := lowerLevel
	noAuthenticator.sessionAcr = record.AcrLevel2Mandatory

	authenticatorChanged := noAuthenticator
	authenticatorChanged.otpEnabled = true

	noScope := authenticatorChanged
	noScope.userOtpGen = noScope.sessionOtpGen

	noConsent := noScope
	noConsent.effectiveScope = "openid profile"

	partialConsent := noConsent
	partialConsent.consentScope = scope("openid")

	passes := partialConsent
	passes.consentScope = scope("openid profile")

	return []silentWorld{noSession, expired, tooOld, disabled, otherUser, lowerLevel, noAuthenticator,
		authenticatorChanged, noScope, noConsent, partialConsent, passes}
}

// silentRefusals is what decideSilentAuthentication answers in each of silentRefusalWorlds, up to
// the first that is not a refusal.
func silentRefusals(t *testing.T) []silentRefusal {
	t.Helper()
	var refusals []silentRefusal
	for _, world := range silentRefusalWorlds() {
		answer, _ := driveSilentAuthentication(t, world)
		if answer.errorCode == "" {
			break
		}
		refusals = append(refusals, silentRefusal{answer.errorCode, answer.errorDescription})
	}
	return refusals
}

// silentRefusal is one row of the silent checks table: the error and its description.
type silentRefusal struct{ code, description string }

// The silent checks table on prompt says what prompt=none is refused with and in which order, and an
// app reading error and error_description decides from it what to show the user next. Its rows are
// decideSilentAuthentication's refusals, one each, in the order it asks.
func TestConceptDocs_TheSilentChecksAreTheCodesRefusalsInOrder(t *testing.T) {
	assertSilentChecksTable(t, filepath.Dir(guard.SourceRoot(t)), silentChecksSection, silentRefusals(t))
}

// signInLevel is one row of the sign-in table: a level, whether the user has an authenticator, and
// the acr and amr the sign-in ends with.
type signInLevel struct {
	level      record.AcrLevel
	userHasOTP bool
	acr, amr   string
}

// signInLevels is, for every level and both answers to "has the user an authenticator", what a
// sign-in with no session ends with: the acr is the target, as SetAcrLevel writes it with no
// session, and the amr is pwd, with otp when the step-up rule sends the ceremony to level 2 and
// decideLevel2Arm asks for a code there.
func signInLevels(t *testing.T) []signInLevel {
	t.Helper()
	var levels []signInLevel
	for _, level := range []record.AcrLevel{record.AcrLevel1, record.AcrLevel2Optional, record.AcrLevel2Mandatory} {
		for _, userHasOTP := range []bool{false, true} {
			var authContext ceremony.AuthContext
			if err := authContext.SetAcrLevel(level, nil); err != nil {
				t.Fatalf("setting the acr for %s: %v", level, err)
			}
			amr := `["pwd"]`
			stepUp, err := ceremony.StepUpOwed(level, nil)
			if err != nil {
				t.Fatalf("the step-up rule for %s: %v", level, err)
			}
			if stepUp != ceremony.StepUpNone {
				state, _, err := decideLevel2Arm(level, userHasOTP)
				if err != nil {
					t.Fatalf("level 2 for %s: %v", level, err)
				}
				if state == ceremony.AuthStateLevel2OTP {
					amr = `["pwd", "otp"]`
				}
			}
			levels = append(levels, signInLevel{level, userHasOTP, authContext.AcrLevel.String(), amr})
		}
	}
	return levels
}

// The sign-in table on ACR and AMR says which acr and amr an app gets for each level, with and
// without an authenticator, and an app deciding whether a second factor was used reads it there.
// Each of its rows is what the ceremony ends with, and every level and answer has one.
func TestConceptDocs_TheSignInTableIsWhatTheCeremonyEndsWith(t *testing.T) {
	assertSignInTable(t, filepath.Dir(guard.SourceRoot(t)), signInLevelsSection, signInLevels(t))
}

func TestConceptDocs_ASilentChecksTableOutOfOrderFails(t *testing.T) {
	root := t.TempDir()
	writeConceptFixture(t, root, "site/prompt.mdx", "### The silent checks\n\n"+
		"| Check | `error` | `error_description` |\n|---|---|---|\n"+
		"| The user is enabled | `access_denied` | \"The user account is disabled\" |\n"+
		"| A session | `login_required` | \"User authentication is required\" |\n")

	report := guard.Run(func(r guard.Reporter) {
		assertSilentChecksTable(r, root, conceptSection{"site/prompt.mdx", "### The silent checks"}, []silentRefusal{
			{"login_required", "User authentication is required"},
			{"access_denied", "The user account is disabled"},
		})
	})

	if report.Stopped {
		t.Fatalf("the check stopped rather than reporting: %s", report.Fatal)
	}
	want := []string{
		`site/prompt.mdx: ### The silent checks row 1 says access_denied "The user account is disabled", the code's refusal 1 is login_required "User authentication is required"`,
		`site/prompt.mdx: ### The silent checks row 2 says login_required "User authentication is required", the code's refusal 2 is access_denied "The user account is disabled"`,
	}
	if !slices.Equal(report.Errors, want) {
		t.Errorf("failures\n%q\nwant\n%q", report.Errors, want)
	}
}

func TestConceptDocs_ASilentChecksTableMissingARefusalFails(t *testing.T) {
	root := t.TempDir()
	writeConceptFixture(t, root, "site/prompt.mdx", "### The silent checks\n\n"+
		"| Check | `error` | `error_description` |\n|---|---|---|\n"+
		"| A session | `login_required` | \"User authentication is required\" |\n"+
		"| A row no code answers | `login_required` | \"Something else\" |\n")

	report := guard.Run(func(r guard.Reporter) {
		assertSilentChecksTable(r, root, conceptSection{"site/prompt.mdx", "### The silent checks"}, []silentRefusal{
			{"login_required", "User authentication is required"},
			{"login_required", "Something else"},
			{"access_denied", "The user account is disabled"},
		})
	})

	if report.Stopped {
		t.Fatalf("the check stopped rather than reporting: %s", report.Fatal)
	}
	want := []string{`site/prompt.mdx: ### The silent checks has no row for the code's refusal 3, access_denied "The user account is disabled"`}
	if !slices.Equal(report.Errors, want) {
		t.Errorf("failures\n%q\nwant\n%q", report.Errors, want)
	}
}

func TestConceptDocs_ASilentChecksTableWithAnExtraRowFails(t *testing.T) {
	root := t.TempDir()
	writeConceptFixture(t, root, "site/prompt.mdx", "### The silent checks\n\n"+
		"| Check | `error` | `error_description` |\n|---|---|---|\n"+
		"| A session | `login_required` | \"User authentication is required\" |\n"+
		"| A row no code answers | `login_required` | \"Something else\" |\n")

	report := guard.Run(func(r guard.Reporter) {
		assertSilentChecksTable(r, root, conceptSection{"site/prompt.mdx", "### The silent checks"}, []silentRefusal{
			{"login_required", "User authentication is required"},
		})
	})

	want := []string{`site/prompt.mdx: ### The silent checks row 2 says login_required "Something else", which the code never answers`}
	if report.Stopped || !slices.Equal(report.Errors, want) {
		t.Errorf("failures %+v\nwant\n%q", report, want)
	}
}

func TestConceptDocs_ASilentChecksTableAgreeingWithTheCodePasses(t *testing.T) {
	root := t.TempDir()
	writeConceptFixture(t, root, "site/prompt.mdx", "### The silent checks\n\n"+
		"| Check | `error` | `error_description` |\n|---|---|---|\n"+
		"| A session | `login_required` | \"User authentication is required\" |\n"+
		"| The user is enabled | `access_denied` | \"The user account is disabled\" |\n\n"+
		"### Next\n\n| Check | `error` | `error_description` |\n|---|---|---|\n| Other | `x` | \"y\" |\n")

	report := guard.Run(func(r guard.Reporter) {
		assertSilentChecksTable(r, root, conceptSection{"site/prompt.mdx", "### The silent checks"}, []silentRefusal{
			{"login_required", "User authentication is required"},
			{"access_denied", "The user account is disabled"},
		})
	})

	if report.Stopped || len(report.Errors) > 0 {
		t.Errorf("a table agreeing with the code was refused: %+v", report)
	}
}

func TestConceptDocs_ASilentChecksTableWithoutItsColumnsStops(t *testing.T) {
	root := t.TempDir()
	writeConceptFixture(t, root, "site/prompt.mdx", "### The silent checks\n\n"+
		"| Check | `error` | Description |\n|---|---|---|\n| A session | `login_required` | User authentication is required |\n")

	report := guard.Run(func(r guard.Reporter) {
		assertSilentChecksTable(r, root, conceptSection{"site/prompt.mdx", "### The silent checks"},
			[]silentRefusal{{"login_required", "User authentication is required"}})
	})

	if !report.Stopped || !strings.Contains(report.Fatal, "`error_description`") {
		t.Errorf("a table without its columns did not stop the check naming them: %+v", report)
	}
}

func TestConceptDocs_AMissingSilentChecksSectionStops(t *testing.T) {
	root := t.TempDir()
	writeConceptFixture(t, root, "site/prompt.mdx", "### Silent checks\n\n"+
		"| Check | `error` | `error_description` |\n|---|---|---|\n| A session | `login_required` | \"x\" |\n")

	report := guard.Run(func(r guard.Reporter) {
		assertSilentChecksTable(r, root, conceptSection{"site/prompt.mdx", "### The silent checks"},
			[]silentRefusal{{"login_required", "x"}})
	})

	if !report.Stopped || !strings.Contains(report.Fatal, "### The silent checks") {
		t.Errorf("a page without the section did not stop the check naming it: %+v", report)
	}
}

func TestConceptDocs_ASignInTableDisagreeingWithTheCodeFails(t *testing.T) {
	root := t.TempDir()
	writeConceptFixture(t, root, "site/acr.mdx", "### A sign-in with no session\n\n"+
		"| Level | User has two-factor authentication | `acr` | `amr` |\n|---|---|---|---|\n"+
		"| `urn:goiabada:level1` | No | `urn:goiabada:level1` | `[\"pwd\"]` |\n"+
		"| `urn:goiabada:level2_optional` | No | `urn:goiabada:level2_optional` | `[\"pwd\", \"otp\"]` |\n"+
		"| `urn:goiabada:level3` | No | `urn:goiabada:level3` | `[\"pwd\"]` |\n")

	report := guard.Run(func(r guard.Reporter) {
		assertSignInTable(r, root, conceptSection{"site/acr.mdx", "### A sign-in with no session"}, []signInLevel{
			{record.AcrLevel1, false, "urn:goiabada:level1", `["pwd"]`},
			{record.AcrLevel2Optional, false, "urn:goiabada:level2_optional", `["pwd"]`},
			{record.AcrLevel2Mandatory, true, "urn:goiabada:level2_mandatory", `["pwd", "otp"]`},
		})
	})

	if report.Stopped {
		t.Fatalf("the check stopped rather than reporting: %s", report.Fatal)
	}
	want := []string{
		`site/acr.mdx: ### A sign-in with no session row 2 says urn:goiabada:level2_optional, No ends with acr urn:goiabada:level2_optional and amr ["pwd", "otp"], the code ends it with acr urn:goiabada:level2_optional and amr ["pwd"]`,
		`site/acr.mdx: ### A sign-in with no session row 3 names urn:goiabada:level3, No, which is no level and answer the code has`,
		`site/acr.mdx: ### A sign-in with no session has no row for urn:goiabada:level2_mandatory, Yes`,
	}
	if !slices.Equal(report.Errors, want) {
		t.Errorf("failures\n%q\nwant\n%q", report.Errors, want)
	}
}

func TestConceptDocs_ASignInTableNamingARowTwiceFails(t *testing.T) {
	root := t.TempDir()
	writeConceptFixture(t, root, "site/acr.mdx", "### A sign-in with no session\n\n"+
		"| Level | User has two-factor authentication | `acr` | `amr` |\n|---|---|---|---|\n"+
		"| `urn:goiabada:level1` | No | `urn:goiabada:level1` | `[\"pwd\"]` |\n"+
		"| `urn:goiabada:level1` | No | `urn:goiabada:level1` | `[\"pwd\"]` |\n")

	report := guard.Run(func(r guard.Reporter) {
		assertSignInTable(r, root, conceptSection{"site/acr.mdx", "### A sign-in with no session"}, []signInLevel{
			{record.AcrLevel1, false, "urn:goiabada:level1", `["pwd"]`},
		})
	})

	want := []string{`site/acr.mdx: ### A sign-in with no session row 2 repeats urn:goiabada:level1, No`}
	if report.Stopped || !slices.Equal(report.Errors, want) {
		t.Errorf("failures %+v\nwant\n%q", report, want)
	}
}

func TestConceptDocs_ASignInTableAgreeingWithTheCodePasses(t *testing.T) {
	root := t.TempDir()
	writeConceptFixture(t, root, "site/acr.mdx", "### A sign-in with no session\n\n"+
		"| Level | User has two-factor authentication | `acr` | `amr` |\n|---|---|---|---|\n"+
		"| `urn:goiabada:level1` | No | `urn:goiabada:level1` | `[\"pwd\"]` |\n"+
		"| `urn:goiabada:level2_mandatory` | Yes | `urn:goiabada:level2_mandatory` | `[\"pwd\", \"otp\"]` |\n")

	report := guard.Run(func(r guard.Reporter) {
		assertSignInTable(r, root, conceptSection{"site/acr.mdx", "### A sign-in with no session"}, []signInLevel{
			{record.AcrLevel1, false, "urn:goiabada:level1", `["pwd"]`},
			{record.AcrLevel2Mandatory, true, "urn:goiabada:level2_mandatory", `["pwd", "otp"]`},
		})
	})

	if report.Stopped || len(report.Errors) > 0 {
		t.Errorf("a table agreeing with the code was refused: %+v", report)
	}
}

func TestConceptDocs_ASignInSectionWithNoTableStops(t *testing.T) {
	root := t.TempDir()
	writeConceptFixture(t, root, "site/acr.mdx", "### A sign-in with no session\n\nLevel 1 asks for a password.\n")

	report := guard.Run(func(r guard.Reporter) {
		assertSignInTable(r, root, conceptSection{"site/acr.mdx", "### A sign-in with no session"},
			[]signInLevel{{record.AcrLevel1, false, "urn:goiabada:level1", `["pwd"]`}})
	})

	if !report.Stopped || !strings.Contains(report.Fatal, "### A sign-in with no session") {
		t.Errorf("a section with no table did not stop the check naming it: %+v", report)
	}
}

// assertSilentChecksTable is the reporting half of the silent checks table's check: one failure per
// row that differs from the code's refusal at its position, per row past the code's last refusal and
// per refusal past the table's last row; a stop for a section, table or column not found.
func assertSilentChecksTable(r guard.Reporter, root string, section conceptSection, want []silentRefusal) {
	r.Helper()
	columns, err := conceptTableColumns(root, section, "`error`", "`error_description`")
	if err != nil {
		r.Fatalf("%v", err)
		return
	}
	for i, row := range columns {
		got := silentRefusal{row[0], row[1]}
		if i >= len(want) {
			r.Errorf("%s: %s row %d says %s %q, which the code never answers",
				section.page, section.heading, i+1, got.code, got.description)
			continue
		}
		if got != want[i] {
			r.Errorf("%s: %s row %d says %s %q, the code's refusal %d is %s %q",
				section.page, section.heading, i+1, got.code, got.description, i+1, want[i].code, want[i].description)
		}
	}
	for i := len(columns); i < len(want); i++ {
		r.Errorf("%s: %s has no row for the code's refusal %d, %s %q",
			section.page, section.heading, i+1, want[i].code, want[i].description)
	}
}

// assertSignInTable is the reporting half of the sign-in table's check: one failure per row whose
// acr or amr differs from the code's, per row naming a level and answer the code does not have or
// one already named, and per level and answer with no row; a stop for a section, table or column
// not found.
func assertSignInTable(r guard.Reporter, root string, section conceptSection, want []signInLevel) {
	r.Helper()
	columns, err := conceptTableColumns(root, section, "Level", "User has two-factor authentication", "`acr`", "`amr`")
	if err != nil {
		r.Fatalf("%v", err)
		return
	}
	yesNo := map[bool]string{false: "No", true: "Yes"}
	seen := map[string]bool{}
	for i, row := range columns {
		key := row[0] + ", " + row[1]
		index := slices.IndexFunc(want, func(w signInLevel) bool {
			return w.level.String() == row[0] && yesNo[w.userHasOTP] == row[1]
		})
		switch {
		case index < 0:
			r.Errorf("%s: %s row %d names %s, which is no level and answer the code has",
				section.page, section.heading, i+1, key)
		case seen[key]:
			r.Errorf("%s: %s row %d repeats %s", section.page, section.heading, i+1, key)
		case want[index].acr != row[2] || want[index].amr != row[3]:
			r.Errorf("%s: %s row %d says %s ends with acr %s and amr %s, the code ends it with acr %s and amr %s",
				section.page, section.heading, i+1, key, row[2], row[3], want[index].acr, want[index].amr)
		}
		seen[key] = true
	}
	for _, w := range want {
		if key := w.level.String() + ", " + yesNo[w.userHasOTP]; !seen[key] {
			r.Errorf("%s: %s has no row for %s", section.page, section.heading, key)
		}
	}
}

// conceptTableColumns is the named columns of the first Markdown table in a section, row by row, each
// cell with the backticks and double quotes around it removed.
func conceptTableColumns(root string, section conceptSection, headers ...string) ([][]string, error) {
	text, err := conceptSectionText(root, section)
	if err != nil {
		return nil, err
	}
	rows := conceptTableRows(text)
	if len(rows) == 0 {
		return nil, fmt.Errorf("%s: %s has no table", section.page, section.heading)
	}
	var indexes []int
	for _, header := range headers {
		index := slices.Index(rows[0], header)
		if index < 0 {
			return nil, fmt.Errorf("%s: %s's table has no column headed %s", section.page, section.heading, header)
		}
		indexes = append(indexes, index)
	}
	var columns [][]string
	for _, row := range rows[1:] {
		var cells []string
		for _, index := range indexes {
			cell := ""
			if index < len(row) {
				cell = strings.Trim(row[index], "`\"")
			}
			cells = append(cells, cell)
		}
		columns = append(columns, cells)
	}
	return columns, nil
}

// conceptSectionText is the text under a heading, up to the next heading of the same level or above,
// a heading inside a code fence not counting as one.
func conceptSectionText(root string, section conceptSection) (string, error) {
	content, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(section.page)))
	if err != nil {
		return "", fmt.Errorf("reading %s: %w", section.page, err)
	}
	level := conceptHeadingLevel(section.heading)
	var body []string
	inFence, inSection := false, false
	for _, line := range strings.Split(string(content), "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "```") {
			inFence = !inFence
		}
		if !inFence {
			if inSection {
				if headingLevel := conceptHeadingLevel(line); headingLevel > 0 && headingLevel <= level {
					return strings.Join(body, "\n"), nil
				}
			} else if strings.TrimRight(line, " \r") == section.heading {
				inSection = true
				continue
			}
		}
		if inSection {
			body = append(body, line)
		}
	}
	if !inSection {
		return "", fmt.Errorf("%s has no section headed %q", section.page, section.heading)
	}
	return strings.Join(body, "\n"), nil
}

// conceptHeadingLevel is the number of #s a Markdown heading line opens with, or 0 for any other line.
func conceptHeadingLevel(line string) int {
	level := len(line) - len(strings.TrimLeft(line, "#"))
	if level == 0 || !strings.HasPrefix(line[level:], " ") {
		return 0
	}
	return level
}

// conceptTableRows is the first Markdown table in text, its header row first and its delimiter row
// left out, each cell trimmed.
func conceptTableRows(text string) [][]string {
	var rows [][]string
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "|") {
			if len(rows) > 0 {
				break
			}
			continue
		}
		cells := strings.Split(strings.Trim(line, "|"), "|")
		for i := range cells {
			cells[i] = strings.TrimSpace(cells[i])
		}
		if len(rows) > 0 && strings.Trim(strings.Join(cells, ""), "-: ") == "" {
			continue
		}
		rows = append(rows, cells)
	}
	return rows
}

func writeConceptFixture(t *testing.T, root, name, content string) {
	t.Helper()
	path := filepath.Join(root, filepath.FromSlash(name))
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("creating %s: %v", filepath.Dir(path), err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("writing %s: %v", path, err)
	}
}
