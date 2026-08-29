package data

// The cross-engine parity comparison (#284, seam 3): a pure function over four parsed golden
// files that says whether the four supported engines build the same schema.
//
// It lives here, in the core module with no database of its own, because that is the only
// place it can run once. The data tier runs one engine per process, selected by
// GOIABADA_DB_TYPE, so a comparison that lived there would run four times in CI, each time
// doing identical work that needs no database at all. Reading committed files instead means
// no database state can make it green.
//
// It is test-only code on purpose. Nothing the server does depends on it, and a check that
// judges the schema has no business being linked into a binary that serves tokens.
//
// Two halves, and the split is what decision 5 rests on:
//
//   - CANONICALISATION maps spelling and never meaning. TEXT, varchar(40), character
//     varying(40) and nvarchar(40) are four spellings of one type, and the four collation
//     names all say "case-sensitive" after #283, so those compare equal. A column's declared
//     length, its signedness and its fractional-second precision stay comparable, because
//     those are facts about the database rather than words for the same fact: written
//     otherwise, SQLite's missing length and MySQL's bigint unsigned would silently vanish
//     instead of being counted.
//   - THE ALLOWLIST excuses what is left, and every rule carries the number of places it
//     excuses and a digest over which places those are. The count is what stops a rule
//     written to excuse 89 columns from going on to excuse the 200th, and the digest is what
//     stops one accepted exception being corrected while a different one appears under the
//     same rule at the same count.
//
// Wiring this to the four committed golden files is a separate test; everything here is
// exercised against synthetic shapes, which is what makes a vocabulary bug catchable with no
// database at all.

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/leodip/goiabada/core/data/schemadump"
)

// parityDialects is every engine the comparison requires, in the order failure messages
// print them. Three engines agreeing is not parity, so a dump missing from the input is
// refused rather than compared.
var parityDialects = []schemadump.Dialect{
	schemadump.SQLite, schemadump.MySQL, schemadump.Postgres, schemadump.MSSQL,
}

// ---------------------------------------------------------------------------
// The canonical vocabulary
// ---------------------------------------------------------------------------

// parityType is one column type in the common vocabulary. Family is the only field every
// type carries; the rest are meaningful for one family each and stay at their zero value
// otherwise, so two types of different families never compare equal by accident.
type parityType struct {
	Family string

	// Bound is a string or byte column's declared length in characters. Two sentinels
	// stand for the cases a number cannot: parityBoundUnbounded for a type whose whole
	// point is that it has no limit, and parityBoundUndeclared for SQLite, which declares
	// TEXT where the other three declare a width. Undeclared is deliberately not folded
	// onto unbounded: SQLite storing an over-long value where SQL Server would refuse it
	// is the difference this exists to record.
	Bound int

	// Width is an integer column's declared width in bits, and Unsigned its signedness.
	// MySQL's bigint unsigned against bigint elsewhere is a real difference in the range
	// a column accepts, so it survives canonicalisation and reaches the allowlist.
	Width    int
	Unsigned bool

	// Precision is a datetime column's declared fractional-second digits, or
	// parityPrecisionUndeclared where the engine has no way to declare any.
	Precision int
}

const (
	parityString   = "string"
	parityInt      = "int"
	parityBool     = "bool"
	parityBytes    = "bytes"
	parityDatetime = "datetime"
	parityNumeric  = "numeric"

	parityBoundUndeclared     = -1
	parityBoundUnbounded      = -2
	parityPrecisionUndeclared = -1
)

func (t parityType) String() string {
	switch t.Family {
	case parityString, parityBytes:
		switch t.Bound {
		case parityBoundUnbounded:
			return t.Family + "(unbounded)"
		case parityBoundUndeclared:
			return t.Family + "(no declared length)"
		default:
			return fmt.Sprintf("%s(%d)", t.Family, t.Bound)
		}
	case parityInt:
		if t.Unsigned {
			return fmt.Sprintf("uint%d", t.Width)
		}
		return fmt.Sprintf("int%d", t.Width)
	case parityDatetime:
		if t.Precision == parityPrecisionUndeclared {
			return "datetime(no declared precision)"
		}
		return fmt.Sprintf("datetime(%d)", t.Precision)
	default:
		return t.Family
	}
}

// parityTypeRule is how one engine's spelling maps onto the common vocabulary. arg says what
// a parenthesised argument means for that spelling, so varchar(40) and datetime2(6) are read
// with the same code and neither is guessed from the number.
type parityTypeRule struct {
	family    string
	width     int
	unsigned  bool
	bound     int
	precision int
	arg       string // "", parityArgLength or parityArgPrecision
}

const (
	parityArgLength    = "length"
	parityArgPrecision = "precision"
)

// parityTypes is the whole vocabulary, per engine, keyed by the lowercased spelling with its
// parenthesised argument removed. A spelling that is not here is a failure naming it rather
// than a guess: the comparison is only worth anything if an unrecognised type stops it, and
// a migration introducing one is exactly the moment somebody should be asked what it means
// on the other three engines.
//
// Every entry is the spelling an engine's own catalog reports, not the spelling a migration
// writes. SQLite reports the declared type verbatim, which is why its half carries three
// ways of writing a boolean and two ways of writing an integer: the migrations wrote them
// that way, and folding them together here would hide it.
var parityTypes = map[schemadump.Dialect]map[string]parityTypeRule{
	schemadump.SQLite: {
		"text": {family: parityString, bound: parityBoundUndeclared},
		// There is deliberately no "longtext" here, and adding one would undo a fix.
		// SQLite has no such type: it accepts any type name and assigns affinity by
		// substring, so a column declared longtext is a TEXT column with a MySQL name on
		// it. browser_sessions.data was exactly that until 000043, and while both
		// spellings mapped onto this same value the cross-engine check could not see it.
		// Left out, an engine reporting longtext is refused by name, which is what the
		// vocabulary is for (#284).
		"varchar": {family: parityString, bound: parityBoundUndeclared, arg: parityArgLength},
		"blob":    {family: parityBytes, bound: parityBoundUnbounded},
		// SQLite treats INT and INTEGER identically, both 8 bytes wide. They are kept
		// apart because the migrations chose between them per column and the other three
		// engines make that choice mean something: an INT column here stands opposite an
		// int on MySQL, and an INTEGER one opposite a bigint.
		"int":      {family: parityInt, width: 32},
		"integer":  {family: parityInt, width: 64},
		"boolean":  {family: parityBool},
		"numeric":  {family: parityNumeric},
		"datetime": {family: parityDatetime, precision: parityPrecisionUndeclared, arg: parityArgPrecision},
	},
	schemadump.MySQL: {
		"varchar": {family: parityString, arg: parityArgLength},
		"char":    {family: parityString, arg: parityArgLength},
		// MySQL has no unbounded string. longtext is its largest at 4 GiB, which is what
		// text is on PostgreSQL and nvarchar(max) is on SQL Server, so it maps onto
		// unbounded; the smaller two carry their real ceiling, because a column capped at
		// 64 KiB on one engine alone is a truncation waiting to happen and not a spelling.
		"text":            {family: parityString, bound: 65535},
		"mediumtext":      {family: parityString, bound: 16777215},
		"longtext":        {family: parityString, bound: parityBoundUnbounded},
		"blob":            {family: parityBytes, bound: 65535},
		"mediumblob":      {family: parityBytes, bound: 16777215},
		"longblob":        {family: parityBytes, bound: parityBoundUnbounded},
		"varbinary":       {family: parityBytes, arg: parityArgLength},
		"int":             {family: parityInt, width: 32},
		"int unsigned":    {family: parityInt, width: 32, unsigned: true},
		"bigint":          {family: parityInt, width: 64},
		"bigint unsigned": {family: parityInt, width: 64, unsigned: true},
		"smallint":        {family: parityInt, width: 16},
		// tinyint(1) is MySQL's boolean and is special-cased before this table is read.
		// Any other width is an integer.
		"tinyint":   {family: parityInt, width: 8},
		"datetime":  {family: parityDatetime, precision: 0, arg: parityArgPrecision},
		"timestamp": {family: parityDatetime, precision: 0, arg: parityArgPrecision},
		"decimal":   {family: parityNumeric},
	},
	schemadump.Postgres: {
		"character varying": {family: parityString, bound: parityBoundUnbounded, arg: parityArgLength},
		"character":         {family: parityString, arg: parityArgLength},
		"text":              {family: parityString, bound: parityBoundUnbounded},
		"bytea":             {family: parityBytes, bound: parityBoundUnbounded},
		"integer":           {family: parityInt, width: 32},
		"bigint":            {family: parityInt, width: 64},
		"smallint":          {family: parityInt, width: 16},
		"boolean":           {family: parityBool},
		// An unqualified PostgreSQL timestamp is microsecond precision, which is exactly
		// what (6) means on the other three, so the two spellings map onto one value
		// rather than reading as a difference nobody wrote.
		"timestamp without time zone": {family: parityDatetime, precision: 6, arg: parityArgPrecision},
		"numeric":                     {family: parityNumeric},
	},
	schemadump.MSSQL: {
		"nvarchar":  {family: parityString, arg: parityArgLength},
		"varchar":   {family: parityString, arg: parityArgLength},
		"nchar":     {family: parityString, arg: parityArgLength},
		"char":      {family: parityString, arg: parityArgLength},
		"varbinary": {family: parityBytes, arg: parityArgLength},
		"binary":    {family: parityBytes, arg: parityArgLength},
		"int":       {family: parityInt, width: 32},
		"bigint":    {family: parityInt, width: 64},
		"smallint":  {family: parityInt, width: 16},
		"tinyint":   {family: parityInt, width: 8},
		"bit":       {family: parityBool},
		"datetime2": {family: parityDatetime, precision: 7, arg: parityArgPrecision},
		"decimal":   {family: parityNumeric},
		"numeric":   {family: parityNumeric},
	},
}

// splitTypeSpelling separates a type's name from its parenthesised argument, keeping any
// words that follow the argument as part of the name. It is what lets one lookup table hold
// "character varying(40)", "timestamp(6) without time zone" and "bigint unsigned".
func splitTypeSpelling(s string) (name, arg string) {
	openIdx := strings.Index(s, "(")
	closeIdx := strings.LastIndex(s, ")")
	if openIdx < 0 || closeIdx < openIdx {
		return strings.ToLower(strings.Join(strings.Fields(s), " ")), ""
	}
	arg = strings.TrimSpace(s[openIdx+1 : closeIdx])
	name = s[:openIdx] + " " + s[closeIdx+1:]
	return strings.ToLower(strings.Join(strings.Fields(name), " ")), arg
}

// canonicalType maps one engine's spelling onto the common vocabulary.
func canonicalType(d schemadump.Dialect, spelling string) (parityType, error) {
	name, arg := splitTypeSpelling(spelling)
	if d == schemadump.MySQL && name == "tinyint" && arg == "1" {
		return parityType{Family: parityBool}, nil
	}
	rule, ok := parityTypes[d][name]
	if !ok {
		return parityType{}, fmt.Errorf("%s spells a type %q, which the parity vocabulary does not carry", d, spelling)
	}
	t := parityType{
		Family: rule.family, Bound: rule.bound,
		Width: rule.width, Unsigned: rule.unsigned, Precision: rule.precision,
	}
	if arg == "" {
		return t, nil
	}
	switch rule.arg {
	case parityArgLength:
		if strings.EqualFold(arg, "max") {
			t.Bound = parityBoundUnbounded
			return t, nil
		}
		n, err := strconv.Atoi(arg)
		if err != nil {
			return parityType{}, fmt.Errorf("%s spells a type %q whose length is not a number", d, spelling)
		}
		t.Bound = n
	case parityArgPrecision:
		n, err := strconv.Atoi(arg)
		if err != nil {
			return parityType{}, fmt.Errorf("%s spells a type %q whose precision is not a number", d, spelling)
		}
		t.Precision = n
	}
	return t, nil
}

// parityCollations maps each engine's collation name onto what it decides, which is the one
// axis of the schema a specification governs: RFC 6749 section 1.9 makes every protocol
// parameter value case-sensitive unless noted, and OIDC Core section 2 says the same of sub,
// so two columns identical in every other respect still disagree if one folds MyApp onto
// myapp. All four are case-sensitive, pinned by #283.
//
// PostgreSQL's "default" is the database's own collation, which #283 pins at the database
// level rather than per column, so no column here declares an override.
var parityCollations = map[string]string{
	"BINARY":                                 "case-sensitive", // SQLite, the declared default
	"utf8mb4_0900_as_cs":                     "case-sensitive", // MySQL
	"default":                                "case-sensitive", // PostgreSQL
	"Latin1_General_100_CS_AS_KS_WS_SC_UTF8": "case-sensitive", // SQL Server
}

// canonicalCollation reads a collation only for a column that holds a string, because that
// is the only place it decides anything. SQLite reports BINARY for every column including
// its integers and blobs, where the other three report nothing at all, and comparing that
// would produce a rule excusing two hundred columns for a property none of them has.
func canonicalCollation(d schemadump.Dialect, raw string, family string) (string, error) {
	if family != parityString || raw == "" {
		return "", nil
	}
	canonical, ok := parityCollations[raw]
	if !ok {
		return "", fmt.Errorf("%s reports collation %q, which the parity vocabulary does not carry", d, raw)
	}
	return canonical, nil
}

// parityDefault is a column's default. Present is separate from Value because "" is a
// legitimate default and also what a column with no default reports, and folding the two
// together would make DEFAULT ” on three engines compare equal to no default at all on the
// fourth.
type parityDefault struct {
	Present bool
	Value   string
}

func (d parityDefault) String() string {
	if !d.Present {
		return "no default"
	}
	return "default " + strconv.Quote(d.Value)
}

// canonicalDefault strips the wrapping each engine puts round a default expression and
// leaves the expression itself alone.
//
// Whether there is a default at all is read from the shape rather than from the expression
// being empty, because the two are different questions and only the dumper can answer the
// first: MySQL's catalog reports DEFAULT ” as the empty string, exactly as it reports a
// column with no default (#284).
//
// Four rules, each removing a spelling and none removing a fact:
//
//   - SQL Server parenthesises everything, so ((0)) is 0 and (”) is ”.
//   - PostgreSQL casts a literal to the column's type, so ”::character varying is ”. Only
//     a trailing cast outside any parentheses is removed, which leaves the regclass cast
//     inside nextval('widgets_id_seq'::regclass) where it belongs.
//   - DEFAULT NULL is no default: a nullable column with either takes NULL. MySQL and
//     PostgreSQL report nothing where SQLite and SQL Server report NULL, and all four
//     behave the same way.
//   - A string literal's quotes go, because MySQL's catalog reports the value where the
//     other three report the literal. The cost is that an unquoted keyword and a quoted
//     string of the same characters become one value, which no column in this schema has.
//   - The boolean keywords become the digits the other three write, PostgreSQL being the
//     only engine that renders a boolean default as false rather than 0. Only where the
//     value was not quoted: 'false' is a five-character string and stays one.
func canonicalDefault(d schemadump.Dialect, raw string, has bool) parityDefault {
	if !has {
		return parityDefault{}
	}
	v := strings.TrimSpace(raw)
	if v == "" {
		return parityDefault{Present: true, Value: ""}
	}
	switch d {
	case schemadump.MSSQL:
		v = stripOuterParens(v)
	case schemadump.Postgres:
		v = stripTrailingCast(v)
	}
	if strings.EqualFold(v, "null") {
		return parityDefault{}
	}
	if literal := stripQuotes(v); literal != v {
		return parityDefault{Present: true, Value: literal}
	}
	switch strings.ToLower(v) {
	case "false":
		v = "0"
	case "true":
		v = "1"
	}
	return parityDefault{Present: true, Value: v}
}

// stripOuterParens removes as many balanced enclosing parentheses as the expression carries,
// so ((0)) reads as 0. An unbalanced or partially enclosing pair is left alone: (a)+(b) is
// not (a)+(b) with its outermost pair removed.
func stripOuterParens(v string) string {
	for len(v) >= 2 && v[0] == '(' && v[len(v)-1] == ')' {
		depth := 0
		enclosing := true
		for i, r := range v {
			switch r {
			case '(':
				depth++
			case ')':
				depth--
			}
			if depth == 0 && i < len(v)-1 {
				enclosing = false
			}
		}
		if !enclosing {
			return v
		}
		v = strings.TrimSpace(v[1 : len(v)-1])
	}
	return v
}

// stripTrailingCast removes PostgreSQL's ::type suffix when it applies to the whole
// expression, which is the case for every literal default the catalog renders.
func stripTrailingCast(v string) string {
	depth, quoted := 0, false
	for i := 0; i < len(v)-1; i++ {
		switch v[i] {
		case '\'':
			quoted = !quoted
		case '(':
			if !quoted {
				depth++
			}
		case ')':
			if !quoted {
				depth--
			}
		case ':':
			if !quoted && depth == 0 && v[i+1] == ':' {
				return strings.TrimSpace(v[:i])
			}
		}
	}
	return v
}

// stripQuotes removes a SQL string literal's surrounding quotes and undoubles the quotes
// inside it. Anything not quoted end to end is returned unchanged.
func stripQuotes(v string) string {
	if len(v) < 2 || v[0] != '\'' || v[len(v)-1] != '\'' {
		return v
	}
	return strings.ReplaceAll(v[1:len(v)-1], "''", "'")
}

// ---------------------------------------------------------------------------
// What a disagreement looks like
// ---------------------------------------------------------------------------

// parityDivergence is one place the four engines disagree, on one axis of one object. Says
// carries every engine's answer, including the ones that agree, because the interesting
// question at a failure is which engine is the odd one out.
type parityDivergence struct {
	Table  string
	Object string // the column, index or foreign key; empty for the table itself
	Axis   string
	Says   map[schemadump.Dialect]string
}

// The axes, named here so a rule's predicate and the comparison cannot drift apart by a
// typo. parityAxisVocabulary is the one no rule may excuse: it means an engine spelled
// something the comparison could not read, so every other answer about that column is a
// guess.
const (
	parityAxisTable      = "table"
	parityAxisColumn     = "column"
	parityAxisType       = "type"
	parityAxisNullable   = "nullable"
	parityAxisDefault    = "default"
	parityAxisCollation  = "collation"
	parityAxisGenerated  = "generated"
	parityAxisIndex      = "index"
	parityAxisIndexName  = "index-name"
	parityAxisForeignKey = "foreign-key"
	parityAxisOnDelete   = "on-delete"
	parityAxisVocabulary = "vocabulary"
)

// Key is a divergence's stable identity, and it is what a rule's membership digest is taken
// over. It names the object and the axis and never the values, so a rule's membership does
// not move when the thing it excuses is spelled differently.
func (d parityDivergence) Key() string {
	if d.Object == "" {
		return d.Table + ":" + d.Axis
	}
	return d.Table + "." + d.Object + ":" + d.Axis
}

func (d parityDivergence) String() string {
	parts := make([]string, 0, len(parityDialects))
	for _, dialect := range parityDialects {
		parts = append(parts, fmt.Sprintf("%s=%s", dialect, d.Says[dialect]))
	}
	return d.Key() + "  " + strings.Join(parts, "  ")
}

// ---------------------------------------------------------------------------
// The allowlist
// ---------------------------------------------------------------------------

// parityRule is one place the four engines are allowed to differ. Why is not decoration: it
// is the whole reason a rule can be reviewed, since the count says how much is being excused
// and only the reason says whether it should be.
//
// Count and Digest together pin what the rule covers. The count alone is not enough, which
// the reviewer showed with a rule at two members where one accepted exception is corrected
// and a different one appears: {users.email, users.subject} and {users.email,
// clients.redirect_uri} both count two. The digest is taken over the sorted keys, so it
// moves when the membership does and costs one line per rule rather than the list.
type parityRule struct {
	Name    string
	Why     string
	Count   int
	Digest  string
	Excuses func(parityDivergence) bool
}

// parityRuleResult is what one rule turned out to cover on this run.
type parityRuleResult struct {
	Rule    parityRule
	Members []string
	Digest  string
}

// parityDigest is the membership digest: sixteen hex characters of a SHA-256 over the sorted
// keys. Truncated because it is written into a rule by hand and read by eye at review, and
// sixty-four bits is far beyond what an accidental collision between two schemas needs.
func parityDigest(keys []string) string {
	sorted := append([]string(nil), keys...)
	sort.Strings(sorted)
	sum := sha256.Sum256([]byte(strings.Join(sorted, "\n")))
	return hex.EncodeToString(sum[:])[:16]
}

// drift reports how a rule has moved since it was written, and "" when it has not.
//
// The digest cannot say WHICH member moved, because it is a digest; what it can do is refuse
// to pass. So the failure prints the whole membership as it stands now, which is what a
// reader needs beside their own change to see what appeared, and the two values to paste
// back into the rule once they have decided the movement was intended.
func (r parityRuleResult) drift() string {
	sameCount := len(r.Members) == r.Rule.Count
	if sameCount && r.Digest == r.Rule.Digest {
		return ""
	}
	moved := fmt.Sprintf("recorded %d place(s), found %d", r.Rule.Count, len(r.Members))
	if sameCount {
		moved += ", and they are not the same places"
	}
	covers := "(nothing at all)"
	if len(r.Members) > 0 {
		covers = strings.Join(r.Members, "\n    ")
	}
	return fmt.Sprintf("allowlist rule %q no longer covers what it was written for: %s.\n"+
		"  recorded digest %s, found digest %s\n"+
		"  why the rule exists: %s\n"+
		"  what it covers now:\n    %s\n"+
		"  update it to Count: %d, Digest: %q once every place above is the idiom the rule describes",
		r.Rule.Name, moved, r.Rule.Digest, r.Digest, r.Rule.Why,
		covers, len(r.Members), r.Digest)
}

// applyAllowlist sorts every divergence into the rule that excuses it, and reports the ones
// no rule does.
//
// A divergence two rules both excuse is a failure rather than a first-match win. Counts are
// the point of decision 5, and a divergence quietly landing under whichever rule was
// declared first makes both counts mean nothing.
func applyAllowlist(divergences []parityDivergence, rules []parityRule) (results []parityRuleResult, unexcused []parityDivergence, conflicts []string) {
	members := make([][]string, len(rules))
	for _, d := range divergences {
		matched := []int{}
		if d.Axis != parityAxisVocabulary {
			for i, rule := range rules {
				if rule.Excuses != nil && rule.Excuses(d) {
					matched = append(matched, i)
				}
			}
		}
		switch len(matched) {
		case 0:
			unexcused = append(unexcused, d)
		case 1:
			members[matched[0]] = append(members[matched[0]], d.Key())
		default:
			names := make([]string, 0, len(matched))
			for _, i := range matched {
				names = append(names, strconv.Quote(rules[i].Name))
			}
			conflicts = append(conflicts, fmt.Sprintf(
				"%s is excused by more than one allowlist rule (%s), so neither rule's count means anything; narrow one of them",
				d.Key(), strings.Join(names, ", ")))
		}
	}
	results = make([]parityRuleResult, len(rules))
	for i, rule := range rules {
		sort.Strings(members[i])
		results[i] = parityRuleResult{Rule: rule, Members: members[i], Digest: parityDigest(members[i])}
	}
	return results, unexcused, conflicts
}

// ---------------------------------------------------------------------------
// The comparison
// ---------------------------------------------------------------------------

// checkParity is the whole check: it reports one line per problem, and nothing at all when
// the four engines describe one schema modulo the allowlist. Pure, so the real four-engine
// case is one input to it rather than the only one.
func checkParity(dumps map[schemadump.Dialect]schemadump.Schema, rules []parityRule) []string {
	var missing []string
	for _, d := range parityDialects {
		if len(dumps[d]) == 0 {
			missing = append(missing, string(d))
		}
	}
	if len(missing) > 0 {
		return []string{fmt.Sprintf("no schema to compare for %s: parity is a claim about all four engines, and three agreeing is not it",
			strings.Join(missing, ", "))}
	}

	divergences := compareDumps(dumps)
	results, unexcused, conflicts := applyAllowlist(divergences, rules)

	problems := append([]string(nil), conflicts...)
	for _, d := range unexcused {
		problems = append(problems, "the engines disagree and no allowlist rule excuses it: "+d.String())
	}
	for _, r := range results {
		if drift := r.drift(); drift != "" {
			problems = append(problems, drift)
		}
	}
	return problems
}

// compareDumps walks the four schemas together, table by table.
//
// A table missing on an engine stops there rather than reporting every column, index and
// foreign key it holds as missing too: one line saying the table is absent is the finding,
// and thirty lines saying its columns are absent bury it.
func compareDumps(dumps map[schemadump.Dialect]schemadump.Schema) []parityDivergence {
	var out []parityDivergence
	for _, table := range unionOfTables(dumps) {
		shapes := map[schemadump.Dialect]schemadump.TableShape{}
		says := map[schemadump.Dialect]string{}
		complete := true
		for _, d := range parityDialects {
			shape, ok := dumps[d].Table(table)
			shapes[d], says[d] = shape, presence(ok)
			complete = complete && ok
		}
		if !complete {
			out = append(out, parityDivergence{Table: table, Axis: parityAxisTable, Says: says})
			continue
		}
		out = append(out, compareColumns(table, shapes)...)
		out = append(out, compareIndexes(table, shapes)...)
		out = append(out, compareForeignKeys(table, shapes)...)
	}
	return out
}

func presence(ok bool) string {
	if ok {
		return "present"
	}
	return "absent"
}

func unionOfTables(dumps map[schemadump.Dialect]schemadump.Schema) []string {
	seen := map[string]bool{}
	for _, d := range parityDialects {
		for _, entry := range dumps[d] {
			seen[entry.Name] = true
		}
	}
	return sortedKeys(seen)
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// compareColumns compares the five axes a column carries across engines: its type, its
// nullability, its default, its collation and whether the engine numbers it.
//
// The default constraint's NAME is deliberately not among them. SQL Server is the only
// engine that names a default at all, so comparing it would report all sixty-four of them as
// divergent and say nothing. It is compared where it means something, which is the per-engine
// assertion against that engine's own golden file.
func compareColumns(table string, shapes map[schemadump.Dialect]schemadump.TableShape) []parityDivergence {
	var out []parityDivergence

	names := map[string]bool{}
	for _, d := range parityDialects {
		for _, c := range shapes[d].Columns {
			names[c.Name] = true
		}
	}

	for _, name := range sortedKeys(names) {
		columns := map[schemadump.Dialect]schemadump.ColumnShape{}
		says := map[schemadump.Dialect]string{}
		complete := true
		for _, d := range parityDialects {
			c, ok := shapes[d].Column(name)
			columns[d], says[d] = c, presence(ok)
			complete = complete && ok
		}
		if !complete {
			out = append(out, parityDivergence{Table: table, Object: name, Axis: parityAxisColumn, Says: says})
			continue
		}

		types := map[schemadump.Dialect]parityType{}
		collations := map[schemadump.Dialect]string{}
		readable := true
		for _, d := range parityDialects {
			t, err := canonicalType(d, columns[d].Type)
			if err != nil {
				out = append(out, vocabulary(table, name, d, err))
				readable = false
				continue
			}
			collation, err := canonicalCollation(d, columns[d].Collation, t.Family)
			if err != nil {
				out = append(out, vocabulary(table, name, d, err))
				readable = false
				continue
			}
			types[d], collations[d] = t, collation
		}
		if !readable {
			continue
		}

		out = appendIfDisagreed(out, table, name, parityAxisType, func(d schemadump.Dialect) string {
			return types[d].String()
		})
		out = appendIfDisagreed(out, table, name, parityAxisCollation, func(d schemadump.Dialect) string {
			if collations[d] == "" {
				return "no collation"
			}
			return collations[d]
		})
		out = appendIfDisagreed(out, table, name, parityAxisNullable, func(d schemadump.Dialect) string {
			if columns[d].Nullable {
				return "nullable"
			}
			return "not null"
		})
		out = appendIfDisagreed(out, table, name, parityAxisDefault, func(d schemadump.Dialect) string {
			return canonicalDefault(d, columns[d].Default, columns[d].HasDefault).String()
		})
		out = appendIfDisagreed(out, table, name, parityAxisGenerated, func(d schemadump.Dialect) string {
			if columns[d].Generated {
				return "generated"
			}
			return "not generated"
		})
	}
	return out
}

func vocabulary(table, object string, d schemadump.Dialect, err error) parityDivergence {
	says := map[schemadump.Dialect]string{}
	for _, other := range parityDialects {
		says[other] = "-"
	}
	says[d] = err.Error()
	return parityDivergence{Table: table, Object: object, Axis: parityAxisVocabulary, Says: says}
}

// appendIfDisagreed records one divergence when the four engines do not all say the same
// thing on one axis, and nothing when they do.
func appendIfDisagreed(out []parityDivergence, table, object, axis string, say func(schemadump.Dialect) string) []parityDivergence {
	return appendIfDisagreedAmong(out, table, object, axis, parityDialects, say)
}

// appendIfDisagreedAmong is the same over a subset of the engines, for an axis some engine
// cannot answer at all. Only the index name is such an axis today: an engine that named its
// own index has nothing to say about what a migration spelled.
//
// Says still carries a line per engine, with "-" for the ones outside the comparison,
// because the reader's first question at a failure is which engine is the odd one out and a
// report missing three of four columns cannot answer it.
//
// Fewer than two engines needs no guard of its own: one engine agrees with itself and none
// agree vacuously, so both fall out of the loop reporting nothing, which is the answer.
func appendIfDisagreedAmong(out []parityDivergence, table, object, axis string, among []schemadump.Dialect, say func(schemadump.Dialect) string) []parityDivergence {
	says := map[schemadump.Dialect]string{}
	for _, d := range parityDialects {
		says[d] = "-"
	}
	agreed := true
	for _, d := range among {
		says[d] = say(d)
		agreed = agreed && says[d] == says[among[0]]
	}
	if agreed {
		return out
	}
	return append(out, parityDivergence{Table: table, Object: object, Axis: axis, Says: says})
}

// compareIndexes identifies an index by the tuple (ordered key columns, uniqueness) and not
// by its name, because a name does not survive the crossing. Every SQL Server primary key
// and inline UNIQUE in this schema is named by the engine with a random per-database suffix,
// which differs between two databases built from identical DDL, so twenty-eight objects
// there have no comparable name at all (#284, decision 2).
//
// The name is still compared, across whichever engines got theirs from a migration, which
// is the roughly thirty explicit CREATE INDEX statements. That is worth doing because a name
// is what a later migration says when it drops an index: idx_email misspelled on one engine
// breaks that migration on that engine alone, and nothing else in the repository would catch
// it.
//
// Two or more migration-named engines are enough, rather than all four. Requiring all four
// meant one engine-named index in the set switched the comparison off for the engines whose
// names did come from a migration, so the misspelling it exists to catch shipped whenever it
// landed on a key any engine happened to declare inline (#284).
func compareIndexes(table string, shapes map[schemadump.Dialect]schemadump.TableShape) []parityDivergence {
	byKey := map[schemadump.Dialect]map[string][]schemadump.IndexShape{}
	keys := map[string]bool{}
	for _, d := range parityDialects {
		byKey[d] = map[string][]schemadump.IndexShape{}
		for _, ix := range shapes[d].Indexes {
			key := indexKey(ix)
			byKey[d][key] = append(byKey[d][key], ix)
			keys[key] = true
		}
	}

	var out []parityDivergence
	for _, key := range sortedKeys(keys) {
		before := len(out)
		out = appendIfDisagreed(out, table, key, parityAxisIndex, func(d schemadump.Dialect) string {
			switch n := len(byKey[d][key]); n {
			case 0:
				return "absent"
			case 1:
				return "present"
			default:
				return fmt.Sprintf("present %d times", n)
			}
		})
		if len(out) != before {
			continue
		}
		// The name is compared across exactly the engines whose index for this key came
		// from a migration, and an engine that named its own drops itself from that set
		// rather than disabling the comparison. Its placeholder says nothing about what
		// a migration spelled, but it says nothing about the engines beside it either,
		// and those are the ones a later DROP INDEX breaks on.
		//
		// A key with one migration-named engine is then a singleton with nothing to
		// compare, which is what client_logos and user_profile_pictures are today: MySQL
		// names the unique index by hand where the other three declare it inline.
		//
		// The length test is what keeps an engine holding no index for this key out of
		// the set, where the loop below would find nothing to disagree with and let it
		// in. The presence comparison above has already returned for that case, so it
		// costs nothing and stops the two coming apart.
		migrationNamed := make([]schemadump.Dialect, 0, len(parityDialects))
		for _, d := range parityDialects {
			named := len(byKey[d][key]) > 0
			for _, ix := range byKey[d][key] {
				named = named && ix.Origin == schemadump.OriginCreated
			}
			if named {
				migrationNamed = append(migrationNamed, d)
			}
		}
		out = appendIfDisagreedAmong(out, table, key, parityAxisIndexName, migrationNamed, func(d schemadump.Dialect) string {
			names := make([]string, 0, len(byKey[d][key]))
			for _, ix := range byKey[d][key] {
				names = append(names, ix.Name)
			}
			sort.Strings(names)
			return strings.Join(names, ",")
		})
	}
	return out
}

// indexKey is decision 2's identity for an index: its ordered key columns and whether it is
// unique. Two indexes agreeing on both are the same index however each engine named it.
func indexKey(ix schemadump.IndexShape) string {
	kind := "index"
	if ix.Unique {
		kind = "unique index"
	}
	return fmt.Sprintf("%s(%s)", kind, strings.Join(ix.Columns, ","))
}

// compareForeignKeys keys a foreign key by the tuple every catalog reports, which is what
// the dumper already does and for the same reason: SQLite's PRAGMA foreign_key_list omits
// the constraint name even when the table declares one.
func compareForeignKeys(table string, shapes map[schemadump.Dialect]schemadump.TableShape) []parityDivergence {
	byKey := map[schemadump.Dialect]map[string]schemadump.ForeignKeyShape{}
	keys := map[string]bool{}
	for _, d := range parityDialects {
		byKey[d] = map[string]schemadump.ForeignKeyShape{}
		for _, fk := range shapes[d].ForeignKeys {
			key := foreignKeyKey(fk)
			byKey[d][key] = fk
			keys[key] = true
		}
	}

	var out []parityDivergence
	for _, key := range sortedKeys(keys) {
		before := len(out)
		out = appendIfDisagreed(out, table, key, parityAxisForeignKey, func(d schemadump.Dialect) string {
			_, ok := byKey[d][key]
			return presence(ok)
		})
		if len(out) != before {
			continue
		}
		out = appendIfDisagreed(out, table, key, parityAxisOnDelete, func(d schemadump.Dialect) string {
			return byKey[d][key].OnDelete
		})
	}
	return out
}

func foreignKeyKey(fk schemadump.ForeignKeyShape) string {
	return fmt.Sprintf("%s->%s.%s", fk.Column, fk.RefTable, fk.RefColumn)
}
