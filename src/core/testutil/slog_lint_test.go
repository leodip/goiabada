package testutil

// Seam 8: the rule table AssertSlogConvention enforces, over fixture source text written into a
// temp tree and walked through the same function the real caller uses.
//
// The synthetic half exists because the real half cannot fail informatively. A guard that has
// quietly stopped matching anything passes on a clean tree exactly as it passes on a correct one,
// and by stage 6 the tree is clean by construction, so the only thing left holding the rule would
// be a test that never proves it can fire (#320).

import (
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestSlogConvention_TheRuleTable writes one fixture per row of the six rules and asserts the
// exact set of findings, with lines. Every "caught" fixture is a shape the tree carried before
// the sweep; every "passed" fixture is one that must survive it untouched, and several of those
// are the near miss of a caught row rather than an obviously innocent line.
func TestSlogConvention_TheRuleTable(t *testing.T) {
	root := t.TempDir()
	write := func(rel, src string) {
		t.Helper()
		path := filepath.Join(root, filepath.FromSlash(rel))
		require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
		require.NoError(t, os.WriteFile(path, []byte(src), 0o644))
	}

	// ---- rule 1: the message is a string literal ----------------------------------------------

	// The four ways 125 sites used to build a message. Each produces a record no collector can
	// group and no reader can grep, with the value that matters buried in the one unindexed field.
	write("core/caught/message_sprintf.go", `package caught

import (
	"fmt"
	"log/slog"
)

func sprintfMessage(id string) { slog.Info(fmt.Sprintf("user %s not found", id)) }
`)
	write("core/caught/message_concat.go", `package caught

import "log/slog"

func concatMessage(name string) { slog.Warn("client " + name + " is disabled") }
`)
	write("core/caught/message_variable.go", `package caught

import "log/slog"

func variableMessage(text string) { slog.Error(text) }
`)
	write("core/caught/message_err_error.go", `package caught

import "log/slog"

func errorAsMessage(err error) { slog.Error(err.Error()) }
`)

	// The message sits at a different argument in each shape, which is the whole reason
	// slogEmissions maps a name to an index rather than assuming one: first for slog.Info, second
	// for slog.InfoContext, third for slog.Log and slog.LogAttrs. Read at the wrong index the
	// rule would judge a context or a level and never fire.
	write("core/caught/message_every_shape.go", `package caught

import (
	"context"
	"log/slog"
)

func everyShape(ctx context.Context, text string) {
	slog.InfoContext(ctx, text)
	slog.Log(ctx, slog.LevelInfo, text)
	slog.LogAttrs(ctx, slog.LevelWarn, text)
}
`)

	// ---- rule 2: the message text -------------------------------------------------------------

	// Capitalised, empty, whitespace-led, digit-led and punctuation-led all fail the same check,
	// which is what "starts with a lowercase letter" means once the first rune may not exist.
	// Then the component prefix, which nine spellings used, and the two banned openers.
	write("core/caught/message_text.go", `package caught

import "log/slog"

func messageText() {
	slog.Info("Starting the server")
	slog.Info("")
	slog.Info(" leading space")
	slog.Info("2 factor enrolled")
	slog.Info("-- a banner --")
	slog.Warn("logout: id token hint rejected")
	slog.Warn("2: step two")
	slog.Warn("ünicode: a prefix is not ascii-only")
	slog.Error("failed to reach the database")
	slog.Error("error while reaching the database")
}
`)

	// The near misses, and they are the rows that decide whether rule 2 is a rule or a substring
	// search. A colon that is not a prefix, a one-word message, "failed " that is not "failed to"
	// and "errors" that is not "error ".
	write("core/passed/message_text.go", `package passed

import "log/slog"

func messageText() {
	slog.Info("auth server started")
	slog.Warn("unable to reach the database")
	slog.Info("using database: falling back to sqlite")
	slog.Info("sql")
	slog.Info("failed logins exceeded the threshold")
	slog.Info("errors were counted")
}
`)

	// ---- rule 3: the attribute key vocabulary -------------------------------------------------

	// Read from a bare literal, from every attribute constructor, from a slog.Attr composite
	// literal and from slog.Group's own key/value run. slog.String("badKey", ...) is the first of
	// the three evasions the census prototype was written against: it is not a bare literal at a
	// key position, so a rule reading only those walks past it.
	write("core/caught/keys.go", `package caught

import (
	"log/slog"
	"time"
)

func keys(err error, at time.Time) {
	slog.Info("a record", "clientId", 1)
	slog.Info("a record", "request-id", "x")
	slog.Info("a record", "err", err)
	slog.Info("a record", "request_id", "x")
	slog.Info("a record", "_leading", 1)
	slog.Info("a record", "9lives", 1)
	slog.Info("a record", "", 1)
	slog.Info("a record", slog.String("badKey", "x"))
	slog.Info("a record", slog.Int("userId", 1), slog.Bool("isNew", true))
	slog.Info("a record", slog.Duration("tookLong", 0), slog.Time("startedAt", at))
	slog.Info("a record", slog.Any("theThing", nil), slog.Float64("theRate", 1))
	slog.Info("a record", slog.Int64("bigId", 1), slog.Uint64("hugeId", 1))
	slog.Info("a record", slog.Group("theGroup", "innerKey", 1))
}

func attrLiteral() slog.Attr {
	return slog.Attr{Key: "notSnake", Value: slog.StringValue("x")}
}
`)

	// A helper with no emission in the file at all: the keys it builds reach a record somewhere
	// else, so the scan is over the whole file rather than under an emission call.
	write("core/caught/keys_helper.go", `package caught

import "log/slog"

func buildAttrs() []slog.Attr {
	return []slog.Attr{slog.String("sessionIdentifier", "x")}
}
`)

	// The vocabulary of decision 3, and the documented ceiling: an elided composite literal has
	// no type to resolve, so its key is not read. Keep this row -- it is the boundary, not an
	// oversight, and removing it would make a later reader think the lint covers the shape.
	write("core/passed/keys.go", `package passed

import "log/slog"

func keys() {
	slog.Info("a record", "client_identifier", "x", "user_id", 1, "x1", true)
	slog.Info("a record", slog.String("session_identifier", "x"), slog.Group("db", "name", "goiabada"))
}

func elidedAttr() []slog.Attr {
	return []slog.Attr{{Key: "notSnake", Value: slog.StringValue("x")}}
}
`)

	// request_id is the key no call site writes, and core/logging is the one package that does,
	// because it is the handler that injects it. Both halves are rows: the refusal is
	// core/caught/keys.go above, the exemption is here.
	write("core/logging/inject.go", `package logging

import "log/slog"

func inject(id string) slog.Attr { return slog.String("request_id", id) }
`)

	// ---- rule 4: a *Context variant wherever a context is in scope ----------------------------

	// The parameter may be on the immediate function, on a method, or on any function enclosing
	// the call. The closure row is the second evasion: the literal itself takes neither
	// parameter, so a rule reading the immediate signature reports nothing.
	write("core/caught/context_variants.go", `package caught

import (
	"context"
	"log/slog"
	"net/http"
)

func withContext(ctx context.Context) { slog.Info("a record") }

func withRequest(r *http.Request) { slog.Warn("a record") }

type handler struct{}

func (h handler) serve(r *http.Request) { slog.Error("a record") }

func nestedClosure(r *http.Request) func() {
	return func() { slog.Debug("a record") }
}

func handlerFunc() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) { slog.Info("a record") }
}
`)

	// Resolution is by import path, so all three packages are seen under an alias. A rule reading
	// the text "context.Context" or "slog." reports nothing here.
	write("core/caught/context_aliased.go", `package caught

import (
	gocontext "context"
	slogpkg "log/slog"
	nethttp "net/http"
)

func aliasedContext(ctx gocontext.Context) { slogpkg.Info("a record") }

func aliasedRequest(r *nethttp.Request) { slogpkg.Warn("a record") }
`)

	// The *Context forms, the two that carry a context by construction, a startup line with
	// neither parameter, and the near miss: http.ResponseWriter is not *http.Request, so this row
	// differs from the caught handlerFunc row in exactly one parameter.
	write("core/passed/context_variants.go", `package passed

import (
	"context"
	"log/slog"
	"net/http"
)

func withContext(ctx context.Context) { slog.InfoContext(ctx, "a record") }

func withRequest(r *http.Request) { slog.WarnContext(r.Context(), "a record") }

func logAttrs(ctx context.Context) {
	slog.Log(ctx, slog.LevelInfo, "a record")
	slog.LogAttrs(ctx, slog.LevelWarn, "a record")
}

func atStartup() { slog.Info("auth server started") }

func writerOnly(w http.ResponseWriter) { slog.Info("a record") }
`)

	// ---- rule 5: only the handler's own files install one --------------------------------------

	write("core/caught/handler_install.go", `package caught

import "log/slog"

func install(h slog.Handler) {
	slog.SetDefault(slog.New(h))
}

func logger() *slog.Logger { return slog.Default() }

func with() *slog.Logger { return slog.With("key", "value") }

func asValue() func(*slog.Logger) { return slog.SetDefault }
`)

	// The allowlist is by path, not by package: core/testutil/slog_capture.go installs the
	// servers' own handler over a recorder (decision 11), and admitting the package rather than
	// the file would let any other file in it install one unnoticed.
	write("core/testutil/another_install.go", `package testutil

import "log/slog"

func install(h slog.Handler) { slog.SetDefault(slog.New(h)) }
`)

	// The five admitted paths: the package that owns the handler, the two mains, schemadump, and
	// the capture helper.
	write("core/logging/install.go", `package logging

import "log/slog"

func Install(h slog.Handler) { slog.SetDefault(slog.New(h)) }
`)
	write("core/cmd/schemadump/main.go", `package main

import "log/slog"

func main() { slog.SetDefault(slog.New(nil)) }
`)
	write("authserver/cmd/goiabada-authserver/main.go", `package main

import "log/slog"

func main() { slog.SetDefault(slog.New(nil)) }
`)
	write("adminconsole/cmd/goiabada-adminconsole/main.go", `package main

import "log/slog"

func main() { slog.SetDefault(slog.New(nil)) }
`)
	write("core/testutil/slog_capture.go", `package testutil

import "log/slog"

func CaptureSlog(h slog.Handler) *slog.Logger {
	previous := slog.Default()
	slog.SetDefault(slog.New(h))
	return previous
}
`)

	// ---- rule 6: the wrappers that carry a caller's attributes ---------------------------------

	// The keys a forwarder's caller writes, read at the call site because that is the only place
	// they exist. All three forms: the unexported wrapper called bare inside its own package, and
	// the two exported ones called through the import. This is the shape that kept 179 camelCase
	// keys through a sweep that visited every slog call in the tree, with all three tier callers
	// green, because the final emission sees only record... and has no key to read.
	write("authserver/internal/handlers/apihandlers/forwarded_keys.go", `package apihandlers

import (
	"net/http"

	"github.com/leodip/goiabada/authserver/internal/apiresponse"
)

func bare(w http.ResponseWriter, r *http.Request, err error) {
	writeInternalServerError(w, r, err, "clientId", 1, "group_id", 2)
}

func qualified(w http.ResponseWriter, r *http.Request, err error) {
	apiresponse.WriteInternalServerError(w, r, err, "userId", 3)
}

func logOnly(r *http.Request, err error) {
	apiresponse.LogInternalServerError(r, err, "permissionId", 4)
}
`)

	// A slice built and then spread is the one attribute shape that is neither an argument at a
	// call site nor a slog.Attr, and the tree has exactly one: the web-origins failure. Both
	// halves are read, the composite literal and the append onto it.
	write("authserver/internal/handlers/apihandlers/forwarded_slice.go", `package apihandlers

import "net/http"

func slice(w http.ResponseWriter, r *http.Request, err error) {
	attrs := []any{"clientId", 1}
	if r != nil {
		attrs = append(attrs, "originHeader", "x")
	}
	writeInternalServerError(w, r, err, attrs...)
}
`)

	// A closure is a forwarder too, and its scope is the file, because that is as far as its
	// name reaches. reject is listed, so rule 6 is silent here and rule 3 reads its call site.
	write("authserver/internal/handlers/handler_account_logout.go", `package handlers

import (
	"log/slog"
	"net/http"
)

func classify(r *http.Request) {
	reject := func(gate string, args ...any) {
		record := []any{"gate", gate}
		record = append(record, args...)
		slog.WarnContext(r.Context(), "id_token_hint rejected", record...)
	}
	reject("aud", "badReason", "x")
}
`)

	// An unlisted forwarder is the finding itself. Nothing about it looks wrong at the emission,
	// and its callers' keys are unread until someone adds it to the table, so the refusal is
	// what keeps rule 3 closed rather than true of the four wrappers that happened to exist.
	write("core/caught/forwarder_unlisted.go", `package caught

import "log/slog"

func logWithAttrs(attrs ...any) {
	slog.Info("a thing happened", attrs...)
}
`)

	// One bound to no name at all, which could never be listed: refused where it is written.
	write("core/caught/forwarder_anonymous.go", `package caught

import "log/slog"

func run(emit func(...any)) { emit("k", 1) }

func caller() {
	run(func(attrs ...any) { slog.Info("inline", attrs...) })
}
`)

	// The near misses, and they are what stops rule 6 being "any variadic any". A run handed to
	// fmt or to a SQL driver reaches no record, and every other variadic ...any in this tree is
	// one of those two.
	write("core/passed/variadic_fmt.go", `package passed

import "fmt"

func outf(format string, a ...any) { fmt.Printf(format, a...) }
`)
	write("core/passed/variadic_sql.go", `package passed

import "database/sql"

func exec(db *sql.DB, query string, args ...any) error {
	_, err := db.Exec(query, args...)
	return err
}
`)

	// The scope half: the same identifier outside the directory where it names the forwarder is
	// a different function, and reading its arguments as attributes would be a textual match
	// wearing this rule's error message.
	write("core/passed/same_name_elsewhere.go", `package passed

func writeInternalServerError(status int, fields ...string) {}

func useIt() { writeInternalServerError(500, "clientId", "x") }
`)

	// And a []any that is spread into nothing is not an attribute run, whatever it is called.
	write("core/passed/slice_not_attrs.go", `package passed

func queryArgs() []any {
	attrs := []any{"clientId", 1}
	return attrs
}
`)

	// ---- rule 6, the two boundaries it closes by refusal ---------------------------------------

	// How the callee resolves. A dot import leaves the forwarder call with no selector, so the
	// keys on the line below it are read by nothing; the import is the finding, exactly as it is
	// for log/slog, and the camelCase key it hides needs no row of its own.
	write("core/caught/forwarder_dot_import.go", `package caught

import (
	"net/http"

	. "github.com/leodip/goiabada/authserver/internal/apiresponse"
)

func dotForwarder(w http.ResponseWriter, r *http.Request, err error) {
	WriteInternalServerError(w, r, err, "clientId", 1)
}
`)

	// The same function one indirection out. Whatever calls the value writes its keys against a
	// local name, and rule 6 resolves a call by import path or by scope, so neither finds it.
	// Both spellings, because a forwarder is reached qualified from outside its package and bare
	// from inside the scope it is listed under.
	write("authserver/internal/handlers/apihandlers/forwarder_value.go", `package apihandlers

import (
	"net/http"

	"github.com/leodip/goiabada/authserver/internal/apiresponse"
)

func qualifiedValue() func(http.ResponseWriter, *http.Request, error, ...any) {
	return apiresponse.WriteInternalServerError
}

func bareValue() func(http.ResponseWriter, *http.Request, error, ...any) {
	return writeInternalServerError
}
`)

	// How the run is built. The two readable declarations that are not the := composite the tree
	// happens to use: a var with a value, whose keys are read, and an append whose base is the
	// composite rather than the run, whose keys are read too. Both used to be silent.
	write("core/caught/run_var_decl.go", `package caught

import "log/slog"

func varDeclaredRun() {
	var attrs = []any{"clientId", 1}
	slog.Info("a thing happened", attrs...)
}
`)
	write("core/caught/run_append_base.go", `package caught

import "log/slog"

func appendBaseRun() {
	attrs := append([]any{"clientId", 1}, "group_id", 2)
	slog.Info("a thing happened", attrs...)
}
`)

	// And the four this rule refuses rather than reads, each reported where the run reaches the
	// record. An alias and a builder's return put the keys in an expression the walk has not
	// followed; a spread of a slice that is not the enclosing variadic parameter carries a run
	// from anywhere at all; and a closure writing to the run is seen by neither reading, since
	// this one does not descend into the closure and the closure has no spread site in view.
	write("core/caught/run_alias.go", `package caught

import "log/slog"

func aliasedRun() {
	attrs := []any{"clientId", 1}
	other := attrs
	slog.Info("a thing happened", other...)
}
`)
	write("core/caught/run_builder.go", `package caught

import "log/slog"

func builtElsewhere() []any { return []any{"clientId", 1} }

func builderRun() {
	attrs := builtElsewhere()
	slog.Info("a thing happened", attrs...)
}
`)
	write("core/caught/run_foreign_spread.go", `package caught

import "log/slog"

func foreignSpreadRun(extra []any) {
	attrs := []any{"client_id", 1}
	attrs = append(attrs, extra...)
	slog.Info("a thing happened", attrs...)
}
`)
	write("core/caught/run_closure_write.go", `package caught

import "log/slog"

func closureWrittenRun() {
	attrs := []any{"client_id", 1}
	add := func() { attrs = append(attrs, "groupId", 2) }
	add()
	slog.Info("a thing happened", attrs...)
}
`)

	// A run that is not a name at all: nothing to collect assignments for, so the expression is
	// the finding.
	write("core/caught/run_expression.go", `package caught

import "log/slog"

func expressionRun() {
	slog.Info("a thing happened", attrsFromNowhere()...)
}

func attrsFromNowhere() []any { return []any{"clientId", 1} }
`)

	// The shapes the tree actually uses, which the refusals above must leave alone: the 500
	// writer's and the request logger's make-then-append, and a var declared empty and appended
	// to. Each is a near miss of a caught row rather than an obviously innocent line.
	write("core/passed/run_make_appends.go", `package passed

import "log/slog"

func madeAndAppended() {
	attrs := make([]any, 0, 4)
	attrs = append(attrs, "client_id", 1)
	attrs = append(attrs, "group_id", 2)
	slog.Info("a thing happened", attrs...)
}
`)
	write("core/passed/run_var_empty.go", `package passed

import "log/slog"

func varDeclaredEmpty() {
	var attrs []any
	attrs = append(attrs, "client_id", 1)
	slog.Info("a thing happened", attrs...)
}
`)

	// ---- the evasions, and the parser boundary ------------------------------------------------

	// One pair of brackets, and the callee is no longer a bare selector. The third evasion.
	write("core/caught/paren_callee.go", `package caught

import "log/slog"

func parenCallee() { (slog.Info)("Capitalised") }
`)

	// An emission handed round as a value writes the same record one indirection later, with no
	// package selector left at the call that runs it. errors_lint.go refuses a constructor value
	// for the same reason.
	write("core/caught/emission_value.go", `package caught

import (
	"context"
	"log/slog"
)

func emissionValue() func(string, ...any) { return slog.Info }

func logAttrsValue() func(context.Context, slog.Level, string, ...slog.Attr) { return slog.LogAttrs }
`)

	// A dot import binds Info, SetDefault and String unqualified, so every rule above walks past
	// the file. The import is the finding; the capitalised message on the line after it needs no
	// separate row and gets none.
	write("core/caught/dot_import_slog.go", `package caught

import . "log/slog"

func dotInfo() { Info("Capitalised") }
`)

	// Named rather than shaped: a dot import of anything else hides no slog call, and refusing it
	// would be a style rule wearing this one's error message.
	write("core/passed/dot_import_other.go", `package passed

import . "github.com/leodip/goiabada/core/uuidutil"

func dotOther() string { return New() }
`)

	// ---- what is not production code ----------------------------------------------------------

	write("core/passed/mocks/logger_mock.go", `package mocks

import "log/slog"

func mocked() { slog.Info("Capitalised", "badKey", 1) }
`)
	write("core/passed/capture_test.go", `package passed

import "log/slog"

func inATest() { slog.SetDefault(slog.New(nil)) }
`)
	write("core/passed/build_not_production.go", `//go:build !production

package passed

import "log/slog"

func devOnly() { slog.Info("Capitalised") }
`)
	// A build constraint that can still be true in a production build is walked, which is the
	// direction that must never be the permissive one.
	write("core/caught/build_linux.go", `//go:build linux

package caught

import "log/slog"

func onLinux() { slog.Info("Capitalised") }
`)
	// A file that does not parse is a compile error the build tier owns.
	write("core/passed/unparseable.go", `package passed

func broken( {
`)

	violations, files, err := findSlogViolations(root, nil)
	require.NoError(t, err)
	assert.Equal(t, 46, files,
		"every parseable, production-reachable fixture outside a mocks directory and a _test.go file is parsed")
	assert.Equal(t, []string{
		`authserver/internal/handlers/apihandlers/forwarded_keys.go:10 attribute key "clientId"`,
		`authserver/internal/handlers/apihandlers/forwarded_keys.go:14 attribute key "userId"`,
		`authserver/internal/handlers/apihandlers/forwarded_keys.go:18 attribute key "permissionId"`,
		`authserver/internal/handlers/apihandlers/forwarded_slice.go:6 attribute key "clientId"`,
		`authserver/internal/handlers/apihandlers/forwarded_slice.go:8 attribute key "originHeader"`,
		`authserver/internal/handlers/apihandlers/forwarder_value.go:10 apiresponse.WriteInternalServerError as a value`,
		`authserver/internal/handlers/apihandlers/forwarder_value.go:14 writeInternalServerError as a value`,
		`authserver/internal/handlers/handler_account_logout.go:14 attribute key "badReason"`,
		`core/caught/build_linux.go:7 message "Capitalised" does not start with a lowercase letter`,
		`core/caught/context_aliased.go:9 slog.Info inside a function taking a context.Context or an *http.Request`,
		`core/caught/context_aliased.go:11 slog.Warn inside a function taking a context.Context or an *http.Request`,
		`core/caught/context_variants.go:9 slog.Info inside a function taking a context.Context or an *http.Request`,
		`core/caught/context_variants.go:11 slog.Warn inside a function taking a context.Context or an *http.Request`,
		`core/caught/context_variants.go:15 slog.Error inside a function taking a context.Context or an *http.Request`,
		`core/caught/context_variants.go:18 slog.Debug inside a function taking a context.Context or an *http.Request`,
		`core/caught/context_variants.go:22 slog.Info inside a function taking a context.Context or an *http.Request`,
		`core/caught/dot_import_slog.go:3 dot import of "log/slog"`,
		`core/caught/emission_value.go:8 slog.Info as a value`,
		`core/caught/emission_value.go:10 slog.LogAttrs as a value`,
		`core/caught/forwarder_anonymous.go:8 an unnamed function literal forwards a variadic ...any into a record`,
		`core/caught/forwarder_dot_import.go:6 dot import of "github.com/leodip/goiabada/authserver/internal/apiresponse"`,
		`core/caught/forwarder_unlisted.go:5 logWithAttrs forwards a variadic ...any into a record`,
		`core/caught/handler_install.go:6 slog.New`,
		`core/caught/handler_install.go:6 slog.SetDefault`,
		`core/caught/handler_install.go:9 slog.Default`,
		`core/caught/handler_install.go:11 slog.With`,
		`core/caught/handler_install.go:13 slog.SetDefault as a value`,
		`core/caught/keys.go:9 attribute key "clientId"`,
		`core/caught/keys.go:10 attribute key "request-id"`,
		`core/caught/keys.go:11 attribute key "err"`,
		`core/caught/keys.go:12 attribute key "request_id"`,
		`core/caught/keys.go:13 attribute key "_leading"`,
		`core/caught/keys.go:14 attribute key "9lives"`,
		`core/caught/keys.go:15 attribute key ""`,
		`core/caught/keys.go:16 slog.String key "badKey"`,
		`core/caught/keys.go:17 slog.Bool key "isNew"`,
		`core/caught/keys.go:17 slog.Int key "userId"`,
		`core/caught/keys.go:18 slog.Duration key "tookLong"`,
		`core/caught/keys.go:18 slog.Time key "startedAt"`,
		`core/caught/keys.go:19 slog.Any key "theThing"`,
		`core/caught/keys.go:19 slog.Float64 key "theRate"`,
		`core/caught/keys.go:20 slog.Int64 key "bigId"`,
		`core/caught/keys.go:20 slog.Uint64 key "hugeId"`,
		`core/caught/keys.go:21 attribute key "innerKey"`,
		`core/caught/keys.go:21 slog.Group key "theGroup"`,
		`core/caught/keys.go:25 slog.Attr key "notSnake"`,
		`core/caught/keys_helper.go:6 slog.String key "sessionIdentifier"`,
		`core/caught/message_concat.go:5 message is not a string literal`,
		`core/caught/message_err_error.go:5 message is not a string literal`,
		`core/caught/message_every_shape.go:9 message is not a string literal`,
		`core/caught/message_every_shape.go:10 message is not a string literal`,
		`core/caught/message_every_shape.go:11 message is not a string literal`,
		`core/caught/message_sprintf.go:8 message is not a string literal`,
		`core/caught/message_text.go:6 message "Starting the server" does not start with a lowercase letter`,
		`core/caught/message_text.go:7 message "" does not start with a lowercase letter`,
		`core/caught/message_text.go:8 message " leading space" does not start with a lowercase letter`,
		`core/caught/message_text.go:9 message "2 factor enrolled" does not start with a lowercase letter`,
		`core/caught/message_text.go:10 message "-- a banner --" does not start with a lowercase letter`,
		`core/caught/message_text.go:11 message "logout: id token hint rejected" starts with a component prefix`,
		`core/caught/message_text.go:12 message "2: step two" does not start with a lowercase letter`,
		`core/caught/message_text.go:13 message "ünicode: a prefix is not ascii-only" starts with a component prefix`,
		`core/caught/message_text.go:14 message "failed to reach the database" starts with "failed to"`,
		`core/caught/message_text.go:15 message "error while reaching the database" starts with "error "`,
		`core/caught/message_variable.go:5 message is not a string literal`,
		`core/caught/paren_callee.go:5 message "Capitalised" does not start with a lowercase letter`,
		`core/caught/run_alias.go:8 attribute run "other" is built in a form this rule cannot read`,
		`core/caught/run_append_base.go:6 attribute key "clientId"`,
		`core/caught/run_builder.go:9 attribute run "attrs" is built in a form this rule cannot read`,
		`core/caught/run_closure_write.go:9 attribute run "attrs" is built in a form this rule cannot read`,
		`core/caught/run_expression.go:6 attribute run spread into a record is not a named slice`,
		`core/caught/run_foreign_spread.go:8 attribute run "attrs" is built in a form this rule cannot read`,
		`core/caught/run_var_decl.go:6 attribute key "clientId"`,
		`core/testutil/another_install.go:5 slog.New`,
		`core/testutil/another_install.go:5 slog.SetDefault`,
	}, describeSlog(violations))

	// The per-module scoping the sweep stages leaned on: the same rule, one subtree at a time.
	// Ten of core/passed's fourteen fixtures are parsed: the mocks file, the test file and the
	// !production file are exempt, and the unparseable one is not counted.
	scoped, scopedFiles, err := findSlogViolations(root, []string{"core/passed"})
	require.NoError(t, err)
	assert.Equal(t, 10, scopedFiles)
	assert.Empty(t, describeSlog(scoped), "the caught subtree is outside the named directory")
}

// TestSlogConvention_TheTreeItself is the real half, and it is unscoped: every module has moved,
// so the whole source root is held, cmd/goiabada-setup and any module added later included. This
// is the measurement of goal 3 of #320, and it is stronger than the census prototype it grew from
// because it resolves the name written at each call site through the file's own imports.
func TestSlogConvention_TheTreeItself(t *testing.T) {
	AssertSlogConvention(t)
}

// describeSlog renders findings as "file:line what", which is what a reader compares. The fix
// text is guidance and would make this table churn every time the wording improved.
func describeSlog(violations []slogViolation) []string {
	if len(violations) == 0 {
		return nil
	}
	out := make([]string, 0, len(violations))
	for _, v := range violations {
		out = append(out, v.file+":"+strconv.Itoa(v.line)+" "+v.what)
	}
	return out
}
