# Guard development

Add or change a repository guard and test both its finder and reporting behavior.

Paths in backticks are relative to the repository root unless a module directory is named. Read the
sections relevant to the change; [AGENTS.md](../../AGENTS.md) lists the common commands.

## Guard shape

Every tree-wide guard splits in two, and a new one is written the same way. A *finder* walks the
tree and returns findings; a *reporting half* turns them into `Errorf` and turns a walk that reached
nothing into `Fatalf`. The reporting half takes a `guard.Reporter` -- `Helper`, `Errorf`, `Fatalf`,
the measured surface of `*testing.T`, and an interface rather than a `testing.TB` parameter because
`testing.TB` cannot be implemented outside the testing package. The exported `Assert*` keeps its
`*testing.T` and delegates, so no caller moves. Both halves are then driven from a rule test: the
finder directly, the reporting half through `guard.Run`, which runs it on its own goroutine so a
recorded `Fatalf` ends it in `runtime.Goexit` the way the real one does. Every guard follows this:
those in `core/guard`, the newest `AssertNoLiteralStackSecrets`, which refuses a data key or
database password supplied by literal in any runnable file -- workflows, Compose and other YAML,
devcontainer and editor configurations, Dockerfiles, Makefiles, env files (`.env` and `.env.*` among
them, unless git tracks no copy of it and the repository's `.gitignore` files, its own directory's
or a parent's, read as git reads them, keep it out of the repository), shell scripts, Go mains and
Markdown code blocks -- and the published sample key and passwords anywhere outside the refusal and
its tests (#501), and before it `AssertNoStaleDeferredBodyCloses`, which refuses a deferred
func-literal close of a response body reading a variable the same function reassigns after the defer
is registered, in a later statement, a nested closure or the next iteration of a loop, so only the
last response is closed (#591), and before it `AssertNoGuardInTestsReachedFrom`, which refuses a
test importing `core/guard`, directly or through first-party production code, in any package a
module reaches, called over the setup wizard because `go mod tidy` reads those tests and would put
TOML in its `go.sum` (#500), and before it `AssertImportsOnly`, which holds one package's production
files to importing the standard library and an allowlist its caller names, which #387 wrote as
`record`'s own lint, holding that package to `core/builtin` and `core/errs`, before #500 moved it
here when `core/adminpassword` became the second package held to one, to `core/errs` alone, so the
setup wizard links nothing more to reach the admin password rule, and before it
`AssertNoParentImport`, which holds each child handler package a caller names to naming no import of
its parent, which the auth server calls over `apihandlers` and `accounthandlers` and the admin
console over its six, and which #387 wrote as that server's own lint before #440 moved it here for
both applications, and before it `AssertContextValuesThroughAccessors`, which refuses a
`context.WithValue` or a context `Value` read in a production file outside the module's accessor
package, resolved with `go/types`, and which each application calls with its own `internal/reqctx`
and no exemption, the admin console's last, `internal/handlertest`'s write of chi's route context,
gone once it set path values with `r.SetPathValue` (#433, #440, #462), and
`AssertNoAgreementPointers`, which refuses a comment pointing at an issue's agreement or a probe
file instead of stating the fact with its issue number (#428), plus `authserver/internal/data`'s
begin-transaction, benign-sentinel, page-offset, id-list-bound, transaction-pass-through and
SQL-context lints, the auth server's API error-code and audit-catalog lints, its discarded-error
lint in `internal/server`, which refuses `_` in the error position of a hash, encryption or
key-generation call (#409) and resolves the data cipher's methods by receiver type with `go/types`
(#434), its admin-route classification lint beside it, which holds every admin write route, and
every admin read whose handler applies a ceiling of the administrative policy, to a row naming the
ceilings its handler applies or why it needs none, in both directions (#402), and its write-once
lint in `internal/ceremony`, which refuses a write to an `AuthContext` request field outside
`authflow.Authorization.Run`, resolved with `go/types` (#436). `AssertImportsOnly` and
`AssertNoParentImport` both parse imports with `go/parser` rather than matching text, because an
alias binds a different name to the same path and one of the 39 production files did exactly that.
`git grep -n 'func assert.*\(r Reporter\|r guard\.Reporter\)' -- '*.go'` lists them; no count is
kept here, because the one that was drifted each time a guard was added (#442). Each owes three
cases: a tree that must fail, a tree that must pass, and the walk that reached nothing. One of
`core/guard`'s, `AssertNotCalledArity`, owes a fourth: a test that measures testify's matching
against testify, because a guard whose premise is a reading of a dependency stops meaning anything
the moment that dependency changes and nothing says so (#421). Without the last two the first proves
nothing, and without the reporting half under test a defect in the five lines that report disables
the guard across every module with nothing going red -- which is what blinding
`AssertNoDeadInterfaces` demonstrated on `8883642d` (#333).

## gofmt guard

Every module's unit tier runs `TestGoSourcesAreGofmted`, which holds every Go file under `src/` to
gofmt's formatting through `core/guard.AssertGofmted`. The walk is repository-wide from each tier
because `cmd/goiabada-setup`'s own tier calls none of the tree-wide guards. CI's Lint job checks the
same thing per module, where an unformatted file also costs that module its vet, unparam and
golangci-lint run.

## Architecture guard

`ARCHITECTURE.md` at the repository root records the allowed module edges, the intended final owner
of every top-level `core` package, why each symbol in `core/builtin` is still there, the temporary
exceptions to those rules, the third-party modules the admin console must not compile, and the
packages no shipped binary may link. Its five tables are data, not prose: `AssertArchitecture` in
`core/guard/architecture.go` parses them and checks four against the real import graph and the
built-in identifiers table against every production reference to `core/builtin`; all three module
unit tiers call it. The check runs in both directions, which is what makes the document a burn-down
list rather than a wish — an edge the tables do not allow is a failure, and so is an exception left
standing for an edge that no longer exists, so the issue that removes an edge has to remove its row
with it (#332). A new top-level `core` package fails the tier until the table says where it belongs,
and so does a new symbol in `core/builtin`, whose row has to name the strongest of `kernel`,
`both-apps`, `moving` and `contract` that the reference graph backs (#351). A sixth table lives in
`src/core/OWNERSHIP.md`, one row per exported symbol any `core` package declares:
`core/guard.AssertSymbolOwnership` reads it from the same three tiers, four justifications are
computed from the reference graph and three are asserted with a note the guard requires (#385). Rule
9 walks the production closure of the three shipped mains, the auth server, the admin console and
the setup wizard, and refuses `testing` and everything under it, `net/http/httptest` and every
testify package, so a production import of a test helper or mock fails the unit tier rather than
reaching a release, and `net/http/pprof` and `expvar`, which register the process's profiles and
variables on Go's default mux the moment they are linked (#462); the three mains are `shippedMains`
in `architecture.go`, and the guard fails when one is not found (#331). It reads each main with the
`production` tag set because all three release builds set it, the setup wizard's since #463, and
`TestReleaseBuilds_TheRealReleaseBuildsSetProduction` in core's tier holds them to it: every `go
build` in the servers' cross-compile script, the two server Dockerfiles and the wizard's
cross-compile script sets `production`, the mains they build are exactly `shippedMains`, and both
scripts' `build_platform` calls equal `releaseTargets` as a set (#463). Beside it,
`TestReleaseBuilds_TheRealStampsNameVariables` holds every `-ldflags -X` target in the same four
files, the servers' script's `$LDFLAGS` read from its one assignment, to naming a package-level
string variable a production build declares, `main.` resolved against the main its `go build`
compiles: the linker ignores an `-X` that names nothing, so a path a move leaves behind would build
with exit 0 and ship binaries reporting `development` (#442).

## Dead-interface guard

The auth server and admin console unit tiers each run `TestHandlers_NoDeadInterfaces` over their own
`internal/handlers` package, holding every interface it declares to having at least one reference
somewhere in that module, production or test, through `core/guard.AssertNoDeadInterfaces`; the core
and setup tiers never execute it, because those two handler packages are the only call sites. The
walk is recursive, so the auth server's has always covered `apihandlers` and `accounthandlers` and
the ports #387 gave them, and its call names
`internal/{revocation,emaillinks,otpcredential,userclaims,userconsent,authorizerequest,bootstrap,authflow,recovery}`
beside it, because a package that declares a port nobody reaches is the same defect wherever it sits
(#387, #437, #580, #498). Liveness is `go/types` object identity and not a matching spelling — a
shadowed name and a same-named type in another package each count as nothing, which is how the
census behind #333 first read `TCPConnectionTester` as live — and structural satisfaction does not
count at all, since an interface no code names is what dead means here (#333).

## Vacuous-assertion guard

All three module unit tiers run `TestNotCalledArity` over the whole source root, holding every
testify `AssertNotCalled` to carrying one matcher per parameter of the method it names, through
`core/guard.AssertNotCalledArity`. testify matches a recorded call on the method name *and* the
whole argument list, so `AssertNotCalled(t, "Log")` against a three-parameter `Log` compares lists
that can never be equal and passes whatever the subject did; the compiler sees a variadic call and
says nothing. Forty-one such sites shipped, one of them false since #241. The receiver is resolved
with `go/types` rather than by spelling, because one method name can sit on two doubles at two
arities (`CreateUser` is 3 on `Database` and 2 on `UserCreator`), and four shapes are reported
rather than skipped: a method named through anything but a string literal, an unresolvable receiver,
a name the double does not declare, and a variadic method. It does not widen to `AssertCalled`,
whose arity mismatch fails loudly, or to `.On(...)`, where a stub matching nothing panics (#421).

## Core symbol ownership table

`src/core/OWNERSHIP.md` has one row per exported symbol every `core` package declares, so adding or
moving one has one more step: `cd src/core && go run ./cmd/ownershipdump`, and commit it. It refuses
to invent a justification, so the answer is to move the symbol or to write `test-support`,
`contract` or `moving` with the reason. The lint tier runs it and fails on a tree it changed.

## Generated mocks

The `*_mock.go` files are written by mockery, at the version `versions.yaml` pins as
`tools.mockery`, and committed. Regenerate with `src/authserver/generate-mocks.sh` inside the dev
container, which refuses to run on any other version rather than stamp one that did not produce the
output. Each generated file opens with `src/mockery-header.txt`, inlined by
`template-data.boilerplate-file` in the two `.mockery.yaml` files and written from the pin by
`./version-manager.sh update`, so a clone reads which generator wrote the tree instead of having to
install one to find out. That is checked in both halves, because they catch different things: every
module's unit tier runs `TestGeneratedMocksArePinned`, which holds the pin, the header and every
generated file to each other through `core/guard.AssertGeneratedMocksArePinned` and needs no
generator; the lint tier and CI's Lint job run the generator itself and fail on a tree it changed,
which is the only thing that catches an interface newly named in a config. Keying on mockery's own
`Code generated ... DO NOT EDIT` marker rather than on the filename is what leaves the countries and
timezones tables, which have generators of their own, out of it (#338).

## Lint tier

`./run-tests.sh --type lint` runs golangci-lint and `unparam -exported` over the four modules with
the commands CI's Lint job uses, then regenerates the Tailwind CSS, the mocks and the core ownership
table and fails if any differs from what is committed; `all` includes it. It fails rather than skips
when a binary is missing, and refuses `--race`. It is where `sloglint` holds most of the logging
convention in [Logging](conventions.md#logging), which is why it is a tier of the script and not
CI-only (#320), and where `gosec` holds shipping code to every rule, each false positive suppressed
inline with its reason, which `nolintlint` requires (#426), and where the rest of `.golangci.yml`'s
set holds the tree, each measured before it was enabled and listed with why in that file: among them
`testifylint`, under which an error assertion is `require`, never `assert`, and `errorlint`,
`rowserrcheck`, `sqlclosecheck` and `noctx`. The CSS and mock regeneration checks are here because
each was CI-only and nothing local could see it: a template class that never reached `main.css`
(#328) and sixteen mocks stale against their own pin (#338). `unparam` joined them for the same
reason: #385 moved an exported parse into the module whose two call sites discard its result, and
only CI could see the finding (#385).

## Agent instruction guard

`AssertAgentDocs` checks that `CLAUDE.md` matches the canonical `AGENTS.md`, the root stays within
10 KiB and 200 lines, its reference files exist, and the authentication guide remains linked. The
state table in [Authentication](authentication.md#auth-states-state-machine) must name exactly the
`AuthState*` constants in `src/authserver/internal/ceremony/auth_context.go`; variables are refused.
It checks membership, not transitions. The rule and reporting tests cover divergent copies, byte
and line limits, broken references, missing inputs and missing or stale states. This preserves
#252's roster check while preventing the root from growing beyond an agent's instruction-loading
budget.

Edit `AGENTS.md` and run `cp AGENTS.md CLAUDE.md` from the repository root. A checked copy
loads directly when Claude starts in a module: an ancestor file's import of a file outside the
working directory can require external-import approval, and a symlink needs extra Git setup on
Windows. This keeps one authored source while both tools receive all the instructions.
