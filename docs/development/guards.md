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
recorded `Fatalf` ends it in `runtime.Goexit` the way the real one does. What a guard holds, and
why, is written in the comment above its `Assert*` function or its test, and the sections below
describe the few that need more.
`git grep -n -E 'func assert[[:alnum:]]*\((r (guard\.)?Reporter|$)' -- '*.go'` lists them, a
declaration whose parameters wrap onto the next line by its opening line; no roster or count is
kept here, because the one that was kept drifted each time a guard was added (#442).

Each guard owes three cases: a tree that must fail, a tree that must pass, and the walk that
reached nothing. A guard whose premise is a reading of a dependency's behavior owes a fourth: a test
that measures that dependency against itself, as `AssertNotCalledArity`'s measures testify's
matching against testify, because such a guard stops meaning anything the moment the dependency
changes and nothing says so (#421). Without the last two the first proves nothing, and without the
reporting half under test a defect in the five lines that report disables the guard across every
module with nothing going red -- which is what blinding `AssertNoDeadInterfaces` demonstrated on
`8883642d` (#333).

A guard that must know which object a name refers to reads the tree through `core/pkgload`, which
returns a module's type-checked packages, and does not load types its own way. Where a file it
missed would pass silently, it reads production code as every one of `pkgload.ReleaseBuilds`
selects it. The context-value, discarded-error and request-field guards also read the test
machine's default build and merge what they find; the ownership census reads its test references
from the test machine's test build. Any other guard on the loader reads only the test machine's
test build. A package that does not load or type-check stops it with one message naming the
package, so every fixture tree compiles, made loadable with `pkgload.MakeLoadable`. So does a
package that imports one of its own module's packages that `./...` skips, in a directory whose name
begins with `_` or `.` or is `testdata`, which the build compiles and no guard would read; the
dead-interface and vacuous-assertion guards also refuse a directory beginning with `_` or `.` among
those they walk. A guard that reads only syntax, such as an import list, parses with `go/parser`
rather than matching text: an alias binds a different name to the same path.

Before writing a guard, look for a `golangci-lint` check that already holds the rule, as #443 did
when it turned on staticcheck's ST1000 for package comments; `.golangci.yml` lists what is enabled
and why. A new guard has a threshold of 250 lines of its own code, the finder and the reporting
half, not counting its rule tests; `credential_read_lint.go`, one rule in one file, is the model.
The threshold is a question, not a ban: a guard over it says in its pull request why no existing
linter check can hold the rule, why the rule cannot be narrower, and why the code it polices should
not change instead (#420).

## Guards that read code or configuration

A guard that works out what code or a workflow does, such as a route's middleware chain or the
images a job pulls, reads the forms the repository writes and reports any other form as one it
cannot read, naming the form to write instead. It is not taught a form the tree does not contain,
nor made to work in a build environment or with a fixture input the repository does not use, such
as `GOPACKAGESDRIVER`, a Windows test host, or a `go.mod` shape no fixture writes. A
guard that learns one more form of Go or of the Actions syntax with each review never finishes,
while one that refuses what it cannot read cannot pass what it misread. #261's OpenAPI status lint
grew by about 2,450 lines over four passes of review comments, each on a form `routes.go` never
writes, and none of them changed what it said about the real route table; #867's workflow guards
went the same way. A Go guard that follows names (variables, receivers, fields, calls) type-checks
the package and reads `types.Info.Uses` and `Defs`, as the auth server's discarded-error lint in
`internal/server` does, and never matches a name by its spelling, so shadowing, block scope and
import aliases need no code of their own. A workflow guard reads the file as YAML through
`readWorkflowJobs` in `core/guard`, never by matching lines.

## Styling contract guard

The auth server and admin console unit tiers each run `TestTemplates_KeepTheStylingContract`,
holding their templates to `core/stylingcontract`'s lists for that server through
`core/guard.AssertStylingContract` (#816). Every page template the caller does not name as outside
the contract (the console's `admin_*.html` and `settings_unavailable.html`) defines a
`data-page` template holding one listed value, which no other page names, and its `<body>`, read as
served in each layout a handler renders it in, writes `data-page`. Every listed value has a page,
every hook class promised on the server is drawn by some page in the contract as served, in any
branch, a class only an admin page or an uncalled partial draws counting for nothing, and the
served `main.css` declares every listed variable. Pages are composed and walked as
`AssertWellFormedTemplates` composes them. Its rule tests cover a tree breaking each rule, one
keeping them all, and the walks that reach nothing.

## gofmt guard

Every module's unit tier runs `TestGoSourcesAreGofmted`, which holds every Go file under `src/` to
gofmt's formatting through `core/guard.AssertGofmted`. The walk is repository-wide from each tier
because `cmd/goiabada-setup`'s own tier calls none of the tree-wide guards. CI's Lint job checks the
same thing per module, where an unformatted file also costs that module its vet, unparam and
golangci-lint run.

## Architecture guard

`ARCHITECTURE.md` at the repository root records the allowed module edges, the intended final owner
of every top-level `core` package, the temporary exceptions to those rules, the third-party modules
the admin console must not compile, and the packages no shipped binary may link. Its four tables are
data, not prose: `AssertArchitecture` in `core/guard/architecture.go` parses them and checks them
against the real import graph; all three module unit tiers call it. The check runs in both
directions, which is what makes the document a burn-down list rather than a wish — an edge the
tables do not allow is a failure, and so is an exception left standing for an edge that no longer
exists, so the issue that removes an edge has to remove its row with it (#332). A new top-level
`core` package fails the tier until the table says where it belongs. A fifth table lives in
`src/core/OWNERSHIP.md`, one row per exported symbol any `core` package declares, `core/builtin`'s
among them: `core/guard.AssertSymbolOwnership` reads it from the same three tiers, four
justifications are computed from the reference graph and three are asserted with a note the guard
requires (#385). Rule 8 walks the production closure of the three shipped mains, the auth server,
the admin console and the setup wizard, and refuses `testing` and everything under it,
`net/http/httptest` and every testify package, so a production import of a test helper or mock fails the unit tier rather than
reaching a release, `net/http/pprof` and `expvar`, which register the process's profiles and
variables on Go's default mux the moment they are linked (#462), and `golang.org/x/tools`, the
package loading `core/pkgload` reads the tree through, so the loader stays developer tooling (#420);
the three mains are `shippedMains`
in `architecture.go`, and the guard fails when one is not found (#331). It reads each main with the
`production` tag set because all three release builds set it, the setup wizard's since #463, and
`TestReleaseBuilds_TheRealReleaseBuildsSetProduction` in core's tier holds them to it: every `go
build` in the servers' cross-compile script, the two server Dockerfiles and the wizard's
cross-compile script sets `production`, the mains they build are exactly `shippedMains`, and both
scripts' `build_platform` calls equal `pkgload.ReleasePlatforms` as a set (#463). Beside it,
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
census behind #333 first read `TCPConnectionTester` as live, and a name a dot import brings in
counts like any other — and structural satisfaction does not count at all, since an interface no
code names is what dead means here (#333). The module is read through `core/pkgload` as the test
machine's test build, so a reference the walk misses shows up as a false finding rather than a
silent pass, and a package that does not type-check stops the guard (#420).

## Vacuous-assertion guard

All three module unit tiers run `TestNotCalledArity` over the whole source root, holding every
testify `AssertNotCalled` to carrying one matcher per parameter of the method it names, through
`core/guard.AssertNotCalledArity`. testify matches a recorded call on the method name *and* the
whole argument list, so `AssertNotCalled(t, "Log")` against a three-parameter `Log` compares lists
that can never be equal and passes whatever the subject did; the compiler sees a variadic call and
says nothing. Forty-one such sites shipped, one of them false since #241. A site is a call of
testify's own method, so a method of that name on a type that is not a testify double is not one,
and the receiver is resolved by type rather than by spelling, because one method name can sit on
two doubles at two arities (`CreateUser` is 3 on `Database` and 2 on `UserCreator`). Each walked
module is read through `core/pkgload` as the test machine's test build, and the rule tests'
fixtures require the testify version `core` pins. Five shapes are reported rather than skipped: a
method named through anything but a string literal, a name the double does not declare, a variadic
method, matchers spread from a slice with `...`, whose number the call does not show, and a call on
a `Mock` field, `d.Mock.AssertNotCalled`, rather than on the double. It does not widen to
`AssertCalled`, whose arity mismatch fails loudly, or to `.On(...)`, where a stub matching nothing
panics (#421).

## Core symbol ownership table

`src/core/OWNERSHIP.md` has one row per exported symbol every `core` package declares, so adding or
moving one has one more step: `cd src/core && go run ./cmd/ownershipdump`, and commit it. It refuses
to invent a justification, so the answer is to move the symbol or to write `test-support`,
`contract` or `moving` with the reason. The lint tier runs it and fails on a tree it changed.

The census reads the tree through `core/pkgload`, type-checked, and a reference is the object an
identifier resolves to, whatever the file spells: a dot import counts, and a local spelled like a
symbol does not. Production references, and the packages a binary links from every production
`main`, are read as each release build selects them, so a file only one platform compiles still
counts. A production reference contradicts a `test-support` row only where a binary of the same
build links its package. Test references come from the test machine's test build. A package that
does not type-check stops the guard and `ownershipdump` with one message naming it. Every fixture
tree of the census therefore compiles, and its helper makes the tree loadable with
`pkgload.MakeLoadable`.

## Generated mocks

The `*_mock.go` files are written by mockery, at the version `versions.yaml` pins as
`tools.mockery`, and committed. Regenerate with `src/authserver/generate-mocks.sh` inside the dev
container, which refuses to run on any other version rather than stamp one that did not produce the
output. Each generated file opens with `src/mockery-header.txt`, inlined by
`template-data.boilerplate-file` in the three `.mockery.yaml` files (core, authserver and
adminconsole) and written from the pin by `./version-manager.sh update`, so a clone reads which
generator wrote the tree instead of having to install one to find out. That is checked in both
halves, because they catch different things: every module's unit tier runs
`TestGeneratedMocksArePinned`, which holds the pin, the header and every generated file to each
other through `core/guard.AssertGeneratedMocksArePinned` and needs no generator; the lint tier and
CI's Lint job run the generator itself and fail on a tree it changed, which is the only thing that
catches an interface newly named in a config. Keying on mockery's own
`Code generated ... DO NOT EDIT` marker rather than on the filename is what leaves the countries and
timezones tables, which have generators of their own, out of it (#338).

## Lint tier

`./run-tests.sh --type lint` runs golangci-lint and `unparam -exported` over the four modules with
the commands CI's Lint job uses, then regenerates the Tailwind CSS, the mocks and the core ownership
table and fails if any differs from what is committed, and runs `check-openapi-client.sh`, which
generates a Go client from `web/openapi.yaml` with oapi-codegen at its `versions.yaml` pin, with
`response-type-suffix: Result`, and fails unless it builds and vets; `all` includes it. It fails rather than skips
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
only CI could see the finding (#385). The client check is here and in CI's Lint job, through the one
script, because every other check on the document compares it with this repository's source, and
oapi-codegen's default settings generated a client from it that failed on 57 name collisions with
nothing to say so (#261).

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
