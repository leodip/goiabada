# Architecture

This file records which module owns what, and it is executable. The five tables below —
[package ownership](#package-ownership), [built-in identifiers ownership](#built-in-identifiers-ownership),
[temporary exceptions](#temporary-exceptions),
[foreign modules](#foreign-modules-the-admin-console-must-not-compile) and
[test frameworks](#test-code-no-shipped-binary-may-link) — are parsed by
`AssertArchitecture` in `src/core/testutil/architecture.go`, which every module's unit tier calls.
A row that stops describing the tree fails the tier, in both directions: an edge the tables do not
allow is a finding, and so is an exception listed for an edge that no longer exists. A sixth table,
one row per exported symbol every `core` package declares, is data in the same sense and lives in
[`src/core/OWNERSHIP.md`](src/core/OWNERSHIP.md); rule 8 below is its rule, and
`AssertSymbolOwnership` reads it from the same three tiers.

That is the whole point of writing it down here rather than in prose. The dependency direction
between these three modules is not visible at a call site and is not a compile error until the day
it becomes a cycle, so it is the kind of rule that decays silently. This repository already learned
that lesson once about prose: `AssertAgentDocs` exists because the state machine documented in
`CLAUDE.md` had moved underneath the description while every test stayed green (#252).

The refactor that these rules were written for is the 16-issue Core Refactor epic, whose checklist
is [#332](https://github.com/leodip/goiabada/issues/332), and it is finished: #360 moved the last
authserver-only package out of `core`, so every `moves in` and `cleared by` cell reads `—` and the
exception table below has no rows. A cell naming an issue again is a debt taken on since.

## Module graph

Four Go modules live under `src/`:

| module | what it is |
|---|---|
| `core` | the shared kernel: contracts both processes compile |
| `authserver` | the OAuth2/OIDC provider process |
| `adminconsole` | the admin UI process, which is an OAuth *client* of the auth server |
| `cmd/goiabada-setup` | the standalone setup wizard |

`authserver`, `adminconsole` and `cmd/goiabada-setup` may import `core`. Nothing else is allowed:
`core` may not import any of the three, and `authserver` and `adminconsole` may not import each
other. The two processes talk over HTTP, never by linking each other's code, and the admin console
is an ordinary API client of the auth server — a consumer of its wire contract, not a peer with
access to its internals.

This much holds today with no exceptions. The rules below are the ones that do not.

## Definitions

The epic moves code on the strength of five distinctions, so they are written down before the table
that applies them.

- **Shared contract** — a type or function both processes compile, whose shape is fixed either by a
  specification outside this repository or by the HTTP boundary between the two processes. Stable
  by obligation rather than by habit: changing one is a change to something external. Belongs in
  `core`.
- **Application service** — behaviour implementing one process's policy: issuing a code, rotating a
  key, deciding a session is still valid, delivering mail. Belongs to that process even when its
  inputs and outputs look generic, because the policy is what makes it correct, and the policy is
  owned by exactly one process.
- **Adapter** — code binding a contract to one concrete technology or topology: a database engine,
  an SMTP server, an HTTP backend for a session store. Belongs to the process that owns the
  resource. An adapter is the usual way a heavy third-party dependency enters a binary.
- **Persistence model** — a struct whose field tags, null handling and scan behaviour describe a
  database row. It belongs with the database, and it is not a wire DTO even when it serializes to
  JSON that looks right.
- **Wire DTO** — a struct whose field tags describe JSON crossing the HTTP boundary between the two
  processes. Belongs in `core`, and must not embed a persistence model: doing so republishes the
  database's shape as the API's, so a column rename becomes a breaking API change (#350).

The test that decides `core` membership is not "is it reusable" but "do both processes consume it,
or is it an intentionally stable cross-process contract". Reusability is a property of almost any
well-written package and is the reason `core` grew into a second application.

The same question asked one grain finer — why does `core` declare *this symbol* — has a row per
exported symbol in [`src/core/OWNERSHIP.md`](src/core/OWNERSHIP.md), which is rule 8 below. It lives
there rather than here because it is some four hundred rows of data, and this document's value is
the prose they would bury (#385).

## Package ownership

Every top-level package under `src/core` has a row. `owner` is where the package must end up, not
where it is today.

- `kernel` — stays in `core`.
- `authserver` / `adminconsole` — moves to that module.
- `split` — part stays in `core` and part moves; the named issue decides the line. No edge rule
  applies to a split package until its issue lands, because at package granularity there is nothing
  yet to check.
- `delete` — has no future; the named issue removes it.

A row whose owner is not `kernel` names the issue that moves it. A `kernel` row names none.

### Package ownership

| package | owner | moves in |
|---|---|---|
| `core/api` | kernel | — |
| `core/boundedread` | kernel | — |
| `core/buildinfo` | kernel | — |
| `core/builtin` | kernel | — |
| `core/cmd` | kernel | — |
| `core/countries` | kernel | — |
| `core/errs` | kernel | — |
| `core/gender` | kernel | — |
| `core/hashutil` | kernel | — |
| `core/hostport` | kernel | — |
| `core/i18n` | kernel | — |
| `core/inputvalidation` | kernel | — |
| `core/internal` | kernel | — |
| `core/locales` | kernel | — |
| `core/localzone` | kernel | — |
| `core/logging` | kernel | — |
| `core/middleware` | kernel | — |
| `core/oauth` | kernel | — |
| `core/securerandom` | kernel | — |
| `core/sessionstore` | kernel | — |
| `core/testutil` | kernel | — |
| `core/timezones` | kernel | — |

Notes on rows that are not self-evident:

- There is no `core/audit` row because there is no `core/audit` in the repository. #333 lists it for
  deletion, and it does exist as a directory of generated mocks in a working tree that has run the
  mock generator, but git has never tracked a file under it. A row for it fails the completeness
  rule, which is how this was found.
- `core/cmd` is kernel because it is one developer tool, `ownershipdump`, which writes the per-symbol
  table described below. The row exists because the guard reads any directory under `core` holding a
  production Go file, and rule 6 fails without it (#385).
- `core/internal` is kernel because it holds `refgraph`, the reference-graph reader behind the
  tree-wide guards and `ownershipdump`: the census left `core/testutil` so that the tool stops
  linking `testing` and testify, and Go's internal rule keeps it from anything outside core (#431).
  It also holds `pinnedfetch`, the pinned download the reference-data generators share (#432).
- `core/testutil` is kernel because it is test support compiled into no binary. It is still held to
  the kernel rule, and #360 is what made that hold rather than merely claim
  it: `core/testutil/fake` imported `core/uuidutil` under an exception rather than a waiver, so the
  edge was noticed when `uuidutil` moved, and `fake` moved with it to the auth server, where it is
  `authserver/internal/fake` since #442. No admin console file ever imported it.
- `core/api` is declarations and nothing else. The model-aware `ToResponse` mapping left for
  `authserver/internal/apimapping` in #350, the model-typed fields became DTOs of its own, and the
  reverse `ToUser()`/`ToGroup()` methods the admin console's `apiclient` called at 32 sites are
  gone; what remains is the wire contract the admin console decodes. The mapping was once #349's
  alone, but moving it without the fields would have left every exception row below standing, so
  the two were one issue.
- `core/builtin` is `kernel`, and it is the one package whose ownership is also recorded symbol
  by symbol, in the table below. Package granularity cannot hold it: a constant is a string, so an
  auth-server-only name declared there costs nothing at compile time and breaks none of the rules
  below. It and `core/buildinfo` are what `core/constants` split into: the identifiers both
  processes agree on here, and the build stamp the release builds set with `-ldflags -X` there,
  which as values the linker writes rather than names two processes share is held by
  `src/core/OWNERSHIP.md` alone (#442).

## Built-in identifiers ownership

Every exported symbol `core/builtin` declares has a row saying why core still declares it, as one
of four justifications, checked against the real reference graph the way the tables above and below
are checked against the import graph. Production references only, for the same reason rules 2 and 3
read production files: a test may name anything from anywhere.

This table exists because nothing else could have caught what it catches. `core/constants`, which
`core/builtin` is what remains of, reached 139 symbols, 108 of them named by a single process, with
every import rule satisfied at every step (#351, #442).

| justification | means |
|---|---|
| `kernel` | a `kernel` core package references it in production, so rule 2 forbids it leaving |
| `both-apps` | both applications reference it in production |
| `moving` | in core, only a package on its way out of core references it; the issue names the move that ends the justification |
| `contract` | none of the above, but it is an intentionally stable cross-process value |

A row states the strongest justification the tree backs, in that order, and a row claiming less than
the tree supports fails. So `contract` is reachable only when nothing else holds, which is the whole
point of it: making somebody write the word turns it into a claim a reviewer can argue with, where
silence is not. Four rows carry it, the permission identifiers #359 left behind.

### Built-in identifiers ownership

| symbol | justification | issue |
|---|---|---|
| `AdminConsoleClientIdentifier` | both-apps | — |
| `AdminConsoleSessionName` | both-apps | — |
| `AdminReadPermissionIdentifier` | contract | — |
| `AuthServerPermissionIdentifiers` | both-apps | — |
| `AuthServerResourceIdentifier` | both-apps | — |
| `BrowserSessionsPermissionIdentifier` | both-apps | — |
| `ManageAccountPermissionIdentifier` | both-apps | — |
| `ManageClientsPermissionIdentifier` | contract | — |
| `ManagePermissionIdentifier` | both-apps | — |
| `ManageSettingsPermissionIdentifier` | contract | — |
| `ManageUsersPermissionIdentifier` | contract | — |

Notes on rows that are not self-evident:

- `AdminConsoleSessionName` is here and its twin is not. The auth server's session backend stores
  the admin console's server-side sessions, so it names that session name at one production site,
  and the two processes must agree on the string or the admin console's sessions are written under
  a name it does not read (#266). Nothing outside the auth server names `AuthServerSessionName`.
- These five were `moving | #359` until #359 carried the seeder that named them out of core. The
  note here then predicted that nothing would reference them afterwards; it was wrong.
  `AdminConsoleClientIdentifier` is `both-apps`, named by the admin console at four production
  sites and by the seeder, now `authserver/internal/bootstrap` (#424). The four permission
  identifiers are `contract`, their only referrers being `authserver/internal/server/routes.go`
  and that seeder. The word is earned and
  not conceded to the guard: they are the scope strings a client asks for and a token carries, and
  the admin console compiles all four through `AuthServerPermissionIdentifiers`, which is
  `both-apps` on its own account and cannot leave core — moving them out beside it would spell
  eight scope strings twice with nothing holding the two spellings equal.
- There is no `ContextKeySettings` row because the two processes share nothing but its spelling.
  Each declares its own, now an unexported key in that module's `internal/reqctx` (#433, #440), and
  each asserts a different type out of it — `*models.Settings` in the auth server against
  `*api.PublicSettingsResponse` in the admin console — so either assertion panics on the other's
  value. It satisfied the letter of `both-apps`, and that row would have been
  true and misleading (#351).
- No row reads `kernel` any more, and that is #385's doing rather than an omission. Every symbol
  that carried the word did so on the strength of one core package: `core/handlerhelpers`, which
  put `Version`, `BuildDate` and `GitCommit` into every rendered page's template data and read
  `AuthServerResourceIdentifier` and `ManagePermissionIdentifier` to decide `isAdmin`. That
  renderer was two applications' renderers in one package, so #385 split it, and the five dropped
  to `both-apps` in the same commit with nothing else in the tree changing. The two identifiers are
  still named by both binaries, which is why they are still here; the three build-stamp variables
  left for `core/buildinfo` when `core/constants` split (#442).
- The six `SessionKey*`, `ContextKeyBearerToken` and `ContextKeyJwtInfo` were here until #385 and
  are not any more, so core declares no context key at all and `core/constants/context_key.go` is
  gone. Each was `kernel` on the strength of one core package: `core/handlerhelpers/auth_helper.go`
  and `core/middleware/middleware_jwt.go` for the session keys, the latter alone for the bearer
  key, `core/handlerhelpers/http_helper.go` for `ContextKeyJwtInfo`, which read it to bind the
  admin page data. Every one of those files held one application's implementation, so #385 moved
  them — the OAuth client, the JWT session middleware and the console's renderer to
  `adminconsole/internal`, the bearer middleware and the auth server's renderer to
  `authserver/internal` — and every key went with its one writer, to that module's own
  `internal/constants`. Both modules' have since moved on, the auth server's in #433 and the admin
  console's in #440: their context keys to `internal/reqctx`, as unexported keys behind typed
  accessors, and their session keys to `internal/sessionkeys`, so neither module has an
  `internal/constants` any more.
- `ManageAccountPermissionIdentifier` dropped from `kernel` to `both-apps` in the same commit, for
  the same reason and with no change in the tree beyond it: `core/middleware/middleware_jwt.go`
  was its one core referrer, through `buildScopeString`. Both applications still name it, so it
  stays in core on the weaker claim.

## Rules

The guard reports findings by these names.

1. **module direction** — only the edges in [Module graph](#module-graph). Checked in production
   and test files alike, because a test that imports across a forbidden edge still proves the two
   modules are coupled.
2. **kernel purity** — a `kernel` package may not import a package owned by `authserver`,
   `adminconsole` or `delete`. This is the rule that keeps `core` from being an application.
3. **process isolation** — `adminconsole` may not import an `authserver`-owned package, and vice
   versa. `cmd/goiabada-setup` may import neither.
4. **dead package** — a `delete` package must have no importer anywhere, production or test. If one
   appears, the row is wrong and the package is not dead.
5. **foreign closure** — the modules in
   [Foreign modules](#foreign-modules-the-admin-console-must-not-compile) must be reachable from the
   admin console's production packages exactly as declared there.
6. **table hygiene** — every top-level `core` package has exactly one ownership row; every non-kernel
   row names an issue and every kernel row names none; every exception corresponds to a violation
   that exists right now; every violation has an exception.
7. **built-in identifiers** — every exported symbol `core/builtin` declares has exactly one row in
   [Built-in identifiers ownership](#built-in-identifiers-ownership-1), and each row states the strongest
   justification the reference graph backs. A symbol with no row fails, a row for a symbol that is
   gone fails, and a row claiming less than the tree supports fails. Only a `moving` row names an
   issue, because it is the only justification that expires.
8. **core symbols** — every exported symbol any `core` package declares has exactly one row in
   [`src/core/OWNERSHIP.md`](src/core/OWNERSHIP.md), stating the strongest of seven justifications
   the reference graph backs. Four are computed — `kernel`, `both-apps`, `own-package`, `reachable`
   — and three are asserted with a note the guard requires to be non-empty: `test-support`,
   `contract` and `moving`. Same both directions as rule 7, and the same reason: `core/constants`
   reached 139 symbols, 108 named by a single process, with every rule above green throughout. That
   file's own header carries the definitions and the ceilings (#385).
9. **test code** — no shipped binary links a package the
   [Test frameworks](#test-code-no-shipped-binary-may-link) table refuses, or any package under one.
   The shipped binaries are the three a release ships: the auth server, the admin console and the
   setup wizard. Each is walked from its `main` package, and the guard fails when one of the three is
   not where it looks, so a renamed main cannot drop out of the rule unnoticed (#331).

Rules 2, 3, 4, 7 and 8 read production files only. A test may import a mock, a fixture or a helper from
anywhere; that is what test code is for, and holding it to the production graph would make
`core/testutil` unusable from the tiers that call it. Rule 1 is the exception, for the reason given
above. Rule 5 reads production files because it is about what lands in a shipped binary, and rule
8's `test-support` half and rule 9 read them the same way, for the same reason.

## Temporary exceptions

Each row is one exact package edge that exists today and violates a rule above, with the issue that
removes it. An exception is not a waiver: when the edge goes, the row must go with it, and the guard
fails until it does. That is how the epic burned down, and the table is empty because it finished.
A row added here now is a debt taken on deliberately, not one inherited.

Both ends name a package, never a module and never a parent. A row granting `core/middleware`
an edge grants it to `core/middleware` alone: not to `core`, and not to `core/oauth`, which
would need a row of its own. A module-wide grant would let a second package acquire the same
dependency in silence, and the count of rows is the only measure of how much is owed.

### Temporary exceptions

| from | to | issue |
|---|---|---|

No rows. The heading, the header and the separator stay because `parseArchitectureDoc` reads the
table by name and an absent section fails differently from an empty one. #350 owned ten of these
rows and #360 the last three: two for `core/hashutil`, settled by splitting the bcrypt half out to
`authserver/internal/passwordhash` so what stayed is a SHA-256 helper both processes call, and one
for `core/testutil/fake`, settled by moving it and `core/uuidutil` to the auth server together.

## Foreign modules the admin console must not compile

The admin console is a web UI that talks to the auth server over HTTP. It opens no database, sends
no mail and generates no TOTP codes, so the libraries that do those things have no business in its
binary. `adminconsole/go.mod` no longer requires them at all, tidied in #346, but a `go.mod` line
is what the module graph permits rather than what the linker pulls in. What matters is the import
closure, and #344 emptied it of them.

This is the concrete harm the epic exists to fix, and it is measurable, so the guard measures it.
`reachable today` is asserted against the real transitive import closure of the admin console's
production packages. A module listed `no` that becomes reachable is a regression; a module listed
`yes` that stops being reachable is a row to correct: deleted, or kept at `no` where the epic's
point is that it must never come back, as the five driver rows below are. `cleared by` is the issue
expected to do it and is documentation only — if an earlier issue gets there first, the guard says
so and the row changes then.

A row may name a package inside a module the admin console otherwise compiles legitimately:
`golang.org/x/crypto/bcrypt` is one, because `core/sessionstore/codec.go` reaches
`golang.org/x/crypto` for `chacha20poly1305`, so a row for the parent module would be false
(#360).

### Foreign modules

| module | why it must not be there | reachable today | cleared by |
|---|---|---|---|
| `modernc.org/sqlite` | SQLite driver | no | — |
| `github.com/go-sql-driver/mysql` | MySQL driver | no | — |
| `github.com/jackc/pgx/v5` | PostgreSQL driver | no | — |
| `github.com/microsoft/go-mssqldb` | SQL Server driver | no | — |
| `github.com/huandu/go-sqlbuilder` | SQL construction | no | — |
| `github.com/pquerna/otp` | TOTP generation | no | — |
| `github.com/go-chi/cors` | CORS policy is the auth server's | no | — |
| `golang.org/x/crypto/bcrypt` | provider-only password hashing | no | — |

Every driver used to arrive the same way, through one edge:

```
adminconsole/cmd/goiabada-adminconsole -> core/validators -> core/data -> core/data/<engine> -> driver
```

`core/data/database.go` imported all four engine packages until #353 moved the selection to
`authserver/internal/datafactory`, so importing `core/data` at all compiled every driver. The paths
in this history are the ones that existed then: `core/data` is `authserver/internal/data` since
#359, and the engine packages moved under it in #354. Exactly
one of the core packages the admin console imports reached `core/data`: `core/validators`. #338
closed the other, `core/oauth`, and the rows stayed `yes`, which is why the table asserts
reachability rather than counting edges.

**#344 severed that edge, and the five rows above are `no` because of it.** It moved the seven
validators that touch a database or a country table to the auth server and left `core/validators`,
`core/inputvalidation` since #442, holding `identifier_validator.go` and
`angle_brackets_validator.go`, which import `strings`, `regexp` and `core/i18n`. Ninety packages
left the admin console's production closure with them, including `core/data`, all four drivers and
`go-sqlbuilder`.

These rows read #353 until then, on the argument that `core/data/database.go` was the only
production file in `core` importing an engine package and so the single cut point; #353 made that
cut in the end, for #354. The drivers were expected to leave at 13/16 and left at 9/16, because
severing the one edge that reached `core/data` did the same job from the other end. Which is why
`reachable today` is asserted against the real closure and not derived from an argument about
which issue owns the cut.

`github.com/pquerna/otp` is listed at `no` deliberately. It is not reachable now, it never will be
now that `otp` is the auth server's (#346), and the row states that it must not arrive.

The table is a declared list, not a discovery mechanism: it asserts these modules and says nothing
about a dependency nobody has written a row for. Closing that would mean an allowlist of every
module the admin console legitimately compiles, churned on every dependency change, which is a wider
rule than #332 asks for. #360 checked off the categories in its point 5 — database drivers,
sqlbuilder, OTP and image libraries, provider-only crypto — and each is a row above, asserted `no`.

## Test code no shipped binary may link

A shipped binary carries no test code: no assertion library, no mock, no test helper, and none of
the test frameworks they are written with. Both servers and the setup wizard are clean, and before
#331 nothing kept them so. The generated mocks carry `//go:build !production`, so a production
import of one breaks only the release build, which no pull-request job compiles; every other helper
carries no tag at all, so a production import of one would link it, and `testing` or testify behind
it, and fail nowhere.

Test code is defined here by the frameworks, not by where a helper lives or what it is called. A
row refuses its package and every package under it, and the refusal is transitive, so a first-party
helper is caught through the framework it imports, the moment it imports one, with no list of
helpers to keep. That covers 16 of the 18 test-support packages in the tree when it was written,
every mock among them. The two it does not cover import no framework:
`authserver/internal/fake`, a random-string source over `crypto/rand`, and
`core/internal/refgraph`, which is tooling rather than test code. Linking either would be odd, not
harmful. Keying on a path instead — `testutil`, `mocks`, a name ending in `test` — would be a rule
about spelling, which no guard in this repository is.

The walk starts from each shipped `main` package rather than from every production package of a
module, which is where it differs from rule 5: the graph counts `core/testutil`'s untagged files as
production, so a module-wide walk would find `testing` in `core` itself. The three mains are listed
in the guard, as `shippedMains`, rather than found by looking for `package main`, because
`schemadump`, `droptestdb`, `ownershipdump` and the two reference-data generators are main packages
too and ship in no release. A file belongs to a binary the way the rest of this document decides
it: the `production` tag set and every other tag free, so a file in any of the five release targets
counts. That is exact because every release build of all three sets `production`: the servers'
cross-compile script, the two server Dockerfiles and the setup wizard's cross-compile script, so a
`//go:build !production` helper anywhere in the wizard's closure stays out of the wizard as the
generated mocks stay out of the servers. A rule test in core's unit tier,
`TestReleaseBuilds_TheRealReleaseBuildsSetProduction`, reads those four files and fails when a
`go build` in them does not set the tag, when one of them is missing or holds no `go build`, when the
mains they build stop being exactly `shippedMains`, or when either script's `build_platform` calls
differ as a set from `releaseTargets` (#463).

The refusal does not stop at the edge of the four modules. Past it, the walk follows the imports
the go command reports: `go list -deps` under the `production` tag, run over each shipped main for
each of the five release targets, `releaseTargets` in the guard, supplies the imports of every
third-party and standard-library package a main reaches, so a dependency whose own production code
imports `testing` or testify is refused like a first-party helper that does. First-party packages
are still read from source, with every tag but `production` free, because that covers all five
targets at once. A package the go command cannot load is a finding, since the walk cannot see what
it imports.

### Test frameworks

| package | what it is |
|---|---|
| `testing` | the standard library's test framework, and `testing/fstest`, `testing/iotest`, `testing/quick` and the rest under it |
| `net/http/httptest` | the standard library's test server and response recorder |
| `github.com/stretchr/testify` | the assertions, `require`, `mock` and `suite` the tests and the generated mocks are written with |

## The guard

`AssertArchitecture` lives in `src/core/testutil/architecture.go` and is called from all three
module unit tiers, so it fires whichever tier runs — the same arrangement as the gofmt, error,
slog and agent-document guards.

It reads imports from the AST rather than matching text, so an import inside a comment or a string
is not a finding and a renamed import alias still is one. Rule 9 is the one rule that also asks the
go command, for what the packages outside the four modules import, since no source of theirs is
under the source root. It parses production and test files
separately because the rules above treat them differently. Rule 7 reads the same way, one level
down: `src/core/testutil/builtin_ownership.go` reads the exported declarations of
`core/builtin` and, from every production file that imports it, the symbols selected off whatever
identifier that file binds the import to.

Rule 8 lives beside them rather than in this file. `AssertSymbolOwnership` in
`src/core/testutil/symbol_ownership.go` is called from the same three tiers and checks
`src/core/OWNERSHIP.md`; `src/core/cmd/ownershipdump` writes the computed rows from the same census,
`core/internal/refgraph`, so the tool and the guard cannot read the tree differently, and
`./run-tests.sh --type lint` runs the tool and fails on a tree it changed. References from outside a declaring package are read as
selectors, like rule 7's; references from inside it are resolved with `go/types`, because there an
identifier carries no selector and matching one by spelling would let a local or a struct field
justify its namesake.

`src/core/testutil/architecture_lint_test.go` is the core tier's caller;
`src/core/testutil/architecture_rules_test.go`,
`src/core/testutil/builtin_ownership_rules_test.go`,
`src/core/testutil/symbol_ownership_rules_test.go` and
`src/core/internal/refgraph/symbol_ownership_test.go` hold the guard's own tests. They run the rule table
against fixture trees written into a temp directory, one fixture per rule and per deliberate
leniency, and then take the real tables apart one row at a time — dropping each exception and
flipping each declared reachability, and adding a test-framework row for a package every shipped
binary links — because the tree satisfies this document by construction, so
passing proves nothing on its own. A guard that has quietly stopped matching anything passes a clean
tree exactly the way it passes a correct one; `errors_lint_test.go` sets out the same reasoning for
the same problem (#279).
