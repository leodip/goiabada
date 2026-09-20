# Architecture

This file records which module owns what, and it is executable. The four tables below —
[package ownership](#package-ownership), [core constants ownership](#core-constants-ownership),
[temporary exceptions](#temporary-exceptions) and
[foreign modules](#foreign-modules-the-admin-console-must-not-compile) — are parsed by
`AssertArchitecture` in `src/core/testutil/architecture.go`, which every module's unit tier calls.
A row that stops describing the tree fails the tier, in both directions: an edge the tables do not
allow is a finding, and so is an exception listed for an edge that no longer exists. A fifth table,
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
| `core/cmd` | kernel | — |
| `core/constants` | kernel | — |
| `core/countries` | kernel | — |
| `core/customerrors` | kernel | — |
| `core/enums` | kernel | — |
| `core/errs` | kernel | — |
| `core/hashutil` | kernel | — |
| `core/i18n` | kernel | — |
| `core/locales` | kernel | — |
| `core/logging` | kernel | — |
| `core/middleware` | kernel | — |
| `core/mocks` | kernel | — |
| `core/oauth` | kernel | — |
| `core/sessionstore` | kernel | — |
| `core/stringutil` | kernel | — |
| `core/testutil` | kernel | — |
| `core/timezones` | kernel | — |
| `core/validators` | kernel | — |

Notes on rows that are not self-evident:

- There is no `core/audit` row because there is no `core/audit` in the repository. #333 lists it for
  deletion, and it does exist as a directory of generated mocks in a working tree that has run the
  mock generator, but git has never tracked a file under it. A row for it fails the completeness
  rule, which is how this was found.
- `core/cmd` is kernel because it is one developer tool, `ownershipdump`, which writes the per-symbol
  table described below. The row exists because the guard reads any directory under `core` holding a
  production Go file, and rule 6 fails without it (#385).
- `core/mocks` and `core/testutil` are kernel because they are test support compiled into no binary.
  They are still held to the kernel rule, and #360 is what made that hold rather than merely claim
  it: `core/testutil/fake` imported `core/uuidutil` under an exception rather than a waiver, so the
  edge was noticed when `uuidutil` moved, and `fake` moved with it to
  `authserver/internal/testutil/fake`. No admin console file ever imported it.
- `core/api` is declarations and nothing else. The model-aware `ToResponse` mapping left for
  `authserver/internal/apimapping` in #350, the model-typed fields became DTOs of its own, and the
  reverse `ToUser()`/`ToGroup()` methods the admin console's `apiclient` called at 32 sites are
  gone; what remains is the wire contract the admin console decodes. The mapping was once #349's
  alone, but moving it without the fields would have left every exception row below standing, so
  the two were one issue.
- `core/constants` is `kernel`, and it is the one package whose ownership is also recorded symbol
  by symbol, in the table below. Package granularity cannot hold it: a constant is a string, so an
  auth-server-only name declared there costs nothing at compile time and breaks none of the rules
  below.

## Core constants ownership

Every exported symbol `core/constants` declares has a row saying why core still declares it, as one
of four justifications, checked against the real reference graph the way the tables above and below
are checked against the import graph. Production references only, for the same reason rules 2 and 3
read production files: a test may name anything from anywhere.

This table exists because nothing else could have caught what it catches. The package reached 139
symbols, 108 of them named by a single process, with every import rule satisfied at every step
(#351).

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

### Core constants ownership

| symbol | justification | issue |
|---|---|---|
| `AdminConsoleClientIdentifier` | both-apps | — |
| `AdminConsoleSessionName` | both-apps | — |
| `AdminReadPermissionIdentifier` | contract | — |
| `AuthServerResourceIdentifier` | both-apps | — |
| `BrowserSessionsPermissionIdentifier` | both-apps | — |
| `BuildDate` | both-apps | — |
| `BuiltInAuthServerPermissionIdentifiers` | both-apps | — |
| `GitCommit` | both-apps | — |
| `ManageAccountPermissionIdentifier` | both-apps | — |
| `ManageClientsPermissionIdentifier` | contract | — |
| `ManagePermissionIdentifier` | both-apps | — |
| `ManageSettingsPermissionIdentifier` | contract | — |
| `ManageUsersPermissionIdentifier` | contract | — |
| `UserinfoPermissionIdentifier` | both-apps | — |
| `Version` | both-apps | — |

Notes on rows that are not self-evident:

- `AdminConsoleSessionName` is here and its twin is not. The auth server's session backend stores
  the admin console's server-side sessions, so it names that session name at one production site,
  and the two processes must agree on the string or the admin console's sessions are written under
  a name it does not read (#266). Nothing outside the auth server names `AuthServerSessionName`.
- These five were `moving | #359` until #359 carried the seeder that named them out of core. The
  note here then predicted that nothing would reference them afterwards; it was wrong.
  `AdminConsoleClientIdentifier` is `both-apps`, named by the admin console at four production
  sites and by the moved seeder. The four permission identifiers are `contract`, their only
  referrers being `authserver/internal/server/routes.go` and that seeder. The word is earned and
  not conceded to the guard: they are the scope strings a client asks for and a token carries, and
  the admin console compiles all four through `BuiltInAuthServerPermissionIdentifiers`, which is
  `both-apps` on its own account and cannot leave core — moving them out beside it would spell
  eight scope strings twice with nothing holding the two spellings equal.
- There is no `ContextKeySettings` row because the two processes share nothing but its spelling.
  Each declares its own, and each asserts a different type out of it — `*models.Settings` in the
  auth server against `*api.PublicSettingsResponse` in the admin console — so either assertion
  panics on the other's value. It satisfied the letter of `both-apps`, and that row would have been
  true and misleading (#351).
- No row reads `kernel` any more, and that is #385's doing rather than an omission. Every symbol
  that carried the word did so on the strength of one core package: `core/handlerhelpers`, which
  put `Version`, `BuildDate` and `GitCommit` into every rendered page's template data and read
  `AuthServerResourceIdentifier` and `ManagePermissionIdentifier` to decide `isAdmin`. That
  renderer was two applications' renderers in one package, so #385 split it, and the five dropped
  to `both-apps` in the same commit with nothing else in the tree changing. They are still named
  by both binaries, which is why they are still here.
- The six `SessionKey*`, `ContextKeyBearerToken` and `ContextKeyJwtInfo` were here until #385 and
  are not any more, so core declares no context key at all and `core/constants/context_key.go` is
  gone. Each was `kernel` on the strength of one core package: `core/handlerhelpers/auth_helper.go`
  and `core/middleware/middleware_jwt.go` for the session keys, the latter alone for the bearer
  key, `core/handlerhelpers/http_helper.go` for `ContextKeyJwtInfo`, which read it to bind the
  admin page data. Every one of those files held one application's implementation, so #385 moved
  them — the OAuth client, the JWT session middleware and the console's renderer to
  `adminconsole/internal`, the bearer middleware and the auth server's renderer to
  `authserver/internal` — and every key went with its one writer, to that module's own
  `internal/constants`.
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
7. **core constants** — every exported symbol `core/constants` declares has exactly one row in
   [Core constants ownership](#core-constants-ownership-1), and each row states the strongest
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

Rules 2, 3, 4, 7 and 8 read production files only. A test may import a mock, a fixture or a helper from
anywhere; that is what test code is for, and holding it to the production graph would make
`core/testutil` unusable from the tiers that call it. Rule 1 is the exception, for the reason given
above. Rule 5 reads production files because it is about what lands in a shipped binary, and rule
8's `test-support` half reads them the same way, for the same reason.

## Temporary exceptions

Each row is one exact package edge that exists today and violates a rule above, with the issue that
removes it. An exception is not a waiver: when the edge goes, the row must go with it, and the guard
fails until it does. That is how the epic burned down, and the table is empty because it finished.
A row added here now is a debt taken on deliberately, not one inherited.

Both ends name a package, never a module and never a parent. A row granting `core/handlerhelpers`
an edge grants it to `core/handlerhelpers` alone: not to `core`, and not to `core/oauth`, which
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
validators that touch a database or a country table to the auth server and left `core/validators`
holding `identifier_validator.go` and `angle_brackets_validator.go`, which import `strings`,
`regexp` and `core/i18n`. Ninety packages left the admin console's production closure with them,
including `core/data`, all four drivers and `go-sqlbuilder`.

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

## The guard

`AssertArchitecture` lives in `src/core/testutil/architecture.go` and is called from all three
module unit tiers, so it fires whichever tier runs — the same arrangement as the gofmt, error,
slog and agent-document guards.

It reads imports from the AST rather than matching text, so an import inside a comment or a string
is not a finding and a renamed import alias still is one. It parses production and test files
separately because the rules above treat them differently. Rule 7 reads the same way, one level
down: `src/core/testutil/constants_ownership.go` reads the exported declarations of
`core/constants` and, from every production file that imports it, the symbols selected off whatever
identifier that file binds the import to.

Rule 8 lives beside them rather than in this file. `AssertSymbolOwnership` in
`src/core/testutil/symbol_ownership.go` is called from the same three tiers and checks
`src/core/OWNERSHIP.md`; `src/core/cmd/ownershipdump` writes the computed rows from the same census,
so the tool and the guard cannot read the tree differently, and `./run-tests.sh --type lint` runs
the tool and fails on a tree it changed. References from outside a declaring package are read as
selectors, like rule 7's; references from inside it are resolved with `go/types`, because there an
identifier carries no selector and matching one by spelling would let a local or a struct field
justify its namesake.

`src/core/testutil/architecture_lint_test.go` is the core tier's caller;
`src/core/testutil/architecture_rules_test.go`,
`src/core/testutil/constants_ownership_rules_test.go` and
`src/core/testutil/symbol_ownership_rules_test.go` hold the guard's own tests. They run the rule table
against fixture trees written into a temp directory, one fixture per rule and per deliberate
leniency, and then take the real tables apart one row at a time — dropping each exception and
flipping each declared reachability — because the tree satisfies this document by construction, so
passing proves nothing on its own. A guard that has quietly stopped matching anything passes a clean
tree exactly the way it passes a correct one; `errors_lint_test.go` sets out the same reasoning for
the same problem (#279).
