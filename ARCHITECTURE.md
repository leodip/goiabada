# Architecture

This file records which module owns what, and it is executable. The three tables below —
[package ownership](#package-ownership), [temporary exceptions](#temporary-exceptions) and
[foreign modules](#foreign-modules-the-admin-console-must-not-compile) — are parsed by
`AssertArchitecture` in `src/core/testutil/architecture.go`, which every module's unit tier calls.
A row that stops describing the tree fails the tier, in both directions: an edge the tables do not
allow is a finding, and so is an exception listed for an edge that no longer exists.

That is the whole point of writing it down here rather than in prose. The dependency direction
between these three modules is not visible at a call site and is not a compile error until the day
it becomes a cycle, so it is the kind of rule that decays silently. This repository already learned
that lesson once about prose: `AssertAgentDocs` exists because the state machine documented in
`CLAUDE.md` had moved underneath the description while every test stayed green (#252).

The refactor that these rules were written for is the 29-issue Core Refactor epic. Its full
checklist lives in [#332](https://github.com/leodip/goiabada/issues/332); every `moves in` and
`cleared by` cell below names one of its issues.

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
| `core/auditlog` | authserver | #359 |
| `core/cmd` | authserver | #358 |
| `core/communication` | authserver | #347 |
| `core/config` | split | #351 |
| `core/constants` | split | #352 |
| `core/countries` | kernel | — |
| `core/customerrors` | kernel | — |
| `core/data` | authserver | #359 |
| `core/encryption` | authserver | #360 |
| `core/enums` | kernel | — |
| `core/errs` | kernel | — |
| `core/handlerhelpers` | kernel | — |
| `core/hashutil` | authserver | #360 |
| `core/i18n` | kernel | — |
| `core/imaging` | authserver | #348 |
| `core/locales` | kernel | — |
| `core/logging` | kernel | — |
| `core/middleware` | split | #335 |
| `core/mocks` | kernel | — |
| `core/models` | authserver | #359 |
| `core/oauth` | split | #338 |
| `core/oauthdb` | authserver | #340 |
| `core/oidc` | authserver | #360 |
| `core/otp` | authserver | #348 |
| `core/phonecountries` | authserver | #345 |
| `core/ratelimit` | authserver | #336 |
| `core/rsautil` | authserver | #360 |
| `core/sessionstore` | split | #334 |
| `core/stringutil` | kernel | — |
| `core/testutil` | kernel | — |
| `core/timezones` | kernel | — |
| `core/uithemes` | authserver | #348 |
| `core/urlutil` | authserver | #360 |
| `core/user` | authserver | #346 |
| `core/useragent` | authserver | #346 |
| `core/uuidutil` | authserver | #360 |
| `core/validators` | split | #344 |

Notes on rows that are not self-evident:

- There is no `core/audit` row because there is no `core/audit` in the repository. #333 lists it for
  deletion, and it does exist as a directory of generated mocks in a working tree that has run the
  mock generator, but git has never tracked a file under it. A row for it fails the completeness
  rule, which is how this was found.
- `core/mocks` and `core/testutil` are kernel because they are test support compiled into no binary.
  They are still held to the kernel rule: `core/testutil/fake` imports `core/uuidutil` today, and
  that is an exception below rather than a waiver, because #360 moves `uuidutil` and the edge has to
  be noticed then.
- `core/api` stays, but only as declarations. The model-aware `ToResponse` mapping leaves in #349
  and the model-typed fields leave in #350; what remains is the wire contract the admin console
  decodes.
- `core/oauth` is the largest split. The admin console is an OAuth client: it needs token response
  values, PKCE and JWT/JWKS validation. It does not issue codes or tokens and does not rotate
  signing keys. #338 draws that line; #339, #341, #342 and #343 carry the provider half away.

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

Rules 2, 3 and 4 read production files only. A test may import a mock, a fixture or a helper from
anywhere; that is what test code is for, and holding it to the production graph would make
`core/testutil` unusable from the tiers that call it. Rule 1 is the exception, for the reason given
above. Rule 5 reads production files because it is about what lands in a shipped binary.

## Temporary exceptions

Each row is one exact package edge that exists today and violates a rule above, with the issue that
removes it. An exception is not a waiver: when the edge goes, the row must go with it, and the guard
fails until it does. That is how the epic burns down — #335 already instructs its implementer to
"remove the exact architecture exceptions introduced by #332 for these edges".

Both ends name a package, never a module and never a parent. `adminconsole/internal/handlers` is
granted its dependency on `core/models`; `adminconsole` is not, and neither is
`adminconsole/internal/handlers/adminuserhandlers`, which is why it has a row of its own. A
module-wide grant would let a second package acquire the same dependency in silence, and the count
of rows is the only measure of how much is left to do.

### Temporary exceptions

| from | to | issue |
|---|---|---|
| `core/api` | `core/models` | #350 |
| `core/customerrors` | `core/models` | #350 |
| `core/handlerhelpers` | `core/hashutil` | #360 |
| `core/handlerhelpers` | `core/models` | #337 |
| `core/i18n` | `core/models` | #337 |
| `core/testutil/fake` | `core/uuidutil` | #360 |
| `adminconsole/internal/apiclient` | `core/models` | #350 |
| `adminconsole/internal/handlers` | `core/models` | #350 |
| `adminconsole/internal/handlers/accounthandlers` | `core/models` | #350 |
| `adminconsole/internal/handlers/adminclienthandlers` | `core/models` | #350 |
| `adminconsole/internal/handlers/admingrouphandlers` | `core/models` | #350 |
| `adminconsole/internal/handlers/adminresourcehandlers` | `core/models` | #350 |
| `adminconsole/internal/handlers/adminuserhandlers` | `core/models` | #350 |
| `adminconsole/internal/middleware` | `core/models` | #350 |

Fourteen rows, and #350 owns nine of them: the admin console's dependency on persistence models is
the single largest piece of the boundary still to close.

## Foreign modules the admin console must not compile

The admin console is a web UI that talks to the auth server over HTTP. It opens no database, sends
no mail and generates no TOTP codes, so the libraries that do those things have no business in its
binary. They are there anyway: `adminconsole/go.mod` lists all four database drivers as indirect
dependencies, every one of them arriving through `core`.

This is the concrete harm the epic exists to fix, and it is measurable, so the guard measures it.
`reachable today` is asserted against the real transitive import closure of the admin console's
production packages. A module listed `no` that becomes reachable is a regression; a module listed
`yes` that stops being reachable is a row to delete. `cleared by` is the issue expected to do it and
is documentation only — if an earlier issue gets there first, the guard says so and the row changes
then.

### Foreign modules

| module | why it must not be there | reachable today | cleared by |
|---|---|---|---|
| `modernc.org/sqlite` | SQLite driver | yes | #353 |
| `github.com/go-sql-driver/mysql` | MySQL driver | yes | #353 |
| `github.com/jackc/pgx/v5` | PostgreSQL driver | yes | #353 |
| `github.com/microsoft/go-mssqldb` | SQL Server driver | yes | #353 |
| `github.com/huandu/go-sqlbuilder` | SQL construction | yes | #353 |
| `github.com/pquerna/otp` | TOTP generation | no | — |

Every driver arrives the same way, through one edge:

```
adminconsole/cmd/goiabada-adminconsole -> core/oauth -> core/data -> core/data/<engine> -> driver
```

`core/data/database.go` imports all four engine packages, so importing `core/data` at all compiles
every driver. Four of the core packages the admin console imports reach `core/data`: `core/oauth`,
`core/middleware`, `core/validators` and `core/sessionstore`. Closing one path changes
nothing on its own, which is why the table asserts reachability rather than counting edges.

All five rows say #353 rather than #359, which is worth explaining because the ordering does not
suggest it. `core/data/database.go` is the only production file in `core` that imports an engine
package — every other importer is an auth-server test — so it is the single cut point, and #353
point 7 already requires that `core/data` stop importing the four engines. The drivers therefore
leave the admin console's binary at 22/29, six issues before the persistence packages themselves
move. #353 reads like a staging step, so the effect is easy to miss; the guard will not miss it,
because these rows go stale the moment it lands.

`github.com/pquerna/otp` is listed at `no` deliberately. It is not reachable now, `core/otp` moves
to the auth server in #348, and the row states that it must not arrive in the meantime.

The table is a declared list, not a discovery mechanism: it asserts these modules and says nothing
about a dependency nobody has written a row for. Closing that would mean an allowlist of every
module the admin console legitimately compiles, churned on every dependency change, which is a wider
rule than #332 asks for. #360 is where the categories in its point 5 — database drivers, sqlbuilder,
OTP and image libraries, provider-only crypto — are checked off, and each is listed here.

## The guard

`AssertArchitecture` lives in `src/core/testutil/architecture.go` and is called from all three
module unit tiers, so it fires whichever tier runs — the same arrangement as the gofmt, error,
slog and agent-document guards.

It reads imports from the AST rather than matching text, so an import inside a comment or a string
is not a finding and a renamed import alias still is one. It parses production and test files
separately because the rules above treat them differently.

`src/core/testutil/architecture_lint_test.go` is the core tier's caller;
`src/core/testutil/architecture_rules_test.go` holds the guard's own tests. They run the rule table
against fixture trees written into a temp directory, one fixture per rule and per deliberate
leniency, and then take the real tables apart one row at a time — dropping each exception and
flipping each declared reachability — because the tree satisfies this document by construction, so
passing proves nothing on its own. A guard that has quietly stopped matching anything passes a clean
tree exactly the way it passes a correct one; `errors_lint_test.go` sets out the same reasoning for
the same problem (#279).
