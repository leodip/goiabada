# Architecture

This file records which module owns what, and it is executable. The four tables below —
[package ownership](#package-ownership), [temporary exceptions](#temporary-exceptions),
[foreign modules](#foreign-modules-the-admin-console-must-not-compile) and
[refused packages](#packages-no-shipped-binary-may-link) — are parsed by
`AssertArchitecture` in `src/core/guard/architecture.go`, which every module's unit tier calls.
A row that stops describing the tree fails the tier, in both directions: an edge the tables do not
allow is a finding, and so is an exception listed for an edge that no longer exists. A fifth table,
one row per exported symbol every `core` package declares, is data in the same sense and lives in
[`src/core/OWNERSHIP.md`](src/core/OWNERSHIP.md); rule 7 below is its rule, and
`AssertSymbolOwnership` reads it from the same three tiers.

That is the whole point of writing it down here rather than in prose. The dependency direction
between these three modules is not visible at a call site and is not a compile error until the day
it becomes a cycle, so it is the kind of rule that decays silently. This repository already learned
that lesson once about prose: `AssertAgentDocs` exists because the state machine documented in
`CLAUDE.md` had moved underneath the description while every test stayed green (#252). That
description now lives in the [authentication guide](docs/development/authentication.md), with
the same roster check.

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
exported symbol in [`src/core/OWNERSHIP.md`](src/core/OWNERSHIP.md), which is rule 7 below. It lives
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
| `core/adminpassword` | kernel | — |
| `core/api` | kernel | — |
| `core/boundedread` | kernel | — |
| `core/brandkit` | kernel | — |
| `core/buildinfo` | kernel | — |
| `core/builtin` | kernel | — |
| `core/cmd` | kernel | — |
| `core/countries` | kernel | — |
| `core/docsreader` | kernel | — |
| `core/errs` | kernel | — |
| `core/gender` | kernel | — |
| `core/guard` | kernel | — |
| `core/hashutil` | kernel | — |
| `core/healthcheck` | kernel | — |
| `core/hostport` | kernel | — |
| `core/httpmw` | kernel | — |
| `core/i18n` | kernel | — |
| `core/inputvalidation` | kernel | — |
| `core/internal` | kernel | — |
| `core/issuerlength` | kernel | — |
| `core/locales` | kernel | — |
| `core/localzone` | kernel | — |
| `core/logging` | kernel | — |
| `core/loopback` | kernel | — |
| `core/metrics` | kernel | — |
| `core/oauth` | kernel | — |
| `core/palette` | kernel | — |
| `core/passwordblocklist` | kernel | — |
| `core/passwordrules` | kernel | — |
| `core/personname` | kernel | — |
| `core/phonecountries` | kernel | — |
| `core/pkgload` | kernel | — |
| `core/requestid` | kernel | — |
| `core/routing` | kernel | — |
| `core/securerandom` | kernel | — |
| `core/sessionstore` | kernel | — |
| `core/sourceroot` | kernel | — |
| `core/stylingcontract` | kernel | — |
| `core/timezones` | kernel | — |

Notes on rows that are not self-evident:

- There is no `core/audit` row because there is no `core/audit` in the repository. #333 listed it for
  deletion; #328 deleted the last file git tracked under it, a generated mock, and the mock
  generator no longer writes there. A row for it fails the completeness rule, which is how this was
  found.
- `core/cmd` is kernel because it holds three developer tools: `ownershipdump`, which writes the
  per-symbol table described below, `imagescanreport`, which turns the weekly scan of the
  published images into the issue listing what someone can act on (#520), and `screenshotcheck`,
  which decodes the images `e2e/screenshots.sh` captured before it writes them (#534). The row exists because the
  guard reads any directory under `core` holding a production Go file, and rule 6 fails without it
  (#385).
- `core/internal` is kernel because it holds `refgraph`, the reference-graph reader behind the
  tree-wide guards and `ownershipdump`: the census left `core/testutil`, now `core/guard`, so that
  the tool stops linking `testing` and testify, and Go's internal rule keeps it from anything
  outside core (#431). The four module directories the graph resolves against are declared once
  (#442), in `core/sourceroot` since #480: Go's internal rule kept them, while they lived here,
  from the one consumer outside core.
  It also holds `pinnedfetch`, the pinned download the reference-data generators share (#432).
- `core/sourceroot` is kernel because it is the one declaration of the four module directories and
  of the ascent that finds the root from them. The tree-wide guards read it through
  `guard.SourceRoot`, `ownershipdump` and the auth server's `schemadump` root their walks with it,
  and it is an exported leaf rather than part of `refgraph` because Go's internal rule kept the
  auth server from reading it there (#480). Like `core/cmd` and `core/guard`, it is developer
  tooling compiled into no shipped binary.
- `core/pkgload` is kernel because it is the one loader the guards that need types read the tree
  through, a module's packages type-checked for one build through `golang.org/x/tools/go/packages`,
  and the one declaration of the release platforms, which rule 8 reads too. It is an exported leaf
  rather than part of `refgraph` because the auth server's tests load through it and Go's internal
  rule keeps them out of `core/internal`, as `core/sourceroot` set the precedent for; it imports
  neither `testing` nor testify, so `ownershipdump` can load through it. Like `core/guard`, it is
  developer tooling compiled into no shipped binary, and the refused-packages table holds its
  dependency to that (#420).
- `core/guard` is kernel because it is test support compiled into no binary, and it holds the
  tree-wide guards and nothing else: it was `core/testutil` until #442, when its one helper that was
  no guard, `SkipWithoutIPv6Loopback`, left for `core/hostport/hostporttest`. It is still held to
  the kernel rule, and #360 is what made that hold rather than merely claim
  it: `core/testutil/fake` imported `core/uuidutil` under an exception rather than a waiver, so the
  edge was noticed when `uuidutil` moved, and `fake` moved with it to the auth server, where it is
  `authserver/internal/fake` since #442. No admin console file ever imported it.
- `core/docsreader` is kernel because it is test support compiled into no binary: the docs tests of
  every module read the site's sections and tables through it, so a fix to how a heading inside a
  fence or an escaped pipe in a cell is read is made once, where a dozen per-package copies each
  had to be fixed before (#536). It is a leaf of its own rather than a file in `core/guard` because
  the setup wizard's docs tests read through it too, and a test the wizard reaches may not import
  `core/guard`, whose dependencies would land in the wizard's go.sum: it imports nothing but
  `core/errs` and the standard library, and its own tests do the same (#500).
- `core/metrics` is kernel because both servers expose their metrics through it: the registry whose
  labels take only declared values, the Prometheus text exposition and the request middleware. It is
  written here rather than taken from `prometheus/client_golang`, which would add eight modules and
  link `expvar` into both binaries, and which takes any string as a label value (#400).
- `core/healthcheck` is kernel because both binaries run it as their `healthcheck` command: one
  `GET` of the server's own `/health`, which the images' health check and the setup wizard's
  Compose file run, since an image built `FROM scratch` holds no other program to ask with. Each
  binary names its own listener variables and defaults; the rule picking the listener, the call
  and the exit codes are written once, so the two checks cannot disagree (#808).
- `core/requestid` is kernel because both servers carry the same request id, made the same way:
  adopted from the `X-Request-Id` a client or proxy sent, or minted as `<hostname>/<10 base62>-<counter>`,
  as chi's middleware made it until #462 replaced it. `core/logging`'s handler reads it onto every
  record, so it sits below `core/logging` and `core/httpmw`, which mounts nothing of it: the
  middleware is `requestid.Middleware` itself.
- `core/routing` is kernel because both servers register their routes on it: a router on
  `net/http.ServeMux` offering the part of chi's surface the two route tables use, with the rules
  every route follows decided once, there: a group's middleware meets an unmatched path under it,
  the 404 and the 405 with its `Allow`, HEAD only where registered, non-canonical paths, and route
  names in chi's spelling, which the metrics' `route` label and the audit log read (#462). It
  imports nothing but the standard library, so `core/metrics` and `core/httpmw` read routes from it.
  It replaced chi, which no module requires any more.
- `core/phonecountries` is kernel because both applications offer a user the same phone country
  list: the auth server validates and stores its ids on the user row, and the admin console's two
  phone pages build their list from it rather than ask the admin API, which refuses a token carrying
  `authserver:manage-account` alone. It was `authserver/internal/phonecountries` from #344, when no
  console code read it, until #563 brought it back.
- `core/adminpassword` is kernel because the auth server's first start and the setup wizard apply
  its one rule, and it is a package of its own rather than a file in `core/inputvalidation` because
  the wizard links whatever its home imports: there, the identifier validator's `core/i18n` import
  brought the message catalogs, `core/oauth`, a TOML parser and a JWT library into a binary that
  uses none of them. `core/guard`'s `imports_only_lint_test.go` holds it to `core/errs`,
  `core/passwordblocklist`, itself a standard-library leaf whose list and context-word check the
  rule applies (#550), and the standard library through `AssertImportsOnly`, the rule
  `authserver/internal/record` is held by too. The call is made from there rather than beside the package because `go mod tidy` reads the
  tests of every package the wizard imports, and a test in `core/adminpassword` importing
  `core/guard` put chi and TOML in the wizard's `go.sum`. `AssertNoGuardInTestsReachedFrom` refuses
  any test the wizard reaches that does so (#500).
- `core/issuerlength` is kernel for `core/adminpassword`'s reason: the auth server's start holds the
  base URL to the issuer's length, since the first start seeds it as the issuer, the general settings
  save holds every issuer to it, and the setup wizard holds the auth server URL it writes to it, so a
  URL the wizard writes is one the start accepts and the save keeps. `inputvalidation.TextLength`
  counts the same unit, but the wizard cannot link that package, so the leaf counts it itself, and
  `core/guard`'s `imports_only_lint_test.go` holds it to `core/errs` and the standard library (#615).
- `core/loopback` is kernel for `core/adminpassword`'s reason: it answers which hosts are the
  loopback interface, and whether a URL is plain `http` off it, once for the auth server's
  redirect-URI matching and intakes and for the setup wizard's URL checks, so the two cannot
  disagree on which URLs are loopback. `core/guard`'s `imports_only_lint_test.go` holds it to the
  standard library (#590).
- `core/passwordblocklist` is kernel because it is written for the two places the `nist` password
  policy is applied, which must agree: the auth server's account validator, on every path that sets
  a password, and `core/adminpassword`, the first administrator's rule the setup wizard shares. It
  holds the generated list of commonly used passwords and the check against the account's own
  words, and imports the standard library alone, for `core/adminpassword`'s reason: the wizard links
  whatever it imports, and `core/guard`'s `imports_only_lint_test.go` holds it there (#550).
- `core/passwordrules` is kernel because both applications show the stored password policy's
  rules under a new password's field, the auth server on its registration, activation and reset
  forms and the admin console on its change-password, new user and Authentication tab pages, and
  both word them through its one function from the rules the public settings carry, so the two
  cannot word the same rules differently. It is a package of its own rather than part of `core/api`,
  which declares and does nothing, and of `core/i18n`, which owns no message of a domain (#550).
- `core/personname` is kernel because both applications write a full name and must write the
  same one: the auth server for the `name` claim and the emails' `{{name}}`, the admin console for
  every name it shows, its user search's answer among them. Its one function holds the rule that
  writes a name in Han, Hiragana, Katakana or Hangul family name first with no space, so a user
  reads the same in a token, an email and the console. It is a package of its own rather than part
  of `core/api`, which declares and does nothing, and the console reaches no auth server package
  (#662).
- `core/brandkit` is kernel because both applications draw a brand's corners, font family, uploaded
  font and background fit from it: the auth server in the brand's full stylesheet, and the admin
  console's brand editor on its sample of a sign-in page as they are picked, before the brand is
  saved, so the sample cannot show a shape, a family or a fit the saved brand would draw differently
  (#813). Both also size a brand asset's upload from its byte limits. It is a package of its own
  rather than part of `core/api`, which declares and does nothing, and the console reaches no auth
  server package.
- `core/palette` is kernel because a brand's colors are checked against one list of contrast pairs
  wherever they are checked: the auth server's tests hold the built-in themes to it, its brand
  answers state a custom palette's warnings from the same check, and the admin console's live
  preview is to list them from it too, so the preview cannot list a pair the save does not (#815
  decision 6). For the same reason it holds the one derivation of a basic palette's colors, which
  the auth server saves and the preview draws. It also names the 23 color tokens and holds the test
  of a color, the two the auth server holds a stored palette to when it reads or writes a brand. It
  is a package of its own rather than part of `core/brandkit`, which holds what a brand draws rather
  than what its colors are held to, and the console reaches no auth server package.
- `core/stylingcontract` is kernel because the styling contract is one promise across both
  applications' pages: the auth server's tier and the admin console's each hold their templates to
  its lists through `core/guard.AssertStylingContract`, the docs test holds the reference page to
  them, and both renderers bind a page's `data-page` value through its `PageName`, so the two
  cannot read a page's name differently (#816). It is a package of its own rather than part of
  `core/brandkit`, which holds what a brand draws rather than what the pages promise any CSS, and
  the console reaches no auth server package.
- `core/api` is declarations and nothing else. The model-aware `ToResponse` mapping left for
  `authserver/internal/apimapping` in #350, the model-typed fields became DTOs of its own, and the
  reverse `ToUser()`/`ToGroup()` methods the admin console's `apiclient` called at 32 sites are
  gone; what remains is the wire contract the admin console decodes. The mapping was once #349's
  alone, but moving it without the fields would have left every exception row below standing, so
  the two were one issue.
- `core/builtin` is `kernel`, and package granularity cannot hold it: a constant is a string, so
  an auth-server-only name declared there costs nothing at compile time and breaks none of the
  rules below. Its symbols are held where every core package's are, one row each in
  `src/core/OWNERSHIP.md`, which rule 7 checks (#351, #420). It and `core/buildinfo` are what
  `core/constants` split into: the identifiers both processes agree on here, and the build stamp
  the release builds set with `-ldflags -X` there, values the linker writes rather than names two
  processes share (#442).

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
   appears, the row is wrong and the package is not dead: a mocks package one test keeps alive is the
   shape #333 deleted.
5. **foreign closure** — the modules in
   [Foreign modules](#foreign-modules-the-admin-console-must-not-compile) must be reachable from the
   admin console's production packages exactly as declared there.
6. **table hygiene** — every top-level `core` package has exactly one ownership row; every non-kernel
   row names an issue and every kernel row names none; every exception corresponds to a violation
   that exists right now; every violation has an exception.
7. **core symbols** — every exported symbol any `core` package declares has exactly one row in
   [`src/core/OWNERSHIP.md`](src/core/OWNERSHIP.md), stating the strongest of seven justifications
   the reference graph backs. Four are computed — `kernel`, `both-apps`, `own-package`, `reachable`
   — and three are asserted with a note the guard requires to be non-empty: `test-support`,
   `contract` and `moving`. A symbol with no row fails, a row for a symbol that is gone fails, and
   a row claiming less than the tree supports fails, because `core/constants` reached 139 symbols,
   108 named by a single process, with every rule above green throughout. That file's own header
   carries the definitions and the ceilings (#385).
8. **refused package** — no shipped binary links a package the
   [Refused packages](#packages-no-shipped-binary-may-link) table refuses, or any package under one:
   the test frameworks, the two packages that publish a process's internals on Go's default mux, and
   the package loading the guards read the source tree through.
   The shipped binaries are the three a release ships: the auth server, the admin console and the
   setup wizard. Each is walked from its `main` package, and the guard fails when one of the three is
   not where it looks, so a renamed main cannot drop out of the rule unnoticed (#331).

Rules 2 and 3 read production files only. A test may import a mock, a fixture or a helper from
anywhere; that is what test code is for, and holding it to the production graph would make
`core/guard` unusable from the tiers that call it. Rules 5 and 8 read production files too, because
they are about what lands in a shipped binary. Rules 1 and 4 read test files as well, for the reasons
given in their entries. Rule 7 reads both: its four computed justifications come from production
references, and so does what contradicts a `test-support` row, since that is about what a binary
links; what supports one is a reference from a test anywhere, or from the declaring package's own
production code.

## Temporary exceptions

Each row is one exact package edge that exists today and violates a rule above, with the issue that
removes it. An exception is not a waiver: when the edge goes, the row must go with it, and the guard
fails until it does. That is how the epic burned down, and the table is empty because it finished.
A row added here now is a debt taken on deliberately, not one inherited.

Both ends name a package, never a module and never a parent. A row granting `core/httpmw`
an edge grants it to `core/httpmw` alone: not to `core`, and not to `core/oauth`, which
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
| `github.com/boombuler/barcode` | QR rendering of the enrolment key | no | — |
| `golang.org/x/crypto/bcrypt` | provider-only password hashing | no | — |
| `github.com/yuin/goldmark` | Markdown rendering of legal documents, the auth server's alone (#622) | no | — |

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

`github.com/boombuler/barcode` is listed at `no` deliberately. `otp` is the auth server's (#346),
and since #646 it computes one-time codes and writes and reads enrolment keys with the standard
library, so barcode, which draws the enrolment QR code, is the one module it brings in. It is not
reachable now, it never will be, and the row states that it must not arrive.

The table is a declared list, not a discovery mechanism: it asserts these modules and says nothing
about a dependency nobody has written a row for. Closing that would mean an allowlist of every
module the admin console legitimately compiles, churned on every dependency change, which is a wider
rule than #332 asks for. #360 checked off the categories in its point 5 — database drivers,
sqlbuilder, OTP and image libraries, provider-only crypto — and each is a row above, asserted `no`.

## Packages no shipped binary may link

A shipped binary carries no test code, nothing that publishes the process's internals, and none of
the tooling the guards read the source tree with. The rows below are all three kinds.

The second kind is two packages of the standard library, `net/http/pprof` and `expvar`, which
register live heap, goroutine, CPU and trace profiles under `/debug/pprof/` and the process's
variables under `/debug/vars` on Go's default mux the moment they are linked. Neither server serves
the default mux, so linking them is one listener written the obvious way away from publishing
both, and a `grep` of the source would not say they were there: until #462 both servers linked them
through chi's middleware package, which no file needed for them. The rule holds them out by the same
walk as the test frameworks, through a dependency as through first-party code.

The third kind is `golang.org/x/tools`, Go's package loader and the analysis tooling around it, which
`core/pkgload` loads the source tree through for the guards and `ownershipdump`. It imports no test
framework, so the first kind's row would not catch it, and a production import of the loader would
link it into a binary with nothing going red. Its row is what holds the loader to being developer
tooling (#420).

The rest of this section is about the first kind. A shipped binary carries no test code: no assertion library, no mock, no test helper, and none of
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
module, which is where it differs from rule 5: the graph counts `core/guard`'s untagged files as
production, so a module-wide walk would find `testing` in `core` itself. The three mains are listed
in the guard, as `shippedMains`, rather than found by looking for `package main`, because
`schemadump`, `droptestdb`, `ownershipdump`, `imagescanreport`, `screenshotcheck` and the two
reference-data generators are main packages too and ship in no release. A file belongs to a binary the way the rest of this
document decides it: the `production` tag set and every other tag free, so a file in any of the five
release platforms counts. That is exact because every release build of all three sets `production`:
the servers' cross-compile script, the two server Dockerfiles and the setup wizard's cross-compile
script, so a `//go:build !production` helper anywhere in the wizard's closure stays out of the
wizard as the generated mocks stay out of the servers. A rule test in core's unit tier,
`TestReleaseBuilds_TheRealReleaseBuildsSetProduction`, reads those four files and fails when a
`go build` in them does not set the tag, when one of them is missing or holds no `go build`, when the
mains they build stop being exactly `shippedMains`, or when either script's `build_platform` calls
differ as a set from `pkgload.ReleasePlatforms`, the one declaration of the release platforms, which
the loader's release builds read too (#463, #420).

The refusal does not stop at the edge of the four modules. Past it, the walk follows the imports
the go command reports: `go list -deps` under the `production` tag, run over each shipped main for
each of the five release platforms, `pkgload.ReleasePlatforms`, with a release's cgo and
architecture levels, `pkgload.ReleaseEnv`, supplies the imports of every third-party and
standard-library package a main reaches, so a dependency whose own production code imports
`testing` or testify is refused like a first-party helper that does. First-party packages
are still read from source, with every tag but `production` free, because that covers all five
platforms at once. A package the go command cannot load is a finding, since the walk cannot see what
it imports.

### Refused packages

| package | what it is |
|---|---|
| `testing` | the standard library's test framework, and `testing/fstest`, `testing/iotest`, `testing/quick` and the rest under it |
| `net/http/httptest` | the standard library's test server and response recorder |
| `github.com/stretchr/testify` | the assertions, `require`, `mock` and `suite` the tests and the generated mocks are written with |
| `net/http/pprof` | the profiler, which registers live heap, goroutine, CPU and trace profiles under `/debug/pprof/` on the default mux |
| `expvar` | the process's variables, its command line and memory statistics among them, which it registers under `/debug/vars` on the default mux |
| `golang.org/x/tools` | Go's package loader and analysis tooling, which `core/pkgload` loads the source tree through for the guards and `ownershipdump` |

## The guard

`AssertArchitecture` lives in `src/core/guard/architecture.go` and is called from all three
module unit tiers, so it fires whichever tier runs — the same arrangement as the gofmt, error,
slog and agent-document guards.

It reads imports from the AST rather than matching text, so an import inside a comment or a string
is not a finding and a renamed import alias still is one. Rule 8 is the one rule that also asks the
go command, for what the packages outside the four modules import, since no source of theirs is
under the source root. It parses production and test files
separately because the rules above treat them differently.

Rule 7 lives beside them rather than in this file. `AssertSymbolOwnership` in
`src/core/guard/symbol_ownership.go` is called from the same three tiers and checks
`src/core/OWNERSHIP.md`; `src/core/cmd/ownershipdump` writes the computed rows from the same census,
`core/internal/refgraph`, so the tool and the guard cannot read the tree differently, and
`./run-tests.sh --type lint` runs the tool and fails on a tree it changed. The census loads the four
modules type-checked through `core/pkgload`, production code as every release build selects it, and
reads a reference as the object an identifier resolves to, so a local or a struct field spelled like
a symbol never justifies its namesake.

`src/core/guard/architecture_lint_test.go` is the core tier's caller;
`src/core/guard/architecture_rules_test.go`,
`src/core/guard/symbol_ownership_rules_test.go` and
`src/core/internal/refgraph/symbol_ownership_test.go` hold the guard's own tests. They run the rule table
against fixture trees written into a temp directory, one fixture per rule and per deliberate
leniency, and then take the real tables apart one row at a time — dropping each exception and
flipping each declared reachability, and adding a refused-package row for a package every shipped
binary links — because the tree satisfies this document by construction, so
passing proves nothing on its own. A guard that has quietly stopped matching anything passes a clean
tree exactly the way it passes a correct one; `errors_lint_test.go` sets out the same reasoning for
the same problem (#279).
