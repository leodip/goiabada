# Database changes

Change SQL, migrations and transactional writes across SQLite, MySQL, PostgreSQL and SQL Server.

Paths in backticks are relative to the repository root unless a module directory is named. Read the
sections relevant to the change; [AGENTS.md](../../AGENTS.md) lists the common commands.

## Database Pattern

`data.Database` (`src/authserver/internal/data/database.go`) is the composition interface. The four
engine adapters embed `commondb.Database`; common resource files hold each engine's SQL side by
side. An adapter overrides only operations that need it. A call on `commondb.Database`'s own
receiver cannot dispatch to an adapter override; `TestDatabase_NoSelfCallToAnOverriddenMethod`
refuses such calls.
- All methods accept `ctx context.Context` then `tx *sql.Tx` (nil = no transaction); the context
  reaches `BeginTx`, `QueryContext` and `ExecContext` (#386)
- Every statement is plain SQL in each engine's own form, with no query builder: a `statement`
  (`commondb/statement.go`) holds its SQLite, MySQL, PostgreSQL and SQL Server text side by side in
  the shared implementation's file for its resource, and the handle's `Dialect` field
  (`data.Dialect`) picks the version that runs, so the text in the source is the text the engine
  receives. `TestStatements_EveryEngineHasItsVersion` refuses one missing a version; an IN list is
  written by `inList`, inside `forEachIdBatch` (#644)
- Each record's read column list and whole-row INSERT and UPDATE are written out per engine in
  `commondb/`, with a shared explicit scan function. The `db`, `fieldtag` and `fieldopt` tags stay
  on the records as the column contract: a `dont-update` column is protected by its absence from the
  UPDATE's text, and `TestRecordMapping_EveryRecordMatchesItsTagsOnEveryEngine` holds the SQL to the
  tags on all four engines through the scripted driver (#644)
- Nothing above the data layer takes the whole interface: each handler, middleware and service
  declares an unexported port beside the function that takes it, naming only what that file calls
  (#386)
- Schema in `src/authserver/internal/data/sqlitedb/schema.golden` (generated; see [Schema golden
  files](#schema-golden-files))
- Migrations are applied by Goiabada's own runner in `src/authserver/internal/data/migrator/`, built
  per engine by each `NewMigrator()`

**Supported**: SQLite, MySQL, PostgreSQL, SQL Server

## Transactions

Open every transaction through `RunInTransaction`; the data package's
`begin_transaction_lint_test.go` refuses a bare `BeginTransaction` in production code. The common
implementation in `src/authserver/internal/data/commondb/db.go` makes at most three attempts when
the engine aborts a transaction as a deadlock victim, including a deadlock reported at commit.
Keep attempt-local state inside the callback, return failures, and write the response and external
effects after it succeeds. Audit events describe the committed outcome.

Preserve the row locks that make security decisions atomic:

- A termination takes the session row first: it deletes it, or, for a session whose apps it tells,
  takes it with `AcquireUserSessionRow` and reads the apps before the deletion cascades them away.
  Issuance takes that row before inserting its code or signing implicit tokens in the same
  transaction, so neither slips past a termination's sweep before its commit (#139), and a sign-in
  adding an app to the session is either read by the termination or finds the session gone (#784).
  The termination reads the apps with `GetCommittedUserSessionClients`, which takes `FOR SHARE` on
  MySQL: under InnoDB's REPEATABLE READ an ordinary read after the wait answers the snapshot of the
  transaction's first read, without the app that sign-in added.
  A credential change and a user's deletion that tell apps take each of the user's session rows
  this way, in id order, after the user's row: the deletion takes it with `GetUserByIdForUpdate`.
- Refresh rotation takes the user's row first (`AcquireUserRow`), as credential changes do through
  their write and generation increment. A rotation cannot stamp a child from a token a revocation
  already moved past, and the revocation's sweep cannot miss that child (#131).
- An OTP claim is rechecked under the user's row (`otpcredential.OTPClaim.Recheck`) before binding
  it to a session or issuing it. Authenticator removal takes that row first and lowers sessions in
  the same transaction, so a removed authenticator's code cannot subsequently be bound or issued
  (#542).
- A credential change that emails the user reads the user's row with `GetUserByIdForUpdate` in the
  change's own transaction and addresses the notice to that row, not to a read from before it
  (#724). A password write and a new set of recovery codes read it first; the authenticator's
  establish, removal and disabling count read it after their write to that row; a recovery code's
  claim takes it first, the order a removal and a new set take the user's row and the codes in.

There is no additional global lock order. Concurrent transactions on the same account can still
deadlock on MySQL, PostgreSQL or SQL Server; the loser rolls back and is retried. Add a test that
forces a suspected deadlock and proves the retry resolves it, rather than changing the locking
policy to hide it (#301). SQLite's pool has one connection and cannot deadlock this way.

A commit failure other than a classified deadlock is never retried: the server may have committed
before the failure reached the caller. It carries `data.ErrCommitOutcomeUnknown`; the refresh
rotation endpoint answers 409 `ROTATION_OUTCOME_UNKNOWN`. Cancellation before the driver is asked
to commit rolls back without that tag. Cancellation while COMMIT is in flight carries it, even
when the driver returns the context's own error, as pgx and go-mssqldb do (#371).

## Multi-row writes and list saves

A request that writes more than one row validates the whole request first, bounds and duplicates
included, so a refusal writes nothing; then writes in one `RunInTransaction` whose body reads what
it needs on the transaction, returns each failure through `errs.Wrap` and writes no response, since
a deadlock victim's body is rerun; then answers, audit events after the commit. A save replacing a
whole list is the common case, and there are nine: a client's redirect URIs, sign-out redirect URIs,
web origins and introspection resources, user, group, client and resource permissions, and a user's
groups. Each requires the list as its caller loaded it (`expectedRedirectURIs` and its siblings;
absent or `null` is a 400, `[]` means an empty list was loaded), reads the stored rows on the
transaction, and answers 409 `CONCURRENT_UPDATE` with nothing written when they differ from it as a
set; otherwise it applies `replaceSet`'s plan, which deletes every row whose key is not wanted and
every extra copy of one that is, so a duplicate left by an overlap is repaired by the next save. A
unique-key race answers the same 409, through the one failure writer `writeListSaveFailure`. No list
save locks its list: overlapping saves merge item by item, and the data tier's `list_save_test.go`
shows it on MySQL, PostgreSQL and SQL Server. A row lock is for one row read, decided on and written
back with a security consequence, which today means #245's public/confidential switch
(`AcquireClientRow`), #139's issuance (`AcquireUserSessionRow`), #131's refresh rotation
(`AcquireUserRow`), #542's session writes (`AcquireUserSessionRow`) and one-time code claims
(`AcquireUserRow`), #407's settings section saves (`AcquireSettingsRow`), each of which reads
the settings row again under it and writes its own section onto what it read, through
`apihandlers.saveSettingsSection`, so a save of another section committed meanwhile is not written
back over (#428), #810's change of default brand and brand deletion (`AcquireSettingsRow`), which
read the settings row's `default_brand_id` under it: `MakeBrandDefault` then reads the brand and
writes the pointer, and `DeleteBrand` refuses the brand the pointer names, so a deletion racing a
change of default never leaves the pointer on a deleted brand, and the data tier's `brand_test.go`
shows each order on every engine; `UpdateSettings`, which the section saves write through, leaves
the pointer alone (`dont-update`), #812's client brand (`AcquireSettingsRow`): `SetClientBrand`
reads the brand under it and writes `clients.brand_id`, and `DeleteBrand` puts the brand's clients
back on the default under it before deleting, answering how many it moved, so an assignment racing
a deletion is either moved and counted or refused as a brand that does not exist, which
`client_brand_test.go` shows in each order on every engine; `UpdateClient` leaves the column alone
(`dont-update`), and #622's legal document lifecycle writes
(`AcquireLegalDocumentRow`): a draft
save, publish, retire, restore, delete and a change of apps each read the document again under its
row and decide on that, so a publish clears only the draft it froze, a save cannot rename a document
published meanwhile or undo a retirement, and the data tier's `legal_document_lifecycle_test.go`
shows each order on every engine. One list save also takes a row for that reason: a save adding to a client's
introspection resources takes the client's row (`AcquireClientRow`) and refuses a client it then
finds public, because making a client public takes that row first and clears the list in the same
transaction (#676)

## Brand assets

A brand asset's row (`brand_assets`) never changes after its upload, and nothing but the cleanup
worker's sweep deletes one (#813 decision 2). A brand names an asset in each of its six slots by a
nullable foreign key with no cascade, so replacing, emptying or deleting a brand only leaves the
asset unattached; `DeleteUnattachedBrandAssets` then deletes, in one statement on the claimed run,
every asset no slot names that is older than a day. No lock orders the sweep and a brand write. A
Save attaching an old unattached asset while the sweep runs makes the slot's foreign key refuse the
sweep's delete, which fails that run's step and is logged; the next run deletes the rest. A brand
write checks its slots' assets before it writes, so a sweep deleting one in between fails the write
on the same foreign key. The handler then reads the slots' assets again and answers the slot whose
asset is gone with that slot's refusal; a write that fails while every asset is still stored stays a
500. Reading a brand for a page reads
its assets with `GetBrandAssetsByIds`, which leaves out the bytes; only the public asset route reads
them, with `GetBrandAssetById`.

## A brand's footer links and contact

A brand's footer links are one `footer_links` text column holding the whole list as JSON
(`record.BrandFooterLinks`, `[]` for none), not a table (#814 decision 8): at most three, always
read and written whole with their brand and in order, and never looked up by a URL or a label, so
a brand save stays one statement, a page's brand read adds no query, and a brand's deletion or a
new built-in language needs nothing more. The engine cannot check the text, so every value is
validated before it is written (`apihandlers.validateBrandFooter`), and a read holds the stored text
to `record.ParseBrandFooterLinks`: a value that does not parse, or a link with no URL or no label,
reads as no links and is logged at Warn, and the page is still drawn. The support contact is three
plain columns, `support_email`, `support_url` and `support_phone`, `''` when unset. A list matched
item by item, as redirect URIs are on every sign-in, takes its own table and a list save instead.

## A brand's custom palette

A brand on the theme `custom` holds its palette in one nullable `palette` text column, as JSON
(`record.BrandPalette`): its mode, `basic` or `advanced`, and the 23 colors of each of the two
modes, `NULL` for a brand on a built-in theme (#815 decision 3). It is stored whole for the footer
links' reasons: read and written with its brand, never looked up by a color, so a page's brand read
stays one row. Both modes' 23 colors are stored whatever the mode, a basic palette's other 19 as
`palette.Derive` worked them out at the save, so what a page draws and what a warning describes is
what the row holds, and a later change to the derivation reaches a brand only when it is saved
again (decision 1). The engine cannot check the text, so `CreateBrand` and `UpdateBrand` refuse a
palette that is not exactly the 23 tokens of each mode, each `#rrggbb`, and a read holds the stored
text to the same shape: a value that does not parse reads as no palette and is logged at Warn, and
the brand is then drawn as one with an unknown theme. A palette is held to its shape, never to its
contrast: a failing pair never stops a write.

## A brand's custom CSS

A brand's custom CSS is one `custom_css` text column, `''` for none (#816 decision 4), read and
written whole with its brand for the footer links' reasons. It is unbounded on every engine: the
admin API bounds it to 65,536 bytes. The rules it is held to are the admin API's alone
(`apihandlers.validateBrandCustomCSS`, which runs `customcss.Check`): the data layer stores and
reads the text as given and checks nothing, so a value written to the row by hand reaches the
brand's full stylesheet unchecked.

## Email template edits

An administrator's edit of one email in one language is one row of `email_templates`, unique on
`email_template` and `language` (#818 decision 7). Each of `subject`, `button_label` and `body` is
`NULL` for a field left as the built-in text, and a row holds at least one of them:
`SaveEmailTemplate` refuses an edit with none, whose row the caller deletes with
`DeleteEmailTemplate` instead, which answers whether there was one. Nothing about an edit's validity
is stored. The save is one insert-or-replace statement per engine (`ON CONFLICT` on SQLite and
PostgreSQL, `ON DUPLICATE KEY UPDATE` on MySQL, `MERGE` under `HOLDLOCK` on SQL Server), so two
saves of one email and language leave the last one's edit and neither is refused as a second row;
the data tier's `email_template_test.go` shows two overlapping first saves on every engine. Two
first saves can deadlock each other on MySQL and SQL Server, so the caller saves inside
`RunInTransaction`. The record mapping test reads the statement through its `upsert` hook. The data
layer stores any email and language it is given, refusing only an empty one, one ending in a space
and one that is not ASCII, which the engines' `=` would fold onto another row; holding them to the
19 emails and the six built-in languages is the caller's.

## Schema golden files

Each engine's fully migrated catalog is recorded in
`src/authserver/internal/data/<engine>db/schema.golden`, and the data tier compares a freshly
migrated database against the file for the engine it is running on. A migration therefore has one
more step: `cd src/authserver && go run ./cmd/schemadump` inside the dev container, which
regenerates all four files at once, and commit them. Skip it and CI goes red on every database job.

## Migration source rules

The authserver internal tier runs `TestMigrationSource_TheFourCommittedDirectories` in
`src/authserver/internal/data`, which holds the four `migrations/` directories to the rules
decidable from the text alone: naming, pairing, one number meaning one change, the collation pins on
MySQL and SQL Server, a named `CONSTRAINT` on every added SQL Server `DEFAULT` and a spelled-out
`NULL` or `NOT NULL` on every `ALTER COLUMN`, and each `schema.golden`'s recorded version. A
migration landing on fewer than four engines therefore owes a `-- parity: <engines> only. <why>`
line in every up.sql carrying it, and a `.down.sql` with no statement in it owes `-- Migration
NNNNNN down: intentional no-op.`
