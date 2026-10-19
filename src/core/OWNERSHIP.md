# Core symbol ownership

Every exported symbol a package under `src/core` declares has a row here saying why `core` declares
it. `ARCHITECTURE.md` records the same thing two grains coarser — which module each top-level `core`
package must end up in, and why each symbol in `core/builtin` is still there — and this table
is the rest of that question, asked per symbol because that is the grain at which it decays.

Nothing else could catch what this catches. A package both processes genuinely share can still hide
an implementation only one of them uses, and no import rule notices: `core/constants` reached 139
symbols, 108 of them named by a single process, with every rule in `ARCHITECTURE.md` green at every
step (#351). The cost is that adding an exported symbol to `core` now costs a deliberate line, which
is the point rather than a side effect (#385).

## The justifications

A row states the strongest justification the tree backs, in this order. Four are computed from the
reference graph; three are asserted by a human and each of those needs a note.

| justification | who says it | means |
|---|---|---|
| `kernel` | computed | another `core` package names it in production |
| `both-apps` | computed | both applications name it in production |
| `own-package` | computed | the declaring package's own production code names it, from a declaration that is itself justified |
| `reachable` | computed | a justified declaration in the same package names it in its type or signature, or it is a const or var of a justified type |
| `test-support` | asserted, checked | no package a binary links names it in production, and something names it — a test anywhere, or the declaring package's own production code |
| `contract` | asserted | none of the above, and it is an intentionally stable cross-process value |
| `moving` | asserted | none of the above; the named issue carries it out of `core` |

`own-package` is here because the table asks two questions at once — does the package belong in
`core`, and does the symbol belong to the package — and they come apart for a package with
behaviour. `sessionstore.SessionIdBytes` is the width the store mints an identifier at, inside a
store both processes depend on; asserting a word for it would record a judgement where the tree
already has an answer. `reachable` is here for the same reason one step further out:
`api.RedirectURIResponse` is the element type of `ClientResponse.RedirectURIs`, and outside its
package only the auth server's mapping names it, so a `contract` row on it would be true and
misleading.

**Circular evidence is not evidence.** `kernel` and `both-apps` are read off references from outside
the declaring package and are the only seeds; `own-package` and `reachable` then require a source
that is already justified, and iterate to a fixpoint. Two references never count for the symbol they
name: a method's receiver, because a method rides with its receiver and so cannot vouch for it, and
the declared type of a const or var the same package writes. Without both, `core/enums` justified
itself — `AcrLevel` would have been `own-package` because `AcrLevel1 AcrLevel = …` and
`func (acr AcrLevel) IsHigherThan` named it — and the guard would have been blind to exactly the
package #385 deleted. An asserted row is not a seed either: two mutually referring symbols could otherwise
each be justified by the other's assertion, and the table would not even be stable under
regeneration.

**Every asserted row carries a note, and an empty one fails.** `contract`, `moving` and
`test-support` are the three nothing can check, and a word with nothing behind it is what turns an
escape hatch into a shrug. The guard checks only that the cell is non-empty, and that a `moving`
note names an issue; the reviewer does the rest.

## What is and is not a row

- **Production files only**, which is what the justifications are about and the same reading rules 2,
  3 and 7 of `ARCHITECTURE.md` already use. A test may name anything it likes from anywhere. The one
  place a test reference decides anything is the second half of a `test-support` row.
- **`test-support` asks a different question from the other six**, and deliberately: not "who names
  it" but "does a binary ship it", which is what `ARCHITECTURE.md`'s package table already says about
  `core/guard`. Test support here is written in files with no `_test.go` suffix — that package
  and the admin console's `handlertest` among them — so
  `adminconsole/internal/handlertest/json.go` naming `guard.Reporter` in a production file is not
  a reason to refuse `Reporter` the word. A reference from a package a binary links is.
- **A method is not a row.** It rides with its receiver type, which has one. `guard/constants-table`
  treats a method the same way.
- **One row per Go package, not per top-level directory.** `core/sessionstore` and a subpackage of it
  are two packages, so nothing hides in a subdirectory the table never enumerated. A package whose
  every file carries `//go:build !production` — the generated mock subpackages — declares nothing any
  build includes and has no rows.
- **`core/builtin` is here too**, and is also the subject of `ARCHITECTURE.md`'s fourth table. That
  table is stricter rather than looser: in a package of identifiers, an identifier its own sibling
  names is not use at all, so `own-package` would be vacuous there. `core/buildinfo`, the build
  stamp that left `core/constants` beside it, is held by this table alone (#442).

**ceiling:** a reference from outside the declaring package is a selector on the identifier the
import binds, resolved by name within the file. A package-level declaration shadowing that name is
caught; a local variable inside a function shadowing it would be read as the package. Nothing in this
tree does that, and closing it means type-checking every package in four modules rather than parsing
them. Revisit if a row ever rests on a reference that turns out to be a false one (#385). References
from inside the declaring package are not read that way — they carry no selector, and matching them
by spelling would let a local, a parameter or a struct field justify its namesake — so those are
resolved with `go/types` over each package's own syntax, against a stub importer. The residual
ceiling there is a dot import, of which this tree has none; revisit if one is ever written under
`src/`, which would need a real importer rather than a stub.

## Regenerating

```
cd src/core && go run ./cmd/ownershipdump
```

It rewrites the table below and nothing else: the prose above it is the document's own. It writes the
computed rows, preserves the asserted ones and every note, and refuses — naming each offender — to
invent a justification for a symbol that has none. `guard.AssertSymbolOwnership` compares the
result against the tree from all three module unit tiers, and `./run-tests.sh --type lint` runs the
command itself and fails on a tree it changed.

### Core symbol ownership

| package | symbol | justification | note |
|---|---|---|---|
| `core/adminpassword` | `Check` | contract | The one rule for which admin passwords the first start seeds the first administrator with. The setup wizard, which is not one of the two applications, writes the configuration that start reads, and the two must agree on which passwords seed, so the rule is defined once here for both rather than copied into each (#500 decision 6). |
| `core/api` | `AccountEmailVerificationSendResponse` | both-apps | — |
| `core/api` | `AccountLogoutFormPostResponse` | both-apps | — |
| `core/api` | `AccountLogoutRedirectResponse` | both-apps | — |
| `core/api` | `AccountLogoutRequest` | both-apps | — |
| `core/api` | `AccountLogoutResponseModeFormPost` | both-apps | — |
| `core/api` | `AccountOTPEnrollmentResponse` | both-apps | — |
| `core/api` | `AddGroupMemberRequest` | both-apps | — |
| `core/api` | `AuditLogResponse` | both-apps | — |
| `core/api` | `ClientLogoInfoResponse` | both-apps | — |
| `core/api` | `ClientLogoUploadResponse` | both-apps | — |
| `core/api` | `ClientResponse` | both-apps | — |
| `core/api` | `CreateClientRequest` | both-apps | — |
| `core/api` | `CreateClientResponse` | both-apps | — |
| `core/api` | `CreateGroupAttributeRequest` | both-apps | — |
| `core/api` | `CreateGroupAttributeResponse` | both-apps | — |
| `core/api` | `CreateGroupRequest` | both-apps | — |
| `core/api` | `CreateGroupResponse` | both-apps | — |
| `core/api` | `CreateResourceRequest` | both-apps | — |
| `core/api` | `CreateResourceResponse` | both-apps | — |
| `core/api` | `CreateUserAdminRequest` | both-apps | — |
| `core/api` | `CreateUserAttributeRequest` | both-apps | — |
| `core/api` | `CreateUserAttributeResponse` | both-apps | — |
| `core/api` | `CreateUserResponse` | both-apps | — |
| `core/api` | `ErrorResponse` | both-apps | — |
| `core/api` | `GenerateUserEmailVerificationCodeResponse` | contract | Admin API response DTO, which is what `core/api` is for. The auth server writes it and no admin console file reads it yet; #385 exempts this package by name. |
| `core/api` | `GetAuditEventTypesResponse` | both-apps | — |
| `core/api` | `GetAuditLogsResponse` | both-apps | — |
| `core/api` | `GetClientPermissionsResponse` | both-apps | — |
| `core/api` | `GetClientResponse` | both-apps | — |
| `core/api` | `GetClientSecretResponse` | both-apps | — |
| `core/api` | `GetClientSessionsResponse` | both-apps | — |
| `core/api` | `GetClientsResponse` | both-apps | — |
| `core/api` | `GetGroupAttributeResponse` | both-apps | — |
| `core/api` | `GetGroupAttributesResponse` | both-apps | — |
| `core/api` | `GetGroupMembersResponse` | both-apps | — |
| `core/api` | `GetGroupPermissionsResponse` | both-apps | — |
| `core/api` | `GetGroupResponse` | both-apps | — |
| `core/api` | `GetGroupsResponse` | both-apps | — |
| `core/api` | `GetPermissionsByResourceResponse` | both-apps | — |
| `core/api` | `GetPhoneCountriesResponse` | contract | The response of `GET /api/v1/admin/phone-countries`, a published admin API route that stays when the admin console stops calling it, because its pages build the list from `core/phonecountries` (#563 decisions 1 and 2). The auth server writes it and no admin console file reads it. |
| `core/api` | `GetResourceResponse` | both-apps | — |
| `core/api` | `GetResourcesResponse` | both-apps | — |
| `core/api` | `GetSettingsKeysResponse` | both-apps | — |
| `core/api` | `GetUserAttributeResponse` | both-apps | — |
| `core/api` | `GetUserAttributesResponse` | both-apps | — |
| `core/api` | `GetUserConsentsResponse` | both-apps | — |
| `core/api` | `GetUserGroupsResponse` | both-apps | — |
| `core/api` | `GetUserPermissionsResponse` | both-apps | — |
| `core/api` | `GetUserResponse` | both-apps | — |
| `core/api` | `GetUserSessionResponse` | contract | Admin API response DTO, which is what `core/api` is for. The auth server writes it and no admin console file reads it yet; #385 exempts this package by name. |
| `core/api` | `GetUserSessionsResponse` | both-apps | — |
| `core/api` | `GetUsersByPermissionResponse` | both-apps | — |
| `core/api` | `GroupAttributeResponse` | both-apps | — |
| `core/api` | `GroupResponse` | both-apps | — |
| `core/api` | `GroupWithPermissionResponse` | both-apps | — |
| `core/api` | `PermissionResponse` | both-apps | — |
| `core/api` | `PhoneCountryResponse` | contract | The element of `GET /api/v1/admin/phone-countries`, a published admin API route that stays when the admin console stops calling it, because its pages build the list from `core/phonecountries` (#563 decisions 1 and 2). The auth server writes it and no admin console file reads it. |
| `core/api` | `ProfilePictureInfoResponse` | both-apps | — |
| `core/api` | `ProfilePictureUploadResponse` | both-apps | — |
| `core/api` | `PublicSettingsResponse` | both-apps | — |
| `core/api` | `RedirectURIResponse` | reachable | — |
| `core/api` | `ResourcePermissionUpsert` | both-apps | — |
| `core/api` | `ResourceResponse` | both-apps | — |
| `core/api` | `SearchGroupsWithPermissionAnnotationResponse` | both-apps | — |
| `core/api` | `SearchUsersResponse` | both-apps | — |
| `core/api` | `SearchUsersWithGroupAnnotationResponse` | both-apps | — |
| `core/api` | `SearchUsersWithPermissionAnnotationResponse` | both-apps | — |
| `core/api` | `SendTestEmailRequest` | both-apps | — |
| `core/api` | `SessionClientResponse` | both-apps | — |
| `core/api` | `SessionLoadRequest` | both-apps | — |
| `core/api` | `SessionLoadResponse` | both-apps | — |
| `core/api` | `SessionOwnerResponse` | both-apps | — |
| `core/api` | `SessionTouchRequest` | both-apps | — |
| `core/api` | `SessionWriteRequest` | both-apps | — |
| `core/api` | `SessionWriteResponse` | both-apps | — |
| `core/api` | `SetPasswordTypeEmail` | both-apps | — |
| `core/api` | `SetPasswordTypeNow` | both-apps | — |
| `core/api` | `SettingsAuditLogsResponse` | both-apps | — |
| `core/api` | `SettingsEmailResponse` | both-apps | — |
| `core/api` | `SettingsGeneralResponse` | both-apps | — |
| `core/api` | `SettingsSessionsResponse` | both-apps | — |
| `core/api` | `SettingsSigningKeyResponse` | both-apps | — |
| `core/api` | `SettingsTokensResponse` | both-apps | — |
| `core/api` | `SettingsUIThemeResponse` | both-apps | — |
| `core/api` | `SuccessResponse` | both-apps | — |
| `core/api` | `UpdateAccountEmailRequest` | both-apps | — |
| `core/api` | `UpdateAccountOTPRequest` | both-apps | — |
| `core/api` | `UpdateAccountPasswordRequest` | both-apps | — |
| `core/api` | `UpdateAccountPhoneRequest` | both-apps | — |
| `core/api` | `UpdateClientAdministrativeScopesRequest` | both-apps | — |
| `core/api` | `UpdateClientAuthenticationRequest` | both-apps | — |
| `core/api` | `UpdateClientOAuth2FlowsRequest` | both-apps | — |
| `core/api` | `UpdateClientPermissionsRequest` | both-apps | — |
| `core/api` | `UpdateClientRedirectURIsRequest` | both-apps | — |
| `core/api` | `UpdateClientResponse` | both-apps | — |
| `core/api` | `UpdateClientSettingsRequest` | both-apps | — |
| `core/api` | `UpdateClientTokensRequest` | both-apps | — |
| `core/api` | `UpdateClientWebOriginsRequest` | both-apps | — |
| `core/api` | `UpdateGroupAttributeRequest` | both-apps | — |
| `core/api` | `UpdateGroupAttributeResponse` | both-apps | — |
| `core/api` | `UpdateGroupPermissionsRequest` | both-apps | — |
| `core/api` | `UpdateGroupRequest` | both-apps | — |
| `core/api` | `UpdateGroupResponse` | both-apps | — |
| `core/api` | `UpdateResourcePermissionsRequest` | both-apps | — |
| `core/api` | `UpdateResourceRequest` | both-apps | — |
| `core/api` | `UpdateResourceResponse` | both-apps | — |
| `core/api` | `UpdateSettingsAuditLogsRequest` | both-apps | — |
| `core/api` | `UpdateSettingsEmailRequest` | both-apps | — |
| `core/api` | `UpdateSettingsGeneralRequest` | both-apps | — |
| `core/api` | `UpdateSettingsSessionsRequest` | both-apps | — |
| `core/api` | `UpdateSettingsTokensRequest` | both-apps | — |
| `core/api` | `UpdateSettingsUIThemeRequest` | both-apps | — |
| `core/api` | `UpdateUserAddressRequest` | both-apps | — |
| `core/api` | `UpdateUserAttributeRequest` | both-apps | — |
| `core/api` | `UpdateUserAttributeResponse` | contract | Admin API response DTO, which is what `core/api` is for. The auth server writes it and no admin console file reads it yet; #385 exempts this package by name. |
| `core/api` | `UpdateUserEmailRequest` | both-apps | — |
| `core/api` | `UpdateUserEnabledRequest` | both-apps | — |
| `core/api` | `UpdateUserGroupsRequest` | both-apps | — |
| `core/api` | `UpdateUserOTPRequest` | both-apps | — |
| `core/api` | `UpdateUserPasswordRequest` | both-apps | — |
| `core/api` | `UpdateUserPermissionsRequest` | both-apps | — |
| `core/api` | `UpdateUserPhoneRequest` | both-apps | — |
| `core/api` | `UpdateUserProfileRequest` | both-apps | — |
| `core/api` | `UpdateUserResponse` | both-apps | — |
| `core/api` | `UserAttributeResponse` | both-apps | — |
| `core/api` | `UserConsentResponse` | both-apps | — |
| `core/api` | `UserResponse` | both-apps | — |
| `core/api` | `UserSessionDetailResponse` | both-apps | — |
| `core/api` | `UserSessionResponse` | reachable | — |
| `core/api` | `UserWithGroupMembershipResponse` | both-apps | — |
| `core/api` | `UserWithPermissionResponse` | both-apps | — |
| `core/api` | `VerifyAccountEmailRequest` | both-apps | — |
| `core/api` | `WebOriginResponse` | reachable | — |
| `core/boundedread` | `ErrResponseTooLarge` | own-package | — |
| `core/boundedread` | `Read` | kernel | — |
| `core/buildinfo` | `BuildDate` | both-apps | — |
| `core/buildinfo` | `GitCommit` | kernel | — |
| `core/buildinfo` | `Version` | kernel | — |
| `core/builtin` | `AdminConsoleClientIdentifier` | both-apps | — |
| `core/builtin` | `AdminConsoleSessionName` | both-apps | — |
| `core/builtin` | `AdminReadPermissionIdentifier` | own-package | — |
| `core/builtin` | `AuthServerPermissionIdentifiers` | both-apps | — |
| `core/builtin` | `AuthServerResourceIdentifier` | both-apps | — |
| `core/builtin` | `BrowserSessionsPermissionIdentifier` | both-apps | — |
| `core/builtin` | `ManageAccountPermissionIdentifier` | both-apps | — |
| `core/builtin` | `ManageClientsPermissionIdentifier` | own-package | — |
| `core/builtin` | `ManagePermissionIdentifier` | both-apps | — |
| `core/builtin` | `ManageSettingsPermissionIdentifier` | own-package | — |
| `core/builtin` | `ManageUsersPermissionIdentifier` | own-package | — |
| `core/countries` | `All` | kernel | — |
| `core/countries` | `ByAlpha2` | contract | The lookup half of the country table whose other half the admin console uses. Moving it would put one ISO 3166 dataset in two places. |
| `core/countries` | `Country` | kernel | — |
| `core/docsreader` | `Row` | kernel | — |
| `core/docsreader` | `Rows` | test-support | Test support: compiled into no binary, and the docs tests of every module read the site's tables through it. |
| `core/docsreader` | `Section` | kernel | — |
| `core/docsreader` | `SectionText` | own-package | — |
| `core/docsreader` | `Table` | test-support | Test support: compiled into no binary, and the docs tests of every module read the site's tables through it. |
| `core/docsreader` | `Tables` | test-support | Test support: compiled into no binary, and the docs tests of every module read the site's tables through it. |
| `core/errs` | `Errorf` | kernel | — |
| `core/errs` | `Join` | both-apps | — |
| `core/errs` | `New` | kernel | — |
| `core/errs` | `WithStack` | kernel | — |
| `core/errs` | `Wrap` | kernel | — |
| `core/errs` | `Wrapf` | kernel | — |
| `core/gender` | `Female` | own-package | — |
| `core/gender` | `Gender` | both-apps | — |
| `core/gender` | `IsValid` | contract | The `Gender` type's own bound, and the only statement of which of its values are legal, which is why a caller holding an int asks here rather than comparing against `Other` itself. The admin console names only `Gender`, so the tree justifies the type and not this (#385 decision 17). |
| `core/gender` | `Male` | reachable | — |
| `core/gender` | `Other` | own-package | — |
| `core/guard` | `AssertAgentDocs` | test-support | Test support: compiled into no binary, and nothing outside `core/guard` names it in production. |
| `core/guard` | `AssertArchitecture` | test-support | Test support: compiled into no binary, and nothing outside `core/guard` names it in production. |
| `core/guard` | `AssertAuditLogContext` | test-support | Test support: compiled into no binary, and nothing outside `core/guard` names it in production. |
| `core/guard` | `AssertContextValuesThroughAccessors` | test-support | Test support: compiled into no binary, and nothing outside `core/guard` names it in production. |
| `core/guard` | `AssertErrorCodeDoc` | test-support | Test support: compiled into no binary, and nothing outside `core/guard` names it in production. |
| `core/guard` | `AssertGeneratedMocksArePinned` | test-support | Test support: compiled into no binary, and nothing outside `core/guard` names it in production. |
| `core/guard` | `AssertGeneratedSourceTypeChecks` | test-support | Type-checks a generator's rendered output against its package; named only by the generators' render tests. |
| `core/guard` | `AssertGofmted` | test-support | Test support: compiled into no binary, and nothing outside `core/guard` names it in production. |
| `core/guard` | `AssertImportsOnly` | test-support | Test support: compiled into no binary, and nothing outside `core/guard` names it in production. |
| `core/guard` | `AssertMetricsCatalog` | test-support | Test support: compiled into no binary, and nothing outside `core/guard` names it in production. |
| `core/guard` | `AssertNoAgreementPointers` | test-support | Test support: compiled into no binary, and nothing outside `core/guard` names it in production. |
| `core/guard` | `AssertNoCredentialQueryFallback` | test-support | Test support: compiled into no binary, and nothing outside `core/guard` names it in production. |
| `core/guard` | `AssertNoDeadInterfaces` | test-support | Test support: compiled into no binary, and nothing outside `core/guard` names it in production. |
| `core/guard` | `AssertNoGuardInTestsReachedFrom` | test-support | Test support: compiled into no binary, and nothing outside `core/guard` names it in production. |
| `core/guard` | `AssertNoHTMLSinks` | test-support | Test support: compiled into no binary, and nothing outside `core/guard` names it in production. |
| `core/guard` | `AssertNoLegacyErrors` | test-support | Test support: compiled into no binary, and nothing outside `core/guard` names it in production. |
| `core/guard` | `AssertNoParentImport` | test-support | Test support: compiled into no binary, and nothing outside `core/guard` names it in production. |
| `core/guard` | `AssertNoStaleDeferredBodyCloses` | test-support | Test support: compiled into no binary, and nothing outside `core/guard` names it in production. |
| `core/guard` | `AssertNotCalledArity` | test-support | Test support: compiled into no binary, and nothing outside `core/guard` names it in production. |
| `core/guard` | `AssertRequestPathContext` | test-support | Test support: compiled into no binary, and nothing outside `core/guard` names it in production. |
| `core/guard` | `AssertScriptSyntax` | test-support | Test support: compiled into no binary, and nothing outside `core/guard` names it in production. |
| `core/guard` | `AssertSectionSays` | test-support | Test support: compiled into no binary, and nothing outside `core/guard` names it in production. |
| `core/guard` | `AssertSlogConvention` | test-support | Test support: compiled into no binary, and nothing outside `core/guard` names it in production. |
| `core/guard` | `AssertSymbolOwnership` | test-support | Test support: compiled into no binary, and nothing outside `core/guard` names it in production. |
| `core/guard` | `AssertTemplatesHtmlLangNotHardcoded` | test-support | Test support: compiled into no binary, and nothing outside `core/guard` names it in production. |
| `core/guard` | `AssertTemplatesNoCsrfField` | test-support | Test support: compiled into no binary, and nothing outside `core/guard` names it in production. |
| `core/guard` | `AssertTemplatesNoHTMLInTitle` | test-support | Test support: compiled into no binary, and nothing outside `core/guard` names it in production. |
| `core/guard` | `AssertWellFormedTemplates` | test-support | Test support: compiled into no binary, and nothing outside `core/guard` names it in production. |
| `core/guard` | `ContextValueExemption` | test-support | Test support: compiled into no binary, and nothing outside `core/guard` names it in production. |
| `core/guard` | `HTMLSinkAllowance` | test-support | Test support: compiled into no binary, and nothing outside `core/guard` names it in production. |
| `core/guard` | `ReadScripts` | test-support | Test support: compiled into no binary, and nothing outside `core/guard` names it in production. |
| `core/guard` | `Report` | test-support | Test support: compiled into no binary, and nothing outside `core/guard` names it in production. |
| `core/guard` | `Reporter` | test-support | Test support: compiled into no binary, and nothing outside `core/guard` names it in production. |
| `core/guard` | `Run` | test-support | Test support: compiled into no binary, and nothing outside `core/guard` names it in production. |
| `core/guard` | `Script` | test-support | Test support: compiled into no binary, and nothing outside `core/guard` names it in production. |
| `core/guard` | `ScriptEnd` | test-support | Test support: compiled into no binary, and nothing outside `core/guard` names it in production. |
| `core/guard` | `ScriptIdent` | test-support | Test support: compiled into no binary, and nothing outside `core/guard` names it in production. |
| `core/guard` | `ScriptKind` | test-support | Test support: compiled into no binary, and nothing outside `core/guard` names it in production. |
| `core/guard` | `ScriptPunct` | test-support | Test support: compiled into no binary, and nothing outside `core/guard` names it in production. |
| `core/guard` | `ScriptString` | test-support | Test support: compiled into no binary, and nothing outside `core/guard` names it in production. |
| `core/guard` | `ScriptTemplate` | test-support | Test support: compiled into no binary, and nothing outside `core/guard` names it in production. |
| `core/guard` | `ScriptToken` | test-support | Test support: compiled into no binary, and nothing outside `core/guard` names it in production. |
| `core/guard` | `ScriptValue` | test-support | Test support: compiled into no binary, and nothing outside `core/guard` names it in production. |
| `core/guard` | `SourceRoot` | test-support | Test support: compiled into no binary, and nothing outside `core/guard` names it in production. |
| `core/guard` | `TokenizeScript` | test-support | Test support: compiled into no binary, and nothing outside `core/guard` names it in production. |
| `core/hashutil` | `HashString` | both-apps | — |
| `core/hostport` | `Join` | both-apps | — |
| `core/hostport` | `Unbracket` | own-package | — |
| `core/hostport/hostporttest` | `SkipWithoutIPv6Loopback` | test-support | Test support: compiled into no binary, and nothing outside `core/hostport/hostporttest` names it in production. |
| `core/httpmw` | `BodyLimit` | both-apps | — |
| `core/httpmw` | `BodyLimitPolicy` | both-apps | — |
| `core/httpmw` | `CSRF` | both-apps | — |
| `core/httpmw` | `CSRFPolicy` | both-apps | — |
| `core/httpmw` | `CookieReset` | both-apps | — |
| `core/httpmw` | `ParseTrustedProxies` | both-apps | — |
| `core/httpmw` | `RealIP` | both-apps | — |
| `core/httpmw` | `RequestLogger` | both-apps | — |
| `core/httpmw` | `SecurityHeaders` | both-apps | — |
| `core/httpmw` | `SkipCSRF` | both-apps | — |
| `core/i18n` | `CatalogTag` | both-apps | The cross-process half of a refusal's language: the admin console sends it as `Accept-Language` on every admin API call, and the auth server resolves it against the same catalogs, so its answer is in the language of the console's page (#559 decision 3). The auth server names it in its own right too: the two registration mails read it to take the language the registration page was matched to, rather than the first `Accept-Language` tag alone (#607). It stays because it reads the localizer this package keeps private, as `Raw` does, and exporting the localizer to move it would undo #385 decision 11. |
| `core/i18n` | `ErrCodeAccountChangedSinceLoaded` | contract | Catalog key of an account API refusal whose `error_description` is written in the request's language while its `error_code` stays the call site's (#559 decision 2). Only the auth server writes it, and it is a stable identifier because an operator's override catalog names it to translate the sentence. |
| `core/i18n` | `ErrCodeAccountCurrentPasswordIncorrect` | contract | Catalog key of an account API refusal whose `error_description` is written in the request's language while its `error_code` stays the call site's (#559 decision 2). Only the auth server writes it, and it is a stable identifier because an operator's override catalog names it to translate the sentence. |
| `core/i18n` | `ErrCodeAccountCurrentPasswordRequired` | contract | Catalog key of an account API refusal whose `error_description` is written in the request's language while its `error_code` stays the call site's (#559 decision 2). Only the auth server writes it, and it is a stable identifier because an operator's override catalog names it to translate the sentence. |
| `core/i18n` | `ErrCodeAccountLogoutClientIdentifierInvalid` | contract | Catalog key of an account API refusal whose `error_description` is written in the request's language while its `error_code` stays the call site's (#559 decision 2). Only the auth server writes it, and it is a stable identifier because an operator's override catalog names it to translate the sentence. |
| `core/i18n` | `ErrCodeAccountLogoutClientUnresolved` | contract | Catalog key of an account API refusal whose `error_description` is written in the request's language while its `error_code` stays the call site's (#559 decision 2). Only the auth server writes it, and it is a stable identifier because an operator's override catalog names it to translate the sentence. |
| `core/i18n` | `ErrCodeAccountLogoutRedirectURINotRegistered` | contract | Catalog key of an account API refusal whose `error_description` is written in the request's language while its `error_code` stays the call site's (#559 decision 2). Only the auth server writes it, and it is a stable identifier because an operator's override catalog names it to translate the sentence. |
| `core/i18n` | `ErrCodeAccountLogoutRedirectURIRequired` | contract | Catalog key of an account API refusal whose `error_description` is written in the request's language while its `error_code` stays the call site's (#559 decision 2). Only the auth server writes it, and it is a stable identifier because an operator's override catalog names it to translate the sentence. |
| `core/i18n` | `ErrCodeAccountNewPasswordRequired` | contract | Catalog key of an account API refusal whose `error_description` is written in the request's language while its `error_code` stays the call site's (#559 decision 2). Only the auth server writes it, and it is a stable identifier because an operator's override catalog names it to translate the sentence. |
| `core/i18n` | `ErrCodeAccountOTPAlreadyEnabled` | contract | Catalog key of an account API refusal whose `error_description` is written in the request's language while its `error_code` stays the call site's (#559 decision 2). Only the auth server writes it, and it is a stable identifier because an operator's override catalog names it to translate the sentence. |
| `core/i18n` | `ErrCodeAccountOTPCodeInvalid` | contract | Catalog key of an account API refusal whose `error_description` is written in the request's language while its `error_code` stays the call site's (#559 decision 2). Only the auth server writes it, and it is a stable identifier because an operator's override catalog names it to translate the sentence. |
| `core/i18n` | `ErrCodeAccountOTPCodeRequired` | contract | Catalog key of an account API refusal whose `error_description` is written in the request's language while its `error_code` stays the call site's (#559 decision 2). Only the auth server writes it, and it is a stable identifier because an operator's override catalog names it to translate the sentence. |
| `core/i18n` | `ErrCodeAccountOTPEnrollmentNotPending` | contract | Catalog key of an account API refusal whose `error_description` is written in the request's language while its `error_code` stays the call site's (#559 decision 2). Only the auth server writes it, and it is a stable identifier because an operator's override catalog names it to translate the sentence. |
| `core/i18n` | `ErrCodeAccountOTPSecretKeyNotAccepted` | contract | Catalog key of an account API refusal whose `error_description` is written in the request's language while its `error_code` stays the call site's (#559 decision 2). Only the auth server writes it, and it is a stable identifier because an operator's override catalog names it to translate the sentence. |
| `core/i18n` | `ErrCodeAccountPasswordIncorrect` | contract | Catalog key of an account API refusal whose `error_description` is written in the request's language while its `error_code` stays the call site's (#559 decision 2). Only the auth server writes it, and it is a stable identifier because an operator's override catalog names it to translate the sentence. |
| `core/i18n` | `ErrCodeAddressAngleBrackets` | contract | Wire `error_code` value. `openapi.yaml` publishes it as a stable identifier, so a third-party client can switch on it although the admin console does not (#385 decision 10). |
| `core/i18n` | `ErrCodeAddressCountryInvalid` | both-apps | — |
| `core/i18n` | `ErrCodeAddressLine1TooLong` | both-apps | — |
| `core/i18n` | `ErrCodeAddressLine2TooLong` | both-apps | — |
| `core/i18n` | `ErrCodeAddressLocalityTooLong` | both-apps | — |
| `core/i18n` | `ErrCodeAddressPostalCodeTooLong` | both-apps | — |
| `core/i18n` | `ErrCodeAddressRegionTooLong` | both-apps | — |
| `core/i18n` | `ErrCodeAdminResourcePermissionsDescriptionHtmlNotAllowed` | both-apps | — |
| `core/i18n` | `ErrCodeAdminResourcePermissionsDescriptionTooLong` | both-apps | Catalog key of the permission description bound, which the admin console's permission form and the admin API's permission save both say (#559). |
| `core/i18n` | `ErrCodeAdminResourcePermissionsIdentifierRequired` | contract | Wire `error_code` value. `openapi.yaml` publishes it as a stable identifier, so a third-party client can switch on it although the admin console does not (#385 decision 10). |
| `core/i18n` | `ErrCodeAttributeKeyRequired` | both-apps | — |
| `core/i18n` | `ErrCodeAttributeValueAngleBrackets` | contract | Wire `error_code` value. `openapi.yaml` publishes it as a stable identifier, so a third-party client can switch on it although the admin console does not (#385 decision 10). |
| `core/i18n` | `ErrCodeAttributeValueTooLong` | contract | Catalog key of an admin API refusal whose `error_description` is written in the request's language while its `error_code` stays the call site's (#559 decision 2). Only the auth server writes it, and it is a stable identifier because an operator's override catalog names it to translate the sentence. |
| `core/i18n` | `ErrCodeAuthorizeClientDisabled` | contract | Wire `error_code` value. `openapi.yaml` publishes it as a stable identifier, so a third-party client can switch on it although the admin console does not (#385 decision 10). |
| `core/i18n` | `ErrCodeAuthorizeClientIdMissing` | contract | Wire `error_code` value. `openapi.yaml` publishes it as a stable identifier, so a third-party client can switch on it although the admin console does not (#385 decision 10). |
| `core/i18n` | `ErrCodeAuthorizeClientNotFound` | contract | Wire `error_code` value. `openapi.yaml` publishes it as a stable identifier, so a third-party client can switch on it although the admin console does not (#385 decision 10). |
| `core/i18n` | `ErrCodeAuthorizeRedirectURIMissing` | contract | Wire `error_code` value. `openapi.yaml` publishes it as a stable identifier, so a third-party client can switch on it although the admin console does not (#385 decision 10). |
| `core/i18n` | `ErrCodeAuthorizeRedirectURINotAbsolute` | contract | Wire `error_code` value. `openapi.yaml` publishes it as a stable identifier, so a third-party client can switch on it although the admin console does not (#385 decision 10). |
| `core/i18n` | `ErrCodeAuthorizeRedirectURINotRegistered` | contract | Wire `error_code` value. `openapi.yaml` publishes it as a stable identifier, so a third-party client can switch on it although the admin console does not (#385 decision 10). |
| `core/i18n` | `ErrCodeClientAdministrativeScopesAllowedRequired` | contract | Catalog key of an admin API refusal whose `error_description` is written in the request's language while its `error_code` stays the call site's (#559 decision 2). Only the auth server writes it, and it is a stable identifier because an operator's override catalog names it to translate the sentence. |
| `core/i18n` | `ErrCodeClientAdministrativeScopesConsoleAlwaysAllowed` | contract | Catalog key of an admin API refusal whose `error_description` is written in the request's language while its `error_code` stays the call site's (#559 decision 2). Only the auth server writes it, and it is a stable identifier because an operator's override catalog names it to translate the sentence. |
| `core/i18n` | `ErrCodeClientDefaultAcrInvalid` | contract | Catalog key of an admin API refusal whose `error_description` is written in the request's language while its `error_code` stays the call site's (#559 decision 2). Only the auth server writes it, and it is a stable identifier because an operator's override catalog names it to translate the sentence. |
| `core/i18n` | `ErrCodeClientDefaultAcrNotApplicable` | contract | Catalog key of an admin API refusal whose `error_description` is written in the request's language while its `error_code` stays the call site's (#559 decision 2). Only the auth server writes it, and it is a stable identifier because an operator's override catalog names it to translate the sentence. |
| `core/i18n` | `ErrCodeClientDisplayNameTooLong` | contract | Catalog key of an admin API refusal whose `error_description` is written in the request's language while its `error_code` stays the call site's (#559 decision 2). Only the auth server writes it, and it is a stable identifier because an operator's override catalog names it to translate the sentence. |
| `core/i18n` | `ErrCodeClientIdentifierInUse` | contract | Catalog key of an admin API refusal whose `error_description` is written in the request's language while its `error_code` stays the call site's (#559 decision 2). Only the auth server writes it, and it is a stable identifier because an operator's override catalog names it to translate the sentence. |
| `core/i18n` | `ErrCodeClientIdentifierNamesResource` | contract | Catalog key of an admin API refusal whose `error_description` is written in the request's language while its `error_code` stays the call site's (#559 decision 2). Only the auth server writes it, and it is a stable identifier because an operator's override catalog names it to translate the sentence. |
| `core/i18n` | `ErrCodeClientIdentifierRequired` | both-apps | — |
| `core/i18n` | `ErrCodeClientPermissionsClientCredentialsDisabled` | contract | Catalog key of an admin API refusal whose `error_description` is written in the request's language while its `error_code` stays the call site's (#559 decision 2). Only the auth server writes it, and it is a stable identifier because an operator's override catalog names it to translate the sentence. |
| `core/i18n` | `ErrCodeClientRedirectURIEmpty` | contract | Catalog key of an admin API refusal whose `error_description` is written in the request's language while its `error_code` stays the call site's (#559 decision 2). Only the auth server writes it, and it is a stable identifier because an operator's override catalog names it to translate the sentence. |
| `core/i18n` | `ErrCodeClientRedirectURIInsecureHTTP` | contract | Catalog key of an admin API refusal whose `error_description` is written in the request's language while its `error_code` stays the call site's (#559 decision 2). Only the auth server writes it, and it is a stable identifier because an operator's override catalog names it to translate the sentence. |
| `core/i18n` | `ErrCodeClientRedirectURIInvalid` | contract | Catalog key of an admin API refusal whose `error_description` is written in the request's language while its `error_code` stays the call site's (#559 decision 2). Only the auth server writes it, and it is a stable identifier because an operator's override catalog names it to translate the sentence. |
| `core/i18n` | `ErrCodeClientRedirectURINotAbsolute` | contract | Catalog key of an admin API refusal whose `error_description` is written in the request's language while its `error_code` stays the call site's (#559 decision 2). Only the auth server writes it, and it is a stable identifier because an operator's override catalog names it to translate the sentence. |
| `core/i18n` | `ErrCodeClientRedirectURITooLong` | contract | Catalog key of an admin API refusal whose `error_description` is written in the request's language while its `error_code` stays the call site's (#559 decision 2). Only the auth server writes it, and it is a stable identifier because an operator's override catalog names it to translate the sentence. |
| `core/i18n` | `ErrCodeClientRedirectURIsDuplicate` | contract | Catalog key of an admin API refusal whose `error_description` is written in the request's language while its `error_code` stays the call site's (#559 decision 2). Only the auth server writes it, and it is a stable identifier because an operator's override catalog names it to translate the sentence. |
| `core/i18n` | `ErrCodeClientRedirectURIsNoRedirectFlow` | contract | Catalog key of an admin API refusal whose `error_description` is written in the request's language while its `error_code` stays the call site's (#559 decision 2). Only the auth server writes it, and it is a stable identifier because an operator's override catalog names it to translate the sentence. |
| `core/i18n` | `ErrCodeClientRedirectURIsTooMany` | contract | Catalog key of an admin API refusal whose `error_description` is written in the request's language while its `error_code` stays the call site's (#559 decision 2). Only the auth server writes it, and it is a stable identifier because an operator's override catalog names it to translate the sentence. |
| `core/i18n` | `ErrCodeClientSecretInvalid` | contract | Catalog key of an admin API refusal whose `error_description` is written in the request's language while its `error_code` stays the call site's (#559 decision 2). Only the auth server writes it, and it is a stable identifier because an operator's override catalog names it to translate the sentence. |
| `core/i18n` | `ErrCodeClientSelfRegisteredIdentifierFixed` | contract | Catalog key of an admin API refusal whose `error_description` is written in the request's language while its `error_code` stays the call site's (#559 decision 2). Only the auth server writes it, and it is a stable identifier because an operator's override catalog names it to translate the sentence. |
| `core/i18n` | `ErrCodeClientSystemLevelDeleteNotAllowed` | contract | Catalog key of an admin API refusal whose `error_description` is written in the request's language while its `error_code` stays the call site's (#559 decision 2). Only the auth server writes it, and it is a stable identifier because an operator's override catalog names it to translate the sentence. |
| `core/i18n` | `ErrCodeClientSystemLevelIdentifierFixed` | contract | Catalog key of an admin API refusal whose `error_description` is written in the request's language while its `error_code` stays the call site's (#559 decision 2). Only the auth server writes it, and it is a stable identifier because an operator's override catalog names it to translate the sentence. |
| `core/i18n` | `ErrCodeClientTokensIncludeClaimsInAccessTokenInvalid` | contract | Catalog key of an admin API refusal whose `error_description` is written in the request's language while its `error_code` stays the call site's (#559 decision 2). Only the auth server writes it, and it is a stable identifier because an operator's override catalog names it to translate the sentence. |
| `core/i18n` | `ErrCodeClientTokensIncludeClaimsInIdTokenInvalid` | contract | Catalog key of an admin API refusal whose `error_description` is written in the request's language while its `error_code` stays the call site's (#559 decision 2). Only the auth server writes it, and it is a stable identifier because an operator's override catalog names it to translate the sentence. |
| `core/i18n` | `ErrCodeClientTokensOfflineIdleTimeoutAboveMaxLifetime` | contract | Catalog key of an admin API refusal whose `error_description` is written in the request's language while its `error_code` stays the call site's (#559 decision 2). Only the auth server writes it, and it is a stable identifier because an operator's override catalog names it to translate the sentence. |
| `core/i18n` | `ErrCodeClientTokensOfflineIdleTimeoutOutOfRange` | contract | Catalog key of an admin API refusal whose `error_description` is written in the request's language while its `error_code` stays the call site's (#559 decision 2). Only the auth server writes it, and it is a stable identifier because an operator's override catalog names it to translate the sentence. |
| `core/i18n` | `ErrCodeClientTokensOfflineMaxLifetimeOutOfRange` | contract | Catalog key of an admin API refusal whose `error_description` is written in the request's language while its `error_code` stays the call site's (#559 decision 2). Only the auth server writes it, and it is a stable identifier because an operator's override catalog names it to translate the sentence. |
| `core/i18n` | `ErrCodeClientTokensTokenExpirationOutOfRange` | contract | Catalog key of an admin API refusal whose `error_description` is written in the request's language while its `error_code` stays the call site's (#559 decision 2). Only the auth server writes it, and it is a stable identifier because an operator's override catalog names it to translate the sentence. |
| `core/i18n` | `ErrCodeClientWebOriginEmpty` | contract | Catalog key of an admin API refusal whose `error_description` is written in the request's language while its `error_code` stays the call site's (#559 decision 2). Only the auth server writes it, and it is a stable identifier because an operator's override catalog names it to translate the sentence. |
| `core/i18n` | `ErrCodeClientWebOriginInvalid` | contract | Catalog key of an admin API refusal whose `error_description` is written in the request's language while its `error_code` stays the call site's (#559 decision 2). Only the auth server writes it, and it is a stable identifier because an operator's override catalog names it to translate the sentence. |
| `core/i18n` | `ErrCodeClientWebOriginTooLong` | contract | Catalog key of an admin API refusal whose `error_description` is written in the request's language while its `error_code` stays the call site's (#559 decision 2). Only the auth server writes it, and it is a stable identifier because an operator's override catalog names it to translate the sentence. |
| `core/i18n` | `ErrCodeClientWebOriginsDuplicate` | contract | Catalog key of an admin API refusal whose `error_description` is written in the request's language while its `error_code` stays the call site's (#559 decision 2). Only the auth server writes it, and it is a stable identifier because an operator's override catalog names it to translate the sentence. |
| `core/i18n` | `ErrCodeClientWebOriginsExpectedInvalid` | contract | Catalog key of an admin API refusal whose `error_description` is written in the request's language while its `error_code` stays the call site's (#559 decision 2). Only the auth server writes it, and it is a stable identifier because an operator's override catalog names it to translate the sentence. |
| `core/i18n` | `ErrCodeClientWebsiteURLInvalid` | contract | Catalog key of an admin API refusal whose `error_description` is written in the request's language while its `error_code` stays the call site's (#559 decision 2). Only the auth server writes it, and it is a stable identifier because an operator's override catalog names it to translate the sentence. |
| `core/i18n` | `ErrCodeClientWebsiteURLSchemeInvalid` | contract | Catalog key of an admin API refusal whose `error_description` is written in the request's language while its `error_code` stays the call site's (#559 decision 2). Only the auth server writes it, and it is a stable identifier because an operator's override catalog names it to translate the sentence. |
| `core/i18n` | `ErrCodeClientWebsiteURLTooLong` | contract | Catalog key of an admin API refusal whose `error_description` is written in the request's language while its `error_code` stays the call site's (#559 decision 2). Only the auth server writes it, and it is a stable identifier because an operator's override catalog names it to translate the sentence. |
| `core/i18n` | `ErrCodeDescriptionAngleBrackets` | contract | Wire `error_code` value. `openapi.yaml` publishes it as a stable identifier, so a third-party client can switch on it although the admin console does not (#385 decision 10). |
| `core/i18n` | `ErrCodeDisplayNameAngleBrackets` | contract | Wire `error_code` value. `openapi.yaml` publishes it as a stable identifier, so a third-party client can switch on it although the admin console does not (#385 decision 10). |
| `core/i18n` | `ErrCodeEmailAlreadyExists` | contract | Catalog key of an admin API refusal whose `error_description` is written in the request's language while its `error_code` stays the call site's (#559 decision 2). Only the auth server writes it, and it is a stable identifier because an operator's override catalog names it to translate the sentence. |
| `core/i18n` | `ErrCodeEmailAlreadyRegistered` | both-apps | — |
| `core/i18n` | `ErrCodeEmailInvalidFormat` | both-apps | — |
| `core/i18n` | `ErrCodeEmailRequired` | both-apps | — |
| `core/i18n` | `ErrCodeEmailTooLong` | both-apps | — |
| `core/i18n` | `ErrCodeEmailVerificationAccountChanged` | contract | Catalog key of an admin API refusal whose `error_description` is written in the request's language while its `error_code` stays the call site's (#559 decision 2). Only the auth server writes it, and it is a stable identifier because an operator's override catalog names it to translate the sentence. |
| `core/i18n` | `ErrCodeEmailVerificationCodeInvalid` | contract | Catalog key of an account API refusal whose `error_description` is written in the request's language while its `error_code` stays the call site's (#559 decision 2). Only the auth server writes it, and it is a stable identifier because an operator's override catalog names it to translate the sentence. |
| `core/i18n` | `ErrCodeGroupAttributeGroupIdRequired` | contract | Catalog key of an admin API refusal whose `error_description` is written in the request's language while its `error_code` stays the call site's (#559 decision 2). Only the auth server writes it, and it is a stable identifier because an operator's override catalog names it to translate the sentence. |
| `core/i18n` | `ErrCodeGroupDescriptionTooLong` | contract | Catalog key of an admin API refusal whose `error_description` is written in the request's language while its `error_code` stays the call site's (#559 decision 2). Only the auth server writes it, and it is a stable identifier because an operator's override catalog names it to translate the sentence. |
| `core/i18n` | `ErrCodeGroupIdentifierInUse` | contract | Catalog key of an admin API refusal whose `error_description` is written in the request's language while its `error_code` stays the call site's (#559 decision 2). Only the auth server writes it, and it is a stable identifier because an operator's override catalog names it to translate the sentence. |
| `core/i18n` | `ErrCodeGroupIdentifierRequired` | contract | Catalog key of an admin API refusal whose `error_description` is written in the request's language while its `error_code` stays the call site's (#559 decision 2). Only the auth server writes it, and it is a stable identifier because an operator's override catalog names it to translate the sentence. |
| `core/i18n` | `ErrCodeGroupMemberAlreadyMember` | contract | Catalog key of an admin API refusal whose `error_description` is written in the request's language while its `error_code` stays the call site's (#559 decision 2). Only the auth server writes it, and it is a stable identifier because an operator's override catalog names it to translate the sentence. |
| `core/i18n` | `ErrCodeGroupMemberNotMember` | contract | Catalog key of an admin API refusal whose `error_description` is written in the request's language while its `error_code` stays the call site's (#559 decision 2). Only the auth server writes it, and it is a stable identifier because an operator's override catalog names it to translate the sentence. |
| `core/i18n` | `ErrCodeHandlerEmailRequired` | contract | Wire `error_code` value. `openapi.yaml` publishes it as a stable identifier, so a third-party client can switch on it although the admin console does not (#385 decision 10). |
| `core/i18n` | `ErrCodeHandlerPasswordConfirmationMismatch` | both-apps | — |
| `core/i18n` | `ErrCodeHandlerPasswordConfirmationRequired` | contract | Wire `error_code` value. `openapi.yaml` publishes it as a stable identifier, so a third-party client can switch on it although the admin console does not (#385 decision 10). |
| `core/i18n` | `ErrCodeHandlerPasswordRequired` | contract | Wire `error_code` value. `openapi.yaml` publishes it as a stable identifier, so a third-party client can switch on it although the admin console does not (#385 decision 10). |
| `core/i18n` | `ErrCodeIdentifierInvalidFormat` | kernel | — |
| `core/i18n` | `ErrCodeIdentifierTooLong` | kernel | — |
| `core/i18n` | `ErrCodeIdentifierTooShort` | kernel | — |
| `core/i18n` | `ErrCodeImageDimensionsTooLarge` | contract | Wire `error_code` value. `openapi.yaml` publishes it as a stable identifier, so a third-party client can switch on it although the admin console does not (#385 decision 10). |
| `core/i18n` | `ErrCodeImageDimensionsTooSmall` | contract | Wire `error_code` value. `openapi.yaml` publishes it as a stable identifier, so a third-party client can switch on it although the admin console does not (#385 decision 10). |
| `core/i18n` | `ErrCodeImageEmpty` | contract | Wire `error_code` value. `openapi.yaml` publishes it as a stable identifier, so a third-party client can switch on it although the admin console does not (#385 decision 10). |
| `core/i18n` | `ErrCodeImageTooLarge` | contract | Wire `error_code` value. `openapi.yaml` publishes it as a stable identifier, so a third-party client can switch on it although the admin console does not (#385 decision 10). |
| `core/i18n` | `ErrCodeImageUndecodable` | contract | Wire `error_code` value. `openapi.yaml` publishes it as a stable identifier, so a third-party client can switch on it although the admin console does not (#385 decision 10). |
| `core/i18n` | `ErrCodeImageUnsupportedType` | contract | Wire `error_code` value. `openapi.yaml` publishes it as a stable identifier, so a third-party client can switch on it although the admin console does not (#385 decision 10). |
| `core/i18n` | `ErrCodeImageUploadNoFile` | contract | Catalog key of an admin API refusal whose `error_description` is written in the request's language while its `error_code` stays the call site's (#559 decision 2). Only the auth server writes it, and it is a stable identifier because an operator's override catalog names it to translate the sentence. |
| `core/i18n` | `ErrCodeImageUploadTooLarge` | contract | Catalog key of an admin API refusal whose `error_description` is written in the request's language while its `error_code` stays the call site's (#559 decision 2). Only the auth server writes it, and it is a stable identifier because an operator's override catalog names it to translate the sentence. |
| `core/i18n` | `ErrCodeLastAdministrator` | contract | Catalog key of an admin API refusal whose `error_description` is written in the request's language while its `error_code` stays the call site's (#559 decision 2). Only the auth server writes it, and it is a stable identifier because an operator's override catalog names it to translate the sentence. |
| `core/i18n` | `ErrCodeListSaveChangedConcurrently` | contract | Catalog key of an admin API refusal whose `error_description` is written in the request's language while its `error_code` stays the call site's (#559 decision 2). Only the auth server writes it, and it is a stable identifier because an operator's override catalog names it to translate the sentence. |
| `core/i18n` | `ErrCodeListSaveChangedSinceLoaded` | contract | Catalog key of an admin API refusal whose `error_description` is written in the request's language while its `error_code` stays the call site's (#559 decision 2). Only the auth server writes it, and it is a stable identifier because an operator's override catalog names it to translate the sentence. |
| `core/i18n` | `ErrCodeLoginAccountDisabled` | contract | Wire `error_code` value. `openapi.yaml` publishes it as a stable identifier, so a third-party client can switch on it although the admin console does not (#385 decision 10). |
| `core/i18n` | `ErrCodeLoginAuthFailed` | contract | Wire `error_code` value. `openapi.yaml` publishes it as a stable identifier, so a third-party client can switch on it although the admin console does not (#385 decision 10). |
| `core/i18n` | `ErrCodeLoginEmailRequired` | contract | Wire `error_code` value. `openapi.yaml` publishes it as a stable identifier, so a third-party client can switch on it although the admin console does not (#385 decision 10). |
| `core/i18n` | `ErrCodeLoginPasswordRequired` | contract | Wire `error_code` value. `openapi.yaml` publishes it as a stable identifier, so a third-party client can switch on it although the admin console does not (#385 decision 10). |
| `core/i18n` | `ErrCodeOtpAccountDisabled` | contract | Wire `error_code` value. `openapi.yaml` publishes it as a stable identifier, so a third-party client can switch on it although the admin console does not (#385 decision 10). |
| `core/i18n` | `ErrCodeOtpCodeRequired` | both-apps | — |
| `core/i18n` | `ErrCodeOtpIncorrectCode` | contract | Wire `error_code` value. `openapi.yaml` publishes it as a stable identifier, so a third-party client can switch on it although the admin console does not (#385 decision 10). |
| `core/i18n` | `ErrCodePasswordLowercaseRequired` | both-apps | — |
| `core/i18n` | `ErrCodePasswordNumberRequired` | both-apps | — |
| `core/i18n` | `ErrCodePasswordSpecialCharRequired` | both-apps | — |
| `core/i18n` | `ErrCodePasswordTooLong` | both-apps | — |
| `core/i18n` | `ErrCodePasswordTooShort` | both-apps | — |
| `core/i18n` | `ErrCodePasswordUppercaseRequired` | both-apps | — |
| `core/i18n` | `ErrCodePermissionBuiltInDeleted` | contract | Catalog key of an admin API refusal whose `error_description` is written in the request's language while its `error_code` stays the call site's (#559 decision 2). Only the auth server writes it, and it is a stable identifier because an operator's override catalog names it to translate the sentence. |
| `core/i18n` | `ErrCodePermissionBuiltInRenamed` | contract | Catalog key of an admin API refusal whose `error_description` is written in the request's language while its `error_code` stays the call site's (#559 decision 2). Only the auth server writes it, and it is a stable identifier because an operator's override catalog names it to translate the sentence. |
| `core/i18n` | `ErrCodePermissionDuplicateIds` | contract | Catalog key of an admin API refusal whose `error_description` is written in the request's language while its `error_code` stays the call site's (#559 decision 2). Only the auth server writes it, and it is a stable identifier because an operator's override catalog names it to translate the sentence. |
| `core/i18n` | `ErrCodePermissionDuplicated` | contract | Catalog key of an admin API refusal whose `error_description` is written in the request's language while its `error_code` stays the call site's (#559 decision 2). Only the auth server writes it, and it is a stable identifier because an operator's override catalog names it to translate the sentence. |
| `core/i18n` | `ErrCodePermissionIdentifierInUse` | contract | Catalog key of an admin API refusal whose `error_description` is written in the request's language while its `error_code` stays the call site's (#559 decision 2). Only the auth server writes it, and it is a stable identifier because an operator's override catalog names it to translate the sentence. |
| `core/i18n` | `ErrCodePermissionIdentifierRequired` | contract | Catalog key of an admin API refusal whose `error_description` is written in the request's language while its `error_code` stays the call site's (#559 decision 2). Only the auth server writes it, and it is a stable identifier because an operator's override catalog names it to translate the sentence. |
| `core/i18n` | `ErrCodePhoneCountryInvalid` | both-apps | — |
| `core/i18n` | `ErrCodePhoneCountryRequired` | both-apps | — |
| `core/i18n` | `ErrCodePhoneInvalidFormat` | both-apps | — |
| `core/i18n` | `ErrCodePhoneNumberRequired` | both-apps | — |
| `core/i18n` | `ErrCodePhoneNumberTooLong` | both-apps | — |
| `core/i18n` | `ErrCodePhoneNumberTooShort` | both-apps | — |
| `core/i18n` | `ErrCodePhoneSimplePattern` | both-apps | — |
| `core/i18n` | `ErrCodeProfileDobInFuture` | both-apps | — |
| `core/i18n` | `ErrCodeProfileDobInvalidFormat` | both-apps | — |
| `core/i18n` | `ErrCodeProfileFamilyNameInvalid` | both-apps | — |
| `core/i18n` | `ErrCodeProfileGenderInvalid` | both-apps | — |
| `core/i18n` | `ErrCodeProfileGivenNameInvalid` | both-apps | — |
| `core/i18n` | `ErrCodeProfileLocaleInvalid` | both-apps | — |
| `core/i18n` | `ErrCodeProfileMiddleNameInvalid` | both-apps | — |
| `core/i18n` | `ErrCodeProfileNicknameInvalid` | both-apps | — |
| `core/i18n` | `ErrCodeProfileUsernameInvalid` | both-apps | — |
| `core/i18n` | `ErrCodeProfileUsernameTaken` | both-apps | — |
| `core/i18n` | `ErrCodeProfileWebsiteInvalid` | both-apps | — |
| `core/i18n` | `ErrCodeProfileWebsiteTooLong` | both-apps | — |
| `core/i18n` | `ErrCodeProfileZoneInfoInvalid` | both-apps | — |
| `core/i18n` | `ErrCodeResourceDescriptionTooLong` | contract | Catalog key of an admin API refusal whose `error_description` is written in the request's language while its `error_code` stays the call site's (#559 decision 2). Only the auth server writes it, and it is a stable identifier because an operator's override catalog names it to translate the sentence. |
| `core/i18n` | `ErrCodeResourceIdentifierInUse` | contract | Catalog key of an admin API refusal whose `error_description` is written in the request's language while its `error_code` stays the call site's (#559 decision 2). Only the auth server writes it, and it is a stable identifier because an operator's override catalog names it to translate the sentence. |
| `core/i18n` | `ErrCodeResourceIdentifierNamesClient` | contract | Catalog key of an admin API refusal whose `error_description` is written in the request's language while its `error_code` stays the call site's (#559 decision 2). Only the auth server writes it, and it is a stable identifier because an operator's override catalog names it to translate the sentence. |
| `core/i18n` | `ErrCodeResourceIdentifierRequired` | contract | Catalog key of an admin API refusal whose `error_description` is written in the request's language while its `error_code` stays the call site's (#559 decision 2). Only the auth server writes it, and it is a stable identifier because an operator's override catalog names it to translate the sentence. |
| `core/i18n` | `ErrCodeResourceSystemLevelDeleteNotAllowed` | contract | Catalog key of an admin API refusal whose `error_description` is written in the request's language while its `error_code` stays the call site's (#559 decision 2). Only the auth server writes it, and it is a stable identifier because an operator's override catalog names it to translate the sentence. |
| `core/i18n` | `ErrCodeResourceSystemLevelIdentifierFixed` | contract | Catalog key of an admin API refusal whose `error_description` is written in the request's language while its `error_code` stays the call site's (#559 decision 2). Only the auth server writes it, and it is a stable identifier because an operator's override catalog names it to translate the sentence. |
| `core/i18n` | `ErrCodeSMTPNotEnabled` | contract | Catalog key of an account API refusal whose `error_description` is written in the request's language while its `error_code` stays the call site's (#559 decision 2). Only the auth server writes it, and it is a stable identifier because an operator's override catalog names it to translate the sentence. |
| `core/i18n` | `ErrCodeSettingsAppNameAngleBrackets` | contract | Wire `error_code` value. `openapi.yaml` publishes it as a stable identifier, so a third-party client can switch on it although the admin console does not (#385 decision 10). |
| `core/i18n` | `ErrCodeSettingsAuditLogsRetentionDaysNegative` | contract | Catalog key of an admin API refusal whose `error_description` is written in the request's language while its `error_code` stays the call site's (#559 decision 2). Only the auth server writes it, and it is a stable identifier because an operator's override catalog names it to translate the sentence. |
| `core/i18n` | `ErrCodeSettingsAuditLogsRetentionDaysTooLarge` | contract | Catalog key of an admin API refusal whose `error_description` is written in the request's language while its `error_code` stays the call site's (#559 decision 2). Only the auth server writes it, and it is a stable identifier because an operator's override catalog names it to translate the sentence. |
| `core/i18n` | `ErrCodeSettingsEmailAuthenticationRejected` | contract | Catalog key of an admin API refusal whose `error_description` is written in the request's language while its `error_code` stays the call site's (#559 decision 2). Only the auth server writes it, and it is a stable identifier because an operator's override catalog names it to translate the sentence. |
| `core/i18n` | `ErrCodeSettingsEmailConnectFailed` | contract | Catalog key of an admin API refusal whose `error_description` is written in the request's language while its `error_code` stays the call site's (#559 decision 2). Only the auth server writes it, and it is a stable identifier because an operator's override catalog names it to translate the sentence. |
| `core/i18n` | `ErrCodeSettingsEmailConnectFailedHostNotFound` | contract | Catalog key of an admin API refusal whose `error_description` is written in the request's language while its `error_code` stays the call site's (#559 decision 2). Only the auth server writes it, and it is a stable identifier because an operator's override catalog names it to translate the sentence. |
| `core/i18n` | `ErrCodeSettingsEmailConnectFailedRefused` | contract | Catalog key of an admin API refusal whose `error_description` is written in the request's language while its `error_code` stays the call site's (#559 decision 2). Only the auth server writes it, and it is a stable identifier because an operator's override catalog names it to translate the sentence. |
| `core/i18n` | `ErrCodeSettingsEmailConnectFailedTimedOut` | contract | Catalog key of an admin API refusal whose `error_description` is written in the request's language while its `error_code` stays the call site's (#559 decision 2). Only the auth server writes it, and it is a stable identifier because an operator's override catalog names it to translate the sentence. |
| `core/i18n` | `ErrCodeSettingsEmailDestinationRequired` | both-apps | — |
| `core/i18n` | `ErrCodeSettingsEmailMessageRefused` | contract | Catalog key of an admin API refusal whose `error_description` is written in the request's language while its `error_code` stays the call site's (#559 decision 2). Only the auth server writes it, and it is a stable identifier because an operator's override catalog names it to translate the sentence. |
| `core/i18n` | `ErrCodeSettingsEmailNoAuthentication` | contract | Catalog key of an admin API refusal whose `error_description` is written in the request's language while its `error_code` stays the call site's (#559 decision 2). Only the auth server writes it, and it is a stable identifier because an operator's override catalog names it to translate the sentence. |
| `core/i18n` | `ErrCodeSettingsEmailNoSupportedMechanism` | contract | Catalog key of an admin API refusal whose `error_description` is written in the request's language while its `error_code` stays the call site's (#559 decision 2). Only the auth server writes it, and it is a stable identifier because an operator's override catalog names it to translate the sentence. |
| `core/i18n` | `ErrCodeSettingsEmailPasswordUnencrypted` | contract | Catalog key of an admin API refusal whose `error_description` is written in the request's language while its `error_code` stays the call site's (#559 decision 2). Only the auth server writes it, and it is a stable identifier because an operator's override catalog names it to translate the sentence. |
| `core/i18n` | `ErrCodeSettingsEmailSMTPEncryptionInvalid` | contract | Catalog key of an admin API refusal whose `error_description` is written in the request's language while its `error_code` stays the call site's (#559 decision 2). Only the auth server writes it, and it is a stable identifier because an operator's override catalog names it to translate the sentence. |
| `core/i18n` | `ErrCodeSettingsEmailSMTPFromEmailRequired` | contract | Catalog key of an admin API refusal whose `error_description` is written in the request's language while its `error_code` stays the call site's (#559 decision 2). Only the auth server writes it, and it is a stable identifier because an operator's override catalog names it to translate the sentence. |
| `core/i18n` | `ErrCodeSettingsEmailSMTPFromEmailTooLong` | contract | Catalog key of an admin API refusal whose `error_description` is written in the request's language while its `error_code` stays the call site's (#559 decision 2). Only the auth server writes it, and it is a stable identifier because an operator's override catalog names it to translate the sentence. |
| `core/i18n` | `ErrCodeSettingsEmailSMTPFromNameTooLong` | contract | Catalog key of an admin API refusal whose `error_description` is written in the request's language while its `error_code` stays the call site's (#559 decision 2). Only the auth server writes it, and it is a stable identifier because an operator's override catalog names it to translate the sentence. |
| `core/i18n` | `ErrCodeSettingsEmailSMTPHostChanged` | contract | Catalog key of an admin API refusal whose `error_description` is written in the request's language while its `error_code` stays the call site's (#559 decision 2). Only the auth server writes it, and it is a stable identifier because an operator's override catalog names it to translate the sentence. |
| `core/i18n` | `ErrCodeSettingsEmailSMTPHostRequired` | contract | Catalog key of an admin API refusal whose `error_description` is written in the request's language while its `error_code` stays the call site's (#559 decision 2). Only the auth server writes it, and it is a stable identifier because an operator's override catalog names it to translate the sentence. |
| `core/i18n` | `ErrCodeSettingsEmailSMTPHostTooLong` | contract | Catalog key of an admin API refusal whose `error_description` is written in the request's language while its `error_code` stays the call site's (#559 decision 2). Only the auth server writes it, and it is a stable identifier because an operator's override catalog names it to translate the sentence. |
| `core/i18n` | `ErrCodeSettingsEmailSMTPPasswordAndClear` | contract | Catalog key of an admin API refusal whose `error_description` is written in the request's language while its `error_code` stays the call site's (#559 decision 2). Only the auth server writes it, and it is a stable identifier because an operator's override catalog names it to translate the sentence. |
| `core/i18n` | `ErrCodeSettingsEmailSMTPPasswordTooLong` | contract | Catalog key of an admin API refusal whose `error_description` is written in the request's language while its `error_code` stays the call site's (#559 decision 2). Only the auth server writes it, and it is a stable identifier because an operator's override catalog names it to translate the sentence. |
| `core/i18n` | `ErrCodeSettingsEmailSMTPPortOutOfRange` | contract | Catalog key of an admin API refusal whose `error_description` is written in the request's language while its `error_code` stays the call site's (#559 decision 2). Only the auth server writes it, and it is a stable identifier because an operator's override catalog names it to translate the sentence. |
| `core/i18n` | `ErrCodeSettingsEmailSMTPPortRequired` | contract | Catalog key of an admin API refusal whose `error_description` is written in the request's language while its `error_code` stays the call site's (#559 decision 2). Only the auth server writes it, and it is a stable identifier because an operator's override catalog names it to translate the sentence. |
| `core/i18n` | `ErrCodeSettingsEmailSMTPUsernameTooLong` | contract | Catalog key of an admin API refusal whose `error_description` is written in the request's language while its `error_code` stays the call site's (#559 decision 2). Only the auth server writes it, and it is a stable identifier because an operator's override catalog names it to translate the sentence. |
| `core/i18n` | `ErrCodeSettingsEmailSTARTTLSNotOffered` | contract | Catalog key of an admin API refusal whose `error_description` is written in the request's language while its `error_code` stays the call site's (#559 decision 2). Only the auth server writes it, and it is a stable identifier because an operator's override catalog names it to translate the sentence. |
| `core/i18n` | `ErrCodeSettingsEmailSendFailed` | contract | Catalog key of an admin API refusal whose `error_description` is written in the request's language while its `error_code` stays the call site's (#559 decision 2). Only the auth server writes it, and it is a stable identifier because an operator's override catalog names it to translate the sentence. |
| `core/i18n` | `ErrCodeSettingsEmailSendFailedHostNotFound` | contract | Catalog key of an admin API refusal whose `error_description` is written in the request's language while its `error_code` stays the call site's (#559 decision 2). Only the auth server writes it, and it is a stable identifier because an operator's override catalog names it to translate the sentence. |
| `core/i18n` | `ErrCodeSettingsEmailSendFailedRefused` | contract | Catalog key of an admin API refusal whose `error_description` is written in the request's language while its `error_code` stays the call site's (#559 decision 2). Only the auth server writes it, and it is a stable identifier because an operator's override catalog names it to translate the sentence. |
| `core/i18n` | `ErrCodeSettingsEmailSendFailedTimedOut` | contract | Catalog key of an admin API refusal whose `error_description` is written in the request's language while its `error_code` stays the call site's (#559 decision 2). Only the auth server writes it, and it is a stable identifier because an operator's override catalog names it to translate the sentence. |
| `core/i18n` | `ErrCodeSettingsEmailTLSFailed` | contract | Catalog key of an admin API refusal whose `error_description` is written in the request's language while its `error_code` stays the call site's (#559 decision 2). Only the auth server writes it, and it is a stable identifier because an operator's override catalog names it to translate the sentence. |
| `core/i18n` | `ErrCodeSettingsGeneralAppNameTooLong` | contract | Catalog key of an admin API refusal whose `error_description` is written in the request's language while its `error_code` stays the call site's (#559 decision 2). Only the auth server writes it, and it is a stable identifier because an operator's override catalog names it to translate the sentence. |
| `core/i18n` | `ErrCodeSettingsGeneralIssuerTooLong` | contract | Catalog key of an admin API refusal whose `error_description` is written in the request's language while its `error_code` stays the call site's (#559 decision 2). Only the auth server writes it, and it is a stable identifier because an operator's override catalog names it to translate the sentence. |
| `core/i18n` | `ErrCodeSettingsGeneralIssuerURIInvalid` | contract | Catalog key of an admin API refusal whose `error_description` is written in the request's language while its `error_code` stays the call site's (#559 decision 2). Only the auth server writes it, and it is a stable identifier because an operator's override catalog names it to translate the sentence. |
| `core/i18n` | `ErrCodeSettingsGeneralPasswordPolicyInvalid` | contract | Catalog key of an admin API refusal whose `error_description` is written in the request's language while its `error_code` stays the call site's (#559 decision 2). Only the auth server writes it, and it is a stable identifier because an operator's override catalog names it to translate the sentence. |
| `core/i18n` | `ErrCodeSettingsIssuerAngleBrackets` | contract | Wire `error_code` value. `openapi.yaml` publishes it as a stable identifier, so a third-party client can switch on it although the admin console does not (#385 decision 10). |
| `core/i18n` | `ErrCodeSettingsKeysKeyNotFound` | contract | Catalog key of an admin API refusal whose `error_description` is written in the request's language while its `error_code` stays the call site's (#559 decision 2). Only the auth server writes it, and it is a stable identifier because an operator's override catalog names it to translate the sentence. |
| `core/i18n` | `ErrCodeSettingsKeysOnlyPreviousRevocable` | contract | Catalog key of an admin API refusal whose `error_description` is written in the request's language while its `error_code` stays the call site's (#559 decision 2). Only the auth server writes it, and it is a stable identifier because an operator's override catalog names it to translate the sentence. |
| `core/i18n` | `ErrCodeSettingsKeysRotationInProgress` | contract | Catalog key of an admin API refusal whose `error_description` is written in the request's language while its `error_code` stays the call site's (#559 decision 2). Only the auth server writes it, and it is a stable identifier because an operator's override catalog names it to translate the sentence. |
| `core/i18n` | `ErrCodeSettingsSessionsIdleTimeoutAboveMaxLifetime` | contract | Catalog key of an admin API refusal whose `error_description` is written in the request's language while its `error_code` stays the call site's (#559 decision 2). Only the auth server writes it, and it is a stable identifier because an operator's override catalog names it to translate the sentence. |
| `core/i18n` | `ErrCodeSettingsSessionsIdleTimeoutNotPositive` | contract | Catalog key of an admin API refusal whose `error_description` is written in the request's language while its `error_code` stays the call site's (#559 decision 2). Only the auth server writes it, and it is a stable identifier because an operator's override catalog names it to translate the sentence. |
| `core/i18n` | `ErrCodeSettingsSessionsIdleTimeoutTooLarge` | contract | Catalog key of an admin API refusal whose `error_description` is written in the request's language while its `error_code` stays the call site's (#559 decision 2). Only the auth server writes it, and it is a stable identifier because an operator's override catalog names it to translate the sentence. |
| `core/i18n` | `ErrCodeSettingsSessionsMaxLifetimeNotPositive` | contract | Catalog key of an admin API refusal whose `error_description` is written in the request's language while its `error_code` stays the call site's (#559 decision 2). Only the auth server writes it, and it is a stable identifier because an operator's override catalog names it to translate the sentence. |
| `core/i18n` | `ErrCodeSettingsSessionsMaxLifetimeTooLarge` | contract | Catalog key of an admin API refusal whose `error_description` is written in the request's language while its `error_code` stays the call site's (#559 decision 2). Only the auth server writes it, and it is a stable identifier because an operator's override catalog names it to translate the sentence. |
| `core/i18n` | `ErrCodeSettingsSessionsMaxSessionsPerUserOutOfRange` | contract | Catalog key of an admin API refusal whose `error_description` is written in the request's language while its `error_code` stays the call site's (#559 decision 2). Only the auth server writes it, and it is a stable identifier because an operator's override catalog names it to translate the sentence. |
| `core/i18n` | `ErrCodeSettingsSessionsMaxSessionsPerUserRequired` | contract | Catalog key of an admin API refusal whose `error_description` is written in the request's language while its `error_code` stays the call site's (#559 decision 2). Only the auth server writes it, and it is a stable identifier because an operator's override catalog names it to translate the sentence. |
| `core/i18n` | `ErrCodeSettingsSmtpFromNameAngleBrackets` | contract | Wire `error_code` value. `openapi.yaml` publishes it as a stable identifier, so a third-party client can switch on it although the admin console does not (#385 decision 10). |
| `core/i18n` | `ErrCodeSettingsTokensOfflineIdleTimeoutNotPositive` | contract | Catalog key of an admin API refusal whose `error_description` is written in the request's language while its `error_code` stays the call site's (#559 decision 2). Only the auth server writes it, and it is a stable identifier because an operator's override catalog names it to translate the sentence. |
| `core/i18n` | `ErrCodeSettingsTokensOfflineIdleTimeoutTooLarge` | contract | Catalog key of an admin API refusal whose `error_description` is written in the request's language while its `error_code` stays the call site's (#559 decision 2). Only the auth server writes it, and it is a stable identifier because an operator's override catalog names it to translate the sentence. |
| `core/i18n` | `ErrCodeSettingsTokensOfflineMaxLifetimeNotPositive` | contract | Catalog key of an admin API refusal whose `error_description` is written in the request's language while its `error_code` stays the call site's (#559 decision 2). Only the auth server writes it, and it is a stable identifier because an operator's override catalog names it to translate the sentence. |
| `core/i18n` | `ErrCodeSettingsTokensOfflineMaxLifetimeTooLarge` | contract | Catalog key of an admin API refusal whose `error_description` is written in the request's language while its `error_code` stays the call site's (#559 decision 2). Only the auth server writes it, and it is a stable identifier because an operator's override catalog names it to translate the sentence. |
| `core/i18n` | `ErrCodeSettingsTokensTokenExpirationNotPositive` | contract | Catalog key of an admin API refusal whose `error_description` is written in the request's language while its `error_code` stays the call site's (#559 decision 2). Only the auth server writes it, and it is a stable identifier because an operator's override catalog names it to translate the sentence. |
| `core/i18n` | `ErrCodeSettingsTokensTokenExpirationTooLarge` | contract | Catalog key of an admin API refusal whose `error_description` is written in the request's language while its `error_code` stays the call site's (#559 decision 2). Only the auth server writes it, and it is a stable identifier because an operator's override catalog names it to translate the sentence. |
| `core/i18n` | `ErrCodeSettingsUIThemeInvalid` | contract | Catalog key of an admin API refusal whose `error_description` is written in the request's language while its `error_code` stays the call site's (#559 decision 2). Only the auth server writes it, and it is a stable identifier because an operator's override catalog names it to translate the sentence. |
| `core/i18n` | `ErrCodeUserEmailRequired` | contract | Catalog key of an admin API refusal whose `error_description` is written in the request's language while its `error_code` stays the call site's (#559 decision 2). Only the auth server writes it, and it is a stable identifier because an operator's override catalog names it to translate the sentence. |
| `core/i18n` | `ErrCodeUserEmailTooLong` | contract | Catalog key of an admin API refusal whose `error_description` is written in the request's language while its `error_code` stays the call site's (#559 decision 2). Only the auth server writes it, and it is a stable identifier because an operator's override catalog names it to translate the sentence. |
| `core/i18n` | `ErrCodeUserGroupsNotFound` | contract | Wire `error_code` value. `openapi.yaml` publishes it as a stable identifier, so a third-party client can switch on it although the admin console does not (#385 decision 10). |
| `core/i18n` | `ErrCodeUserGroupsTooMany` | contract | Catalog key of an admin API refusal whose `error_description` is written in the request's language while its `error_code` stays the call site's (#559 decision 2). Only the auth server writes it, and it is a stable identifier because an operator's override catalog names it to translate the sentence. |
| `core/i18n` | `ErrCodeUserNewPasswordRequired` | contract | Catalog key of an admin API refusal whose `error_description` is written in the request's language while its `error_code` stays the call site's (#559 decision 2). Only the auth server writes it, and it is a stable identifier because an operator's override catalog names it to translate the sentence. |
| `core/i18n` | `ErrCodeUserOTPEnableNotSupported` | contract | Catalog key of an admin API refusal whose `error_description` is written in the request's language while its `error_code` stays the call site's (#559 decision 2). Only the auth server writes it, and it is a stable identifier because an operator's override catalog names it to translate the sentence. |
| `core/i18n` | `ErrCodeUserOTPNotEnabled` | contract | Catalog key of an admin API refusal whose `error_description` is written in the request's language while its `error_code` stays the call site's (#559 decision 2). Only the auth server writes it, and it is a stable identifier because an operator's override catalog names it to translate the sentence. |
| `core/i18n` | `ErrCodeUserPasswordRequired` | contract | Catalog key of an admin API refusal whose `error_description` is written in the request's language while its `error_code` stays the call site's (#559 decision 2). Only the auth server writes it, and it is a stable identifier because an operator's override catalog names it to translate the sentence. |
| `core/i18n` | `ErrCodeUserSetPasswordTypeInvalid` | contract | Catalog key of an admin API refusal whose `error_description` is written in the request's language while its `error_code` stays the call site's (#559 decision 2). Only the auth server writes it, and it is a stable identifier because an operator's override catalog names it to translate the sentence. |
| `core/i18n` | `LoadBundle` | both-apps | — |
| `core/i18n` | `Locale` | both-apps | — |
| `core/i18n` | `LocaleTag` | both-apps | — |
| `core/i18n` | `LocalizedError` | both-apps | — |
| `core/i18n` | `NewLocalizedError` | kernel | — |
| `core/i18n` | `Raw` | contract | The un-templated half of the message catalog both processes compile. Only the admin console's `JSBootstrap` template function calls it today, the auth server's pages serving no client-side string table; it stays because it reads the localizer and the bundle this package keeps private, so moving it would export the state #385 decision 11 exists to keep unexported, and would put one catalog behind two renderers. The six template helpers that shared this argument read nothing of that state but `T` and `LocaleTag`, and moved into the admin console's `internal/render` in #442. |
| `core/i18n` | `ResolveRequestLocale` | kernel | — |
| `core/i18n` | `SanitizeUILocales` | own-package | — |
| `core/i18n` | `T` | kernel | — |
| `core/i18n` | `UILocalesReader` | reachable | — |
| `core/i18n` | `WithLocale` | both-apps | — |
| `core/inputvalidation` | `ContainsAngleBrackets` | both-apps | — |
| `core/inputvalidation` | `IdentifierValidator` | own-package | — |
| `core/inputvalidation` | `NewIdentifierValidator` | both-apps | — |
| `core/inputvalidation` | `TextLength` | both-apps | — |
| `core/internal/pinnedfetch` | `CheckSHA256` | kernel | — |
| `core/internal/pinnedfetch` | `Doer` | kernel | — |
| `core/internal/pinnedfetch` | `Get` | kernel | — |
| `core/internal/refgraph` | `BuildImportGraph` | kernel | — |
| `core/internal/refgraph` | `CheckOwnership` | kernel | — |
| `core/internal/refgraph` | `DocRow` | own-package | — |
| `core/internal/refgraph` | `ExemptByBuildConstraint` | kernel | — |
| `core/internal/refgraph` | `Flatten` | kernel | — |
| `core/internal/refgraph` | `ImportGraph` | kernel | — |
| `core/internal/refgraph` | `JustificationBothApps` | kernel | — |
| `core/internal/refgraph` | `JustificationContract` | kernel | — |
| `core/internal/refgraph` | `JustificationKernel` | kernel | — |
| `core/internal/refgraph` | `JustificationMoving` | kernel | — |
| `core/internal/refgraph` | `LocalImportName` | kernel | — |
| `core/internal/refgraph` | `ModulePath` | kernel | — |
| `core/internal/refgraph` | `OwnershipCheck` | own-package | — |
| `core/internal/refgraph` | `RenderSymbolOwnership` | kernel | — |
| `core/internal/refgraph` | `SelectedNames` | kernel | — |
| `core/internal/refgraph` | `TableUnder` | kernel | — |
| `core/internal/refgraph` | `Unparen` | kernel | — |
| `core/locales` | `All` | contract | The list half of the locale table whose lookup the auth server validates against. Moving it would put one locale list in two places. |
| `core/locales` | `ByID` | contract | The lookup half of the locale table whose list the admin console renders. Moving it would put one locale list in two places. |
| `core/locales` | `Locale` | contract | The row type both halves of the table share. |
| `core/localzone` | `Install` | both-apps | — |
| `core/logging` | `FieldForLog` | kernel | — |
| `core/logging` | `Install` | both-apps | — |
| `core/logging` | `MaxLoggedField` | own-package | — |
| `core/logging` | `RequestTargetForLog` | kernel | — |
| `core/logging` | `SafeLogValue` | own-package | — |
| `core/logging` | `WrapRequestID` | kernel | — |
| `core/logging/logtest` | `CaptureSlog` | test-support | Test support: compiled into no binary, and nothing outside `core/logging/logtest` names it in production. |
| `core/logging/logtest` | `CapturedRecord` | test-support | Test support: compiled into no binary, and nothing outside `core/logging/logtest` names it in production. |
| `core/logging/logtest` | `SlogCapture` | test-support | Test support: compiled into no binary, and nothing outside `core/logging/logtest` names it in production. |
| `core/metrics` | `Counter` | both-apps | — |
| `core/metrics` | `Described` | own-package | — |
| `core/metrics` | `DurationBuckets` | own-package | — |
| `core/metrics` | `Enum` | both-apps | — |
| `core/metrics` | `Family` | kernel | — |
| `core/metrics` | `Gauge` | own-package | — |
| `core/metrics` | `HTTPRequests` | both-apps | — |
| `core/metrics` | `Histogram` | own-package | — |
| `core/metrics` | `Label` | kernel | — |
| `core/metrics` | `NewRegistry` | both-apps | — |
| `core/metrics` | `RegisterBuildInfo` | both-apps | — |
| `core/metrics` | `RegisterRuntime` | both-apps | — |
| `core/metrics` | `Registry` | both-apps | — |
| `core/metrics` | `Sample` | own-package | — |
| `core/oauth` | `ConformErrorDescription` | both-apps | — |
| `core/oauth` | `ErrorDetail` | both-apps | — |
| `core/oauth` | `GeneratePKCECodeChallenge` | both-apps | — |
| `core/oauth` | `IsWellFormedSpaceDelimited` | kernel | — |
| `core/oauth` | `Jwk` | both-apps | — |
| `core/oauth` | `Jwks` | both-apps | — |
| `core/oauth` | `JwtToken` | both-apps | — |
| `core/oauth` | `NewErrorDetail` | own-package | — |
| `core/oauth` | `NewErrorDetailWithHTTPStatus` | both-apps | — |
| `core/oauth` | `SplitSpaceDelimited` | kernel | — |
| `core/oauth` | `TokenResponse` | both-apps | — |
| `core/phonecountries` | `All` | both-apps | — |
| `core/phonecountries` | `ByUniqueID` | contract | The lookup half of the phone country list, by the id the user row stores (`users.phone_number_country_uniqueid`). Moving it would put one list, whose ids are stored data, in two places (#563 decision 1). |
| `core/phonecountries` | `PhoneCountry` | own-package | — |
| `core/securerandom` | `String` | both-apps | — |
| `core/securerandom` | `StringFromAlphabet` | own-package | — |
| `core/sessionstore` | `Backend` | both-apps | — |
| `core/sessionstore` | `BrowserSessionCookie` | reachable | — |
| `core/sessionstore` | `ConditionalBackend` | kernel | — |
| `core/sessionstore` | `ConditionalStore` | contract | The auth server's browser session store: a `ServerSideStore` with the conditional write and rotation that apply only the caller's change to a fresh read (#579). Only the auth server builds it; it stays because its two writes seal, open, mint identifiers and set cookies with the keys and codec this package keeps private, which is where #579 decision 1 puts the conditional capability, so the admin console's store never carries it. |
| `core/sessionstore` | `ConfiguredKey` | both-apps | — |
| `core/sessionstore` | `ConfiguredKeys` | both-apps | — |
| `core/sessionstore` | `CookieLifetime` | reachable | — |
| `core/sessionstore` | `ErrChanged` | kernel | — |
| `core/sessionstore` | `ErrNotFound` | kernel | — |
| `core/sessionstore` | `ExpiresAt` | contract | The rule deciding when a browser session row stops being usable. The admin console's sessions live in rows the auth server's backend writes, so the rule is cross-process even though only the writing side calls it (#266). |
| `core/sessionstore` | `KeyPair` | both-apps | — |
| `core/sessionstore` | `MaxSessionDataBytes` | own-package | — |
| `core/sessionstore` | `MaxSessionWireBytes` | both-apps | — |
| `core/sessionstore` | `NewConditionalStore` | contract | The constructor of `ConditionalStore`, beside it for the same reason. Only the auth server builds it; it stays because its two writes seal, open, mint identifiers and set cookies with the keys and codec this package keeps private, which is where #579 decision 1 puts the conditional capability, so the admin console's store never carries it. |
| `core/sessionstore` | `NewServerSideStore` | both-apps | — |
| `core/sessionstore` | `NewSession` | own-package | — |
| `core/sessionstore` | `Options` | own-package | — |
| `core/sessionstore` | `ParseKeys` | both-apps | — |
| `core/sessionstore` | `PersistentCookie` | own-package | — |
| `core/sessionstore` | `PreAuthLifetime` | contract | The unauthenticated half of the `ExpiresAt` rule beside it, and the one value that decides it. |
| `core/sessionstore` | `PreviousKeysError` | both-apps | — |
| `core/sessionstore` | `Record` | kernel | — |
| `core/sessionstore` | `ServerSideStore` | own-package | — |
| `core/sessionstore` | `Session` | both-apps | — |
| `core/sessionstore` | `SessionIdBytes` | own-package | — |
| `core/sessionstore` | `Store` | kernel | — |
| `core/sessionstore` | `TouchThreshold` | own-package | — |
| `core/sessionstore/sessiontest` | `MemoryBackend` | test-support | Test support: the in-memory session backend, honouring expiry as the engines do, that tests across the two servers drive the real store over. Its own package precisely so no binary links it (#385). |
| `core/sessionstore/sessiontest` | `NewMemoryBackend` | test-support | Test support: the in-memory session backend, honouring expiry as the engines do, that tests across the two servers drive the real store over. Its own package precisely so no binary links it (#385). |
| `core/sourceroot` | `FindSourceRoot` | kernel | — |
| `core/sourceroot` | `ModuleDirs` | kernel | — |
| `core/timezones` | `All` | contract | The list half of the time zone table whose lookup the auth server validates against. Moving it would put one zone table in two places. |
| `core/timezones` | `ByZone` | contract | The lookup half of the time zone table whose list the admin console renders. Moving it would put one zone table in two places. |
| `core/timezones` | `Zone` | contract | The row type both halves of the table share. |
