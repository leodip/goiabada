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
`countries.Country` is `All`'s element type, and outside its package only the auth server's
phone-country builder names it, so a `contract` row on it would be true and misleading.

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
| `core/api` | `GetPhoneCountriesResponse` | both-apps | — |
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
| `core/api` | `PhoneCountryResponse` | both-apps | — |
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
| `core/countries` | `All` | both-apps | — |
| `core/countries` | `ByAlpha2` | contract | The lookup half of the country table whose other half the admin console uses. Moving it would put one ISO 3166 dataset in two places. |
| `core/countries` | `Country` | own-package | — |
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
| `core/guard` | `AssertMetricsCatalog` | test-support | Test support: compiled into no binary, and nothing outside `core/guard` names it in production. |
| `core/guard` | `AssertNoAgreementPointers` | test-support | Test support: compiled into no binary, and nothing outside `core/guard` names it in production. |
| `core/guard` | `AssertNoCredentialQueryFallback` | test-support | Test support: compiled into no binary, and nothing outside `core/guard` names it in production. |
| `core/guard` | `AssertNoDeadInterfaces` | test-support | Test support: compiled into no binary, and nothing outside `core/guard` names it in production. |
| `core/guard` | `AssertNoLegacyErrors` | test-support | Test support: compiled into no binary, and nothing outside `core/guard` names it in production. |
| `core/guard` | `AssertNoParentImport` | test-support | Test support: compiled into no binary, and nothing outside `core/guard` names it in production. |
| `core/guard` | `AssertNotCalledArity` | test-support | Test support: compiled into no binary, and nothing outside `core/guard` names it in production. |
| `core/guard` | `AssertRequestPathContext` | test-support | Test support: compiled into no binary, and nothing outside `core/guard` names it in production. |
| `core/guard` | `AssertSlogConvention` | test-support | Test support: compiled into no binary, and nothing outside `core/guard` names it in production. |
| `core/guard` | `AssertSymbolOwnership` | test-support | Test support: compiled into no binary, and nothing outside `core/guard` names it in production. |
| `core/guard` | `AssertTemplatesHtmlLangNotHardcoded` | test-support | Test support: compiled into no binary, and nothing outside `core/guard` names it in production. |
| `core/guard` | `AssertTemplatesNoCsrfField` | test-support | Test support: compiled into no binary, and nothing outside `core/guard` names it in production. |
| `core/guard` | `AssertTemplatesNoHTMLInTitle` | test-support | Test support: compiled into no binary, and nothing outside `core/guard` names it in production. |
| `core/guard` | `ContextValueExemption` | test-support | Test support: compiled into no binary, and nothing outside `core/guard` names it in production. |
| `core/guard` | `Report` | test-support | Test support: compiled into no binary, and nothing outside `core/guard` names it in production. |
| `core/guard` | `Reporter` | test-support | Test support: compiled into no binary, and nothing outside `core/guard` names it in production. |
| `core/guard` | `Run` | test-support | Test support: compiled into no binary, and nothing outside `core/guard` names it in production. |
| `core/guard` | `SourceRoot` | test-support | Test support: compiled into no binary, and nothing outside `core/guard` names it in production. |
| `core/guard` | `WalkHTMLTemplates` | test-support | Test support: compiled into no binary, and nothing outside `core/guard` names it in production. |
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
| `core/i18n` | `ErrCodeAddressAngleBrackets` | contract | Wire `error_code` value. `openapi.yaml` publishes it as a stable identifier, so a third-party client can switch on it although the admin console does not (#385 decision 10). |
| `core/i18n` | `ErrCodeAddressCountryInvalid` | contract | Wire `error_code` value. `openapi.yaml` publishes it as a stable identifier, so a third-party client can switch on it although the admin console does not (#385 decision 10). |
| `core/i18n` | `ErrCodeAddressLine1TooLong` | contract | Wire `error_code` value. `openapi.yaml` publishes it as a stable identifier, so a third-party client can switch on it although the admin console does not (#385 decision 10). |
| `core/i18n` | `ErrCodeAddressLine2TooLong` | contract | Wire `error_code` value. `openapi.yaml` publishes it as a stable identifier, so a third-party client can switch on it although the admin console does not (#385 decision 10). |
| `core/i18n` | `ErrCodeAddressLocalityTooLong` | contract | Wire `error_code` value. `openapi.yaml` publishes it as a stable identifier, so a third-party client can switch on it although the admin console does not (#385 decision 10). |
| `core/i18n` | `ErrCodeAddressPostalCodeTooLong` | contract | Wire `error_code` value. `openapi.yaml` publishes it as a stable identifier, so a third-party client can switch on it although the admin console does not (#385 decision 10). |
| `core/i18n` | `ErrCodeAddressRegionTooLong` | contract | Wire `error_code` value. `openapi.yaml` publishes it as a stable identifier, so a third-party client can switch on it although the admin console does not (#385 decision 10). |
| `core/i18n` | `ErrCodeAdminResourcePermissionsDescriptionHtmlNotAllowed` | both-apps | — |
| `core/i18n` | `ErrCodeAdminResourcePermissionsDescriptionTooLong` | contract | Wire `error_code` value. `openapi.yaml` publishes it as a stable identifier, so a third-party client can switch on it although the admin console does not (#385 decision 10). |
| `core/i18n` | `ErrCodeAdminResourcePermissionsIdentifierRequired` | contract | Wire `error_code` value. `openapi.yaml` publishes it as a stable identifier, so a third-party client can switch on it although the admin console does not (#385 decision 10). |
| `core/i18n` | `ErrCodeAttributeValueAngleBrackets` | contract | Wire `error_code` value. `openapi.yaml` publishes it as a stable identifier, so a third-party client can switch on it although the admin console does not (#385 decision 10). |
| `core/i18n` | `ErrCodeAuthorizeAuthCodeNotEnabled` | contract | Wire `error_code` value. `openapi.yaml` publishes it as a stable identifier, so a third-party client can switch on it although the admin console does not (#385 decision 10). |
| `core/i18n` | `ErrCodeAuthorizeClientDisabled` | contract | Wire `error_code` value. `openapi.yaml` publishes it as a stable identifier, so a third-party client can switch on it although the admin console does not (#385 decision 10). |
| `core/i18n` | `ErrCodeAuthorizeClientIdMissing` | contract | Wire `error_code` value. `openapi.yaml` publishes it as a stable identifier, so a third-party client can switch on it although the admin console does not (#385 decision 10). |
| `core/i18n` | `ErrCodeAuthorizeClientNotFound` | contract | Wire `error_code` value. `openapi.yaml` publishes it as a stable identifier, so a third-party client can switch on it although the admin console does not (#385 decision 10). |
| `core/i18n` | `ErrCodeAuthorizeRedirectURIMissing` | contract | Wire `error_code` value. `openapi.yaml` publishes it as a stable identifier, so a third-party client can switch on it although the admin console does not (#385 decision 10). |
| `core/i18n` | `ErrCodeAuthorizeRedirectURINotAbsolute` | contract | Wire `error_code` value. `openapi.yaml` publishes it as a stable identifier, so a third-party client can switch on it although the admin console does not (#385 decision 10). |
| `core/i18n` | `ErrCodeAuthorizeRedirectURINotRegistered` | contract | Wire `error_code` value. `openapi.yaml` publishes it as a stable identifier, so a third-party client can switch on it although the admin console does not (#385 decision 10). |
| `core/i18n` | `ErrCodeDescriptionAngleBrackets` | contract | Wire `error_code` value. `openapi.yaml` publishes it as a stable identifier, so a third-party client can switch on it although the admin console does not (#385 decision 10). |
| `core/i18n` | `ErrCodeDisplayNameAngleBrackets` | contract | Wire `error_code` value. `openapi.yaml` publishes it as a stable identifier, so a third-party client can switch on it although the admin console does not (#385 decision 10). |
| `core/i18n` | `ErrCodeEmailAlreadyRegistered` | contract | Wire `error_code` value. `openapi.yaml` publishes it as a stable identifier, so a third-party client can switch on it although the admin console does not (#385 decision 10). |
| `core/i18n` | `ErrCodeEmailInvalidFormat` | contract | Wire `error_code` value. `openapi.yaml` publishes it as a stable identifier, so a third-party client can switch on it although the admin console does not (#385 decision 10). |
| `core/i18n` | `ErrCodeEmailRequired` | contract | Wire `error_code` value. `openapi.yaml` publishes it as a stable identifier, so a third-party client can switch on it although the admin console does not (#385 decision 10). |
| `core/i18n` | `ErrCodeEmailTooLong` | contract | Wire `error_code` value. `openapi.yaml` publishes it as a stable identifier, so a third-party client can switch on it although the admin console does not (#385 decision 10). |
| `core/i18n` | `ErrCodeHandlerEmailRequired` | contract | Wire `error_code` value. `openapi.yaml` publishes it as a stable identifier, so a third-party client can switch on it although the admin console does not (#385 decision 10). |
| `core/i18n` | `ErrCodeHandlerPasswordConfirmationMismatch` | contract | Wire `error_code` value. `openapi.yaml` publishes it as a stable identifier, so a third-party client can switch on it although the admin console does not (#385 decision 10). |
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
| `core/i18n` | `ErrCodeLoginAccountDisabled` | contract | Wire `error_code` value. `openapi.yaml` publishes it as a stable identifier, so a third-party client can switch on it although the admin console does not (#385 decision 10). |
| `core/i18n` | `ErrCodeLoginAuthFailed` | contract | Wire `error_code` value. `openapi.yaml` publishes it as a stable identifier, so a third-party client can switch on it although the admin console does not (#385 decision 10). |
| `core/i18n` | `ErrCodeLoginEmailRequired` | contract | Wire `error_code` value. `openapi.yaml` publishes it as a stable identifier, so a third-party client can switch on it although the admin console does not (#385 decision 10). |
| `core/i18n` | `ErrCodeLoginPasswordRequired` | contract | Wire `error_code` value. `openapi.yaml` publishes it as a stable identifier, so a third-party client can switch on it although the admin console does not (#385 decision 10). |
| `core/i18n` | `ErrCodeOtpAccountDisabled` | contract | Wire `error_code` value. `openapi.yaml` publishes it as a stable identifier, so a third-party client can switch on it although the admin console does not (#385 decision 10). |
| `core/i18n` | `ErrCodeOtpCodeRequired` | contract | Wire `error_code` value. `openapi.yaml` publishes it as a stable identifier, so a third-party client can switch on it although the admin console does not (#385 decision 10). |
| `core/i18n` | `ErrCodeOtpIncorrectCode` | contract | Wire `error_code` value. `openapi.yaml` publishes it as a stable identifier, so a third-party client can switch on it although the admin console does not (#385 decision 10). |
| `core/i18n` | `ErrCodePasswordLowercaseRequired` | contract | Wire `error_code` value. `openapi.yaml` publishes it as a stable identifier, so a third-party client can switch on it although the admin console does not (#385 decision 10). |
| `core/i18n` | `ErrCodePasswordNumberRequired` | contract | Wire `error_code` value. `openapi.yaml` publishes it as a stable identifier, so a third-party client can switch on it although the admin console does not (#385 decision 10). |
| `core/i18n` | `ErrCodePasswordSpecialCharRequired` | contract | Wire `error_code` value. `openapi.yaml` publishes it as a stable identifier, so a third-party client can switch on it although the admin console does not (#385 decision 10). |
| `core/i18n` | `ErrCodePasswordTooLong` | contract | Wire `error_code` value. `openapi.yaml` publishes it as a stable identifier, so a third-party client can switch on it although the admin console does not (#385 decision 10). |
| `core/i18n` | `ErrCodePasswordTooShort` | contract | Wire `error_code` value. `openapi.yaml` publishes it as a stable identifier, so a third-party client can switch on it although the admin console does not (#385 decision 10). |
| `core/i18n` | `ErrCodePasswordUppercaseRequired` | contract | Wire `error_code` value. `openapi.yaml` publishes it as a stable identifier, so a third-party client can switch on it although the admin console does not (#385 decision 10). |
| `core/i18n` | `ErrCodePhoneCountryInvalid` | contract | Wire `error_code` value. `openapi.yaml` publishes it as a stable identifier, so a third-party client can switch on it although the admin console does not (#385 decision 10). |
| `core/i18n` | `ErrCodePhoneCountryRequired` | contract | Wire `error_code` value. `openapi.yaml` publishes it as a stable identifier, so a third-party client can switch on it although the admin console does not (#385 decision 10). |
| `core/i18n` | `ErrCodePhoneInvalidFormat` | contract | Wire `error_code` value. `openapi.yaml` publishes it as a stable identifier, so a third-party client can switch on it although the admin console does not (#385 decision 10). |
| `core/i18n` | `ErrCodePhoneNumberRequired` | contract | Wire `error_code` value. `openapi.yaml` publishes it as a stable identifier, so a third-party client can switch on it although the admin console does not (#385 decision 10). |
| `core/i18n` | `ErrCodePhoneNumberTooLong` | contract | Wire `error_code` value. `openapi.yaml` publishes it as a stable identifier, so a third-party client can switch on it although the admin console does not (#385 decision 10). |
| `core/i18n` | `ErrCodePhoneNumberTooShort` | contract | Wire `error_code` value. `openapi.yaml` publishes it as a stable identifier, so a third-party client can switch on it although the admin console does not (#385 decision 10). |
| `core/i18n` | `ErrCodePhoneSimplePattern` | contract | Wire `error_code` value. `openapi.yaml` publishes it as a stable identifier, so a third-party client can switch on it although the admin console does not (#385 decision 10). |
| `core/i18n` | `ErrCodeProfileDobInFuture` | contract | Wire `error_code` value. `openapi.yaml` publishes it as a stable identifier, so a third-party client can switch on it although the admin console does not (#385 decision 10). |
| `core/i18n` | `ErrCodeProfileDobInvalidFormat` | contract | Wire `error_code` value. `openapi.yaml` publishes it as a stable identifier, so a third-party client can switch on it although the admin console does not (#385 decision 10). |
| `core/i18n` | `ErrCodeProfileFamilyNameInvalid` | contract | Wire `error_code` value. `openapi.yaml` publishes it as a stable identifier, so a third-party client can switch on it although the admin console does not (#385 decision 10). |
| `core/i18n` | `ErrCodeProfileGenderInvalid` | contract | Wire `error_code` value. `openapi.yaml` publishes it as a stable identifier, so a third-party client can switch on it although the admin console does not (#385 decision 10). |
| `core/i18n` | `ErrCodeProfileGivenNameInvalid` | contract | Wire `error_code` value. `openapi.yaml` publishes it as a stable identifier, so a third-party client can switch on it although the admin console does not (#385 decision 10). |
| `core/i18n` | `ErrCodeProfileLocaleInvalid` | contract | Wire `error_code` value. `openapi.yaml` publishes it as a stable identifier, so a third-party client can switch on it although the admin console does not (#385 decision 10). |
| `core/i18n` | `ErrCodeProfileMiddleNameInvalid` | contract | Wire `error_code` value. `openapi.yaml` publishes it as a stable identifier, so a third-party client can switch on it although the admin console does not (#385 decision 10). |
| `core/i18n` | `ErrCodeProfileNicknameInvalid` | contract | Wire `error_code` value. `openapi.yaml` publishes it as a stable identifier, so a third-party client can switch on it although the admin console does not (#385 decision 10). |
| `core/i18n` | `ErrCodeProfileUsernameInvalid` | contract | Wire `error_code` value. `openapi.yaml` publishes it as a stable identifier, so a third-party client can switch on it although the admin console does not (#385 decision 10). |
| `core/i18n` | `ErrCodeProfileUsernameTaken` | contract | Wire `error_code` value. `openapi.yaml` publishes it as a stable identifier, so a third-party client can switch on it although the admin console does not (#385 decision 10). |
| `core/i18n` | `ErrCodeProfileWebsiteInvalid` | contract | Wire `error_code` value. `openapi.yaml` publishes it as a stable identifier, so a third-party client can switch on it although the admin console does not (#385 decision 10). |
| `core/i18n` | `ErrCodeProfileWebsiteTooLong` | contract | Wire `error_code` value. `openapi.yaml` publishes it as a stable identifier, so a third-party client can switch on it although the admin console does not (#385 decision 10). |
| `core/i18n` | `ErrCodeProfileZoneInfoInvalid` | contract | Wire `error_code` value. `openapi.yaml` publishes it as a stable identifier, so a third-party client can switch on it although the admin console does not (#385 decision 10). |
| `core/i18n` | `ErrCodeSettingsAppNameAngleBrackets` | contract | Wire `error_code` value. `openapi.yaml` publishes it as a stable identifier, so a third-party client can switch on it although the admin console does not (#385 decision 10). |
| `core/i18n` | `ErrCodeSettingsIssuerAngleBrackets` | contract | Wire `error_code` value. `openapi.yaml` publishes it as a stable identifier, so a third-party client can switch on it although the admin console does not (#385 decision 10). |
| `core/i18n` | `ErrCodeSettingsSmtpFromNameAngleBrackets` | contract | Wire `error_code` value. `openapi.yaml` publishes it as a stable identifier, so a third-party client can switch on it although the admin console does not (#385 decision 10). |
| `core/i18n` | `ErrCodeUserGroupsNotFound` | contract | Wire `error_code` value. `openapi.yaml` publishes it as a stable identifier, so a third-party client can switch on it although the admin console does not (#385 decision 10). |
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
| `core/inputvalidation` | `CheckAdminPassword` | contract | The one rule for which admin passwords the first start seeds the first administrator with. The setup wizard, which is not one of the two applications, writes the configuration that start reads, and the two must agree on which passwords seed, so the rule is defined once here for both rather than copied into each (#500 decision 6). |
| `core/inputvalidation` | `ContainsAngleBrackets` | both-apps | — |
| `core/inputvalidation` | `IdentifierValidator` | own-package | — |
| `core/inputvalidation` | `NewIdentifierValidator` | both-apps | — |
| `core/internal/pinnedfetch` | `CheckSHA256` | kernel | — |
| `core/internal/pinnedfetch` | `Doer` | kernel | — |
| `core/internal/pinnedfetch` | `Get` | kernel | — |
| `core/internal/refgraph` | `BuildImportGraph` | kernel | — |
| `core/internal/refgraph` | `CheckOwnership` | kernel | — |
| `core/internal/refgraph` | `DocRow` | own-package | — |
| `core/internal/refgraph` | `ExemptByBuildConstraint` | kernel | — |
| `core/internal/refgraph` | `FindSourceRoot` | kernel | — |
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
| `core/securerandom` | `String` | both-apps | — |
| `core/securerandom` | `StringFromAlphabet` | own-package | — |
| `core/sessionstore` | `Backend` | kernel | — |
| `core/sessionstore` | `BrowserSessionCookie` | reachable | — |
| `core/sessionstore` | `ConfiguredKey` | both-apps | — |
| `core/sessionstore` | `ConfiguredKeys` | both-apps | — |
| `core/sessionstore` | `CookieLifetime` | reachable | — |
| `core/sessionstore` | `ErrNotFound` | kernel | — |
| `core/sessionstore` | `ExpiresAt` | contract | The rule deciding when a browser session row stops being usable. The admin console's sessions live in rows the auth server's backend writes, so the rule is cross-process even though only the writing side calls it (#266). |
| `core/sessionstore` | `KeyPair` | both-apps | — |
| `core/sessionstore` | `MaxSessionDataBytes` | own-package | — |
| `core/sessionstore` | `MaxSessionWireBytes` | both-apps | — |
| `core/sessionstore` | `NewServerSideStore` | both-apps | — |
| `core/sessionstore` | `NewSession` | own-package | — |
| `core/sessionstore` | `Options` | own-package | — |
| `core/sessionstore` | `ParseKeys` | both-apps | — |
| `core/sessionstore` | `PersistentCookie` | own-package | — |
| `core/sessionstore` | `PreAuthLifetime` | contract | The unauthenticated half of the `ExpiresAt` rule beside it, and the one value that decides it. |
| `core/sessionstore` | `PreviousKeysError` | both-apps | — |
| `core/sessionstore` | `Record` | kernel | — |
| `core/sessionstore` | `ServerSideStore` | both-apps | — |
| `core/sessionstore` | `Session` | both-apps | — |
| `core/sessionstore` | `SessionIdBytes` | own-package | — |
| `core/sessionstore` | `Store` | kernel | — |
| `core/sessionstore` | `TouchThreshold` | own-package | — |
| `core/sessionstore/sessiontest` | `MemoryBackend` | test-support | Test support: the in-memory session backend, honouring expiry as the engines do, that tests across the two servers drive the real store over. Its own package precisely so no binary links it (#385). |
| `core/sessionstore/sessiontest` | `NewMemoryBackend` | test-support | Test support: the in-memory session backend, honouring expiry as the engines do, that tests across the two servers drive the real store over. Its own package precisely so no binary links it (#385). |
| `core/timezones` | `All` | contract | The list half of the time zone table whose lookup the auth server validates against. Moving it would put one zone table in two places. |
| `core/timezones` | `ByZone` | contract | The lookup half of the time zone table whose list the admin console renders. Moving it would put one zone table in two places. |
| `core/timezones` | `Zone` | contract | The row type both halves of the table share. |
