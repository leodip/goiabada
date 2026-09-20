# Core symbol ownership

Every exported symbol a package under `src/core` declares has a row here saying why `core` declares
it. `ARCHITECTURE.md` records the same thing two grains coarser — which module each top-level `core`
package must end up in, and why each symbol left in `core/constants` is still there — and this table
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
`countries.Country` is named
by nothing because it is only ever `AllInfo`'s element type, and a `contract` row on it would be
true and misleading.

**Circular evidence is not evidence.** `kernel` and `both-apps` are read off references from outside
the declaring package and are the only seeds; `own-package` and `reachable` then require a source
that is already justified, and iterate to a fixpoint. Two references never count for the symbol they
name: a method's receiver, because a method rides with its receiver and so cannot vouch for it, and
the declared type of a const or var the same package writes. Without both, `core/enums` justifies
itself — `AcrLevel` would be `own-package` because `AcrLevel1 AcrLevel = …` and
`func (acr AcrLevel) IsHigherThan` name it — and the guard would be blind to exactly the package
#385 deletes. An asserted row is not a seed either: two mutually referring symbols could otherwise
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
  `core/testutil` and `core/mocks`. Three packages here are test support written in files with no
  `_test.go` suffix — those two and each application's `handlertest` — so
  `adminconsole/internal/handlertest/json.go` naming `testutil.Reporter` in a production file is not
  a reason to refuse `Reporter` the word. A reference from a package a binary links is.
- **A method is not a row.** It rides with its receiver type, which has one. `guard/constants-table`
  treats a method the same way.
- **One row per Go package, not per top-level directory.** `core/sessionstore` and a subpackage of it
  are two packages, so nothing hides in a subdirectory the table never enumerated. A package whose
  every file carries `//go:build !production` — the generated mock subpackages — declares nothing any
  build includes and has no rows.
- **`core/constants` is here too**, and is also the subject of `ARCHITECTURE.md`'s fourth table. That
  table is stricter rather than looser: in a constants-only package, a constant naming its own
  sibling is not use at all, so `own-package` would be vacuous there.

**ceiling:** a reference from outside the declaring package is a selector on the identifier the
import binds, resolved by name within the file. A package-level declaration shadowing that name is
caught; a local variable inside a function shadowing it would be read as the package. Nothing in this
tree does that, and closing it means type-checking every package in four modules rather than parsing
them. Revisit if a row ever rests on a reference that turns out to be a false one (#385). References
from inside the declaring package are not read that way — they carry no selector, and matching them
by spelling would let a local, a parameter or a struct field justify its namesake — so those are
resolved with `go/types` over each package's own syntax, against a stub importer. The residual
ceiling there is a dot import, of which this tree has none.

## Regenerating

```
cd src/core && go run ./cmd/ownershipdump
```

It rewrites the table below and nothing else: the prose above it is the document's own. It writes the
computed rows, preserves the asserted ones and every note, and refuses — naming each offender — to
invent a justification for a symbol that has none. `testutil.AssertSymbolOwnership` compares the
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
| `core/api` | `DCRErrorInvalidClientMetadata` | moving | #385 decision 8 moves the RFC 7591 registration types to `authserver/internal/oidc`, tags and error-code strings unchanged. |
| `core/api` | `DCRErrorInvalidRedirectURI` | moving | #385 decision 8 moves the RFC 7591 registration types to `authserver/internal/oidc`, tags and error-code strings unchanged. |
| `core/api` | `DynamicClientRegistrationError` | moving | #385 decision 8 moves the RFC 7591 registration types to `authserver/internal/oidc`, tags and error-code strings unchanged. |
| `core/api` | `DynamicClientRegistrationRequest` | moving | #385 decision 8 moves the RFC 7591 registration types to `authserver/internal/oidc`, tags and error-code strings unchanged. |
| `core/api` | `DynamicClientRegistrationResponse` | moving | #385 decision 8 moves the RFC 7591 registration types to `authserver/internal/oidc`, tags and error-code strings unchanged. |
| `core/api` | `ErrorResponse` | both-apps | — |
| `core/api` | `GenerateUserEmailVerificationCodeResponse` | contract | Admin API response DTO, which is what `core/api` is for. The auth server writes it and no admin console file reads it yet; #385 exempts this package by name. |
| `core/api` | `GetAuditEventTypesResponse` | both-apps | — |
| `core/api` | `GetAuditLogsResponse` | both-apps | — |
| `core/api` | `GetClientPermissionsResponse` | both-apps | — |
| `core/api` | `GetClientResponse` | both-apps | — |
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
| `core/constants` | `AdminConsoleClientIdentifier` | both-apps | — |
| `core/constants` | `AdminConsoleSessionName` | both-apps | — |
| `core/constants` | `AdminReadPermissionIdentifier` | own-package | — |
| `core/constants` | `AuthServerResourceIdentifier` | kernel | — |
| `core/constants` | `BrowserSessionsPermissionIdentifier` | both-apps | — |
| `core/constants` | `BuildDate` | kernel | — |
| `core/constants` | `BuiltInAuthServerPermissionIdentifiers` | both-apps | — |
| `core/constants` | `ContextKeyJwtInfo` | kernel | — |
| `core/constants` | `GitCommit` | kernel | — |
| `core/constants` | `ManageAccountPermissionIdentifier` | both-apps | — |
| `core/constants` | `ManageClientsPermissionIdentifier` | own-package | — |
| `core/constants` | `ManagePermissionIdentifier` | kernel | — |
| `core/constants` | `ManageSettingsPermissionIdentifier` | own-package | — |
| `core/constants` | `ManageUsersPermissionIdentifier` | own-package | — |
| `core/constants` | `UserinfoPermissionIdentifier` | both-apps | — |
| `core/constants` | `Version` | kernel | — |
| `core/countries` | `AllInfo` | both-apps | — |
| `core/countries` | `ByAlpha2` | contract | The lookup half of the country table whose other half the admin console uses. Moving it would put one ISO 3166 dataset in two places. |
| `core/countries` | `Country` | own-package | — |
| `core/customerrors` | `ConformErrorDescription` | both-apps | — |
| `core/customerrors` | `ErrClientDisabled` | moving | #385 moves it to `authserver/internal/protocolvalidation`; only the auth server ever emits it. |
| `core/customerrors` | `ErrCodeRedirectURIDeregistered` | moving | #385 moves it to `authserver/internal/protocolvalidation`; only the auth server ever emits it. |
| `core/customerrors` | `ErrNoAuthContext` | moving | #385 moves it to `authserver/internal/handlerhelpers`, beside the handler helper that returns it. |
| `core/customerrors` | `ErrUserDisabled` | moving | #385 moves it to `authserver/internal/protocolvalidation`; only the auth server ever emits it. |
| `core/customerrors` | `ErrorDetail` | kernel | — |
| `core/customerrors` | `NewErrorDetail` | contract | One of the two neutral `ErrorDetail` constructors. `NewErrorDetailWithHttpStatusCode` beside it is `both-apps`, and the pair is one API that both processes compile. |
| `core/customerrors` | `NewErrorDetailWithHttpStatusCode` | both-apps | — |
| `core/customerrors` | `NewErrorDetailWithHttpStatusCodeAndWWWAuthenticate` | moving | #385 decision 17 moves it to `authserver/internal/apiresponse`; it builds an RFC 6750 bearer-token error header, which is provider-side by definition. |
| `core/enums` | `AcrLevel` | moving | #385 decision 6 moves it to `authserver/internal/models`, which carries it on a column the seeder writes. |
| `core/enums` | `AcrLevel1` | moving | #385 decision 6 moves it to `authserver/internal/models`, which carries it on a column the seeder writes. |
| `core/enums` | `AcrLevel2Mandatory` | moving | #385 decision 6 moves it to `authserver/internal/models`, which carries it on a column the seeder writes. |
| `core/enums` | `AcrLevel2Optional` | moving | #385 decision 6 moves it to `authserver/internal/models`, which carries it on a column the seeder writes. |
| `core/enums` | `AcrLevelFromString` | moving | #385 decision 6 moves it to `authserver/internal/models`, which carries it on a column the seeder writes. |
| `core/enums` | `AcrMax` | moving | #385 decision 6 moves it to `authserver/internal/models`, which carries it on a column the seeder writes. |
| `core/enums` | `AuthMethod` | moving | #385 decision 6 moves it to `authserver/internal/ceremony`, beside the `AuthContext.AuthMethods` that accumulates it. |
| `core/enums` | `AuthMethodOTP` | moving | #385 decision 6 moves it to `authserver/internal/ceremony`, beside the `AuthContext.AuthMethods` that accumulates it. |
| `core/enums` | `AuthMethodPassword` | moving | #385 decision 6 moves it to `authserver/internal/ceremony`, beside the `AuthContext.AuthMethods` that accumulates it. |
| `core/enums` | `Gender` | both-apps | — |
| `core/enums` | `GenderFemale` | reachable | — |
| `core/enums` | `GenderMale` | reachable | — |
| `core/enums` | `GenderOther` | reachable | — |
| `core/enums` | `IsGenderValid` | contract | The `Gender` type's own bound, and the only statement of which of its values are legal. #385 decision 17 keeps it beside the type, which moves to `core/gender`. |
| `core/enums` | `KeyState` | moving | #385 decision 7 moves it to `authserver/internal/models`; `commondb` builds a SQL WHERE with it and `data` imports nothing above `models`. |
| `core/enums` | `KeyStateCurrent` | both-apps | — |
| `core/enums` | `KeyStateFromString` | moving | #385 decision 7 moves it to `authserver/internal/models`; `commondb` builds a SQL WHERE with it and `data` imports nothing above `models`. |
| `core/enums` | `KeyStateNext` | both-apps | — |
| `core/enums` | `KeyStatePrevious` | both-apps | — |
| `core/enums` | `PasswordPolicy` | moving | #385 decision 6 moves it to `authserver/internal/models`, which carries it on a column the seeder writes. |
| `core/enums` | `PasswordPolicyFromString` | moving | #385 decision 6 moves it to `authserver/internal/models`, which carries it on a column the seeder writes. |
| `core/enums` | `PasswordPolicyHigh` | moving | #385 decision 6 moves it to `authserver/internal/models`, which carries it on a column the seeder writes. |
| `core/enums` | `PasswordPolicyLow` | moving | #385 decision 6 moves it to `authserver/internal/models`, which carries it on a column the seeder writes. |
| `core/enums` | `PasswordPolicyMedium` | moving | #385 decision 6 moves it to `authserver/internal/models`, which carries it on a column the seeder writes. |
| `core/enums` | `PasswordPolicyNone` | moving | #385 decision 6 moves it to `authserver/internal/models`, which carries it on a column the seeder writes. |
| `core/enums` | `SMTPEncryption` | moving | #385 decision 6 moves it to `authserver/internal/emaildelivery`, the only thing that acts on it. |
| `core/enums` | `SMTPEncryptionFromString` | moving | #385 decision 6 moves it to `authserver/internal/emaildelivery`, the only thing that acts on it. |
| `core/enums` | `SMTPEncryptionNone` | moving | #385 decision 6 moves it to `authserver/internal/emaildelivery`, the only thing that acts on it. |
| `core/enums` | `SMTPEncryptionSSLTLS` | moving | #385 decision 6 moves it to `authserver/internal/emaildelivery`, the only thing that acts on it. |
| `core/enums` | `SMTPEncryptionSTARTTLS` | moving | #385 decision 6 moves it to `authserver/internal/emaildelivery`, the only thing that acts on it. |
| `core/enums` | `ThreeStateSetting` | moving | #385 decision 6 moves it to `authserver/internal/models`, which carries it on a column the seeder writes. |
| `core/enums` | `ThreeStateSettingDefault` | moving | #385 decision 6 moves it to `authserver/internal/models`, which carries it on a column the seeder writes. |
| `core/enums` | `ThreeStateSettingFromString` | moving | #385 decision 6 moves it to `authserver/internal/models`, which carries it on a column the seeder writes. |
| `core/enums` | `ThreeStateSettingOff` | moving | #385 decision 6 moves it to `authserver/internal/models`, which carries it on a column the seeder writes. |
| `core/enums` | `ThreeStateSettingOn` | moving | #385 decision 6 moves it to `authserver/internal/models`, which carries it on a column the seeder writes. |
| `core/enums` | `TokenType` | moving | #385 decision 6 moves it to `authserver/internal/issuance`, which produces every value it has. |
| `core/enums` | `TokenTypeBearer` | moving | #385 decision 6 moves it to `authserver/internal/issuance`, which produces every value it has. |
| `core/enums` | `TokenTypeId` | moving | #385 decision 6 moves it to `authserver/internal/issuance`, which produces every value it has. |
| `core/enums` | `TokenTypeRefresh` | moving | #385 decision 6 moves it to `authserver/internal/issuance`, which produces every value it has. |
| `core/errs` | `Errorf` | kernel | — |
| `core/errs` | `Join` | contract | One function of the error kernel both processes compile. CLAUDE.md pattern 7 names it as the only legal `errors.Join` in this tree, so it is part of the convention rather than of one caller. |
| `core/errs` | `New` | kernel | — |
| `core/errs` | `WithStack` | kernel | — |
| `core/errs` | `Wrap` | kernel | — |
| `core/errs` | `Wrapf` | kernel | — |
| `core/handlerhelpers` | `GetFromUrlQueryOrFormPost` | own-package | — |
| `core/handlerhelpers` | `HttpHelper` | own-package | — |
| `core/handlerhelpers` | `LayoutSettings` | both-apps | — |
| `core/handlerhelpers` | `LookupFromUrlQueryOrFormPost` | kernel | — |
| `core/handlerhelpers` | `NewHttpHelper` | both-apps | — |
| `core/handlerhelpers` | `SettingsReader` | reachable | — |
| `core/hashutil` | `HashString` | both-apps | — |
| `core/hashutil` | `VerifyStringHash` | kernel | — |
| `core/i18n` | `Bundle` | own-package | — |
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
| `core/i18n` | `ErrCodeEmailConfirmationMismatch` | contract | Wire `error_code` value. `openapi.yaml` publishes it as a stable identifier, so a third-party client can switch on it although the admin console does not (#385 decision 10). |
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
| `core/i18n` | `FormatDateTime` | kernel | — |
| `core/i18n` | `FormatSince` | kernel | — |
| `core/i18n` | `LoadBundle` | both-apps | — |
| `core/i18n` | `LocaleLabel` | kernel | — |
| `core/i18n` | `LocaleTag` | kernel | — |
| `core/i18n` | `LocalizedError` | both-apps | — |
| `core/i18n` | `Localizer` | own-package | — |
| `core/i18n` | `MiddlewareLocale` | both-apps | — |
| `core/i18n` | `NewLocalizedError` | kernel | — |
| `core/i18n` | `Raw` | kernel | — |
| `core/i18n` | `RefCountry` | kernel | — |
| `core/i18n` | `RefPhoneCountry` | kernel | — |
| `core/i18n` | `RefTimezone` | kernel | — |
| `core/i18n` | `ResolveRequestLocale` | kernel | — |
| `core/i18n` | `SanitizeUILocales` | own-package | — |
| `core/i18n` | `T` | kernel | — |
| `core/i18n` | `Translator` | own-package | — |
| `core/i18n` | `UILocalesReader` | reachable | — |
| `core/i18n` | `WithLocale` | both-apps | — |
| `core/locales` | `Get` | both-apps | — |
| `core/locales` | `Locale` | own-package | — |
| `core/logging` | `FieldForLog` | kernel | — |
| `core/logging` | `Install` | both-apps | — |
| `core/logging` | `MaxLoggedField` | own-package | — |
| `core/logging` | `SafeLogValue` | own-package | — |
| `core/logging` | `SafeLogValueLen` | own-package | — |
| `core/logging` | `TruncateCounted` | kernel | — |
| `core/logging` | `TruncationMarker` | kernel | — |
| `core/logging` | `WrapRequestID` | kernel | — |
| `core/middleware` | `MiddlewareCookieReset` | both-apps | — |
| `core/middleware` | `MiddlewareCsrf` | both-apps | — |
| `core/middleware` | `MiddlewareNoStore` | moving | #385 moves the provider-side middleware to `authserver/internal/middleware`. |
| `core/middleware` | `MiddlewareRealIP` | both-apps | — |
| `core/middleware` | `MiddlewareRequestLogger` | both-apps | — |
| `core/middleware` | `MiddlewareSecurityHeaders` | both-apps | — |
| `core/middleware` | `MiddlewareSkipCsrf` | both-apps | — |
| `core/middleware` | `RequestTargetForLog` | own-package | — |
| `core/mocks` | `TestFS` | test-support | Test support: a hand-written `fs.FS` fake for the template loaders, named only from tests. |
| `core/mocks` | `TestFile` | test-support | Test support: a hand-written `fs.FS` fake for the template loaders, named only from tests. |
| `core/mocks` | `TestFileInfo` | test-support | Test support: a hand-written `fs.FS` fake for the template loaders, named only from tests. |
| `core/oauth` | `GeneratePKCECodeChallenge` | both-apps | — |
| `core/oauth` | `Jwk` | both-apps | — |
| `core/oauth` | `Jwks` | both-apps | — |
| `core/oauth` | `JwtInfo` | kernel | — |
| `core/oauth` | `JwtToken` | both-apps | — |
| `core/oauth` | `ParseResponseType` | moving | #385 moves `response_type` parsing to `authserver/internal/protocolvalidation`; it is provider-side. |
| `core/oauth` | `ResponseTypeInfo` | moving | #385 moves `response_type` parsing to `authserver/internal/protocolvalidation`; it is provider-side. |
| `core/oauth` | `TokenResponse` | both-apps | — |
| `core/sessionstore` | `Backend` | both-apps | — |
| `core/sessionstore` | `DecodeKeyPair` | both-apps | — |
| `core/sessionstore` | `DecodePreviousKeyPair` | both-apps | — |
| `core/sessionstore` | `ErrNotFound` | kernel | — |
| `core/sessionstore` | `ExpiresAt` | contract | The rule deciding when a browser session row stops being usable. The admin console's sessions live in rows the auth server's backend writes, so the rule is cross-process even though only the writing side calls it (#266). |
| `core/sessionstore` | `KeyPair` | own-package | — |
| `core/sessionstore` | `MaxSessionDataBytes` | own-package | — |
| `core/sessionstore` | `MaxSessionWireBytes` | both-apps | — |
| `core/sessionstore` | `NewServerSideStore` | both-apps | — |
| `core/sessionstore` | `NewSession` | own-package | — |
| `core/sessionstore` | `Options` | own-package | — |
| `core/sessionstore` | `PreAuthLifetime` | contract | The unauthenticated half of the `ExpiresAt` rule beside it, and the one value that decides it. |
| `core/sessionstore` | `Record` | kernel | — |
| `core/sessionstore` | `Regenerator` | both-apps | — |
| `core/sessionstore` | `ServerSideStore` | own-package | — |
| `core/sessionstore` | `Session` | own-package | — |
| `core/sessionstore` | `SessionIdBytes` | own-package | — |
| `core/sessionstore` | `Store` | kernel | — |
| `core/sessionstore` | `TouchThreshold` | own-package | — |
| `core/sessionstore/sessiontest` | `MemoryBackend` | test-support | Test support: the in-memory session backend nine test files across the two servers drive. Its own package precisely so no binary links it (#385). |
| `core/sessionstore/sessiontest` | `NewMemoryBackend` | test-support | Test support: the in-memory session backend nine test files across the two servers drive. Its own package precisely so no binary links it (#385). |
| `core/stringutil` | `ConvertToString` | kernel | — |
| `core/stringutil` | `GenerateRandomLetterString` | moving | #385 moves it beside its one production caller in `authserver/internal/handlers/apihandlers`. |
| `core/stringutil` | `GenerateRandomNumberString` | moving | #385 moves it beside its one production caller in `authserver/internal/handlers/apihandlers`. |
| `core/stringutil` | `GenerateSecurityRandomString` | both-apps | — |
| `core/testutil` | `Address` | test-support | Test support: compiled into no binary, and nothing outside `core/testutil` names it in production. |
| `core/testutil` | `AssertAgentDocs` | test-support | Test support: compiled into no binary, and nothing outside `core/testutil` names it in production. |
| `core/testutil` | `AssertArchitecture` | test-support | Test support: compiled into no binary, and nothing outside `core/testutil` names it in production. |
| `core/testutil` | `AssertAuditLogContext` | test-support | Test support: compiled into no binary, and nothing outside `core/testutil` names it in production. |
| `core/testutil` | `AssertEmailSent` | test-support | Test support: compiled into no binary, and nothing outside `core/testutil` names it in production. |
| `core/testutil` | `AssertErrorCodeDoc` | test-support | Test support: compiled into no binary, and nothing outside `core/testutil` names it in production. |
| `core/testutil` | `AssertGeneratedMocksArePinned` | test-support | Test support: compiled into no binary, and nothing outside `core/testutil` names it in production. |
| `core/testutil` | `AssertGofmted` | test-support | Test support: compiled into no binary, and nothing outside `core/testutil` names it in production. |
| `core/testutil` | `AssertNoCredentialQueryFallback` | test-support | Test support: compiled into no binary, and nothing outside `core/testutil` names it in production. |
| `core/testutil` | `AssertNoDeadInterfaces` | test-support | Test support: compiled into no binary, and nothing outside `core/testutil` names it in production. |
| `core/testutil` | `AssertNoLegacyErrors` | test-support | Test support: compiled into no binary, and nothing outside `core/testutil` names it in production. |
| `core/testutil` | `AssertSlogConvention` | test-support | Test support: compiled into no binary, and nothing outside `core/testutil` names it in production. |
| `core/testutil` | `AssertSymbolOwnership` | test-support | Test support: compiled into no binary, and nothing outside `core/testutil` names it in production. |
| `core/testutil` | `AssertTemplatesHtmlLangNotHardcoded` | test-support | Test support: compiled into no binary, and nothing outside `core/testutil` names it in production. |
| `core/testutil` | `AssertTemplatesNoCsrfField` | test-support | Test support: compiled into no binary, and nothing outside `core/testutil` names it in production. |
| `core/testutil` | `AssertTemplatesNoHTMLInTitle` | test-support | Test support: compiled into no binary, and nothing outside `core/testutil` names it in production. |
| `core/testutil` | `CaptureSlog` | test-support | Test support: compiled into no binary, and nothing outside `core/testutil` names it in production. |
| `core/testutil` | `CapturedRecord` | test-support | Test support: compiled into no binary, and nothing outside `core/testutil` names it in production. |
| `core/testutil` | `FindSourceRoot` | kernel | — |
| `core/testutil` | `GuardReport` | test-support | Test support: compiled into no binary, and nothing outside `core/testutil` names it in production. |
| `core/testutil` | `MailpitData` | test-support | Test support: compiled into no binary, and nothing outside `core/testutil` names it in production. |
| `core/testutil` | `MailpitMessage` | test-support | Test support: compiled into no binary, and nothing outside `core/testutil` names it in production. |
| `core/testutil` | `RenderSymbolOwnership` | kernel | — |
| `core/testutil` | `Reporter` | test-support | Test support: compiled into no binary, and nothing outside `core/testutil` names it in production. |
| `core/testutil` | `RunGuard` | test-support | Test support: compiled into no binary, and nothing outside `core/testutil` names it in production. |
| `core/testutil` | `SlogCapture` | test-support | Test support: compiled into no binary, and nothing outside `core/testutil` names it in production. |
| `core/testutil` | `SourceRoot` | test-support | Test support: compiled into no binary, and nothing outside `core/testutil` names it in production. |
| `core/testutil` | `WalkHTMLTemplates` | test-support | Test support: compiled into no binary, and nothing outside `core/testutil` names it in production. |
| `core/timezones` | `Get` | both-apps | — |
| `core/timezones` | `Zone` | own-package | — |
| `core/validators` | `ContainsAngleBrackets` | both-apps | — |
| `core/validators` | `IdentifierValidator` | own-package | — |
| `core/validators` | `NewIdentifierValidator` | both-apps | — |
| `core/validators` | `ValidateNoAngleBrackets` | moving | #385 decision 17 moves it to `authserver/internal/accountvalidation`; it wraps a shared rule in an error only the auth server emits. |
