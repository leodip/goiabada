# Issue 104: client_credentials scope check ignores the resource

**Issue:** [#104](https://github.com/leodip/goiabada/issues/104)
**Issue state:** open (labels: bug, security)
**Spec written:** 2026-07-26
**Last synced:** 2026-07-26 (the issue has no comments)
**Filed from this spec's verification:** [#124](https://github.com/leodip/goiabada/issues/124),
the shared `resource:permission` resolver that removes the structural root cause, see
decision 14. [#125](https://github.com/leodip/goiabada/issues/125), refreshed ROPC tokens
resetting `auth_time` to the refresh moment. [#126](https://github.com/leodip/goiabada/issues/126),
the dead `AuditROPCAuthFailed` constant. None is a gate in either direction: #124 is a refactor
of code this spec leaves correct, and #125 and #126 concern a claim value and an audit constant
that neither vulnerability here depends on.

**On the line numbers in this spec.** They are re-verified as of 2026-07-28, after stages 1, 2, 3
and 7 landed. Those stages shifted `token_validator.go`, `handler_token.go` and `token_issuer.go`
substantially: the client credentials scope validator moved from `:682` to `:733`, and every branch
inside it moved by 40 to 60 lines. A citation sweep was needed because the stale numbers had come to
point at plausible but unrelated code, which makes a recorded verification actively misleading rather
than merely imprecise.

**Expect them to drift again.** Stage 4 edits `token_validator.go:295-305` and will move everything
below it. When a number looks wrong, locate the anchor by its quoted error message or symbol name,
which this spec gives alongside nearly every citation, and prefer that over the number. If you land
here after a stage, re-sweep rather than patching the one number you noticed.

**Found during verification and fixed here rather than filed:** ROPC refresh tokens could not be
redeemed at all when the token requested `openid`, because the server re-validated a scope it had
injected itself. Section 3.6, decision 19, stage 7. It is in this spec because stage 6's test
cannot pass without either this fix or a workaround that misrepresents what the test exercises.
Note the contrast with #125, which also concerns refreshed ROPC tokens: that one is a wrong
`auth_time` **value** and is still deferred, while this one made the grant unusable.

**Note on this spec's relationship to the issue.** The issue's diagnosis, its cited mechanism
and its recommended fix are all correct, and this spec adopts them. Verification added four
things the issue does not contain: the escalation reaches full Admin API access rather than a
sibling resource (section 1), the existing unit tests would pass vacuously after the fix
(decision 2), the scope normalization the code computes is discarded before it reaches the
token (decision 9), and a **second, independent vulnerability** in which `/userinfo` and the
Account API resolve their acting user from `sub` without checking that the token was issued for
a user (section 1, decision 17, stage 6). Line citations in the issue have drifted by a few
lines and are corrected below.

**The issue's recommended fix is adopted as written, including its cardinality.** An earlier draft
of this spec departed from it, comparing a set of permission ids rather than the single resolved
one, on a false premise about which engines enforce `(permission_identifier, resource_id)`
uniqueness. The answer is all four. Decision 18 records the correction and everything it touched.

**This spec therefore covers two vulnerabilities and one functional defect.** Stage 6 is
independent of stages 1 through 5 and could land in either order. It is included here rather than
filed separately because the release note cannot describe `authserver:manage-account` accurately
without it. Stage 7 fixes a ROPC refresh defect found while writing stage 6's tests, where the
server rejects a scope it injected itself; it is in this spec rather than a separate issue because
stage 6's test carried a workaround for it that stage 7 removed.

---

## 1. Context

### The bug

`validateClientCredentialsScopes` (`src/core/validators/token_validator.go:733-818`) decides
whether a client may receive a requested `resource:permission` scope. It runs two checks per
scope. The first confirms the permission exists on the named resource, the second confirms the
client holds it.

The second check discards the resource:

```go
// token_validator.go:798-804
clientHasPermission := false
for _, perm := range client.Permissions {
    if perm.PermissionIdentifier == parts[1] {   // parts[0], the resource, is never consulted
        clientHasPermission = true
        break
    }
}
```

`client.Permissions` is populated at `:285` by `ClientLoadPermissions`
(`src/core/data/commondb/client.go:195-217`), which resolves the client's grants through
`GetPermissionsByIds` across every resource. So the loop matches any permission the client
holds anywhere, on nothing but the bare identifier.

The existence check immediately above (`:778-784`) is correct: it iterates
`GetPermissionsByResourceId(nil, res.Id)`, a list already narrowed to the requested resource.
The resource-scoped `models.Permission` the ownership check needs is therefore already in hand
at that point, exactly as the issue says. Only the ownership check drops it.

The issue cites `:731-743` and `:702-729`. The actual blocks are `:798-804` and `:759-790`.

**The validator is the only gate.** `GenerateTokenResponseForClientCred`
(`src/core/oauth/token_issuer.go:328-337`) copies the validated scope string into the token
verbatim. Nothing downstream re-derives or re-checks it.

### Why collisions are the normal case

`permission_identifier` is unique per resource, never globally, and **every supported engine
enforces exactly that**, no more and no less:

| Engine | Declared in the migration that runs | Snapshot |
|---|---|---|
| MySQL | `mysqldb/migrations/000002_v0_7.up.sql:6` | `mysqldb/schema.sql:205` (inline `UNIQUE KEY`) |
| SQLite | `sqlitedb/migrations/000002_v0_7.up.sql:5` | `sqlitedb/schema.sql:312` |
| PostgreSQL | `postgresdb/migrations/000001_initial_create.up.sql:319` | `postgresdb/schema.sql:1356` |
| SQL Server | `mssqldb/migrations/000001_initial_create.up.sql:342` | `mssqldb/schema.sql:425` |

All four are the same index, `idx_permission_identifier_resource` on
`(permission_identifier, resource_id)`. Verified by execution as well as by reading: inserting a
second `read` on one resource against the running PostgreSQL is refused with `duplicate key value
violates unique constraint "idx_permission_identifier_resource"`.

**An earlier draft of this spec claimed only MySQL enforced this and that the other three
snapshots carried no unique constraint at all.** That was wrong, and the mistake is worth
recording because it is easy to repeat: MySQL declares the constraint inline inside `CREATE TABLE
permissions`, while SQLite, PostgreSQL and SQL Server declare it as a separate `CREATE UNIQUE
INDEX` statement further down the file. Reading only the `CREATE TABLE` block sees it on exactly
one engine. Decision 18 records what the false premise had been used to justify.

So the collision this issue is about is strictly **across** resources, which is legitimate and
expected. Two rows sharing an identifier **within** one resource are not a supported state on any
engine. The Admin API also checks for duplicates within one resource's permission list
(`src/authserver/internal/handlers/apihandlers/handler_api_permissions.go:176`); that check is
defence in depth in front of the constraint, not the only thing holding the invariant up.

The project's own documentation steers users straight into the collision.
`site/src/content/docs/concepts/resources-permissions.mdx:55` instructs readers to "define the
actions users or clients can perform (e.g., `read`, `write`, `delete`)" per resource.

### The escalation reaches the Admin API

This is the part the issue does not cover, and it changes how urgent the fix is.

`manage`, `admin-read`, `manage-users`, `manage-clients`, `manage-settings`, `userinfo` and
`manage-account` are built-in permissions on the system `authserver` resource
(`src/core/constants/constants.go:8-29`, enumerated in
`BuiltInAuthServerPermissionIdentifiers`). They are ordinary rows in `permissions`, and
`manage` is precisely the kind of generic identifier the documentation above encourages on a
custom resource.

The Admin API authorizes from the token's `scope` claim and nothing else.
`RequireBearerTokenScope` and `RequireBearerTokenScopeAnyOf`
(`src/authserver/internal/middleware/api_auth.go:40-105`) call
`jwtToken.HasScope(...)`, which is an exact string match over the space-split claim
(`src/core/oauth/jwt_token.go:81-94`). The session gate in front of it does not apply to this
token type:

```go
// api_auth.go:203-207
sid := jwtToken.GetStringClaim("sid")
if sid == "" {
    // Non-session-bound token (client_credentials, ROPC): no session to check.
    next.ServeHTTP(w, r)
    return
}
```

So a client granted `<any-custom-resource>:manage` can request `authserver:manage`, receive a
token carrying it, and hold full `/api/v1/admin` access. Executed against a model of the
current code, the request is accepted and returns `scope=authserver:manage`.

**Precondition, stated plainly so the severity is not overread.** The attacker must already
authenticate as a confidential client with `ClientCredentialsEnabled`, a valid
`client_secret`, and at least one permission grant whose identifier collides. This is
escalation from a legitimate but lower-privileged client, or from a leaked client secret, not
an unauthenticated attack. Within that precondition it fails open and the escalation is total.

### A second, independent gap: user-context endpoints trust `sub` unconditionally

Found while writing the release note's severity table, and fixed by this spec rather than
deferred, per decision 17.

`/api/v1/account/*` and `/userinfo` derive the acting user from the token's `sub` claim and
never check that the token represents a user at all:

```go
// handler_api_account_email.go:33-53, and identically handler_userinfo.go:32-38
subject := jwtToken.GetStringClaim("sub")
user, err := database.GetUserBySubject(nil, subject)
// ... then mutates that user
```

For a client credentials token, `sub` is the **client identifier**
(`src/core/oauth/token_issuer.go:356`), not a user subject. Neither route guard catches this:
`RequireBearerTokenScope` checks only the scope string, and `RequireValidSession` explicitly
passes through tokens with no `sid` (`api_auth.go:203-207`).

**A UUID is a valid client identifier.** The validator is
`^[a-zA-Z]([a-zA-Z0-9_-]*[a-zA-Z0-9])?$` with a 38 character maximum and no doubled separators
(`src/core/validators/identifier_validator.go:19-40`). A 36 character UUID satisfies all of it
whenever its first hex digit is `a` through `f`, which is 6 of 16 possible values. Executed
against the real regex: `a1b2c3d4-5e6f-4a7b-8c9d-0e1f2a3b4c5d` and
`deadbeef-dead-4eef-8eef-deadbeefcafe` are valid client identifiers,
`3f2504e0-4f89-11d3-9a0c-0305e82c3301` is not, only because it starts with a digit.

So a client whose identifier equals a user's subject, holding `authserver:manage-account`, acts
**as that user** against the Account API: change their email, phone, profile, address.

**The `/userinfo` half of this discloses nothing, and the spec should not imply otherwise.**
Every claim beyond `sub` is gated on the token carrying an OIDC scope,
`jwtToken.HasScope("profile")` and siblings (`handler_userinfo.go:86` onward), and
`validateClientCredentialsScopes:746-750` rejects every OIDC scope outright for this grant. A
client credentials token can therefore only ever carry `authserver:userinfo`, so `/userinfo`
returns `sub` alone (`:78`), which is the identifier the caller already supplied. The material
impersonation impact is the Account API.

The `/userinfo` route is still covered by stage 6, for two reasons: it accepts a token in a
context it was never issued for, which is wrong independently of what leaks today, and its
harmlessness rests entirely on the OIDC-scope rejection in a different file. If that rejection
were ever relaxed, `/userinfo` would start disclosing profile and email claims with no further
change here.

**Bounding the severity honestly.** This is not reachable anonymously. Dynamic Client
Registration generates the identifier server-side (`generateDCRClientIdentifier()`,
`handler_dynamic_client_registration.go:62`), so a registrant cannot choose it. Picking a
colliding identifier requires client-creation rights, meaning `authserver:manage-clients` or
`manage`. The real finding is therefore **escalation from `manage-clients` to acting as any
user**, plus the latent risk of a coincidental collision, rather than an external attack.

**Its relationship to the main issue.** Independent. #104 widens who can obtain
`authserver:manage-account` in the first place, so stage 1 shrinks the exposed population, but
the gap remains for any client legitimately granted it. Fixing one does not fix the other, and
stage 6 does not depend on stages 1 through 5.

### Sibling audit

Every other identifier comparison in the codebase was checked. None share the defect.

| Site | Verdict |
|---|---|
| `token_validator.go:780` (existence check) | correct, list narrowed by `GetPermissionsByResourceId` |
| `token_validator.go:874` (ROPC existence) | correct, same narrowing |
| ROPC ownership, via `UserHasScopePermission` | correct, compares `Id` (`src/core/user/permission_checker.go:81`) |
| `authorize_validator.go:106` (auth code) | correct, existence-only against the resource's own list |
| `user_creator.go:55` | correct, iterates the `authserver` resource's own permissions |
| `handler_api_permissions.go:61`, `handler_api_users_search.go:145`, `handler_api_permission_users.go:52`, four sites in `adminconsole/.../adminresourcehandlers/` | correct, all gate on `resource.ResourceIdentifier` first |

The no-scope branch at `token_validator.go:295-305` is also correct, since it builds each scope
from `perm.Resource.ResourceIdentifier`. Only the explicit-scope ownership check is broken,
exactly as the issue states.

### Secondary findings from verification

**Scope normalization is computed and thrown away.** `validateClientCredentialsScopes:740-743`
collapses whitespace onto a **local** copy of `scope`. `input.Scope` is never reassigned, so
`:314` returns the caller's raw string and that is what reaches the token's `scope` claim.
Executed against `HasScope`:

| Token `scope` claim | `HasScope("billing-api:read")` |
|---|---|
| `"billing-api:read billing-api:write"` | true |
| `"billing-api:read  billing-api:write"` | true, the empty element is inert |
| `"billing-api:read\tbilling-api:write"` | **false** |

The table above is accurate about `HasScope`, but the outcome an earlier draft drew from it was
not. That draft said a client separating scopes with a tab "passes validation, receives a token,
and every scope in it is unmatchable by resource servers and by the Admin API middleware alike."
**It never receives a token.** Executed against the real server, before the stage 2 fix, with two
genuinely granted scopes separated by a tab: the request returns **500**, and the server logs
`invalid scope: billing-api-x:read-y<TAB>billing-api-x:write-z`. The validator does pass, because
it collapses whitespace locally. The **issuer** then rejects: `GenerateTokenResponseForClientCred`
splits the raw scope on spaces alone, so the whole tab-joined string is one element, splitting it
on `:` yields three parts rather than two, and `token_issuer.go:367` errors out. Refresh has both
the same defect shape (`:472` collapses into a local `inputScopeSanitized`, then `:497` puts raw
`input.Scope` into the new token) **and** the same outcome, verified the same way: 500, not a token.

So the defect costs functionality and nothing else, which is what the earlier draft concluded, but
by a blunter route: an unusable 500 rather than a token whose scopes silently match nothing.

**This is the second instance of one mistake in this spec, so it is worth naming.** Section 3.2 made
the same claim about a whitespace-only scope, and was corrected the same way: the request 500s at the
issuer rather than yielding a token. Both times the reasoning stopped at `ValidateTokenRequest`
returning the string and did not follow it into the issuer, which parses the scope **again** and
rejects what the validator tolerated.

**Before asserting that any scope string reaches a token, trace it through
`generateAccessTokenCore` and `GenerateTokenResponseForClientCred`, both of which re-parse it.**
Decision 19 is the counter-example worth reading alongside this: it also traced a scope past the
validator, but into the refresh token's stored record rather than into an issued token, and that
claim held up under measurement. The lesson is not "such claims are always wrong", it is that the
issuer is a second gate and the trace has to reach it.

**Leading and trailing whitespace produces an unactionable error.** `handler_token.go` (pre-stage-2)
passes `r.PostForm.Get("scope")` untrimmed, and the collapse does not trim. Executed:
`"billing-api:read "` tokenizes to `["billing-api:read", ""]`, and the empty token yields
`invalid_scope: Invalid scope format: ''`, which names nothing the caller can act on. Of the
four scope-handling sites, `authorize_validator.go:53-54` trims the whole string and
`validateROPCScopes:833-836` trims per token and skips empties, while
`validateClientCredentialsScopes` and refresh down-scoping do neither.

**Duplicate scopes are preserved, except on the authorize path.** `AuthContext.SetScope`
(`src/core/oauth/auth_context.go:56-71`) collapses whitespace, drops duplicates preserving
first-occurrence order, trims, and assigns the result back to `ac.Scope`. None of the three
token endpoint paths dedupe: client credentials preserves duplicates, refresh preserves them at
`:497`, ROPC preserves them at `:897`. So `scope=api:read api:read` yields a token claim of
`"api:read api:read"`. Unlike the whitespace defect this breaks nothing, since `HasScope`
matches the first occurrence, but it is the same divergence pattern. Addressed by decision 10.

**Scope handling at `:295-305` is downstream of the handler.** The no-scope expansion builds
its scope server-side from `client.Permissions` after the handler has run, so any normalization
applied at `handler_token.go:58-59` does not reach it. In practice this is inert, because the
expansion iterates distinct permission rows resolved through `GetPermissionsByIds`, so it
cannot emit a duplicate even though `clients_permissions` carries no unique constraint on
`(client_id, permission_id)` on any engine. Recorded so nobody later assumes handler-level
normalization covers every path that can set `input.Scope`.

**The no-scope branch re-queries a value it already holds.** `:295-305` calls
`GetResourceByResourceIdentifier(nil, perm.Resource.ResourceIdentifier)` and then uses
`res.ResourceIdentifier`, the string it just passed in. `PermissionsLoadResources` ran at
`:290`. This is one DB round-trip per granted permission, per request. `res` is dereferenced
without a nil check at `:302`, and `PermissionsLoadResources` assigns a zero-valued `Resource` on a
map miss without erroring (`src/core/data/commondb/permission.go:171`), leaving
`ResourceIdentifier == ""`. The old code then passed that empty string to
`GetResourceByResourceIdentifier`, which returns `nil`, and dereferenced it.

**An earlier version of this finding called that "not a live bug", on the grounds that reaching it
needs an orphaned permission and `ON DELETE CASCADE` holds on all four engines. That argument is
wrong.** The cascade runs in the database; these permission rows are already in memory.
`ClientLoadPermissions` and `PermissionsLoadResources` are separate **non-transactional** queries
(`tx` is nil at both call sites), so a resource deleted between them leaves the loop holding rows the
database has since cascade-deleted, and the resource lookup finds nothing for them. Narrow, but a
real panic rather than an impossible one.

**Both halves executed, not argued.** Against a fixture whose permission carries a zero-valued
`Resource`: the old code panics with `invalid memory address or nil pointer dereference`, and the
stage 4 code returns `invalid_scope`, "Invalid scope: ':read'. Could not find a resource with
identifier ''", a 400. So the removal converted a panic into a naming error.

**Both the round-trip and that deref are gone as of stage 4**, which removed the call rather than
guarding it, and in doing so turned a potential panic into a 400: a zero-valued resource now yields
the scope `":<permission>"`, which validation rejects with `invalid_scope`.

**Three existing unit tests would pass vacuously after the fix.** See decision 2.

**The no-scope branch has no unit coverage.** Of the eleven client credentials cases in
`TestValidateTokenRequest_ClientCredentials`, none omits `Scope`. It is exercised only by
`TestToken_ClientCred_NoScopesGiven` (`token_clientcred_test.go:260`), which needs the dev
container.

**Successful issuance is not forensically useful.** Fixed by stage 3, forward-looking only. `AuditTokenIssuedClientCredentialsResponse`
(`handler_token.go:222`) logs `clientId` and nothing else. There is no record of which scopes
were issued to whom, so exploitation before the fix cannot be reconstructed from the audit log.

---

## 2. Goal

A client receives a `resource:permission` scope from the client credentials grant only when it
holds the permission **on that resource**. Two permissions sharing an identifier across
different resources are distinct grants, and holding one conveys nothing about the other. In
particular, a grant on a custom resource never yields any `authserver:*` scope.

Secondarily: the scope string a client sends is normalized once, so the claim in the issued
token is always matchable by `HasScope` and is free of duplicates, and a non-empty raw scope
that normalizes to empty is rejected rather than silently promoted to "all permissions";
every `invalid_scope` returned by the two scope validators leaves an audit record; and a
successful client credentials request records which scopes were issued.

**That boundary is mechanical, not semantic, and the spec says so rather than dressing it up.**
Two conditions define it, neither about what kind of denial occurred. The failure must return
`invalid_scope`, which inside the validator only the two scope validators do. And it must reach the
single call site, which sits after `ValidateTokenRequest` and so after authentication.

An earlier version of this paragraph glossed that as "every scope denial reached after the
applicable principal has authenticated". **That is false**: the OIDC-scope rejection at `:747` and
the refresh down-scope denial at `:488` are both post-authentication too, verified (`:747` runs
inside `validateClientCredentialsScopes`, called at `:307`, after the client secret check at
`:250-283`; `:488` follows the refresh path's own check at `:323-341`). They are excluded by the
error code, not by position.

So coverage includes six authenticated malformed-format and unknown-resource failures (`:754`,
`:764`, `:787`, `:847`, `:861`, `:881`) alongside the two genuine ownership denials (`:807`,
`:892`). Three denials sit outside it, for **two different mechanical reasons**: the handler's
provided-but-empty rejection because it fires **before** authentication, and `:747` and `:488`
because they return `invalid_request` and `invalid_grant`, codes the taxonomy cannot isolate from
unrelated failures. `:488` is itself a real authorization denial, so the coverage fails to match the
semantic category in both directions. Section 3.3 enumerates all three.

The two scope denials that do **not** return `invalid_scope`, the OIDC-scope rejection at
`token_validator.go:747` and refresh down-scope rejection at `:488`, are outside this goal by
decision 12.

Independently: endpoints that act on a user resolved from `sub`, namely `/api/v1/account/*` and
`/userinfo`, accept only tokens issued for a user. A client credentials token is rejected there
regardless of its scopes, so a client identifier that happens to equal a user's subject conveys
nothing.

Independently again: a ROPC refresh token can be redeemed. The server never rejects a refresh
because of a scope it injected into the token itself, and this holds for refresh tokens already
issued before the fix as well as new ones.

### Out of scope

- **Unifying the four scope-handling sites into one helper.** `authorize_validator.go:51`,
  `validateClientCredentialsScopes:733`, `validateROPCScopes:820` and the refresh down-scoping
  block at `:469-498` all tokenize scopes with near-identical code, and the first three share a
  resolve step that could return the resource-scoped `*models.Permission` once, leaving each
  caller to apply only its own ownership rule. This is the structural root cause of this issue:
  ownership checking was hand-rolled per call site rather than shared, so one copy drifted from
  the pattern `UserHasScopePermission` already establishes. It is a much larger diff than a
  security fix should carry. Decisions 9 and 10 remove the behavioural divergence without
  merging the code. Tracked as [#124](https://github.com/leodip/goiabada/issues/124), see
  decision 14.
- **A global unique constraint on `permission_identifier`.** It would forbid legitimate
  configurations that the documentation actively recommends, and it is the wrong layer: the
  code should respect the resource, not the schema forbid reuse.
- **Retroactive detection of exploitation.** Impossible, and the release note must say so. No
  scope was ever recorded on issuance, so there is no data to reconstruct from. Decision 8
  fixes this going forward only.
- **Hardening the unchecked `res` at `:302`.** Decision 7 removes the call entirely rather than
  guarding it, which is why no hardening is needed. Note the reason is **not** that the state is
  unreachable: an earlier version of this entry said "unreachable behind FK cascade", which is wrong
  for the reason section 1 now records. Removing the call is what makes the path fail closed.
- **The wrong `auth_time` on refreshed ROPC tokens.** `createTokenInputFromROPC:916` passes
  `now`, so a token issued by `GenerateTokenResponseForRefreshROPC` reports the refresh moment
  as the authentication moment. A real defect in an OIDC claim's meaning, found while choosing
  stage 6's discriminator, and independent of both vulnerabilities here. Stage 6 reads the
  claim's presence and never its value, so it is unaffected. Filed as
  [#125](https://github.com/leodip/goiabada/issues/125).
- ~~**ROPC refresh rejects a scope the server injected itself.**~~ **Moved into scope**, see
  section 3.6, decision 19 and stage 7. Found while writing stage 6 step 4, where it blocked the
  ROPC refresh case outright. It was fixed here rather than filed separately because stage 6's
  test carried a workaround for it that only stage 7 could remove.
- **The dead `AuditROPCAuthFailed` constant.** Declared and listed but logged by nothing. Filed
  as [#126](https://github.com/leodip/goiabada/issues/126), which deliberately does not
  presuppose that wiring it up is the right answer.
- **The ROPC, authorization code and admin console permission paths.** All verified correct in
  the sibling audit above.
- **`Client.ClientCredentialsEnabled` defaults, and whether client secrets should rotate.**
  Adjacent to the precondition for this attack, neither is part of it.

---

## 3. Proposed solution

Six changes. Sections 3.1 through 3.4 address the scope escalation, in decreasing order of
importance, and 3.1 is the security fix and stands alone. Section 3.5 addresses the separate
user-context vulnerability and is independent of the other four. Section 3.6 fixes an unrelated
ROPC refresh defect and is independent of everything else here.

### 3.1 Compare the resource-scoped permission ID

Resolve the requested permission on the target resource, then accept only if the client holds
that exact permission, as the issue recommends:

```go
// token_validator.go, replacing :723-743
var requestedPermission *models.Permission
for i := range permissions {             // permissions == GetPermissionsByResourceId(nil, res.Id)
    if permissions[i].PermissionIdentifier == parts[1] {
        requestedPermission = &permissions[i]
        break
    }
}
if requestedPermission == nil {
    return customerrors.NewErrorDetailWithHttpStatusCode("invalid_scope",
        fmt.Sprintf("Scope '%v' is not recognized. The resource identified by '%v' doesn't grant the '%v' permission.", scopeStr, parts[0], parts[1]),
        http.StatusBadRequest)
}

clientHasPermission := false
for _, cp := range client.Permissions {
    if cp.Id == requestedPermission.Id {   // resource-aware by construction
        clientHasPermission = true
        break
    }
}
```

`permissions` is already narrowed to the requested resource, and
`(permission_identifier, resource_id)` is unique on every supported engine, so at most one row
can match and the `break` cannot discard a second candidate. The ownership comparison is then a
single id equality.

**An earlier draft of this spec proposed a set of matching ids instead**, on the false premise
recorded in section 1 that three of the four engines permitted duplicate same-identifier rows on
one resource. With that premise removed there is nothing for a set to be robust against: the
extra slice would model a cardinality the data model forbids, which teaches the next reader the
wrong thing about the schema. Decision 18 has the full reasoning, including why defence in depth
was declined here.

**The two loops must stay separate.** Collapsing the resolve and the ownership check into a
single lookup would merge two distinct outcomes, "no such permission on that resource" and "that
permission is not yours", into one. Both messages are asserted verbatim in the integration table
at `token_clientcred_test.go:230-241`, and the distinction is worth keeping on its own merits.

### 3.2 Normalize the scope once, at the handler

```go
// handler_token.go:58-59 and :90 (post-stage-2)
Scope: normalizeScope(r.PostForm.Get("scope")),
```

where `normalizeScope` trims, collapses internal whitespace runs to single spaces, and drops
duplicate scopes preserving first-occurrence order. That is the same operation
`AuthContext.SetScope` (`core/oauth/auth_context.go:56-71`) already performs on the authorize
path, so after this change all four scope-handling sites agree, per decision 10.

A **non-empty raw scope that normalizes to empty** is rejected rather than treated as omitted,
per decision 15. Note the precision: `scope=` with an empty value is indistinguishable from an
omitted parameter through `PostForm.Get` and is deliberately left alone.

```go
if raw != "" && normalized == "" && grantTypeConsumesScope(input.GrantType) {
    // invalid_scope: "The 'scope' parameter was provided but contains no scopes. Either
    // omit it entirely or supply one or more scopes separated by spaces."
    //
    // Grant-neutral by necessity: this fires for three grant types whose omitted-scope
    // behaviour differs. Client credentials returns every scope granted to the client,
    // refresh preserves the original token's scope, ROPC returns "openid". A message
    // naming any one of those would be wrong for the other two.
    //
    // Deliberately NOT audited: this runs before the client is authenticated, so an
    // AuditTokenScopeDenied here would record an unverified client_id. See decision 12.
}
```

`raw != ""` catches whitespace-only input and deliberately not `scope=`, which `PostForm.Get`
cannot distinguish from an omitted parameter. Decision 15 explains why that is correct rather
than a gap.

**This placement is load-bearing and must carry a comment saying so.** Putting the trim inside
`validateClientCredentialsScopes` instead opens a hole. With `scope="   "`, the
`len(input.Scope) == 0` test at `:295` runs first and sees three characters, so the
all-permissions branch is skipped. The validator then trims to empty, hits its own early return
at `:735-737`, and returns nil **without executing the ownership loop at all**. Line `:314`
carries `"   "` through to `GenerateTokenResponseForClientCred`.

**What that does not do is issue a token, and an earlier draft of this spec claimed it did.**
Executed against the issuer's `aud` derivation (`token_issuer.go:361-381`): `"   "` splits into
four empty strings, each fails the `len(parts) != 2` check at `:367`, so the issuer returns
`invalid scope: ` and `handler_token.go:216-219` turns it into a **500**. An empty string
reaching the same code trips `:376` instead, "unable to generate an access token without an
audience". Either way no token is minted, so the natural-looking placement converts a 400 into
a 500, not a rejection into an unchecked scope claim.

The placement is still correct, on the two reasons that survive. The validator's early return
genuinely skips the ownership loop, so the validator is not a place where a scope can be relied
on to have been checked at all. And decision 15's rejection needs to distinguish a raw
whitespace-only string from an omitted one, which only the handler can see. **The comment in the
code must give those two reasons and not the token claim**, since a comment asserting a
vulnerability that does not exist would mislead exactly the reader it is written for.

**Which grant types the provided-but-empty rejection applies to.** Only those that consume
`input.Scope`, verified by grepping every use: client credentials (`:295`, `:302`, `:304`,
`:307`, `:314`), refresh (`:469`, `:472`, `:496`, `:497`) and ROPC (`:717`). The authorization
code grant **never reads `input.Scope`**, since the scope comes from the stored code, so
rejecting on it would break an otherwise valid token exchange for no benefit. RFC 6749 section
4.1.3 does not define `scope` on that request in the first place.

What the rejection changes per grant type, all executed:

| Grant type | `scope="   "` today | after |
|---|---|---|
| client_credentials | `invalid_scope: Invalid scope format: ''` | `invalid_scope`, with a message naming the actual problem |
| refresh_token | `invalid_grant: Scope '' is not recognized` | same rejection, clearer message |
| ROPC | **accepted**, `validateROPCScopes:833-836` skips empties and `:900-902` returns `"openid"` | rejected |
| authorization_code | ignored entirely | ignored entirely, unchanged |

ROPC is the only accept-to-reject change, on a deprecated grant receiving malformed input. It
is called out in decision 15 rather than buried here.

### 3.3 Audit

Add `"scope": validateResult.Scope` to the existing payload at `handler_token.go:222`.

**Note the key naming.** The success payload logs `"clientId": validateResult.Client.Id`
(`:223`), the numeric primary key. The denial event cannot use that key, because
`ValidateTokenRequest` returns `(nil, err)` on failure and discards the client model it
resolved. The client has at least been **looked up** by then, and on the client credentials path
it has also been authenticated (`:250-283`, before scope validation at `:307`); the handler
simply never receives the model. On the ROPC path a public client is never authenticated at all,
per `:650`. So the denial event carries `clientIdentifier`, the string from the form, and the
two events do not put different types behind the same key in one log stream. What that string
attests to varies by grant type, which decision 12 spells out.

**One call site.** The decision 15 rejection is deliberately not audited, because it fires
before the client is authenticated and would otherwise write an unauthenticated,
attacker-chosen identifier into the log. See the discussion above and decision 12.

Add one audit event for any token request denied over scope, keyed on the error code rather
than the grant type:

```go
// inside the existing if err != nil block at handler_token.go:99
if detail, ok := err.(*customerrors.ErrorDetail); ok && detail.GetCode() == "invalid_scope" {
    auditLogger.Log(constants.AuditTokenScopeDenied, map[string]interface{}{
        "clientIdentifier": input.ClientId,   // string, not the numeric id
        "grantType":        input.GrantType,
        "scope":            input.Scope,
    })
}
```

**What this covers, counted precisely.** There are **eleven** scope denial branches once
decision 15 adds one at the handler. Eight are audited, three deliberately are not:

| Path | Branch | Code | Covered |
|---|---|---|---|
| handler | decision 15, non-empty scope normalizing to empty | `invalid_scope` | **no**, see below |
| client credentials | `:747` OIDC scope requested | `invalid_request` | **no** |
| client credentials | `:754` malformed pair | `invalid_scope` | yes |
| client credentials | `:764` unknown resource | `invalid_scope` | yes |
| client credentials | `:787` permission not on resource | `invalid_scope` | yes |
| client credentials | `:807` not granted to client | `invalid_scope` | yes |
| ROPC | `:847`, `:861`, `:881`, `:892` | `invalid_scope` | yes |
| refresh | `:488` down-scope outside the original grant | `invalid_grant` | **no** |

Inside the token validator, `invalid_scope` is returned only by the two scope validators, so the
predicate has no false positives there and stays correct if a scope validator gains another
`invalid_scope` branch.

**The handler branch is excluded, and this reverses an earlier draft of this spec.** That draft
added a second audit call site at the decision 15 rejection, to satisfy a goal worded as "every
`invalid_scope` response is audited". That was the wrong fix, for a reason the wording hid: the
handler rejection fires **before** `ValidateTokenRequest`, so **before the client is
authenticated**. Emitting an audit event there would write an attacker-controlled
`client_id` into the audit log with no authentication behind it, letting anyone flood the log
with rows naming a legitimate client. The event exists to surface a caller reaching for access
it was not granted, and an unauthenticated, spoofable row is not that signal; it actively
degrades it.

**Being pre-authentication is the whole reason, and no semantic argument supports it.** An earlier
version of this passage added that a whitespace-only scope "is malformed input, not an authorization
decision, which is precisely the ground on which `:747` is already excluded". Both halves were
wrong. This event deliberately covers six authenticated malformed-format and unknown-resource
branches, so malformed input is plainly not the wrong *kind* of event for it. And `:747` is excluded
because it returns `invalid_request`, which the predicate cannot isolate, not because of what it
means.

So the goal in section 2 is worded around **authenticated** `invalid_scope` failures, meaning
those returned by the two scope validators, rather than around the bare `invalid_scope` string
that the earlier draft used. The qualifier that does the work is *where* the failure happens, not
what kind it is: it is what excludes the pre-authentication handler branch. The accounting is eight
of eleven.

**Three branches are deliberately outside it, and section 2 enumerates all three to match.**
`:747`, a client credentials request for `openid` or `offline_access`, returns
`invalid_request`, which the file uses twelve times. The refresh down-scope denial at `:488`
returns `invalid_grant`, used 22 times for everything from "Client is disabled" (`:94`) to
"Code is invalid" (`:142`). Neither is isolatable by code, so covering them means threading a
typed error through the validator.

`:747` is little loss: a client asking for `openid` on client credentials has misread the docs. Note
this is a **cost** assessment, not the reason for the exclusion, which is purely that
`invalid_request` cannot be isolated. And it is a soft argument, because the event does log six other
misconfiguration-shaped branches; if `:747` were isolatable there would be no case for dropping it.

**`:488` is a genuine loss and should be recorded as one.** A client asking to refresh with a
scope outside its original grant is reaching for access it does not have, which is precisely the
signal this event exists to surface. It is excluded because `invalid_grant` cannot distinguish
it from 21 unrelated failures, not because it does not belong. That is a limitation of the error
taxonomy, and if `:488` ever gains a typed error, this event should cover it.

**The boundary is therefore positional, not semantic, and the spec should not pretend
otherwise.** "Every `invalid_scope` from the two scope validators" is what the predicate
actually implements. It happens to include authenticated malformed-format requests at `:754`
and `:847`, which are not authorization decisions in any strict sense. Calling all eight
"authorization denials" would be a tidier story and a false one. See decision 12.

### 3.4 Drop the redundant re-lookup

`:295-305` uses `perm.Resource.ResourceIdentifier` directly instead of round-tripping it
through `GetResourceByResourceIdentifier`.

### 3.5 Require a user-bound token on user-context endpoints

New middleware on the two route groups that resolve a user from `sub`:

```go
// RequireUserBoundToken rejects tokens that do not represent an authenticated user.
// Client credentials tokens carry sub = client identifier, which must never be
// mistaken for a user subject.
func RequireUserBoundToken() func(http.Handler) http.Handler
```

**The exact response contract**, since `emitAuthError` (`api_auth.go:22-37`) maps every bearer
403 to `error="insufficient_scope"` in `WWW-Authenticate` and the guard must not invent a
parallel convention:

| Condition | Status | JSON `ErrorCode` | `WWW-Authenticate` |
|---|---|---|---|
| token present, no `auth_time` | 403 | `USER_CONTEXT_REQUIRED` | `Bearer error="insufficient_scope", error_description=...` |
| no bearer token in context | 401 | `ACCESS_TOKEN_REQUIRED` | `Bearer error="invalid_token", ...` |
| context value is not a `JwtToken` | 401 | `INVALID_TOKEN_FORMAT` | `Bearer error="invalid_token", ...` |

The last two mirror `RequireBearerTokenScope` at `:44-54` exactly, reusing `emitAuthError` with
`bearer: true`, so the guard adds no new response shapes.

`insufficient_scope` is imprecise here, since the token does carry the required scope, but
RFC 6750 section 3.1 defines only `invalid_request`, `invalid_token` and `insufficient_scope`,
and none of them means "wrong token type". Reusing the existing 403 mapping keeps the
`WWW-Authenticate` header RFC-conformant, and the JSON `ErrorCode` carries the precise reason,
which is how every other guard in this file already distinguishes its cases.

**Presence only, not shape.** The guard checks that `auth_time` exists and does not validate its
type or range. That is safe because `JwtAuthorizationHeaderToContext` calls
`DecodeAndValidateTokenString(tokenStr, nil, true)` (`core/middleware/middleware_jwt.go:104`)
and only stores the token in context when signature validation succeeds, so claims reaching this
middleware are server-issued and cannot be forged. A malformed `auth_time` is therefore not a
reachable state, and adding a numeric check would be dead code of the kind decision 2 rejected in
turning down an `Id == 0` guard. **Decision 7 is deliberately not cited alongside it**, though an
earlier version of this sentence did: that guard was rejected because the path fails closed without
it, not because its state is unreachable. The state there is reachable, per section 1. **This is a dependency, not an assumption:** if a future change ever puts an
unverified token into that context key, this guard weakens with it.

**Why `auth_time` and not `sid`.** `sid` is conditional: it is set only when a session exists
(`token_issuer.go:659` and `:794`), so ROPC tokens issued without a browser session have no
`sid` and requiring it would break them. `auth_time` is set unconditionally by the single shared
access-token generator that every user token passes through, and the client credentials claim
set (`:353-382`) is built separately and never contains it. Stage 6 step 4 carries the full
five-path trace; that trace, not this paragraph, is the authority on the claim's universality.

**The guard depends on `auth_time` being *present*, not on its value being meaningful, and the
distinction matters.** On the ROPC refresh path the value is wrong:
`createTokenInputFromROPC:916` passes `now`, so a refreshed ROPC token reports `auth_time` as
the moment of the refresh request even though the user did not authenticate then. That is a
pre-existing defect in an OIDC claim's semantics, unrelated to this spec and not fixed by it,
recorded in section 2's out-of-scope list. It does not weaken the guard, which reads presence
only, but this spec must not claim the value is semantically correct on every path, because on
one path it is not.

**It fails closed.** A future token type that forgets `auth_time` is rejected from these
endpoints rather than admitted, which is the safe direction for a guard whose whole job is to
establish that a user is present.

Applied at `routes.go:78-79` (`/userinfo`, both methods) and the `/api/v1/account` group at
`:304-308`, after the existing scope check so that an insufficient-scope caller still gets the
403 it gets today.

### 3.6 Stop ROPC refresh rejecting a scope the server injected

**The defect.** A ROPC token that requested `openid` cannot be refreshed at all, unless the user
separately holds `authserver:userinfo`. Executed: the refresh returns `invalid_grant`, "Scope
'authserver:userinfo' is not recognized. The user does not have the 'authserver:userinfo'
permission."

Three pieces combine:

1. `generateAccessTokenCore` appends `authserver:userinfo` to the scope whenever an OIDC scope is
   present (`token_issuer.go:697-704`), so the issued token can reach `/userinfo`. It returns that
   **post-injection** scope to its caller.
2. `GenerateTokenResponseForROPC:1148` passes that returned scope, not the validated
   `input.Scope`, to `generateRefreshTokenForROPC`, which stores it in `RefreshToken.Scope`.
3. On refresh, the validator re-checks every non-OIDC scope against the user's grants
   (`token_validator.go:597-606`). For ROPC it reads `refreshToken.Scope` (`:396`); for the
   authorization code grant it reads `refreshToken.Code.Scope` (`:417`), which is pre-injection.

So the server injects a scope, records it as though the user had been granted it, then refuses to
refresh because the user was never granted it.

**Why only ROPC breaks.** The authorization code path stores an equally polluted
`RefreshToken.Scope` (`:147` passes `scopeFromAccessToken` too), but nothing reads it: the
validator consults `Code.Scope` instead. ROPC has no `Code` row, so `RefreshToken.Scope` plays
that role and the pollution becomes load-bearing.

**Why it went unnoticed.** No test redeems a ROPC refresh token. The four ROPC tests that mention
refresh assert only that `refresh_token` is non-empty (`ropc_flow_test.go:102`, `:144`, `:457`,
`:637`). Requesting `openid` is the normal case for ROPC, so this is not an edge case.

**The only workaround is absurd.** An operator has to grant every affected user the built-in
`authserver:userinfo` permission, for a scope the server is already appending to their tokens
unconditionally. That does work, which is why stage 6's ROPC test carries exactly that grant until
stage 7 removed it, but it meant configuring a permission to satisfy a check the server should
never have applied.

**Two changes, each with its own reason**, per decision 19:

```go
// 1. token_issuer.go:1148 — record what was granted, not what was decorated.
//    input.Scope is validateResult.Scope, the output of validateROPCScopes.
refreshToken, refreshExpiresIn, err := t.generateRefreshTokenForROPC(
    settings, input, input.Scope, now, privKey, keyPair.KeyIdentifier, nil)
```

```go
// 2. token_validator.go:597 — never re-check a scope the server injected.
//
// Conditioned on the stored scope carrying an OIDC scope, because that is EXACTLY when the
// server injects (token_issuer.go:670-676 sets addUserInfoScope only inside
// `if oidc.IsIdTokenScope(s)`). Unconditional would be wrong: see below.
storedScopeHasOidcScope := false
for _, s := range strings.Split(tokenScope, " ") {
    if oidc.IsIdTokenScope(s) {
        storedScopeHasOidcScope = true
        break
    }
}
// ... then, inside the per-scope loop:
if !oidc.IsIdTokenScope(inputScopeStr) && !oidc.IsOfflineAccessScope(inputScopeStr) &&
    !(storedScopeHasOidcScope && inputScopeStr == userInfoScope) {
```

The first fixes newly issued refresh tokens and aligns ROPC with the authorization code grant's
data model. The second fixes refresh tokens **already issued and stored**, which the first cannot
reach: offline refresh tokens can live for weeks, so without it every existing ROPC refresh token
stays broken until it expires.

**Why the exclusion must be conditional, and this corrects an earlier draft.** That draft skipped
`authserver:userinfo` unconditionally and claimed the change granted nothing new. Both were wrong,
and the reason is that ROPC can carry this scope for a second, unrelated reason. Unlike
`/auth/authorize`, `validateROPCScopes` has **no guard against requesting `authserver:userinfo`
explicitly** (verified: the userinfo rejection exists only in `authorize_validator.go`). So a ROPC
request for `scope=authserver:userinfo` alone succeeds whenever the user genuinely holds that
permission, and because no OIDC scope is present nothing is injected. The stored scope is then
exactly `authserver:userinfo`, representing a real user grant.

Skipping the re-check unconditionally would mean that for such a token, **revoking the user's
`authserver:userinfo` permission never takes effect on refresh**. The re-check is the mechanism by
which revocation reaches an outstanding refresh token, so that is a genuine loss, narrow but real.
Conditioning on the presence of an OIDC scope reproduces the injection condition exactly, so the
skip never applies to an explicitly granted scope **without** an OIDC scope, which is the case
where revocation has to keep working. It does still apply when an explicit grant sits alongside an
OIDC scope, because the two are indistinguishable in the stored record; see the residual case
below, where it costs nothing.

**The privilege claim, restated correctly.** For a stored scope containing an OIDC scope, skipping
the re-check grants nothing: `authserver:userinfo` is appended to every such token regardless of
what the user holds, so re-validating it against user grants is a category error. That argument
does **not** extend to a stored scope without an OIDC scope, which is why the condition exists.

**One residual case, harmless and worth recording.** A user who explicitly requested
`openid authserver:userinfo` while holding the permission produces a stored scope indistinguishable
from the injected case, because the injection is idempotent
(`if !slices.Contains(scopes, userInfoScopeStr)`). Revocation therefore will not bite on refresh
for that token. This is harmless for the reason above: the token carries `openid`, so it would
receive `authserver:userinfo` anyway. The information needed to separate the two cases was never
recorded, and inventing it is not worth a schema change for a scope that is granted implicitly to
every OIDC-scoped token.

### Why this is safe

**The security fix can only tighten.** Every request it newly rejects is one where the client
does not hold the requested permission on the requested resource. No client holding a genuine
grant sees any change, because a genuine grant is a `clients_permissions` row pointing at exactly
the permission the resolve step found. There is no input for which the new code accepts something
the old code rejected. Measured against the implemented code: 7 unit cases change outcome, and all
7 change from accept to reject. Confirmed by reverting the ownership check to the bare-identifier
form and re-running, which fails exactly those 7 and no others.

That holds for the single-id form because the resolve step runs against a list already narrowed
to the requested resource, on which the requested identifier can appear at most once. An earlier
draft argued a set of ids was needed here; section 3.1 and decision 18 record why that argument
rested on a false premise about the schema.

**The normalization grants nothing that was not already grantable.** It newly accepts scope
strings that differ from an already-accepted one by whitespace or a repeated scope alone, which
changes how a request is written and never which `resource:permission` pairs are checked.
Measured after implementation, in place of the withdrawn harness figure: on both the client
credentials and the refresh path a tab-separated scope went from a **500** to an issued token whose
claim `HasScope` matches. Trimming and deduplication are pinned at the handler and helper layers
rather than end to end. Stage 2's status block has the detail.

Decision 15 is what makes that claim hold. Without it, a scope of `"   "` would normalize to
empty, fall into the all-permissions branch at `:295`, and turn a rejected malformed request
into a token carrying every permission the client holds. That grants nothing the client could
not obtain by omitting `scope` entirely, so it is not an escalation, but it converts an
accidentally malformed least-privilege request into a maximal one, which is not a property to
give away in a security fix. With the rejection in place, a whitespace-only scope stays rejected on
the two grants that already rejected it, gaining a message that names the problem, and becomes
rejected on ROPC, which previously treated it as absent. Pinned by the handler-wiring table rather
than counted.

The two sets overlap in exactly one case, a duplicated scope that is also cross-resource
(`reports-api:read reports-api:read` against a client holding only `billing-api:read`). It
changes for both reasons at once and is denied under the new code, which is the outcome the
security fix requires. Deduping cannot launder a denied scope, because normalization runs at
the handler and ownership is checked afterwards, per scope, on the deduplicated list.

---

## 4. Open questions and decisions

1. **Compare `perm.Id`, not the identifier pair.** Status: **Decided**

   The ownership loop compares resource-scoped permission IDs, per the issue's recommendation.
   Verified viable: `ClientLoadPermissions` resolves through `GetPermissionsByIds` and
   `GetPermissionsByResourceId` scans full rows, so IDs are populated on both sides in
   production.

   **Rejected:** comparing `(perm.Resource.ResourceIdentifier, perm.PermissionIdentifier)`. It
   is self-evidently correct at the call site and does not risk matching on zero values, but it
   depends on `PermissionsLoadResources` having run and costs a string compare per entry. IDs
   need no loaded association and match the pattern already established by
   `UserHasScopePermission` (`permission_checker.go:81`).

2. **Fix the three vacuous fixtures. No `Id == 0` guard.** Status: **Decided**

   Three positive subtests build permissions with no `Id` on both sides, so under an ID
   comparison every one matches every other at zero:

   | Subtest | Client permissions | Mocked resource permissions |
   |---|---|---|
   | "Valid client credentials request" `:1413` | `:1439` | `:1446` |
   | "Valid scope" `:1495` | `:1521` | `:1529-1530` |
   | "Multiple valid scopes" `:1755` | `:1781` | `:1790-1792` |

   Left alone they pass identically with the fix, without the fix, and with the ownership check
   deleted. They get distinct non-zero IDs. The two negative subtests stay honest for unrelated
   reasons: "Scope not granted to client" `:1581` gives the client an empty permission slice,
   and "Non-existent permission in scope" `:1711` mocks an empty resource permission list so it
   fails at the existence check before ownership is reached.

   **Rejected:** a `perm.Id == 0` guard in production code. `Id` 0 is unreachable, since every
   path loads permissions from autoincrement primary keys, so the guard would be permanently
   dead code in a security check and would imply to the next reader that zero IDs are a real
   state. Also rejected: leaving the fixtures and letting the new regression tests carry the
   burden. Three permanently green tests that cannot distinguish fixed from broken code is the
   condition that let this ship.

   The ROPC tests in the same file already do this correctly (`token_validator_test.go:4171`
   uses `{Id: 1, PermissionIdentifier: "read", ResourceId: 1}`), so this aligns the older cases
   with existing practice in the file.

3. **Regression tests at two layers, including the escalation case by name.** Status: **Decided**

   Unit cases own the exhaustive table. Integration gets the collision in both directions plus
   `authserver:manage`, because that is the case a reader will look for and it exercises the
   real built-in permissions rather than synthetic ones.

   **Rejected:** folding the integration cases into the existing table at
   `token_clientcred_test.go:205-241`. Its premise is a client holding zero permissions, and
   the collision requires a granted permission, so adding one to the shared setup would undercut
   what its other five rows test.

4. **No ordering constraint between the reject and accept legs.** Status: **Decided**

   Unlike an authorization code test, client credentials consumes no one-shot resource, so
   neither leg can pre-empt the other. Recorded explicitly so nobody later adds an ordering
   comment that implies a hazard that does not exist.

5. **Trim at the handler, not in the validator.** Status: **Decided**

   Superseded in extent by decision 9, which keeps the placement and widens the operation from
   trimming to full normalization. The placement reasoning in section 3.2 is what matters and
   is unchanged.

   **Rejected:** trimming inside `validateClientCredentialsScopes`, which opens the
   all-whitespace hole described in section 3.2. Also rejected: leaving the divergence and
   filing it separately, since `validateClientCredentialsScopes` turned out to be the only
   outlier of the four sites, so fixing it here removes the divergence rather than relocating
   it.

6. **Both audit changes.** Status: **Decided**

   The `scope` field on the success payload, and a new event covering every **authenticated**
   `invalid_scope` failure from the two scope validators, across client credentials and ROPC.
   That is a positional boundary, not a semantic one: it includes malformed-format and
   unknown-resource failures, and only two of the eight branches it covers are authorization
   decisions. An earlier version of this decision said "scope denials that are authorization
   decisions", which section 3.3 already warned against. Decision 12 fixes the exact
   boundary; the phrasing here is deliberately not "every client credentials scope failure",
   which an earlier draft said and which was never true, since the OIDC-scope rejection at
   `:747` is excluded.

   **The precedent an earlier draft cited does not exist, though others do.** That draft named
   `AuditROPCAuthFailed`, which is declared at `constants.go:84`, listed in `AuditEventTypes` at
   `:214`, and **logged by nothing**. It is dead, and it is now tracked separately as
   [#126](https://github.com/leodip/goiabada/issues/126).

   The real precedents are `AuditAuthCodeReuseDetected` (`handler_token.go:371`) and
   `AuditUserDisabled` (`:117`), both emitted when a token request is denied. So this event is
   not the project's first of its kind, and both existing ones fire only after the request has
   been authenticated, which is the same standard decision 12 applies.

   **Rejected:** the forensic field alone. A denied cross-resource request is a high-signal
   indicator, since a legitimate client never asks for a scope it was not granted. Also rejected:
   an event for the ownership denial only, which would leave "resource not found" and
   "permission not recognized" silent and make the trail arbitrary.

7. **Clean up `:295-305`, no empty-identifier guard, and add the missing unit coverage.**
   Status: **Decided** (reasoning corrected 2026-07-28)

   The redundant round-trip goes, and no guard replaces it.

   **The original reasoning here was that this parallels decision 2's rejection of an `Id == 0`
   guard, both being dead code for unreachable states. That parallel is false.** `Id == 0` really is
   unreachable: every path loads permissions from autoincrement primary keys, so no real row carries
   it. A zero-valued `perm.Resource` is **reachable**, via a resource deleted between the two
   non-transactional loads, per section 1.

   The correct reason is that removing the call makes the path fail closed on its own. A zero-valued
   resource yields the scope `":<permission>"`, which `validateClientCredentialsScopes` rejects with
   `invalid_scope`. A guard would turn that 400 into a differently-worded 400. The old code, by
   contrast, dereferenced a nil resource in that race, so the removal fixes a latent panic rather
   than declining to guard an impossibility.

   Also note the terminology: `models.Permission.Resource` is a **value** field, so there is no nil
   to guard. Earlier drafts of this spec said "nil guard" and "orphan guard"; the state is a
   zero-valued struct with an empty identifier.

   **Rejected:** leaving `:295-305` alone as adjacent scope. The counterargument is real, that a
   reviewer bisecting later would rather see the escalation fix by itself, which is why it is a
   separate stage and therefore a separate commit.

8. **Release note and one documentation sentence.** Status: **Decided**

   There is no CHANGELOG in the repo, so the note is drafted here and publishing is a
   release-time action, following the issue 105 precedent. Nothing in `site/` is falsified,
   since identifiers genuinely are per-resource and only the code disagreed, so the docs change
   is an addition rather than a correction.

9. **Full normalization at the handler, not only trimming.** Status: **Decided**

   Extends decision 5. The handler applies trim plus whitespace collapse, so the canonical form
   is established once at the entry point and flows into both validation and the token claim.

   Discovered while executing the case table: two cases failed against decision 5 as written,
   which surfaced that the collapse at `:740-743` operates on a local copy and never reaches
   `input.Scope`. Trimming alone leaves a tab-separated request broken.

   **The original wording here said "producing a token whose every scope is unmatchable by
   `HasScope`", which stage 2 measured and disproved.** The issuer re-parses the scope and rejects
   it, so the request returns a **500** instead. Section 1 has the measurement and the general
   lesson. The decision itself is unaffected: trimming alone leaves the request broken either way,
   and full normalization is what fixes it.

   **Rejected:** keeping decision 5 as agreed and filing the tab case separately. Same single
   site, same one-line change, and it fixes the identical defect in refresh down-scoping at
   `:472` and `:497` at no extra cost.

10. **`normalizeScope` also dedupes.** Status: **Decided**

    Extends decision 9 from trim plus collapse to trim, collapse and drop duplicates preserving
    first-occurrence order, matching `AuthContext.SetScope` (`core/oauth/auth_context.go:56-71`)
    exactly. After this, all four scope-handling sites agree.

    **Stated plainly: unlike decision 9, this fixes nothing that is broken.** A duplicated scope
    in a token claim is inert, since `HasScope` matches the first occurrence and any resource
    server splitting on spaces sees the scope twice and behaves identically. This is chosen for
    consistency, not correctness, and it is the same one function at the same one site that
    decision 9 already introduces. Refresh and ROPC inherit it at no extra cost, both having
    preserved duplicates until now (`:497` and `:897`).

    **Rejected:** trim and collapse only, leaving `authorize` as the sole path that dedupes.
    Defensible on the grounds that the change should touch only what was broken, but it leaves
    three of four sites agreeing and one differing, which is the shape this whole thread of
    decisions exists to remove.

    Carries a documentation obligation, recorded in section 1: handler-level normalization does
    not reach the no-scope expansion at `:295-305`, which runs later and builds its scope
    server-side.

11. **No security advisory for either vulnerability. Release note only.** Status: **Decided**

    This spec covers two vulnerabilities with different disclosure situations, so they get
    separate reasoning rather than one shared rationale. An earlier draft of this decision
    covered only the scope escalation and would have absorbed the second one silently, which
    would have been wrong: the two are not alike on this point.

    Common to both: the repository has published zero security advisories, verified against
    `repos/leodip/goiabada/security-advisories`, while handling thirteen closed and eleven open
    security-labelled issues through releases alone. And a GHSA's practical reach here is
    limited, since Dependabot alerts only consumers importing `github.com/leodip/goiabada/core`
    as a Go module, not the operators running the server, who are the affected population.

    **Cross-resource scope escalation: the disclosure window is already spent.** #104 has been
    public with a full reproduction since 2026-07-25. A GHSA's primary value is coordinated
    private disclosure ahead of a fix, and that option went when the issue was filed publicly.
    What remains is a CVE identifier.

    **User impersonation through `sub`: the window is intact, and the reason is different.**
    This was found during verification for this spec and appears in no public issue, so
    coordinated disclosure was genuinely available. It is declined on **severity and
    precondition** instead: exploiting it requires the ability to choose a client identifier,
    meaning `authserver:manage-clients` or `authserver:manage`. The attacker therefore already
    administers clients, and the escalation is from that to acting as arbitrary users. Real, and
    worth fixing in this release, but not the profile that warrants the project's first advisory.

    **Rejected:** a GHSA for either. For #104, singling out one issue against eleven open
    security issues handled otherwise implicitly ranks #107, #106 and #111 as not warranting it.
    For the impersonation issue, the argument for one is stronger, since the window is unspent,
    and it is declined on precondition rather than on the publicity argument that carries the
    first case. Whether the project publishes advisories at all remains a policy question worth
    having separately, and it should not gate either fix.

    **Consequence to accept knowingly:** stage 6 ships a fix for a vulnerability whose details
    reach the public for the first time in the release note. Operators learn of it and of its
    remedy simultaneously, with no window in which the flaw is described but unpatched.


12. **The denial event covers any grant type, keyed on `invalid_scope`.** Status: **Decided**

    Not gated on `input.GrantType`. Covers **eight of the eleven** scope denial branches: the
    four `invalid_scope` branches in client credentials and all four in ROPC, per the table in
    section 3.3. **One call site**, inside the `if err != nil` block after
    `ValidateTokenRequest`, so every row it writes follows a successful authentication of the
    principal that grant type authenticates.

    **The boundary is positional, not semantic.** It is "every `invalid_scope` from the two
    scope validators", which is a predicate the code can actually express. That includes
    authenticated malformed-format requests (`:754`, `:847`) that are not authorization
    decisions, and excludes the refresh down-scope denial at `:488` that is one. An earlier
    draft of this decision described all eight as authorization decisions, which was a tidier
    description than the truth.

    **That principal is not always the client, and the payload should not be read as if it
    were.** Client credentials authenticates the client itself (`:250-283`), so a row from that
    grant does attest to the named client. ROPC authenticates the **user**, and authenticates
    the client only when it is confidential: `if !client.IsPublic` at `:650` gates the whole
    secret check. For a public ROPC client, `clientIdentifier` in the payload is request context
    supplied by the caller, not proof that the named client's operator made the request. The
    row is still worth having, since the user behind it did authenticate, but an operator
    correlating these rows must not treat the identifier as attested for public ROPC clients.

    **Rejected:** gating on client credentials only, which would leave ROPC scope probing
    unlogged despite being the identical signal, at no saving. Also rejected: a typed
    scope-validation error covering all nine branches, which is the only way to reach `:747`
    (`invalid_request`, twelve uses) and `:488` (`invalid_grant`, 22 uses). The cost of that
    threading is not repaid by `:747`, which is a docs misread.

    **It is not free with respect to `:488`, and an earlier version of this decision said both
    excluded branches were "misconfiguration signals rather than authorization probes".** That
    contradicts section 3.3, which records `:488` as a genuine loss: a client refreshing with a
    scope outside its original grant is reaching for access it does not have, which is exactly this
    event's signal. The typed error is still declined, on the cost of threading it through the
    validator for one branch, but the tradeoff should be stated as a real loss rather than argued
    away.

    **Rejected, having previously been adopted:** a second call site at the decision 15
    rejection. It fires before client authentication, so it would write an attacker-chosen
    `client_id` into the audit log unauthenticated, letting anyone manufacture rows implicating
    a legitimate client. That degrades the exact signal the event exists to provide. It is also
    pre-authentication, which is the entire reason. An earlier version of this decision also
    called it "malformed input rather than an authorization decision, the same ground on which
    `:747` is excluded". That reasoning was wrong twice over: the event covers six authenticated
    malformed-format and unknown-resource branches, and `:747` is excluded by its `invalid_request`
    code rather than by its meaning. Coverage is decided by the error code and the call site's
    position, and by nothing else.

    **Two corrections against earlier drafts of this spec.** One claimed nine of nine and "all
    five client credentials branches"; `:747` returns `invalid_request`, so it was never
    covered. Another added the second call site described above. Section 2's goal is now worded
    around **authenticated** `invalid_scope` failures rather than around the bare `invalid_scope`
    string, which is what
    let both errors look correct.

13. **`AuditTokenScopeDenied = "token_scope_denied"`.** Status: **Decided**

    Grant-agnostic, as decision 12 requires. Sorts immediately after the five `token_issued_*`
    events, so a `token_*` filter groups token issuance with scope denials.

    **That is not the whole token endpoint, and an earlier version of this decision said it was.**
    `HandleTokenPost` also emits `user_disabled`, `bumped_user_session` and
    `auth_code_reuse_detected`, none of which carry the prefix, verified by grepping every
    `auditLogger.Log` call in the handler. The naming choice still stands on the narrower ground:
    grouping denials with issuance is worth having, and the alternatives in the rejected list sort
    away from both.

    **Rejected:** `invalid_scope_requested`, which mirrors the OAuth error code and correlates
    nicely with what the client saw, but sorts away from every related event. Also rejected:
    `scope_denied`, which is ambiguous about the endpoint and forecloses a future
    `authorize_scope_filtered`, a plausible companion given that
    `FilterOutScopesWhereUserIsNotAuthorized` silently drops scopes at authorize time.

14. **File the consolidation refactor as its own issue.** Status: **Decided**

    Filed as [#124](https://github.com/leodip/goiabada/issues/124), labelled `enhancement` and
    `go`. Tracked on GitHub rather than only in this spec's out-of-scope list, because it is the
    structural root cause of #104 and a spec file is not where a maintainer looks for work.

    Deliberately **not** labelled `security`. Nothing in #124 is exploitable once this spec's
    fix lands, and the security queue is eleven issues deep, so labelling a refactor as security
    would dilute the signal on the queue that matters.

    **Rejected:** leaving it as the one-line out-of-scope note. The counterweight is real, that
    eleven open security issues are already the binding constraint and a refactor issue with no
    forcing function tends to sit, but invisibility is worse than backlog noise for a root cause.

15. **Non-empty raw input that normalizes to empty is rejected.** Status: **Decided**

    `scope="   "` does not fall through to "no scope given". It is rejected at the handler with
    a message naming the problem, for the grant types that consume `input.Scope`.

    **`scope=` with an empty value is deliberately NOT covered, and is treated as omitted.**
    `r.PostForm.Get("scope")` returns `""` for both an absent parameter and an explicitly empty
    one, verified by execution:

    | Raw body | `Get("scope")` | `Has("scope")` |
    |---|---|---|
    | no `scope` parameter | `""` | false |
    | `&scope=` | `""` | **true** |
    | `&scope=%20%20` | `"  "` | true |

    So `raw != ""` cannot see `scope=`. That is the correct behaviour here rather than a defect
    to fix with `PostForm.Has`. An explicitly empty `scope=` is **already** accepted today and
    already yields all the client's permissions, because `Get` returns `""` and `:295` takes the
    all-permissions branch. This decision exists to stop normalization converting a *rejection*
    into a maximal grant, and whitespace-only is the only input in that category. Switching to
    `Has` would newly reject `scope=`, which plenty of HTTP clients emit when serializing an
    empty value, breaking working integrations for no security gain.

    **Rejected:** detecting presence with `r.PostForm.Has("scope")`. It would make the decision's
    title literally true at the cost of three new accept-to-reject changes across the consuming
    grant types, none of which closes anything.

    An earlier draft of this decision was titled "present but empty", which overclaimed what the
    sketch implements. The sketch was right; the prose was not.

    Without this, normalization would convert a currently-rejected malformed request into a
    token carrying every permission the client holds. That is not an escalation, since omitting
    `scope` already yields the same set, but it turns an accidentally malformed least-privilege
    request into a maximal one. A security fix should not hand that back, and it also lets
    section 3 claim the normalization grants nothing newly grantable, which is a far easier
    property to defend than "loosens only for semantically valid input".

    **Rejected:** accepting the promotion and documenting the tradeoff. Cheaper, and defensible
    since the capability is not new, but it trades away a real least-privilege property for
    nothing.

    **Two consequences, both deliberate.** The authorization code grant is excluded, because it
    never reads `input.Scope` (verified against every use of that field), so rejecting on it
    would break a valid token exchange for no benefit. And ROPC changes from accept to reject:
    it currently returns `"openid"` for a whitespace-only scope via `:833-836` and `:900-902`.
    That is the only accept-to-reject change in the normalization work, on a deprecated grant
    receiving malformed input.

16. **Engine-specific exposure queries, each executed.** Status: **Decided**

    The release note carries four variants rather than one query with a portability claim. A
    single portable form does not exist: `client_credentials_enabled` is `boolean` on PostgreSQL
    (`postgresdb/schema.sql:50`) so `= 1` is a type error, and MySQL reads `||` as logical OR
    unless `PIPES_AS_CONCAT` is set, so concatenation silently produces garbage rather than
    failing loudly.

    **Rejected:** one query labelled "standard SQL, runs on all four supported engines", which
    is what an earlier draft of this spec claimed on the strength of a SQLite-only run.
    Operators use this query for security triage, so an untested portability claim is worse
    than no claim.

    The join predicate is `p2.resource_id <> p.resource_id`, not `p2.id <> p.id`, because
    "different resource" is what the query is looking for and is the thing that makes a row a
    finding. An earlier draft justified this by claiming three engines permit two rows with the
    same identifier on one resource, so `p2.id <> p.id` would report a same-resource twin as a
    cross-resource collision. That premise was false, per decision 18: every engine enforces
    `(permission_identifier, resource_id)` uniqueness, so the two predicates are in fact
    equivalent on any supported database. `p2.resource_id <> p.resource_id` is kept because it
    states the intent directly rather than relying on the constraint to make an id comparison mean
    "cross-resource".

17. **Fix the user-context gap in this spec, not a follow-up.** Status: **Decided**

    Stage 6 adds `RequireUserBoundToken` to `/api/v1/account/*` and `/userinfo`. Discriminator
    is the `auth_time` claim, per section 3.5.

    **Rejected:** filing it separately, which was my first instinct since it is independent of
    the scope check. Two reasons against. The release note has to describe
    `authserver:manage-account` accurately either way, and describing a live impersonation path
    while pointing at an unscheduled issue is worse than shipping the guard. And the two fixes
    reach operators in the same release, so splitting them means the note either overclaims or
    reads as two half-fixes.

    **Rejected:** requiring `sid` instead of `auth_time`. It looks like the natural
    session-bound check and would break ROPC, whose tokens omit `sid` when no browser session
    exists (`token_issuer.go:794` is conditional).

    **Rejected:** blocking client credentials from being *granted* `authserver:manage-account`
    or `authserver:userinfo` at issuance. Tempting as defence in depth, but it breaks the
    existing integration fixture that mints exactly such a token to test insufficient-scope
    responses (`api_resources_test.go:155`, with 26 invocations across the suite, 11 of them in
    `api_account*_test.go`), and the endpoint is the correct place to enforce what the endpoint
    requires.

18. **Compare a single resolved permission id, not a set. The duplicate-twin premise was
    false.** Status: **Decided** (reverses an earlier decision, 2026-07-27)

    Stage 1 originally landed a set-based ownership check, on the premise that only MySQL enforced
    `(permission_identifier, resource_id)` uniqueness and that SQLite, PostgreSQL and SQL Server
    permitted two rows named `read` on one resource. Code review established the premise is false.
    All four engines create `idx_permission_identifier_resource`, in the migrations that actually
    run and in the snapshots: `mssqldb/000001:342`, `postgresdb/000001:319`,
    `mysqldb/000002:6`, `sqlitedb/000002:5`. Confirmed by execution, not only by reading: a second
    `read` on one resource is refused by the running PostgreSQL with `duplicate key value violates
    unique constraint "idx_permission_identifier_resource"`.

    **How the premise got in.** MySQL declares the constraint inline inside `CREATE TABLE
    permissions`; the other three declare it as a separate `CREATE UNIQUE INDEX` further down the
    same file. Reading only the `CREATE TABLE` block finds it on exactly one engine and reads the
    other three as unconstrained. Section 1 carries the corrected table so the next reader does not
    repeat it, and this spec's own note that migrations rather than snapshots are the source of
    truth should have been applied to this claim and was not.

    **What the false premise had been used to justify**, all now corrected: the set-based
    ownership check itself, two unit subtests mocking duplicate twins in both orderings, the
    "correct in all 7 orderings" claim in "Why this is safe", the `p2.resource_id <> p.resource_id`
    rationale in decision 16, and part of the `DISTINCT` rationale in the release note. The
    `clients_permissions` half of that last one survives on its own merits: that table genuinely
    has no unique constraint on `(client_id, permission_id)` on any engine, verified separately
    against the live schema.

    **Rejected: keeping the set-based form as defence in depth.** It is safe, and it would be the
    more robust choice against a database whose index had been dropped or a dump restored without
    it. Declined anyway. The unique constraint is a deliberate, universal part of the data model
    rather than an incidental optimization, the codebase already relies on schema invariants
    elsewhere, and both forms fail closed, so what the set buys is availability under a corrupt
    schema and nothing security-relevant. Against that, it allocates a slice and, more
    importantly, communicates to every future reader that multiple matching rows are a legitimate
    state when they are not. Teaching the wrong cardinality is the larger cost.

    This is also consistent with decision 2, which rejects an `Id == 0` guard on the same ground: do
    not write code for states the data model forbids. `Id == 0` is unreachable because every path
    loads permissions from autoincrement primary keys, and duplicate same-identifier rows on one
    resource are unreachable because every engine enforces the unique index, so applying the
    principle to one and not the other would have been arbitrary.

    **Decision 7 was originally cited here too, and no longer is.** Its guard was rejected for a
    different reason: the zero-valued `Resource` state it would have guarded is **reachable**, via a
    resource deleted between two non-transactional loads, and the guard is unnecessary only because
    the path fails closed downstream. Grouping the three together made the data-model argument look
    broader than it is.

    **Not reversed by this decision:** the fix itself, which was already correct, and every
    regression case that carries it. The 7 accept-to-reject unit cases and both integration tests
    involve no twins and were re-run against the amended code.

19. **Fix the ROPC refresh defect in this spec, at both the issuer and the validator.**
    Status: **Decided** (2026-07-27)

    Section 3.6 has the mechanism. Two changes: stop storing the post-injection scope on the ROPC
    refresh token (`token_issuer.go:1148`), and stop re-checking the injected
    `authserver:userinfo` against the user's grants on refresh (`token_validator.go:597`),
    **conditioned on the stored scope carrying an OIDC scope**.

    **Why in this spec rather than a separate issue**, unlike #125 and #126 which were both
    deferred. Stage 6's ROPC refresh test cannot pass without either this fix or a workaround, and
    the workaround is a grant of `authserver:userinfo` to the test user that misrepresents what
    the test is exercising. Shipping stage 6 with that workaround, plus an unscheduled issue
    describing why it is there, is worse than fixing a two-line defect in the same release. This
    is the same reasoning decision 17 applied to the user-context gap.

    **Rejected: the validator change alone.** It fixes both new and existing tokens and is enough
    to close the bug. But it leaves the ROPC refresh row recording a scope the user was never
    granted, which is the thing that made this bug possible, and it leaves ROPC's data model
    diverging from the authorization code grant's for no reason.

    **Rejected: the issuer change alone.** It is the more principled half, but it only fixes
    refresh tokens issued after deployment. Offline refresh tokens can live for weeks, so every
    ROPC refresh token already in a deployed database would stay broken until expiry, and the
    release note would have to tell operators to have their users re-authenticate. The validator
    change makes the fix retroactive.

    **Rejected: dropping the injection instead**, so `authserver:userinfo` never enters the scope
    string and nothing downstream needs to know about it. That is arguably the real root cause,
    but it changes what `/userinfo` accepts for **every** grant and every existing token, since
    `RequireBearerTokenScope` matches the scope claim. That is a much larger blast radius than the
    defect warrants, and it would break every currently valid user token's `/userinfo` access.

    **Rejected, having previously been adopted: an unconditional exclusion.** An earlier draft
    skipped `authserver:userinfo` in the re-check regardless of the rest of the stored scope, and
    asserted the change granted nothing new. `validateROPCScopes` has no guard against requesting
    that scope explicitly, so a ROPC token can carry it as a genuine user grant with no OIDC scope
    and no injection. Skipping unconditionally would mean revoking that user's permission never
    takes effect on refresh, which is exactly the loss the re-check exists to prevent. Section 3.6
    has the corrected reasoning and the one residual case that remains, which is harmless.
    Surfaced by code review, not by the case table, because no case in that table had a stored
    scope without an OIDC scope.

    **Consequence to note, and it applies only to the injected case.** After the issuer change,
    `RefreshToken.Scope` records `validateResult.Scope`, so it contains `authserver:userinfo` only
    when the original request asked for it. Two outcomes, and an earlier draft of this decision
    described the first as though it were both:

    - Original request did **not** include it (the normal case, e.g. `scope=openid`, where the
      scope was injected). The stored scope no longer carries it, so a refresh explicitly
      requesting `scope=authserver:userinfo` is now rejected by the down-scope check at `:488` as
      outside the original grant. Nothing is lost, because the scope is re-injected into the new
      access token regardless.
    - Original request **did** include it explicitly, and the user held the permission.
      `validateROPCScopes` returns explicitly requested resource scopes in its output
      (`:897`), so the stored scope still contains it and a refresh requesting it still succeeds
      while the user retains the permission. **Unchanged by this stage.**

    That earlier draft also justified the rejection by noting the scope cannot be requested at
    `/auth/authorize`. That is true but irrelevant here: `/auth/authorize` is not on the ROPC path,
    and it is precisely because `validateROPCScopes` has no equivalent guard that the second
    outcome above exists at all.

    **Not a privilege change**, per section 3.6: the scope is appended to every user token
    carrying an OIDC scope, so declining to re-validate it grants nothing new.

---

## 5. Implementation plan

Stages are independently reviewable and land as separate commits. Stage 1 stands alone and is
the only one that closes the **#104** vulnerability. Stage 6 closes the separate user-context
vulnerability and is likewise self-contained; neither depends on the other. Stage 7 fixes the
unrelated ROPC refresh defect and is self-contained too, with one ordering note: it removes a
workaround that stage 6's test carries, so it must land after stage 6 or the two must be
reconciled by hand.

**Where tests can run.** Unit tests run anywhere with `go test`. Everything under
`src/authserver/tests/integration/` requires the dev container
(`docker exec goiabada-devcontainer-1`, repo at `/workspaces/goiabada`), because the host has
no tailwindcss and cannot resolve the database hostnames. A green local `go test` proves
nothing about stages whose tests are integration-level.

**Case execution.** The tables below were originally validated against a throwaway harness, run
before any code existed, which reported 38 cases passing with 19 diverging before and after the
change.

**Those harness counts are withdrawn and are not carried forward.** The harness modelled the
**set-based** ownership check that decision 18 subsequently reversed, so its pass count cannot
describe the implemented single-id code. Whether any individual harness case would now fail is not
determinable: the harness was a throwaway from an earlier session and no longer exists, so nothing
here should be read as a claim either way. The two twin cases it may have covered are gone from the
suite regardless, per decision 18.

What replaces them is the real suite, which is stronger evidence because it runs against the
shipped code rather than a model of it:

- **Stage 1, measured.** 36 subtests in `TestValidateTokenRequest_ClientCredentials`, all passing.
  Exactly 7 fail when the ownership check is reverted to the bare-identifier form, all 7
  accept-to-reject. Two integration tests, both failing against the reverted form. See stage 1's
  status block.
- **Stage 2, measured.** Implemented on 2026-07-28. The harness's 9 normalization and 3
  whitespace-only figures were **not** reconstructed, deliberately: the harness is gone and a
  per-case census was never what mattered. Stage 2's status block records the behaviours that were
  verified instead, each at the layer that can execute it, including the two end-to-end changes that
  fail when the handler is reverted to pass the raw scope.

**The withdrawn harness modelled the client credentials path only**, which is why the three
whitespace-only cases need reading carefully when stage 2 is implemented. Within client credentials
all three stay rejections and merely gain a message that names the problem. The same input on
**ROPC** is an accept-to-reject change, because `validateROPCScopes:833-836` skips empty tokens and
`:900-902` returns `"openid"` today. That case sits outside the three, it is covered by the handler
table in stage 2 step 3, and it is the only accept-to-reject change the normalization work
introduces.

### Stage 1: the security fix
Status: **Done** (2026-07-27)

**Verified by execution, not by inspection.** Each claim below was checked by reverting the
production change and re-running: the 7 unit cases marked "accepts" in the tables below fail
against the bare-identifier form and pass against the fix, and the positive controls pass under
both. Both integration tests fail against the bare-identifier form, and the failure output
carries the escalated token itself, decoding to `"scope":"authserver:manage"` with
`"aud":"authserver"`.

36 unit subtests in `TestValidateTokenRequest_ClientCredentials`. Full suite green on SQLite
(internal, core, adminconsole, data, integration). The two new integration tests also pass on
PostgreSQL, MySQL and SQL Server.

**This stage was first landed with a set-based ownership check and then amended to the single-id
form**, after code review established that all four engines enforce
`(permission_identifier, resource_id)` uniqueness. Decision 18 records the correction; the
paragraph above is the verification of the amended code, re-run after the change, not carried
forward from the first attempt.

1. Resolve the requested permission on the resource and compare its id. Status: **Done**
   `src/core/validators/token_validator.go:778-808`, per section 3.1, which is the issue's own
   recommendation. Keep both loops and both error messages.

2. Give the three vacuous fixtures distinct non-zero IDs. Status: **Done**
   `token_validator_test.go:1439`, `:1446`, `:1521`, `:1529-1530`, `:1781`, `:1790-1792`, per
   decision 2. Follow the shape already used at `:4171`. **Do not tidy these back to bare
   identifiers.** Without IDs these three tests cannot distinguish the fixed code from the
   broken code, which is why the bug survived them.

3. Add the collision cases to `TestValidateTokenRequest_ClientCredentials`. Status: **Done**

   One fixture: `billing-api` (id 1) and `reports-api` (id 2) both defining `read` with
   permission ids 10 and 20, plus `archive-api` (id 3) defining `read` as id 30. Six cases,
   all executed. The rightmost column is what the current code does, which is what makes each
   case a regression guard rather than a restatement.

   | # | Client holds | Requests | Expected | Rejected by | Current code |
   |---|---|---|---|---|---|
   | 1 | `billing-api:read` | `reports-api:read` | `invalid_scope`, "is not granted to the client" | ownership loop `:800` | **accepts** |
   | 2 | `billing-api:read` | `billing-api:read` | accept, scope `billing-api:read` | n/a, positive control | accepts |
   | 3 | `reports-api:read` | `billing-api:read` | `invalid_scope`, "is not granted to the client" | ownership loop `:800` | **accepts** |
   | 4 | `billing-api:read`, `archive-api:read` | `reports-api:read` | `invalid_scope`, "is not granted to the client" | ownership loop `:800` | **accepts** |
   | 5 | `billing-api:read` | `billing-api:read reports-api:read` | `invalid_scope` naming `reports-api:read` | ownership loop `:800` | **accepts both** |
   | 6 | `billing-api:read` | `reports-api:read billing-api:read` | `invalid_scope` naming `reports-api:read` | ownership loop `:800` | **accepts both** |

   Cases 1 and 2 are the load-bearing pair: they vary **only** the resource, holding the
   permission identifier, the client and the grant fixed, so nothing but the ownership check can
   account for the difference. Case 1 alone would also pass against an implementation that
   over-rejected everything. Cases 5 and 6 differ only in ordering and exist because a
   short-circuit that accepted on the first granted scope would pass one and fail the other.

   Pins decisions 1 and 2.

4. Add the escalation cases to the same subtest. Status: **Done**

   `authserver` (id 4) with built-in `manage` as id 40, alongside `billing-api:manage` as id 12.

   | # | Client holds | Requests | Expected | Current code |
   |---|---|---|---|---|
   | 7 | `billing-api:manage` | `authserver:manage` | `invalid_scope`, "is not granted to the client" | **accepts, issues an admin-capable token** |
   | 8 | `authserver:manage` | `authserver:manage` | accept, scope `authserver:manage` | accepts |

   Case 8 is not redundant with case 2. It confirms the fix does not break a genuine
   `authserver` grant, which is the grant that administrative tooling depends on, and it is the
   positive control that stops case 7 passing for the wrong reason.

5. Add the remaining validator cases. Status: **Done**

   These do not change behaviour and are not regression guards. They exist because the ownership
   check now depends on a resolved `perm` pointer, so every path that returns before that
   resolution needs to stay pinned. All executed.

   | Requests | Expected |
   |---|---|
   | `nope-api:read` | `invalid_scope`, "Could not find a resource with identifier 'nope-api'" |
   | `billing-api:delete` | `invalid_scope`, "doesn't grant the 'delete' permission" |
   | `billing-api:read`, client holds nothing | `invalid_scope`, "is not granted to the client" |
   | `billing-api:read:extra` | `invalid_scope`, "Invalid scope format" |
   | `billing-api:` | `invalid_scope`, "doesn't grant the '' permission" |
   | `:read` | `invalid_scope`, "Could not find a resource with identifier ''" |
   | `::` | `invalid_scope`, "Invalid scope format" |
   | `billing-api` | `invalid_scope`, "Invalid scope format" |
   | `openid` | `invalid_request`, "are not supported in the client credentials flow" |
   | `offline_access` | `invalid_request`, same |
   | `openid billing-api:read` | `invalid_request`, same |
   | `OPENID` | `invalid_scope`, "Invalid scope format" |
   | `OFFLINE_ACCESS` | `invalid_request`, "are not supported" |

   The last two rows look inconsistent and are correct. `IsIdTokenScope`
   (`src/core/oidc/oidc.go:10-13`) is an exact `slices.Contains`, so `OPENID` is not recognized
   as an OIDC scope and falls through to the format check. `IsOfflineAccessScope` (`:15-17`)
   uses `strings.EqualFold`, so `OFFLINE_ACCESS` is recognized. **Keep both rows.** They
   document a real asymmetry between two adjacent helpers, and a future reader will otherwise
   assume one of them is a typo.

   **No duplicate-twin case.** An earlier draft of this step specified two subtests mocking
   `GetPermissionsByResourceId` to return two rows both named `read` on one resource, in both
   orderings, to pin a set-based ownership check. They were written, then deleted: every supported
   engine enforces `(permission_identifier, resource_id)` uniqueness, so the state they mocked
   cannot occur, and a test asserting behaviour in an impossible state teaches the wrong
   cardinality. Decision 18 records the full reasoning. **Do not reintroduce them.**

   One further case belongs here rather than in stage 2, because it tests ownership rather than
   normalization: client holds `billing-api:read`, requests
   `reports-api:read reports-api:read`, expects `invalid_scope` "is not granted to the client".
   It confirms deduping cannot launder a denied scope, the only way decision 10 could interact
   with the security fix. It diverges from current behaviour for two independent reasons at
   once, the collision bug and the missing dedupe, so **keep it even if deduping is ever
   reverted.**

   Also add a mock-error case for each of `GetResourceByResourceIdentifier` and
   `GetPermissionsByResourceId` returning an error, asserting it propagates rather than being
   swallowed into a denial. A propagated error is a 500, a swallowed one is a silent
   `invalid_scope`, and the two are indistinguishable to a caller reading only the status code.

   **What this layer cannot prove:** that the real database returns permissions whose IDs match
   what the mocks assert, and that the handler wires the validator's result into an actual
   token. Step 6 covers the first, step 7 the second.

6. Add `TestToken_ClientCred_CrossResourcePermissionCollision`. Status: **Done**
   `src/authserver/tests/integration/token_clientcred_test.go`, modelled on
   `TestToken_ClientCred_SpecificScope:328`, which already does the create-resource,
   create-permission, grant sequence explicitly. The helpers are `createResourceWithId` and
   `createPermissionWithId` (`utils_test.go:228, 251`).

   Two resources with randomized identifiers, both defining the **same** randomized permission
   identifier. Grant the client resource A's only. Assert `reports`-side request returns
   `invalid_scope` with "Permission to access scope '<B>:<perm>' is not granted to the client.",
   then assert the A-side request returns a token whose `scope` claim equals `<A>:<perm>`.

   Note that `createClientCredentialsTokenWithScope` (`api_resources_test.go:155`) does not fit,
   since it grants and requests the same scope by construction.

   Per decision 4 the two legs may run in either order.

7. Add `TestToken_ClientCred_AuthServerScopeNotReachableByCollision`. Status: **Done**
   Same file. Create a custom resource with a permission identifier of `manage`, grant the
   client only that, then request `authserver:manage` and assert `invalid_scope`. Look up the
   `authserver` resource with `database.GetResourceByResourceIdentifier`, as
   `api_client_permissions_test.go:360` already does.

   **What this proves that step 4 cannot:** that the real `authserver` resource, with its real
   built-in `manage` permission as seeded at startup, is protected. Step 4 asserts the same
   thing against a fixture that merely resembles it.

   **What no test here proves:** that the Admin API would have honoured the escalated token.
   That is established by reading `api_auth.go:58`, `:203-207` and `jwt_token.go:81-94`, and
   after this fix the token cannot be obtained, so it is not testable from this direction.

### Stage 2: normalize the scope at the handler
Status: **Done** (2026-07-28)

**Measured, replacing this stage's predicted figures.** The withdrawn harness put 9 divergences on
normalization and 3 on the whitespace-only rejection. Those numbers are not reconstructed here: the
harness is gone, and a per-case census was never the point. What was verified instead, by reverting
the handler to pass the raw scope and re-running:

| Behaviour | Before | After |
|---|---|---|
| client credentials, two granted scopes tab-separated | **500**, server logs `invalid scope: <the tab-joined string>` | token issued, claim space-separated and matchable by `HasScope` |
| refresh, tab-separated down-scope | **500**, same shape | token reissued, claim space-separated and matchable |

Both were previously believed to yield a token with unmatchable scopes; they yield a 500. Section 1
carries the correction and the general lesson.

Trimming, deduplication and the whitespace-only rejection are pinned at the layer each belongs to
rather than end to end: `normalizeScope`'s 12-row table for the string behaviour, and the 9-row
handler-wiring table for what the validator receives and for which grant types the rejection fires.
The ROPC accept-to-reject change is asserted at the handler, where the rejection lives, not through
full ROPC issuance.

Full suite green on SQLite (1979 passing).

1. Normalize in `handler_token.go`, now at `:58-59` (normalize) and `:90` (pass it on). Status: **Done**
   `normalizeScope` and `grantTypeConsumesScope` are unexported helpers in package `handlers`,
   alongside the call site, which is what lets step 2 test them directly.
   Trim, then collapse whitespace runs, per section 3.2. **Add a comment stating why this lives
   at the handler**, naming the `len(input.Scope) == 0` check at `token_validator.go:295` it
   must run before. Without it, the next person to tidy this will move the trim into the
   validator and reopen the hole described in section 3.2.

   **Do not put the normalization cases in `token_validator_test.go`.** Those tests build a
   `ValidateTokenRequestInput` and call `ValidateTokenRequest` directly, so the handler never
   runs and no raw input ever passes through `normalizeScope`. Every accepting row below would
   fail there with `invalid_scope: Invalid scope format: ''`. The three steps that follow put
   each table at the layer that can actually execute it.

2. Unit-test `normalizeScope` directly. Status: **Done**
   Added as `TestNormalizeScope` in `handler_token_test.go`, plus `TestGrantTypeConsumesScope`
   covering which grant types the rejection applies to.
   A pure string-to-string function, so this table is exhaustive here and thin everywhere else.
   All executed.

   | Input | Output |
   |---|---|
   | `"billing-api:read  billing-api:write"` | `"billing-api:read billing-api:write"` |
   | `"billing-api:read\tbilling-api:write"` | `"billing-api:read billing-api:write"` |
   | `"billing-api:read\nbilling-api:write"` | `"billing-api:read billing-api:write"` |
   | `" billing-api:read"` | `"billing-api:read"` |
   | `"billing-api:read "` | `"billing-api:read"` |
   | `"  billing-api:read  "` | `"billing-api:read"` |
   | `" billing-api:read \t  billing-api:write\t"` | `"billing-api:read billing-api:write"` |
   | `"billing-api:read billing-api:read"` | `"billing-api:read"` |
   | `"billing-api:read billing-api:write billing-api:read"` | `"billing-api:read billing-api:write"` |
   | `"   "` | `""` |
   | `"\t"` | `""` |
   | `""` | `""` |

   The last three rows matter for step 3, which distinguishes the empty result of a provided
   scope from a genuinely omitted one.

   **What this layer cannot prove:** that anything calls `normalizeScope`, or that the handler
   passes its output rather than the raw form.

3. Test the handler wiring. Status: **Done**
   Added as `TestHandleTokenPost_ScopeNormalizationWiring`, **9** rows: the 8 specified here plus an
   explicitly empty `scope=` case added by code review, see below.
   `handler_token_test.go`, which already mocked the validator with
   `mock.AnythingOfType("*validators.ValidateTokenRequestInput")`. That is replaced with
   `mock.MatchedBy` to capture what the handler actually passed.

   | Grant type | Raw form `scope` | Assertion |
   |---|---|---|
   | client_credentials | `"billing-api:read\tbilling-api:write"` | validator receives `"billing-api:read billing-api:write"` |
   | client_credentials | `"  billing-api:read  "` | validator receives `"billing-api:read"` |
   | client_credentials | `"billing-api:read billing-api:read"` | validator receives `"billing-api:read"` |
   | client_credentials | `"   "` | validator **not called**, response is `invalid_scope` naming the empty scope |
   | refresh_token | `"   "` | validator not called, same rejection |
   | ROPC | `"   "` | validator not called, same rejection. **Accept-to-reject change, pins decision 15** |
   | authorization_code | `"   "` | validator **is** called, request proceeds. Pins the exclusion in decision 15 |
   | client_credentials | omitted entirely, no `scope` key in the form | validator receives `""`, no rejection |
   | client_credentials | `scope=`, an explicitly empty value | validator receives `""`, no rejection |

   **Three rows are load-bearing, each against a different plausible wrong implementation, and each
   fails silently without its row.** The last two are NOT redundant and must not be merged.

   - The **authorization_code** row fails if someone applies the rejection to every grant type. That
     grant never reads the scope parameter, so rejecting on it would break a valid exchange.
   - The **omitted** row fails if someone implements the rejection as "empty scope is invalid"
     rather than "provided-but-empty is invalid". An omitted scope must still reach the validator as
     `""`, which is what selects the client credentials all-permissions branch.
   - The **`scope=`** row is the only one that detects a switch of the presence test to
     `r.PostForm.Has("scope")`. `Has` distinguishes the two wire formats where `Get` does not, so
     that switch would honour omission while newly rejecting `scope=`, and the omitted row would not
     notice. Decision 15 and the release note both promise `scope=` keeps working, because HTTP
     clients commonly serialize empty values. Verified: `url.Values.Set("scope", "")` encodes as
     `scope=`, where `Has` is true and `Get` is `""`; and applying the `Has` switch fails this row
     and only this row.

4. Assert the issued claim end to end. Status: **Done**
   Added as `TestToken_ClientCred_TabSeparatedScopeIsNormalized`. Fails against the raw-scope handler.
   `token_clientcred_test.go`. One test: request two granted scopes separated by a tab, assert
   the response `scope` is space-separated, and assert the decoded access token's `scope` claim
   satisfies `HasScope` for both. Deliberately thin, since step 2 owns the exhaustive table.

   **This is the only step that proves the defect is actually fixed.** Steps 2 and 3 show the
   string is normalized and handed over; only this one shows the token a client receives carries
   a matchable claim. Asserting string equality alone would not do it, because the assertion and
   the bug would share the same wrong expectation.

5. Add one refresh_token case. Status: **Done**
   Added as `TestToken_Refresh_TabSeparatedDownScopeIsNormalized`. Also fails against the raw-scope
   handler.
   A down-scope request separated by a tab, asserting the reissued token's `scope` claim is
   space-separated and matchable. Deliberately thin: `:472` and `:497` share the defect but the
   normalization is owned by step 2, so this asserts only that refresh benefits from it. Pins
   decisions 9 and 10.


### Stage 3: audit
Status: **Done** (2026-07-28)

**Every claim in this stage was checked by breaking it.** The plan asserts that misses "fail
loudly" and that two test rows guard specific wrong implementations; all five were verified by
making the mistake and re-running:

| Deliberate mistake | Result |
|---|---|
| `expectedCount` left at 91 | `TestAuditEventTypes_Count` **fails** |
| entry omitted from `allAuditConstants` | `TestAuditEventTypes_MatchesConstants` **fails** |
| entry omitted from the `AuditEventTypes` slice | `_Count` **and** `_MatchesConstants` both fail |
| predicate gated on `GrantType == "client_credentials"` | only the **ROPC** denial row fails |
| a second call site at the provided-but-empty rejection | the no-event row fails, **and** three stage 2 wiring rows fail with it |

The last row is better than the plan predicted. The plan said a second call site "passes every row
but the third"; in fact stage 2's three whitespace-only wiring rows register no audit expectation
either, so `mocks_audit.NewAuditLogger(t)` fails them too. Four independent tests object, not one.

Full suite green on SQLite (1980 passing).

1. Add `"scope": validateResult.Scope` at `handler_token.go:222`. Status: **Done**
   Nothing asserts this payload's shape, verified. `details` is JSON-marshalled into a `TEXT`
   column (`sqlitedb/schema.sql:374`), so there is no width constraint.

2. Add the denial event. Status: **Done**
   All four places updated; each verified to fail loudly if missed, per the table above.
   Constant `AuditTokenScopeDenied = "token_scope_denied"` in
   `src/core/constants/constants.go`, per decision 13. Logged at the handler for any grant type
   whose validation failed with code `invalid_scope`, per decision 12 and the sketch in
   section 3.3.

   **One call site only**, inside the `if err != nil` block after `ValidateTokenRequest`. **Do
   not add a second at the decision 15 rejection**, which is the obvious-looking completeness
   fix and is wrong: that branch runs before client authentication, so it would record an
   unverified `client_id` and let anyone forge audit rows against a legitimate client. An
   earlier draft of this spec made exactly that mistake. See decision 12.

   **This is not a one-line addition. It touches four places and misses fail loudly.**

   | Requirement | Detail |
   |---|---|
   | the constant | `src/core/constants/constants.go` |
   | `AuditEventTypes` slice | insert between `AuditTokenIssuedROPCResponse` and `AuditUpdatedAuditLogsSettings`, now `constants.go:225` and `:227` with the new entry between them |
   | `allAuditConstants` | a **second**, separately maintained list inside `constants_test.go:120`, checked by `TestAuditEventTypes_MatchesConstants:118` |
   | `expectedCount` | bump from 91 to 92 at `constants_test.go:65` |

   Note that `TestAuditEventTypes_Alphabetical:106` compares the string **values**, not the
   constant identifiers, which is why the insertion point is among the `token_issued_*` entries
   rather than where the identifier would sort.

3. Assert the denial event fires. Status: **Done**
   Added as `TestHandleTokenPost_ScopeDenialAudit`, all four cases.
   Extend the handler-level tests. Four cases:

   | Request | Assertion |
   |---|---|
   | client credentials, scope denied by the validator | emits `AuditTokenScopeDenied` with scope and grant type |
   | ROPC, scope denied by the validator | emits the same event. **Pins that the predicate is not grant-gated** |
   | client credentials, `scope="   "` | responds `invalid_scope` and emits **no** audit event. **Pins the single call site** |
   | client credentials, successful | emits `AuditTokenIssuedClientCredentialsResponse` carrying `scope` |

   Deliberately thin: which requests are denied is owned by stage 1's table, so this asserts
   only that a denial reaches the audit logger. Rows two and three are not optional. A
   `GrantType` check accidentally left in place passes every row but the second. A well-meaning
   second call site at the decision 15 rejection passes every row but the third, which asserts
   the **absence** of an event. That assertion looks like an oversight and is not: it is the
   guard against reintroducing an unauthenticated audit row, and `mocks_audit.NewAuditLogger(t)`
   will fail the test if an unexpected `Log` call is made.

### Stage 4: drop the redundant re-lookup
Status: **Done** (2026-07-28)

Full suite green on SQLite (1981 passing). Removing the lookup broke no existing test, which
confirms this plan's claim that no unit case reached the expansion branch.

1. Use the loaded association at `:295-305`. Status: **Done**
   `perm.Resource.ResourceIdentifier` directly, dropping the `GetResourceByResourceIdentifier`
   call and with it the unchecked deref at `:302`. No empty-identifier guard, per decision 7, and
   the comment says why so the next reader does not add one: the state is reachable through a
   concurrent-deletion race, but the path now fails closed with `invalid_scope`, and the removal
   turned what had been a nil dereference in that race into a 400.

2. Add the missing unit coverage for the no-scope branch. Status: **Done**
   Added as `TestValidateTokenRequest_ClientCredentials_NoScopeGiven`. No client credentials unit
   case omitted `Scope` before, so this branch had never been unit tested. Three cases:

   | Client holds | Expected resulting scope |
   |---|---|
   | `billing-api:read`, `reports-api:read` | `billing-api:read reports-api:read` |
   | nothing | empty |
   | `billing-api:read` only | `billing-api:read` |

   **This step's instruction was wrong and the implementation deliberately departs from it.** The
   plan said the new cases "must **not** stub `GetResourceByResourceIdentifier`", on the reasoning
   that an unmet expectation would then prove the round-trip was gone. But
   `validateClientCredentialsScopes` runs on the expanded scope immediately afterwards and looks up
   each resource itself, at what is now `:772`. So the stub is **required**, and its absence would
   simply fail the test for an unrelated reason.

   The working pin is the call **count**: each resource's stub is registered `.Once()`, because
   before the removal every resource was fetched twice per request, once expanding and once
   validating. Verified by restoring the round-trip, which fails exactly the two cases that look
   resources up and correctly leaves the empty-client case passing.

   The first row also confirms the expansion is resource-qualified, so a client holding `read`
   on two resources gets both scopes rather than one twice. Under stage 1's fix that
   distinction now matters.

### Stage 5: documentation and release note
Status: **Not started**

0. Convert recurring bare line citations to symbol anchors. Status: **Not started**
   This spec cites roughly 200 line numbers into `token_validator.go`, `handler_token.go`,
   `token_issuer.go` and `api_auth.go`. Stages 1, 2, 3 and 7 shifted all four, and each stage's
   review round found citations that had come to point at plausible but unrelated code, which makes
   a recorded verification actively misleading rather than merely imprecise. One citation drifted
   twice inside a single stage: `:846` for the `validatedScopes` append, correct when written, then
   moved to `:897` by later edits in the same stage.

   Replace the recurring ones with the form the spec already uses in places,
   `validateROPCScopes` plus the quoted error message, which does not drift and **is mechanically
   checkable**. Bare `:NNN` shorthand is not: its file context lives in the surrounding prose, so
   attributing each citation to a file needs reading rather than matching. That is why no sweep so
   far has been exhaustive, and why the ones performed were reported as covering only the anchors
   named in them.

   **Deliberately scheduled here, after stage 4, not earlier.** Stage 4 edits
   `token_validator.go:295-305` and will move most of that file again, so doing this during stage 3
   would have produced a large docs diff that immediately needed another sweep. Waiting until
   production layout has stabilized means one conversion instead of two.

1. Add the per-resource sentence to the docs. Status: **Not started**
   `site/src/content/docs/concepts/resources-permissions.mdx`, near the scope format section at
   `:11-25` and before the `read`, `write`, `delete` guidance at `:55`. State that permission
   identifiers are scoped to their resource, so `product-api:read` and `reports-api:read` are
   distinct grants and holding one conveys nothing about the other.

   Nothing on the page is falsified, and `client-credentials.mdx:148` stays accurate. This is
   the model the bug depended on readers not having.

2. Draft the release note. Status: **Done** (drafted below; publishing is a release-time action)

   **There is no CHANGELOG in the repo.** Release notes are published as GitHub Releases, so
   this text lives here until then.

   > **Security fix: client credentials scopes were not checked against the resource.**
   >
   > Before this release, the client credentials grant checked only the permission identifier
   > when deciding whether a client could receive a `resource:permission` scope, ignoring which
   > resource the permission belonged to. A client granted `billing-api:read` could obtain a
   > token for `reports-api:read` whenever both resources defined a permission named `read`.
   >
   > The system `authserver` resource carries built-in permissions with generic names, so a
   > client granted a same-named permission on a custom resource could reach the `authserver`
   > scope of **the same name**. The severity depends on which name collided:
   >
   > | Custom permission that collided | Reachable scope | Effect |
   > |---|---|---|
   > | `manage` | `authserver:manage` | full Admin API access |
   > | `manage-users` | `authserver:manage-users` | full access to user, group and permission endpoints |
   > | `manage-clients` | `authserver:manage-clients` | full access to client endpoints |
   > | `manage-settings` | `authserver:manage-settings` | full access to settings and key endpoints |
   > | `admin-read` | `authserver:admin-read` | read-only access to all Admin API endpoints |
   > | `userinfo` | `authserver:userinfo` | `/userinfo` access. Discloses nothing extra, see below |
   > | `manage-account` | `authserver:manage-account` | acts on a user through the Account API, see below |
   >
   > A custom `read` colliding with another custom resource's `read` stays within your own
   > resources and does not reach `authserver` at all.
   >
   > **The last two rows depend on a second issue this release also fixes.** `/userinfo` and the
   > Account API identified the acting user from the token's `sub` claim without checking that
   > the token was issued for a user at all. For a client credentials token, `sub` is the client
   > identifier. A 36 character UUID is a valid client identifier whenever its first hex digit
   > is `a` through `f`, so a client whose identifier equalled a user's subject could **change
   > that user's email, phone and profile** through the Account API.
   >
   > `/userinfo` was not a disclosure risk: every claim beyond `sub` requires an OIDC scope, and
   > the client credentials grant rejects those, so it returned only the identifier the caller
   > already knew. It is fixed alongside the Account API because accepting a token issued for a
   > different context is wrong regardless, and because its safety currently depends on a check
   > in an unrelated file.
   >
   > Reaching any of this required the ability to choose a client identifier, meaning
   > `authserver:manage-clients` or `authserver:manage`; Dynamic Client Registration generates
   > identifiers server-side and could not be used. Both endpoints now reject tokens that were
   > not issued for a user, independently of scope.
   >
   > **The two issues have different preconditions.** Read them separately.
   >
   > *Cross-resource scope escalation* required valid credentials for a confidential client with
   > the client credentials grant enabled, plus at least one permission grant whose identifier
   > collides with a permission on another resource.
   >
   > *User impersonation through `sub`* required no collision at all. A client **directly**
   > granted `authserver:manage-account` or `authserver:userinfo`, whose identifier equalled a
   > user's subject, was enough. Creating such a client required the ability to choose a client
   > identifier, meaning `authserver:manage-clients` or `authserver:manage`.
   >
   > **This is a breaking change for affected deployments, in three distinct ways.**
   >
   > *`invalid_scope` at the token endpoint.* If a client credentials integration starts failing
   > this way, it was relying on a permission it was never granted. Grant the permission on the
   > correct resource in the admin console rather than rolling back.
   >
   > *`invalid_scope` for a whitespace-only scope.* A `scope` parameter containing only
   > whitespace is now rejected with a message saying so. Omit the parameter entirely instead.
   > Sending `scope=` with an empty value is unchanged and still means "omitted". This affects
   > the three grants that read `scope` at the token endpoint, and it is not the same change in
   > each:
   >
   > | Grant | Before | After |
   > |---|---|---|
   > | `client_credentials` | `invalid_scope: Invalid scope format: ''` | `invalid_scope` with a message naming the problem |
   > | `refresh_token` | `invalid_grant: Scope '' is not recognized` | `invalid_scope`, so **the error code changes** |
   > | `password` (ROPC) | **accepted**, treated as `openid` | `invalid_scope`, so **this goes from working to rejected** |
   >
   > `authorization_code` is unaffected: it ignores the `scope` parameter entirely and continues
   > to do so. If you send a whitespace-only scope on ROPC today and rely on receiving an
   > `openid` token, omit the parameter instead.
   >
   > *`403 USER_CONTEXT_REQUIRED` at `/userinfo` and `/api/v1/account/*`.* These endpoints now
   > accept only tokens issued for a user, so a client credentials token is refused there even
   > when it carries `authserver:userinfo` or `authserver:manage-account`. If an integration
   > calls them with a client credentials token, it must switch to a token obtained through the
   > authorization code flow for the user whose account it is acting on. There is no
   > configuration flag to restore the old behaviour, because the old behaviour was the
   > vulnerability. A service that genuinely needs to administer other users' accounts should
   > use the Admin API with `authserver:manage-users`, which is designed for that and is
   > unaffected by this change.
   >
   > **Also fixed: ROPC refresh tokens could not be redeemed.** Unrelated to the two issues above
   > and not a security fix, but it lands in the same release.
   >
   > A token obtained through the password grant (ROPC) requesting `openid` could not be
   > refreshed. The refresh returned `invalid_grant`, "Scope 'authserver:userinfo' is not
   > recognized. The user does not have the 'authserver:userinfo' permission." The server appends
   > `authserver:userinfo` to any token carrying an OIDC scope so that the token can call
   > `/userinfo`, recorded that appended scope on the refresh token as though the user had been
   > granted it, and then refused the refresh because the user never was. Requesting `openid` is
   > the normal case, so this affected essentially every ROPC integration using refresh tokens.
   >
   > **No action needed, and this is not a breaking change.** Refresh tokens issued *before* this
   > release are fixed too: the server no longer re-validates a scope it injected itself, so
   > existing tokens start working without re-authentication. The reissued access token continues
   > to carry `authserver:userinfo`, so `/userinfo` access is unchanged.
   >
   > **If you granted users the built-in `authserver:userinfo` permission as a workaround**, you
   > can remove it, provided your ROPC requests include an OIDC scope such as `openid`. That is
   > the normal case and the one this bug affected. Keep the grant only if your integration
   > requests `authserver:userinfo` **explicitly and without any OIDC scope**: the server then has
   > no way to tell an injected scope from one you deliberately granted, so it still checks the
   > permission, which is what keeps revoking that permission effective.
   >
   > One narrow behaviour change, and it affects a single combination. If your original ROPC
   > request did **not** ask for `authserver:userinfo` (so the server added it for you) and your
   > *refresh* request passes `scope=authserver:userinfo` explicitly, that refresh now returns
   > `invalid_grant`, because the scope is no longer part of the recorded grant. Drop it from the
   > refresh request: it is still added to the new access token automatically, so you lose nothing.
   >
   > If your original request asked for `authserver:userinfo` explicitly and the user holds that
   > permission, nothing changes: the scope stays part of the recorded grant and refresh continues
   > to work as before.
   >
   > **Checking your exposure.** This lists clients holding a permission whose identifier also
   > exists on another resource, with the scopes they could previously have reached. There is no
   > single portable form, because `client_credentials_enabled` is a real boolean on PostgreSQL
   > and the three engines disagree on string concatenation. Use the one for your database.
   >
   > **SQLite:**
   >
   > ```sql
   > SELECT DISTINCT c.client_identifier AS client,
   >        r.resource_identifier  || ':' || p.permission_identifier  AS granted_scope,
   >        r2.resource_identifier || ':' || p2.permission_identifier AS reachable_scope
   > FROM clients_permissions cp
   > JOIN clients     c  ON c.id  = cp.client_id
   > JOIN permissions p  ON p.id  = cp.permission_id
   > JOIN resources   r  ON r.id  = p.resource_id
   > JOIN permissions p2 ON p2.permission_identifier = p.permission_identifier
   >                    AND p2.resource_id <> p.resource_id
   > JOIN resources   r2 ON r2.id = p2.resource_id
   > WHERE c.enabled = 1 AND c.is_public = 0 AND c.client_credentials_enabled = 1
   > ORDER BY 1, 2, 3;
   > ```
   >
   > All three flags are required. A disabled client is refused at
   > `token_validator.go:93` and a public client at `:255`, so neither can use the grant with
   > its **current** configuration. `DISTINCT` is also required: `clients_permissions` has no
   > unique constraint on `(client_id, permission_id)` on any engine, verified against the live
   > schema, so the same permission can be granted to one client twice and without `DISTINCT` a
   > single finding is reported once per duplicate grant. Verified by executing both forms against
   > a duplicated grant.
   >
   > Note that this is a real difference between the two tables and not a general looseness in the
   > schema: `permissions` **does** carry a unique index on
   > `(permission_identifier, resource_id)` on all four engines, so the duplication `DISTINCT`
   > guards against comes from the grant table alone.
   >
   > **This is a snapshot, not history.** All three flags are mutable, and nothing records when
   > they changed. A client that is disabled or public today may have been neither last month,
   > and the reverse is also true: a client the query lists today may have been ineligible
   > throughout the entire window in which the flaw existed. Read the output as *clients
   > currently configured such that they could have exploited a pre-fix server*, and treat the
   > eligibility filters as noise reduction rather than as proof of non-exploitation.
   >
   > **Certainty is not available from this system.** The database keeps no history of these
   > flags, and the audit log does not fill the gap: `updated_client_oauth2_flows` and
   > `updated_client_settings` record only `clientId` and `loggedInUser`, with no before or
   > after values, so they can tell you *that* a client was changed and by whom but never *what*
   > the flags were. If a specific client matters, fall back to your own change management
   > records, backups, or infrastructure-as-code history.
   >
   > **PostgreSQL:** identical, but the `WHERE` clause must use real booleans, since the three
   > columns are `boolean` and `= 1` is a type error:
   >
   > ```sql
   > WHERE c.enabled = true
   >   AND c.is_public = false
   >   AND c.client_credentials_enabled = true
   > ```
   >
   > **MySQL:** identical to SQLite, but replace both `||` concatenations with `CONCAT`, since
   > MySQL reads `||` as logical OR unless `PIPES_AS_CONCAT` is set. The expressions become
   > `CONCAT(r.resource_identifier, ':', p.permission_identifier)` and
   > `CONCAT(r2.resource_identifier, ':', p2.permission_identifier)`.
   >
   > **SQL Server:** identical to SQLite, but replace `||` with `+`.
   >
   > **Second check, for the user-context issue.** The query above finds cross-resource
   > collisions only. The user-context issue needs no collision: a client **directly** granted
   > `authserver:manage-account`, whose identifier happens to equal a user's subject, could act
   > as that user. Run this as well.
   >
   > **SQLite** (for PostgreSQL use the three-boolean `WHERE` clause shown above; for MySQL wrap
   > the concatenation in `CONCAT`; for SQL Server replace `||` with `+`, exactly as above):
   >
   > ```sql
   > SELECT DISTINCT c.client_identifier AS client,
   >        u.username                   AS impersonable_user,
   >        r.resource_identifier || ':' || p.permission_identifier AS user_context_scope_held
   > FROM clients c
   > JOIN users               u  ON u.subject = c.client_identifier
   > JOIN clients_permissions cp ON cp.client_id = c.id
   > JOIN permissions         p  ON p.id = cp.permission_id
   > JOIN resources           r  ON r.id = p.resource_id
   > WHERE c.enabled = 1 AND c.is_public = 0 AND c.client_credentials_enabled = 1
   >   AND r.resource_identifier = 'authserver'
   >   AND p.permission_identifier IN ('manage-account', 'userinfo')
   > ORDER BY 1, 2, 3;
   > ```
   >
   > **Every row is a finding, but the two scopes need different responses.**
   >
   > A row naming **`authserver:manage-account`** means account mutation was possible. Rotate
   > that client's secret, rename or delete the client so its identifier no longer collides, and
   > review recent changes to the named user's email, phone and profile.
   >
   > A row naming **`authserver:userinfo`** and nothing else means the client could call
   > `/userinfo` as that user and receive only `sub`, which it already knew. Nothing was
   > disclosed and nothing could be changed, so **do not investigate account changes for these
   > rows.** Still rename or delete the client, because the identifier collision is a latent
   > hazard if the client is ever granted `manage-account`, but this is hygiene rather than
   > incident response.
   >
   > **Separately, as hygiene**, this lists every client whose identifier equals a user's
   > subject regardless of configuration. Such a client has no legitimate reason to exist even
   > when it currently holds nothing and cannot use the grant, because a later configuration
   > change could make it exploitable:
   >
   > ```sql
   > SELECT DISTINCT c.client_identifier AS client, u.username AS matching_user,
   >        c.enabled, c.is_public, c.client_credentials_enabled
   > FROM clients c
   > JOIN users u ON u.subject = c.client_identifier
   > ORDER BY 1;
   > ```
   >
   > **Reading the results.** Check the `reachable_scope` column against the severity table
   > above. `authserver:manage` means a full Admin API compromise was possible.
   > `authserver:manage-users`, `authserver:manage-clients`, `authserver:manage-settings` and
   > `authserver:admin-read` are serious but bounded to their documented areas.
   > `authserver:manage-account` mattered only if the client's identifier was also a UUID
   > matching a user's subject, so check the `client` column before dismissing such a row, and
   > cross-reference the second query. `authserver:userinfo` conveyed nothing in any
   > configuration: the endpoint returns only `sub`, and a client credentials token cannot carry
   > the OIDC scopes that would unlock anything further. Rows that name only your own resources
   > mean lateral movement between your APIs, whose severity only you can judge.
   >
   > **This shows which clients could have exploited the flaw, not which ones did.** Successful
   > token issuance did not previously record the scopes granted, so there is no audit data to
   > reconstruct past exploitation from. This release adds the scope to the issuance audit record
   > and adds a `token_scope_denied` event for authenticated requests that fail scope validation,
   > both going forward only. For any row reaching `authserver:manage`, `authserver:manage-users`,
   > `authserver:manage-clients` or `authserver:manage-settings`, rotate that client's secret and
   > review recent administrative changes through whatever other logging you have.

   **Both queries were executed on all four engines**, not merely written down: SQLite locally,
   and PostgreSQL 18, MySQL and SQL Server 2022 in the running dev containers
   (`goiabada-postgres-server-1`, `goiabada-mysql-server-1`, `goiabada-mssql-server-1`). Eight
   runs, each engine's variant returning results identical to the others against a shared
   fixture.

   The collision query's fixture distinguishes seven cases: a client with a colliding grant
   appears, a client whose collision reaches `authserver` appears with that scope named, a
   client holding only a unique permission does not appear, and a client with
   `client_credentials_enabled = 0`, one with `enabled = 0`, and one with `is_public = 1` all
   fail to appear despite holding a genuinely colliding permission. A control query run without
   the three eligibility predicates confirms those last three **do** appear once the filters are
   removed, which is what proves the filters are load-bearing rather than incidentally satisfied.
   A duplicated `clients_permissions` row confirms `DISTINCT` collapses it.

   The impersonation query's fixture is adversarial and distinguishes five cases: a colliding
   client holding `authserver:userinfo` **plus an unrelated permission** appears exactly once,
   a colliding client holding no user-context permission does not appear, a colliding client
   that is disabled does not appear, a colliding client that is public does not appear, and a
   non-colliding client holding `authserver:manage-account` does not appear.

   **Two defects this execution caught**, both of which would have misled an operator during
   triage. An earlier draft shipped one collision query claiming to run on all four engines on
   the strength of a SQLite-only run; it fails outright on PostgreSQL and returns garbage on
   MySQL. And an earlier impersonation query used `LEFT JOIN`, which returned a spurious
   null-scope row alongside the genuine row for any client holding an unrelated permission, and
   listed colliding clients holding nothing at all. Inner joins fixed both, and the
   hygiene-only listing moved to its own query where a row without a permission is the point
   rather than noise.

   The final paragraph is required, not optional. A note implying operators can audit their
   history would be wrong, and the absence of that data is precisely what stage 3 exists to fix
   for next time.

### Stage 6: require a user-bound token on user-context endpoints
Status: **Done** (2026-07-27)

**No dependency on stages 1 through 5.** This closes a separate gap and could land first. It is
numbered last only because the scope fix is the issue's subject. Per decision 17.

**Verified by execution.** Three experiments, each run against the real server:

1. **The guard removed from both route groups.** All three rejection cases fail and all five
   acceptance cases still pass. The failing case returns 200 and the response body is the victim
   user's full profile with `"email":"...@attacker.example.com"`, so the vulnerability is
   reproduced rather than argued.
2. **The discriminator switched to `sid`.** Exactly the two ROPC cases fail; the other six pass.
   That is what makes those two cases pin the `auth_time` choice rather than restate it.
3. **The guard as written.** All eight cases pass, on SQLite, PostgreSQL, MySQL and SQL Server.

Full suite green on SQLite (1972 passing). The ordering requirement in step 2 is confirmed by the
suite rather than by inspection: the 11 `createClientCredentialsTokenWithScope` call sites in
`api_account*_test.go` still see `INSUFFICIENT_SCOPE`, because the scope check runs first.

1. Add `RequireUserBoundToken` middleware. Status: **Done**
   `src/authserver/internal/middleware/api_auth.go`, alongside the existing guards. Rejects any
   bearer token with no `auth_time` claim, 403, distinct error code, per section 3.5.

2. Apply it to both route groups. Status: **Done**
   `routes.go:78-79` for `GET` and `POST /userinfo`, and the `/api/v1/account` group at
   `:304-308`. Place it **after** `RequireBearerTokenScope`, so an insufficient-scope caller
   still receives the 403 it receives today. Ordering is load-bearing: putting it first would
   change the error seen by existing integration assertions that mint a client credentials
   `authserver:userinfo` token and expect "Insufficient scope."
   `createClientCredentialsTokenWithScope` has 26 invocations, of which the 11 in
   `api_account*_test.go` are the ones hitting a route group this step touches. The rest target
   Admin API routes and are unaffected either way.

3. Unit-test the middleware. Status: **Done**
   `middleware` package. **Five** cases, one more than this step originally specified: a zero
   `auth_time` was added to pin that the guard reads presence and never the value. Asserting the
   exact contract in section 3.5: a token
   carrying `auth_time` passes through; a token without it yields 403 with `ErrorCode`
   `USER_CONTEXT_REQUIRED` and a `WWW-Authenticate` header; no bearer token in context yields
   401 `ACCESS_TOKEN_REQUIRED`; a non-`JwtToken` context value yields 401
   `INVALID_TOKEN_FORMAT`. Assert the `ErrorCode` and status, not just the status, since all
   three failures would otherwise be indistinguishable to a caller.

   **What this cannot prove:** that real client credentials tokens actually lack `auth_time`, or
   that real user tokens carry it. Step 4 covers that, and it is the part that matters, since
   the whole guard rests on that asymmetry.

   **The asymmetry, verified against every issuance path.** Every user access token is built by
   the single shared `generateAccessTokenCore` (`token_issuer.go:642`), which sets `auth_time`
   unconditionally at `:652`. Its three input constructors all populate `AuthenticatedAt`:
   `createTokenInputFromCode:885`, `createTokenInputFromImplicit:900`, and
   `createTokenInputFromROPC:916`. Traced to five call paths, which is the full set:

   | Path | Reaches the shared generator via |
   |---|---|
   | authorization code | `generateAccessToken:162` |
   | authorization code refresh | `GenerateTokenResponseForRefresh:454` calls `generateAccessToken` |
   | implicit | `generateImplicitAccessToken:1024` |
   | ROPC | `generateROPCAccessToken:1164` |
   | ROPC refresh | `GenerateTokenResponseForRefreshROPC:556` calls `generateROPCAccessToken` |

   The client credentials claim set (`:353-382`) is built separately and never sets it. So the
   guard admits every user token and refuses every client token, which is exactly the property
   it needs. **If a sixth user-token path is ever added that bypasses
   `generateAccessTokenCore`, this guard silently locks it out of both endpoints.**

4. Integration-test the asymmetry and the impersonation path. Status: **Done**
   `src/authserver/tests/integration/`. Eight cases: three rejections and five acceptances, the
   latter covering every path that produces a user access token.

   **`GET` and `POST /userinfo` are separate registrations** (`routes.go:78` and `:79`), so an
   implementation that guards only one passes a plan that tests only the other. The `POST` case
   sends the token as a form-body `access_token` rather than a header, which also exercises the
   distinct extraction path at `core/middleware/middleware_jwt.go:94-101`.

   | Token | Endpoint | Expected |
   |---|---|---|
   | client credentials with `authserver:manage-account`, identifier **equal to a user's subject** | `PUT /api/v1/account/email` | 403, and the user's email is **unchanged** |
   | client credentials with `authserver:userinfo`, identifier equal to a user's subject | `GET /userinfo` | 403 |
   | the same token, sent as a form-body `access_token` | `POST /userinfo` | 403 |
   | authorization code token for that user with `authserver:manage-account` | `PUT /api/v1/account/email` | succeeds |
   | ROPC token for that user with `authserver:manage-account` | `PUT /api/v1/account/email` | succeeds, **pins the `auth_time` over `sid` choice** |
   | access token from an **authorization code refresh** | `PUT /api/v1/account/email` | succeeds |
   | access token from an **ROPC refresh** | `PUT /api/v1/account/email` | succeeds |
   | **implicit** flow access token | `GET /userinfo` | succeeds |

   The first case is the regression guard and it **must be written to fail against current
   `main`**, where it returns 200 and changes the email. Create the client with
   `ClientIdentifier` set to the target user's `Subject.String()`, which requires a subject whose
   first hex digit is `a` through `f`; generate users until one qualifies rather than hardcoding.
   That is 6 of 16 possible first characters, so 3 in 8 subjects qualify and a handful of
   attempts suffices.

   The fourth case is not optional, and the ROPC token it uses must be a **sessionless** one.
   `sid` is set conditionally at `token_issuer.go:794`, so an ROPC token issued in a request that
   does carry a session identifier will have it and would pass a `sid`-based guard by accident.
   Sessionless ROPC tokens have no `sid`, so an implementation that checks
   `sid` instead of `auth_time` passes the first three and fails only this one.

   **The last three cases exist because an earlier draft of this step covered only freshly
   issued authorization code and ROPC tokens**, which is not the full set of user access tokens.
   Implicit and both refresh paths also produce them, and locking any of those out of the
   Account API would be a serious regression shipped by a guard meant to be invisible to real
   users. They all route through `generateAccessTokenCore`, verified above, so these are
   confirmation rather than discovery, but the guard's whole premise is that claim's
   universality and nothing else asserts it end to end. Authorization code refresh already has
   partial coverage at `src/core/oauth/token_issuer_test.go:2195`; implicit and ROPC refresh
   have none against this guard.

   Asserting the email is unchanged, not merely that the status is 403, matters because a guard
   placed after the mutation would still return an error.

### Stage 7: let a ROPC refresh token actually be redeemed
Status: **Done** (2026-07-28)

**Depended on stage 6 only for a cleanup.** The fix itself is independent, but step 3 removed a
workaround that stage 6 step 4 introduced, so landing this stage first would have meant reconciling
that by hand. It landed after stage 6, so it did not arise. Per decision 19.

**Read step 3 before writing any test.** The two changes are **not** jointly necessary for the
obvious case: either one alone makes a newly issued `openid` ROPC refresh succeed. Step 1 stores a
clean `openid`, which the re-check skips as an OIDC scope; step 2 tolerates the polluted record.
So the natural end-to-end test pins neither change individually, and each needs its own assertion.
An earlier draft of this stage claimed the stage 6 case "passes only once both are in", which is
false and would have shipped two changes with one test's worth of evidence.

**Verified by five experiments, which is what the point above demands.** Each was run against the
real code, and together they show every test pins the change it is supposed to and nothing else.
The unit rows are step 5's, abbreviated here: **U1** legacy grant with the request omitted, **U2**
the explicit-only negative control, **U3** legacy grant down-scoped to bare userinfo. The
integration column is `TestROPC_RefreshToken_OpenIdOnly` and stage 6's `sessionless ROPC refresh
token`. Every cell below was executed, including the ones that pass.

| Experiment | U1 | U2 | U3 | Integration |
|---|---|---|---|---|
| Step 1 reverted, issuer stores the decorated scope | pass | pass | pass | `OpenIdOnly` **fails**, stage 6 passes |
| Step 2 reverted, exception removed entirely | **FAIL** | pass | **FAIL** | both pass |
| Exclusion made **unconditional**, the variant decision 19 rejects | pass | **FAIL** | pass | both pass |
| Both steps reverted | **FAIL** | pass | **FAIL** | **both fail** |
| OIDC condition taken from the request instead of the grant | pass | pass | **FAIL** | both pass |

Read the columns rather than the rows, because that is where each claim lives:

- **When the validator exception is absent, U1 and U3 fail together**, which is rows 2 and 4. Both
  express a legacy grant, so both depend on that exception, and neither depends on the issuer
  change: the unit tests hand-build the stored scope and so bypass issuance entirely. That is why
  row 1 leaves all three green. They are **not** interchangeable in general, and row 5 is the
  counterexample: U3 fails there alone, which is the next bullet's point.
- **U2 fails only in row 3.** It is the negative control from review finding 1, and the only thing
  standing between this fix and a revocation hole.
- **U3 fails only in rows 2, 4 and 5.** Row 5 is what makes it more than a duplicate of U1: it is
  the sole test that distinguishes deriving the OIDC condition from the grant rather than from the
  request.
- **The integration column moves only with the issuer change**, rows 1 and 4, because after step 1
  no newly issued refresh token records the injected scope, so nothing downstream has anything to
  re-check.

Rows 1 and 2 jointly are the point the withdrawn "passes only once both are in" wording was
reaching for and got wrong: neither change alone satisfies the whole set, but each is pinned by its
own test rather than by one shared assertion.

**An earlier version of this matrix described the unit outcomes as "both unit cases" and "the
legacy case", singular**, having been measured before U3 existed and not re-run when it was added.
Every cell above is from a re-run with all three rows present.

Full suite green on SQLite (1974 passing). ROPC and user-bound tests pass on PostgreSQL, MySQL and
SQL Server.

1. Record the granted scope on the ROPC refresh token. Status: **Done**
   `token_issuer.go:1148`, pass `input.Scope` rather than `scopeFromAccessToken` to
   `generateRefreshTokenForROPC`, per section 3.6. `input.Scope` is `validateResult.Scope`, the
   output of `validateROPCScopes`, verified at `handler_token.go:327-334`.

   **Do not "fix" the authorization code path at `:147` to match.** It passes the post-injection
   scope too, but nothing reads `RefreshToken.Scope` for that grant: the validator uses
   `refreshToken.Code.Scope` (`:417`). Changing it would be an untested behaviour change to a
   working path. Note it in a comment instead, so the asymmetry does not read as an oversight.

2. Stop re-validating the injected scope against user grants. Status: **Done**
   `token_validator.go:597`, exclude `authserver:userinfo` from the per-scope user-permission
   re-check **only when the stored scope also carries an OIDC scope**, per section 3.6.

   **The condition is load-bearing and must carry a comment saying so.** Unconditional would let a
   revoked, explicitly granted `authserver:userinfo` survive refresh, because `validateROPCScopes`
   permits requesting that scope directly. The condition reproduces the injection condition at
   `token_issuer.go:670-676` exactly. Step 5's negative control is what holds this in place.

   **This is what makes the fix retroactive**, and the comment must say so too: step 1 alone leaves
   every ROPC refresh token already in a deployed database broken until it expires. Build the scope
   string from `constants.AuthServerResourceIdentifier` and
   `constants.UserinfoPermissionIdentifier` rather than a literal, matching
   `authorize_validator.go` and `token_issuer.go:699`.

3. Remove the workaround from stage 6's ROPC helper. Status: **Done**
   `user_bound_token_test.go`, `userAccessTokenViaROPC` granted the test user
   `authserver:userinfo` as well as `authserver:manage-account`, with a comment pointing at this
   defect. The `userinfo` grant and that comment are gone; the helper now carries a comment saying
   its **absence** is load-bearing and must not be restored to silence a failure.

   With the grant removed, the `sessionless ROPC refresh token` case fails against unfixed code
   with `invalid_grant`, "Scope 'authserver:userinfo' is not recognized", and passes once **either**
   step 1 or step 2 is in. That makes it a regression guard for the defect as a whole and for
   neither change individually. Steps 4 and 5 are what separate them. Verify by reverting each step
   on its own and confirming this case passes both times, which is the opposite of what an earlier
   draft of this stage asserted.

4. Assert the refresh token records the granted scope, which pins step 1. Status: **Done**
   Added as `TestROPC_RefreshToken_OpenIdOnly` in `ropc_flow_test.go`.
   `ropc_flow_test.go`. Request `openid` **and nothing else**, then assert on the issued refresh
   token that its scope is exactly `openid`, with no `authserver:userinfo`. Read it from the
   decoded refresh token's `scope` claim, and additionally from the persisted
   `RefreshToken.Scope` row via `database`, since the row is what the validator actually consults.

   Then redeem it and assert a new access token comes back, and that the **new access token's**
   `scope` claim still contains `authserver:userinfo` because `generateAccessTokenCore` re-injects
   it. That pair is the whole point of step 1: the scope leaves the refresh token **record**
   without leaving the issued token.

   Requesting only `openid` matters: it is the normal ROPC case, it needs no permission grants at
   all, and it is precisely the case that was broken. A test that also requested a resource scope
   could pass for the wrong reason if the user happened to hold it.

   This case fails against step 2 applied alone, since the polluted scope would still be recorded.

5. Unit-test the validator exclusion, both directions, which pins step 2. Status: **Done**
   Added as `TestValidateTokenRequest_RefreshToken_ROPC_InjectedUserInfoScope`, the first ROPC
   refresh unit test in the file.
   `token_validator_test.go`. **Three** ROPC refresh cases, one more than this step originally
   specified, hand-building the stored refresh token so they can express states step 1 no longer
   produces. This is the only layer that can: after step 1 no newly issued token has a polluted
   scope, so an integration test cannot construct the legacy case without writing a refresh token
   row directly. In every row the user holds **no** permissions.

   | Stored `RefreshToken.Scope` | Requested `scope` | Expected |
   |---|---|---|
   | `openid authserver:userinfo` (legacy, injected) | omitted | refresh **succeeds** |
   | `authserver:userinfo` alone (explicitly granted) | omitted | refresh **rejected**, `invalid_grant` |
   | `openid authserver:userinfo` (legacy, injected) | `authserver:userinfo` | refresh **succeeds** |

   **The third row was added by code review and pins something the other two cannot: which scope
   the OIDC-scope condition is derived from.** The implementation reads `tokenScope`, the original
   grant, and not the request's scope; the two coincide in every case where the request is omitted,
   so the first two rows are blind to the choice. Here they disagree, the grant carrying `openid`
   and the request not. Deriving the condition from the request would reject this row. Executed:
   switching the source to the request's scope fails this row and only this row.

   Succeeding is the right outcome, because refreshing the full scope would inject
   `authserver:userinfo` into the new access token whatever the user holds, so rejecting the
   narrower request would deny a subset of what the same token can have for the asking. The comment
   at the derivation says this; an earlier version of that comment claimed the opposite behaviour,
   that `tokenScope` was the stricter choice, which was backwards.

   **The second row is the negative control and is not optional.** It is the only thing standing
   between this fix and the revocation hole decision 19 rejects, and it fails against the
   unconditional exclusion an earlier draft specified. Its stored scope deliberately carries no
   OIDC scope, which is the state no case in the section 3 table covered and the reason the
   over-broad version looked correct.

   The first row is the retroactive half from step 2, and it fails against step 1 applied alone.
