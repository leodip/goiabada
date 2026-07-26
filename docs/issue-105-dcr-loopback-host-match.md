# Issue 105: DCR redirect URI loopback check is a host prefix match

**Issue:** [#105](https://github.com/leodip/goiabada/issues/105)
**Issue state:** open (labels: bug, security)
**Spec written:** 2026-07-26
**Last synced:** 2026-07-26 (through comment IC_kwDOKE37NM8AAAABLsvr9A)
**Related:** [#41](https://github.com/leodip/goiabada/issues/41) (closed, shipped in `d0d8c9e`) introduced
the predicate this fix consumes. Not a gate in either direction, see decision 2.
[#108](https://github.com/leodip/goiabada/issues/108) (open) owns the consent default, the
`created_via_dcr` column and the unverified-name marker, see decision 11.
**Filed from this spec's verification:** [#120](https://github.com/leodip/goiabada/issues/120)
(the remaining `innerHTML` sinks, see decision 6),
[#121](https://github.com/leodip/goiabada/issues/121) (custom schemes with
`response_mode=form_post`, see section 2's out-of-scope list) and
[#122](https://github.com/leodip/goiabada/issues/122) (the authorization-time `absolute-URI`
gate, which is what actually closes the scheme-relative code leak, see decision 12).

**Note on this spec's relationship to the issue.** The issue body and its three comments were
written before #41 landed, so much of their design content asks for work that now exists. This
spec keeps the vulnerability as a requirement and re-derives everything else from the code as
it stands. Section 4 records each departure with the verification behind it.

---

## 1. Context

### The bug

`validateRedirectURI` (`src/authserver/internal/handlers/handler_dynamic_client_registration.go:222`)
enforces the "http redirect URIs must be loopback" rule with `strings.HasPrefix` against the
URL host, in two places:

| Branch | Lines | Reached when |
|---|---|---|
| Public clients | `:233-238` | `token_endpoint_auth_method: "none"` |
| Confidential clients | `:259-264` | any other auth method |

The issue cites `230-242` and `258-268`; the actual blocks are the lines above. Both list six
prefixes, of which three (`localhost:`, `127.0.0.1:`, `[::1]:`) are dead weight already
subsumed by the bare forms.

Any host that merely begins with one of those strings passes. Verified by running the current
function's logic: `http://localhost.attacker.com/callback`,
`http://127.0.0.1.attacker.com/callback` and `http://localhost-evil.example.net/cb` are all
accepted, for both `isPublic` values. The comment above the check says its purpose is to
prevent phishing via DCR, which is the property it fails to provide.

**This fails open.** `POST /connect/register` is unauthenticated when DCR is enabled (rate
limited only), so an anonymous caller can register a client whose redirect URI is on a host
they control, walk a logged-in user to `/auth/authorize`, and receive the code. Exposure is
bounded by DCR being disabled by default (`Settings.DynamicClientRegistrationEnabled`).

**But fixing this does not close the phishing threat, and this spec must not claim it does.**
An anonymous caller does not need the prefix bug to obtain an attacker-controlled callback. It
can register with `token_endpoint_auth_method: client_secret_post`, whereupon the confidential
branch accepts **any** `https` URI on any host (`:254-255`, verified: `https://evil.example/cb`
is accepted), and the response hands back the generated client secret. Combined with
`ConsentRequired: false` (`:88`), that reproduces the entire code-capture chain the issue
describes, with no bypass required.

That is not a defect in this function: OIDC Dynamic Client Registration expects Web Clients to
use `https`, and there is no way for the server to know whether a registrant owns the domain it
asserts. The control that is supposed to bind client identity to user authority is the consent
screen, which is #108's subject. So the accurate framing is:

- **This issue** is a validation defect. `localhost.attacker.com` is accepted where the code
  intends to accept only loopback, plus the two adjacent problems below. Worth fixing on its own
  merits, and it removes the specific bypass.
- **#108** is what closes the threat model, because it restores the consent prompt that makes an
  unfamiliar self-registered client visible to the user regardless of which host its callback is
  on.

Neither blocks the other, but a release note claiming this fix closes DCR phishing would be
wrong.

### The predicate already exists

`src/core/urlutil/redirect_uri.go` shipped in `d0d8c9e` (issue #41) and exports
`IsLoopbackHost(host string) bool`. It accepts a bare host, a `host:port` pair, and IPv6 with
or without brackets, so a caller may pass either `url.URL.Host` or `url.URL.Hostname()`. Its
doc comment names this issue as the intended second consumer.

The issue's own recommended helper must not be used. Verified by running both over 17 hosts:
they disagree on 9, with the issue's version returning true for `[[::1]]`, `[localhost]`,
`[localhost]:3000`, `[127.0.0.1]`, `]::1[`, `[::1`, `localhost:evil`, `127.0.0.1:http` and
`localhost:-1`. `strings.Trim(h, "[]")` treats the brackets as a cutset, and
`net.SplitHostPort` accepts service names. Those are exactly the defects #41 decisions 14 and
15 were written against.

### A second, more serious problem in the same function

The non-`http` branch for public clients (`:245-246`) accepts every scheme that is not
`https`. The issue names `javascript:` and `data:` and judges exploitability "limited", citing
that `http.Redirect` will not execute a `javascript:` Location and that `html/template`
neutralises it in `form_post.html`. Both of those are true and were verified. The analysis
misses the admin console.

A three-step chain, each step verified separately:

1. **The payload registers.** `validateRedirectURI("x:<svg/onload=...>", true)` returns nil.
   Verified by running the current function's logic. Note the scheme is `x`, so no denylist of
   dangerous scheme names would catch it.
2. **The admin console renders stored redirect URIs through `innerHTML`.**
   `src/adminconsole/web/template/admin_clients_redirect_uris.html:15` writes each URI into a
   JavaScript array, and `refreshRedirectURIsTable()` assigns it at `:89` with
   `cell1.innerHTML = uri`. The handler passes `map[int64]string`
   (`adminclienthandlers/handler_admin_client_redirect_uris.go:63,76-78`), so `{{ $value }}` is
   the bare URI string. Go's contextual escaping prevents the string breaking out of the JS
   literal, but `innerHTML` re-parses the resulting characters as HTML.
3. **It executes.** Verified in a browser against a page replicating the template's exact
   output: `<svg onload>` arriving through that sink fires. `<script>` does not, which is
   presumably why the sink looked safe. No CSP stops it: the app sets only
   `Content-Security-Policy: frame-ancestors 'none'`
   (`src/core/middleware/middleware_security_headers.go:31`), with no `script-src` directive.

So an anonymous registration can store text that runs JavaScript in an administrator's admin
console session, holding `authserver:manage`. The trigger is the administrator viewing that
client's redirect URIs, which is precisely what `site/src/content/docs/concepts/clients.mdx:215`
advises them to do ("Review client metadata: Check redirect URIs and other metadata of
self-registered clients").

> **Not verified end to end.** The sink was reproduced in an isolated page, not against a
> running admin console with a real DCR registration. The three steps above are each verified,
> the composition is inferred.

**The vector is not confined to the custom-scheme branch.** `https://app.example.com/<svg/onload=alert(1)>`
is accepted today for a confidential client, because that branch returns as soon as the scheme
is `https` (`:254-255`), and it reaches the identical sink. This is why decision 4 places the
character rule ahead of all client-type branching.

### Scope boundaries that are load-bearing

- **This fix covers the DCR path only.** The admin redirect URI endpoint applies no scheme or
  host validation whatsoever: `apihandlers/handler_api_clients.go:724` calls
  `url.ParseRequestURI` plus a trim and a duplicate check. That is defensible, since an
  administrator is trusted where an anonymous registrant is not, but it means the input-side
  fix alone cannot close the sink.
- **The defect class exists in exactly two places.** A sweep for `HasPrefix` against a host
  found only the two blocks above, plus `src/cmd/goiabada-setup/main.go:316,328`, which
  suppresses an http-in-production warning in an interactive CLI on operator-supplied input.
  Not a security gate, not in scope.
- **Error messages reach the caller verbatim.** `:56` passes `err.Error()` into the RFC 7591
  `error_description`, so all three messages in this function are developer-facing API output.
- **No test file exists for this handler.** There is no
  `handler_dynamic_client_registration_test.go`. `validateRedirectURI` is unexported and pure,
  so a unit table is cheap, but it has to be created rather than extended. The integration
  table `TestDCR_RedirectURI_Validation`
  (`src/authserver/tests/integration/dynamic_client_registration_test.go:180`) has 12 rows and
  runs only in `goiabada-devcontainer-1`.
- **Nothing in the repo documents these rules.** The DCR docs section (`clients.mdx:186`)
  covers enabling the feature and general security advice, and says nothing about redirect URI
  validation. Unlike #41 there is no falsified sentence to correct, only a gap. Verified that
  the i18n catalogs need no change either: the admin console redirect URI page copy concerns
  admin-registered URIs and #41's port exception, neither of which this change falsifies.

---

## 2. Goal

`validateRedirectURI` accepts an `http` redirect URI only when its host is exactly one of
`127.0.0.1`, `::1` or `localhost` after case folding, and rejects every redirect URI that is not
an `absolute-URI`, or that carries characters no URI may contain, or whose scheme is known to
execute script. The admin console renders stored redirect URIs as text rather than as markup, and
reads them back as text when deleting, so a hostile string cannot execute even when it arrives
through a path this fix does not police.

**What this does not achieve, stated up front.** It does not close DCR phishing, which needs
#108's consent work, and it does not close the scheme-relative code leak for stored or
admin-registered rows, which needs the validator gate in #122. See the
paragraphs on both in section 1.

Verified behaviour change, measured by running the current and proposed functions over a
corpus against both `isPublic` values. **Exactly 2 inputs widen**, and that count is exhaustive
over the corpus. The narrowings fall into four classes, one representative row each, because the
scheme denylist alone accounts for 18 of them:

| Input | Before | After | Why |
|---|---|---|---|
| `http://localhost.attacker.com/callback` | accept | reject | the bug |
| `http://127.0.0.1.attacker.com/callback` | accept | reject | the bug |
| `http://localhost-evil.example.net/cb` | accept | reject | the bug |
| `http://localhost.evil.tld:8080/cb` | accept | reject | the bug |
| `http://127.0.0.1x/cb` | accept | reject | the bug, no separator needed |
| `x:<svg/onload=alert(1)>` | accept | reject | decision 4, character gate |
| `javascript:alert(1)` | accept | reject | decision 4, scheme gate, script execution |
| `ftp://evil.example/cb` | accept | reject | decision 4, scheme gate, one of 12 added by the extension |
| `//evil.example/cb` | accept | reject | decision 12, absolute-URI gate |
| `/relative/cb` | accept | reject | decision 12, absolute-URI gate |
| `http://127.0.0.1/cb#frag` | accept | reject | decision 12, fragment; already malfunctions today |
| `http://LOCALHOST/cb` | reject | accept | decision 3, case folding |
| `http://LocalHost:3000/cb` | reject | accept | decision 3, case folding |

Every currently working **legitimate** registration keeps working, which is the property that
matters and is the one verified exhaustively: 8 legitimate custom-scheme and loopback shapes plus
the 15 legitimate forms in the case tables, zero false rejections. Three narrowings could in
principle affect a real client, and each is recorded where it is decided: the fragment case
(already broken, decision 12), Android `intent://…#Intent;…` URIs (decision 4), and any client
using one of the 12 newly denied schemes (decision 4).

### Out of scope

- **`ConsentRequired: true` for DCR clients, the `clients.created_via_dcr` column, and the
  unverified-name marker on the consent screen.** All three are recommendations in this issue's
  body and its comments, and all three were decided in #108's own comment 3. Duplicating them
  here would give two specs claiming `handler_dynamic_client_registration.go:88`. See decision
  11.
- **Deleting or flagging redirect URIs already registered through the bug.** No code. Decision
  1 records the reasoning and the release-note query that replaces it.
- **The remaining `innerHTML` sinks.** Counted: the admin templates carry 83 `innerHTML`
  assignments, 50 of them localised literals and 33 data-bearing. Of the 33, 20 assign data
  directly (including `user.Username`, `perm.description` and `key.PublicKeyPEM`), 3 interpolate
  it into markup and so need escaping rather than `textContent` (`${user.Email}` in an `<a href>`
  at `admin_groups_members_add.html:67` and `admin_resources_users_with_permission_add.html:68`,
  and `assignedGroup.groupIdentifier` at `admin_users_groups.html:105`), and 10 interpolate only
  numeric ids. Two of the 20 are the sinks this spec fixes. The rest have different data sources
  and different reachability, so they are tracked in
  [#120](https://github.com/leodip/goiabada/issues/120). See decision 6.
- **Adding scheme or host validation to the admin redirect URI endpoint**
  (`apihandlers/handler_api_clients.go:724`). An administrator is trusted where an anonymous
  registrant is not. Its absence is why decision 6 fixes the sink as well as the input.
- **Allowing `https` redirect URIs for public DCR clients.** Deliberate, not an oversight. See
  decision 7.
- **The authorization-time `absolute-URI` gate**, which is what actually closes the
  scheme-relative code leak for stored and admin-registered rows. This spec adds only the
  registration-side half. See decision 12.
- **Rejecting fragments on the authorization path.** RFC 6749 section 3.1.2 forbids a fragment.
  Raised in this issue's comment 1 and listed out of scope by #41 too. The registration path
  **is** now covered here, because `IsAbsoluteRedirectURI` tests `Fragment == ""` as well as
  `IsAbs()`, so a fragment cannot be registered through DCR. The authorization-time half, which
  is what protects stored and admin-registered rows, is #122. No separate issue is needed.
- **Custom-scheme redirect URIs are already broken with `response_mode=form_post`.** Found
  while verifying the issue's `form_post` claim. `form_post.html:13` renders
  `action="{{.redirectURI}}"`, and Go's `html/template` URL filter replaces *every* non
  http/https/mailto scheme with `#ZgotmplZ`, not only the dangerous ones. Verified: both
  `javascript:alert(1)` and `myapp://callback` render as `#ZgotmplZ`. So a native client with a
  custom scheme requesting `form_post` gets a form that posts back to the current page.
  Reachable: `authorize_validator.go:321` accepts `form_post` for any client regardless of
  redirect URI scheme, and `handler_auth_issue.go:251` renders the template. Fails closed, the
  code reaches nobody. Deliberately not fixed here, because the tempting fix (wrapping the
  value in `template.URL` to bypass the filter) would reintroduce the `javascript:` execution
  the filter is preventing, and the admin path's lack of validation means decision 4's denylist
  would not make that safe. The real fix is a decision about rejecting or downgrading
  `form_post` for non-http schemes, in the authorization path. Tracked in
  [#121](https://github.com/leodip/goiabada/issues/121).

---

## 3. Proposed solution

Four changes: two gates added at the top of `validateRedirectURI`, the two prefix blocks
replaced with the shipped predicate, and the admin console sink changed from markup to text.

```go
func validateRedirectURI(uri string, isPublic bool) error {
	parsed, err := url.ParseRequestURI(uri)
	if err != nil {
		return fmt.Errorf("invalid redirect_uri format: %s", uri)
	}

	// RFC 6749 section 3.1.2 requires an absolute-URI (RFC 3986 section 4.3):
	// scheme ":" hier-part [ "?" query ]. A scheme-relative value such as
	// //evil.example/cb parses cleanly here and would be emitted as a
	// protocol-relative Location, sending the code to that host.
	//
	// Registration-side half of the fix; the gate that closes every entry point is
	// in ValidateClientAndRedirectURI, see decision 12 and #122.
	if !urlutil.IsAbsoluteRedirectURI(uri) {
		return fmt.Errorf("redirect_uri must be an absolute URI with a scheme and no fragment: %s", uri)
	}

	// RFC 3986 excludes these characters from URIs entirely. A redirect URI carrying
	// them is malformed, and it is also how markup reaches the admin console's
	// innerHTML sink. Checked ahead of the client-type branches: an https URI on a
	// confidential client reaches the same sink. See decision 4.
	if strings.ContainsAny(uri, "<>\"{}|\\^` ") {
		return fmt.Errorf("redirect_uri contains characters not permitted in a URI: %s", uri)
	}

	// Schemes that execute script or read local files. Folded, because url.Parse does
	// not lowercase Opaque-form schemes for us in every path. See decision 4.
	if deniedRedirectURISchemes[strings.ToLower(parsed.Scheme)] {
		return fmt.Errorf("redirect_uri scheme %q is not permitted", parsed.Scheme)
	}

	if isPublic {
		if parsed.Scheme == "http" {
			// Registered first: IsLoopbackHost tolerates either Host or Hostname(),
			// and Host is what this function already holds. See decision 2.
			if urlutil.IsLoopbackHost(parsed.Host) {
				return nil
			}
			return fmt.Errorf("public clients can only use http redirect_uris on the loopback hosts 127.0.0.1, [::1] or localhost")
		}
		if parsed.Scheme != "https" {
			return nil
		}
		// Goiabada policy, stricter than OIDC DCR section 2's Native Client rule and
		// differently conditioned, since application_type is not read. See decision 7.
		return fmt.Errorf("public clients registered via DCR cannot use https redirect_uris (security restriction)")
	}

	if parsed.Scheme == "https" {
		return nil
	}
	if parsed.Scheme == "http" {
		if urlutil.IsLoopbackHost(parsed.Host) {
			return nil
		}
		return fmt.Errorf("http redirect_uris must use the loopback hosts 127.0.0.1, [::1] or localhost")
	}
	return fmt.Errorf("confidential clients must use an https redirect_uri, or http on a loopback host")
}

var deniedRedirectURISchemes = map[string]bool{
	// Script or local execution.
	"javascript": true, "data": true, "vbscript": true,
	"file": true, "blob": true, "about": true,
	// Browser-internal schemes.
	"chrome": true, "chrome-extension": true, "moz-extension": true,
	"view-source": true, "filesystem": true, "resource": true,
	// Network protocols a browser cannot deliver a callback to.
	"ftp": true, "ftps": true, "ws": true, "wss": true,
	"gopher": true, "telnet": true,
}
```

The absolute-URI predicate is a new export in `src/core/urlutil/redirect_uri.go`, beside
`IsLoopbackHost`, because #122 needs the identical rule at the authorization layer and a second
implementation is how the two would drift:

```go
// IsAbsoluteRedirectURI reports whether raw satisfies RFC 6749 section 3.1.2: a redirect
// URI MUST be an absolute-URI per RFC 3986 section 4.3, which is
// scheme ":" hier-part [ "?" query ], and MUST NOT include a fragment.
//
// Parses with url.Parse, NOT url.ParseRequestURI, and this is load-bearing.
// ParseRequestURI keeps a literal "#frag" in the path and reports Fragment as empty, so a
// scheme-only test accepts http://127.0.0.1/cb#frag. Verified. See decision 12.
//
// The fragment test is on the raw string rather than on url.URL.Fragment, because Fragment
// is "" both for "/cb" and for "/cb#", so testing it accepts a bare trailing "#". Verified.
//
// A percent-encoded %23 is not a fragment delimiter and stays accepted.
func IsAbsoluteRedirectURI(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil {
		return false
	}
	return u.IsAbs() && !strings.Contains(raw, "#")
}
```

And in both `admin_clients_redirect_uris.html:89` and `admin_clients_web_origins.html:89`:

```js
cell1.textContent = uri;   // was cell1.innerHTML = uri
```

**The three new gates are not redundant, and no one of them is sufficient.** Verified by
attributing each rejection:

| Input | Absolute-URI gate | Character gate | Scheme gate |
|---|---|---|---|
| `//evil.example/cb` | rejects | passes | passes |
| `/relative/cb` | rejects | passes | passes |
| `http://127.0.0.1/cb#frag` | rejects | passes | passes |
| `x:<svg/onload=alert(1)>` | passes | rejects | passes |
| `https://app.example.com/<svg/onload=alert(1)>` | passes | rejects | passes |
| `javascript:alert(1)` | passes | passes | rejects |
| `data:text/html,<script>x</script>` | passes | rejects | rejects |

The absolute-URI gate is what blocks the scheme-relative code-exfiltration case, which the other
two wave through because its scheme is empty rather than dangerous. The character gate is what
actually blocks the verified XSS payload, because the payload's danger is in its characters and
its scheme is the innocuous `x`. The scheme gate is what blocks `javascript:`, `vbscript:`,
`file:///etc/passwd` and `about:blank`, none of which contain an excluded character.

**This departs from the issue in three ways**, each recorded as a decision. The issue's
`isLoopbackHost` snippet is replaced by the shipped `urlutil.IsLoopbackHost` (decision 2). The
issue's proposed "require a reverse-DNS style scheme with a dot" is rejected outright, because
it breaks `myapp://callback`, `myapp:/cb` and an existing passing test row (decision 5). And
the issue treats the scheme problem as confined to the custom-scheme branch, which verification
disproved (decision 4).

**Why this is safe.** The host change can only narrow: it replaces a prefix test with an exact
test over the same three hosts, so the sole widening is case folding, which #41 already
established for the authorization path (decision 3). The three new gates reject only inputs that
are non-absolute URIs, carry a fragment, are malformed, or use an executable scheme, and were run
against 15 legitimate registration forms without a single false rejection; the full 59-case table
was re-run after the absolute-URI predicate was corrected, with no stage 1 row changing.

The one narrowing that could affect a working client is the fragment case: a client that
registered `http://127.0.0.1/cb#frag` can no longer re-register it. That client is already broken
today, since the code is delivered to `/cb%23frag` rather than to its callback, so the change
turns a silent malfunction into a clear registration error. The template change is
behaviour-preserving for any legitimate URI, since both cells display plain text already and the
neighbouring `cell2.innerHTML = getTrashCanMarkup(...)` that genuinely needs markup is untouched.
Reading the cell back with `textContent` additionally repairs deletion for URIs containing `&`,
which is broken today.

---

## 4. Open questions and decisions

All items are settled. Kept as a running log so a reviewer can see what was decided, why, and
what was rejected.

1. **Rows already registered through the bug get no code. A release note carries the audit
   query.** Status: **Decided**

   The fix is forward-looking. Nothing re-validates stored `redirect_uris` rows, and the only
   authorization-time check is `ValidateClientAndRedirectURI`, so a
   `http://localhost.attacker.com/callback` row registered before the fix stays exploitable
   after it. Operators who enabled DCR before the fix need to look:

   ```sql
   SELECT c.client_identifier, r.uri
   FROM redirect_uris r
   JOIN clients c ON c.id = r.client_id
   WHERE LOWER(r.uri) LIKE 'http://%';
   ```

   **`LOWER` is required, not tidiness.** The stored value is the raw request string
   (`handler_dynamic_client_registration.go:110` assigns `URI: uri` unmodified), while validation
   reads `parsed.Scheme`, which `url.Parse` lowercases. Verified:
   `HTTP://localhost.attacker.com/cb` is accepted today and stored with its uppercase scheme. On
   PostgreSQL and other case-sensitive collations, `LIKE 'http://%'` would miss exactly the rows
   an attacker would plant if they were trying to evade an audit.

   Then eyeball for any host that is not a genuine loopback target.

   **Remediation needs coordination, not a bare `DELETE`.** An earlier draft of this decision
   repeated the issue's phrasing that deleting an offending row is safe because "the client
   simply has to re-register". That is misleading in two ways: re-registration mints a **new**
   `client_id` and secret rather than repairing the existing client, and deleting the callback
   breaks that client's authorization flow immediately, with the existing
   "does not have this redirect URI registered" error. For a genuinely hostile row that is the
   desired outcome. For a row an operator is unsure about, the release note should say to identify
   the client owner first, since the deletion is not reversible from the admin console and the
   client cannot be made whole by re-registering.

   **Rejected:** the startup scan with `slog.Warn` per offender (tier 1 of this issue's comment
   2). It sounds free and is not: it adds a scan over every client on every boot, a decision
   about which binary owns it, and a placement problem, since the `AuditLogger` lives in
   `src/authserver/internal/audit/audit.go:20` and takes a `data.Database`, so a `core/data`
   post-migrate routine cannot use it and would have to write `CreateAuditLog` rows directly,
   bypassing the `AuditLogsInDatabaseEnabled` gate that logger applies
   (`audit.go:56`). For a diagnostic on a feature that ships disabled, a release note reaches
   the same operator. **Also rejected:** the deleting sweep, which needs `created_via_dcr` to be
   principled, and that column belongs to #108.

   One correction to this issue's comment 1, which states there is no way to audit for these
   rows: `GetAllClients` (`src/core/data/database.go:35`), `ClientLoadRedirectURIs` (`:37`) and
   `DeleteRedirectURI` (`:96`) all exist, so any of these options needs no new accessor. The
   argument against them is cost and ownership, not feasibility.

2. **Consume `urlutil.IsLoopbackHost` and pass `parsed.Host`. No second predicate.**
   Status: **Decided**

   The helper shipped in `d0d8c9e` and its doc comment already names this call site.

   **Rejected:** transcribing the issue's `isLoopbackHost`. Verified broken, see section 1.
   **Rejected:** the `IsLoopbackHost` plus `IsLoopbackIPHost` split that this issue's comment 1
   asked for and its comment 3 recorded as settled. That split existed to stop RFC 8252 section
   7.3 port flexibility from silently extending to the `localhost` hostname. #41's decision 1
   then chose to extend it deliberately, so both call sites now want the identical set and
   `IsLoopbackIPHost` would be dead code. The later decision wins, and this is a case where the
   issue's own recorded conclusion is stale rather than wrong.

   `Host` rather than `Hostname()` because it is the field this function already holds, and
   #41's decisions 14 and 15 hardened the predicate for exactly that form (`[localhost]:3000`
   and `localhost:evil` both return false). Verified that the two agree on every `http` input
   tested here, so this is a readability choice with no behavioural weight.

   Verified that this fix does not depend on #41 and #41 did not depend on it. They touch
   different call sites: registration intake here, authorization-time matching there. This
   issue's comment 1 framed the sharing as a design preference, correctly, and #41's decision 2
   independently reached the same conclusion.

3. **The uppercase-`localhost` widening is accepted.** Status: **Decided**

   `http://LOCALHOST/cb` and `http://LocalHost:3000/cb` are rejected today by the prefix test
   and accepted after the change, because `IsLoopbackHost` folds case. Verified: those are the
   only two widenings in the corpus.

   RFC 3986 section 6.2.2.1 makes the host case-insensitive, so this is normalisation rather
   than laxity, and #41's decision 10 already established it for the authorization path.
   Rejecting it here would mean the two paths disagree about the same host, which is the
   divergence the shared predicate exists to prevent.

   **Rejected:** a case-sensitive variant for registration only. Smaller diff, but an
   administrator who registers `Localhost` would then be told it is not a loopback host by one
   half of the system and accepted by the other.

4. **A character gate and a scheme denylist, both ahead of the client-type branches.**
   Status: **Decided**

   Reject any redirect URI containing a character RFC 3986 excludes from URIs
   (`< > " { } | \ ^ ` and space), and any URI whose scheme appears in
   `deniedRedirectURISchemes`.

   This addresses recommendation 2 in the issue body, which no comment decided. The issue
   describes the exposure as limited; verification found a script-execution path into the admin
   console, see section 1.

   **The denylist was extended after review, and its scope is now three groups rather than one.**
   It originally covered script execution only (`javascript`, `data`, `vbscript`, `file`, `blob`,
   `about`). Review asked what else survives it, and the answer was a class the original list was
   never aimed at: `ftp://evil.example/cb` was accepted for a **public** client, giving a
   self-registered secretless client a callback on a remote host. That is the same policy intent
   the scheme-relative bypass in decision 12 violates, arriving by a different route. The list now
   covers:

   | Group | Schemes | Why |
   |---|---|---|
   | Script or local execution | `javascript`, `data`, `vbscript`, `file`, `blob`, `about` | the original set; these can execute or read local resources |
   | Browser internals | `chrome`, `chrome-extension`, `moz-extension`, `view-source`, `filesystem`, `resource` | not app callbacks, and `view-source` in particular is a navigation primitive |
   | Network protocols | `ftp`, `ftps`, `ws`, `wss`, `gopher`, `telnet` | a browser cannot deliver an authorization response to any of these, and `ftp` gives a public client a remote callback |

   Verified: all 18 rejected including the case variants `FTP://` and `WS://`, with zero false
   rejections across 8 legitimate shapes (`myapp://callback`, `myapp:/cb`,
   `com.example.app:/oauth`, `org.example.app.oauth://redirect`, `x-myapp://cb`, and the three
   loopback `http` forms).

   **Deliberately still accepted:** `mailto:`, `tel:` and `sms:`. They are nonsensical as redirect
   URIs but inert, since none can receive an authorization response, and denying every scheme that
   is merely useless turns a security control into a taste control. Recorded so the omission reads
   as a choice.

   **A known consequence.** `intent://scan/#Intent;scheme=zxing;end`, the conventional Android
   intent URI form, is now rejected, though by the fragment half of decision 12's gate rather than
   by the denylist. Correct per RFC 6749 section 3.1.2, and worth a release-note line if anyone is
   thought to use it.

   **The placement is load-bearing and departs from what was originally scoped.** The gates were
   going to live in the public custom-scheme branch, since that is where the issue frames the
   problem. Verified that this is insufficient:
   `https://app.example.com/<svg/onload=alert(1)>` is accepted for a confidential client at
   `:254-255` and reaches the same sink, as does
   `http://127.0.0.1/<svg/onload=alert(1)>` on a loopback host. Markup is dangerous in any
   scheme, so the gate belongs before the branching.

   **Rejected:** the scheme denylist alone. Verified that it does not block the actual payload:
   `x:<svg/onload=alert(1)>` has scheme `x`. A denylist can only ever enumerate names, and the
   danger here is not in the name. **Rejected:** the character gate alone. Verified that
   `javascript:alert(1)`, `vbscript:msgbox(1)`, `file:///etc/passwd` and `about:blank` contain
   no excluded character. Both are needed, which is why they are one decision.

   Percent-encoded markup stays accepted (`myapp://cb/%3Cscript%3E`). Verified inert:
   `innerHTML` does not percent-decode, so the literal `%3C` renders as text. Rejecting it
   would break legitimate URIs carrying encoded data for no gain.

5. **No reverse-DNS scheme requirement.** Status: **Decided**

   **Rejected, and the issue proposes it:** "Require a reverse-DNS style scheme with a dot."
   Verified breaking: it rejects `myapp://callback` and `myapp:/cb`, and `myapp://callback` is
   an existing passing row in `dynamic_client_registration_test.go:214` as well as a shape real
   native apps use. RFC 8252 section 7.1 recommends reverse-DNS schemes without requiring them.
   It also buys nothing decision 4 does not already cover, so the cost is a breaking change for
   no additional protection.

6. **The two redirect URI sinks are fixed here. The rest of the pattern is #120.**
   Status: **Decided**

   `cell1.innerHTML = uri` becomes `cell1.textContent = uri` in
   `admin_clients_redirect_uris.html:89` and `admin_clients_web_origins.html:89`. Verified
   identical in shape: same line number, same pure-text cell, in sibling files.

   Fixing the input alone would be insufficient, because the admin redirect URI endpoint has no
   validation (`apihandlers/handler_api_clients.go:724`), so an administrator can store markup
   by hand and reach the same sink. Fixing the sink kills the class for this page regardless of
   how the row arrived.

   The web origins twin is not anonymously reachable. Verified: the DCR handler contains no
   `WebOrigin` references, so DCR never creates them. It is included because it is the same line
   in a sibling file, and leaving it means the next reader finds one fixed and one not.

   **Rejected:** fixing all 23 data-bearing sites. Different data sources, different
   reachability, and 3 of them interpolate data into markup deliberately, so they need escaping
   rather than `textContent`. That is a template audit with its own regression surface, not part
   of a DCR validation fix. **Rejected:** deferring the sink entirely to that audit, which would
   ship the input fix while a proven execution path stays open.

7. **The `https` refusal for public clients stays, and gets documented.** Status: **Decided**

   `:250` rejects any `https` redirect URI for a public DCR client. On a first reading this
   looks like a defect, because RFC 8252 section 7.2 treats claimed `https` URIs as the most
   secure redirect for native apps.

   **It is a deliberate Goiabada policy, and this decision previously overstated its standards
   basis.** OpenID Connect Dynamic Client Registration 1.0 section 2 does say: "Native Clients
   MUST only register redirect_uris using custom URI schemes or loopback URLs using the http
   scheme; loopback URLs use localhost or the IP loopback literals 127.0.0.1 or [::1] as the
   hostname", and adds that authorization servers "MAY reject Redirection URI values using the
   http scheme, other than the loopback case for Native Clients."

   But that rule is conditioned on `application_type: native`, and **Goiabada never reads
   `application_type`.** Verified: `DynamicClientRegistrationRequest`
   (`src/core/api/requests.go:357`) has no such field, and there are zero non-test references to
   it in the tree. OIDC defines `application_type` separately from
   `token_endpoint_auth_method` and defaults it to `web`. So `token_endpoint_auth_method: none`
   establishes that a client is **public**, not that it is **native**, and applying the Native
   Client rule to every public client is Goiabada's own choice rather than an implementation of
   the spec's requirement. Under the spec's own defaults, a registrant that sends only
   `token_endpoint_auth_method: none` is a Web Client, for which `https` is the expected scheme.

   The policy is still defensible, on the reasoning below rather than on the citation: a claimed
   `https` URI is only trustworthy because the operating system verifies domain ownership, and
   Goiabada cannot verify anything about an anonymous registrant's claimed domain. The rule fails
   closed. What changes is that the docs must present it as a Goiabada restriction with a stated
   reason, not as conformance, because a reader who checks the spec will find it does not say what
   a conformance claim would imply.

   Where Goiabada sits relative to others, for the record: Keycloak's
   `secure-redirect-uris-enforcer` permits `https` everywhere plus loopback http plus
   private-use schemes, each behind its own flag (`allow-http-scheme`,
   `allow-ipv4-loopback-address`, `allow-ipv6-loopback-address`,
   `allow-private-use-uri-scheme`), and Curity ships TLS-required with an "Allow HTTP" switch to
   loosen it. Neither conditions the scheme rule on client type. Goiabada is at the stricter
   end.

   **The known consequence, which the docs must state.** Neither Keycloak nor Curity splits on
   client type, and the OIDC rule splits on `application_type`, which Goiabada does not read.
   Goiabada splits on public versus confidential instead, so a browser-based SPA, which is a
   public client and a Web Client, cannot self-register through DCR at all: it needs an `https`
   redirect URI and will be refused one. Public native apps are also refused the claimed-`https`
   pattern that RFC 8252 section 7.2 recommends. Those are the real costs of the rule and they
   should be discoverable rather than surprising.

   Supporting `application_type` properly would let the two cases separate, and is the principled
   way out if either cost ever bites. Its own issue, not this one.

   **Rejected:** allowing `https` for public clients. Goiabada cannot verify that a registrant
   owns a claimed `https` domain, so accepting one from an anonymous caller is a larger version
   of this very bug. **Rejected:** a setting. #41's decision 1 rejected the same shape of knob
   for the same reason: it adds a migration and an admin control whose security implications most
   operators cannot evaluate. Introducing a genuine native-versus-web distinction is a real
   option, and it is its own issue.

8. **Test ownership splits three ways.** Status: **Decided**

   The exhaustive table lives in a new unit file next to the function; the integration table
   gets two thin rows; `urlutil`'s 38-row host table is not duplicated. Full reasoning and the
   layer-by-layer limits are in stage 1 step 2 and stage 4.

   **Rejected:** putting the exhaustive table in the integration suite. It runs only in the
   container, so every iteration would need a container round trip to test a pure function.
   **Rejected:** relying on `urlutil`'s existing table. It proves what the predicate decides,
   not that this function consults it.

9. **All three error messages are rewritten.** Status: **Decided**

   `:241` and `:267` both say "localhost" when the accepted set is three hosts, and `:270`
   offers "or custom scheme" on a branch that rejects custom schemes for confidential clients.
   Verified: `validateRedirectURI("myapp://callback", false)` returns that exact message.

   These are not internal strings. `:56` passes `err.Error()` into the RFC 7591
   `error_description`, so a registrant reads them verbatim, and a message that names the wrong
   rule costs real debugging time. Not localised, because RFC 7591 error responses are protocol
   output rather than UI copy.

10. **No i18n catalog changes.** Status: **Decided**

    Verified rather than assumed, because #41 had three falsified strings and the absence here
    is itself a finding. The admin console redirect URI page copy
    (`active.en.toml`, `active.pt-BR.toml`, rendered at
    `admin_clients_redirect_uris.html:179`) concerns admin-registered URIs and #41's loopback
    port exception. This change alters neither, since it touches the DCR path and the exact-host
    rule was already what that copy implied.

11. **The consent default, `created_via_dcr` and the unverified-name marker stay in #108.**
    Status: **Decided**

    Recommendation 3 of this issue's body (`ConsentRequired: true`) and the
    `clients.created_via_dcr` column decided in this issue's comment 3 are both also in #108,
    whose own comment 3 records decisions on all of it, including the migration across four
    engines and the consent-screen marker. Both would edit
    `handler_dynamic_client_registration.go:88`.

    One spec must own that line. #108 is the better owner: consent is its subject, it has the
    `prompt=none` analysis (`handler_authorize.go:490-510`) that the change requires, and it
    needs the column for the unverified marker regardless. This spec needs the column for
    nothing, because decision 1 declined the sweep that would have used it.

    **Rejected:** landing the one-line consent flip here as cheap hardening. It is one line and
    a large behaviour change, and splitting it from its own analysis is how a release note ends
    up missing the `prompt=none` consequence.

12. **An absolute-URI gate is added here, but the gate that closes the path is #122.**
    Status: **Decided** (added after code review)

    RFC 6749 section 3.1.2 requires a redirect URI to be an `absolute-URI` per RFC 3986 section
    4.3 (`scheme ":" hier-part [ "?" query ]`). Nothing in the codebase enforces it, and the
    consequence is not cosmetic. Verified by replicating
    `handler_auth_issue.go:271-279`: a client registered with `//evil.example/cb` causes
    `Location: //evil.example/cb?code=THECODE&state=st`, which the user agent resolves against the
    current scheme, delivering the authorization code to `https://evil.example/cb`. `http.Redirect`
    does not rewrite it, because `url.Parse` reads `//evil.example` as an authority so its
    relative-path fixup is skipped.

    **This spec's original design did not close it.** Verified: `//evil.example/cb` is accepted by
    the proposed implementation as well as the current one, because its scheme is empty and
    therefore neither `http` nor `https`, so it takes the custom-scheme success path.

    **The gate must parse with `url.Parse`, and a scheme test alone is not equivalent to
    `absolute-URI`.** A first correction to this decision proposed `parsed.Scheme == ""` against the
    existing `url.ParseRequestURI` result. Verified insufficient: `ParseRequestURI` keeps a literal
    `#frag` in the **path** and reports `Fragment` as empty, so
    `http://127.0.0.1/cb#frag` has a non-empty scheme and sails through, as do
    `https://app.example.com/cb#frag` and `http://127.0.0.1/cb?a=1#f`. The predicate therefore
    parses with `url.Parse`.

    **And `u.Fragment == ""` is also not equivalent, which only executing the table revealed.**
    The corrected predicate was going to be `u.IsAbs() && u.Fragment == ""`. Verified wrong:
    `url.Parse` reports `Fragment` as `""` both for `/cb` and for `/cb#`, so that test accepts
    `http://127.0.0.1/cb#`. A bare `#` is a fragment component under RFC 3986, and it breaks the
    callback exactly as `#frag` does, since emission escapes it and the code arrives at `/cb%23`.
    The implemented test is therefore `u.IsAbs() && !strings.Contains(raw, "#")`: RFC 3986 makes
    `#` the fragment delimiter and requires it to be percent-encoded anywhere else, so a literal
    `#` always introduces a fragment and the raw-string test is the exact rule. A percent-encoded
    `%23` stays accepted (verified), correctly, since it is an ordinary encoded character in a
    path.

    **A registration gate is not sufficient, for the same reason decision 6 fixes a sink as well
    as an input.** Registration is one entry point of two: the admin endpoint
    (`apihandlers/handler_api_clients.go:724`) validates nothing beyond parseability, and stored
    rows are never re-validated, so any existing `//host/path` row stays live. The closing fix is
    in `ValidateClientAndRedirectURI`, and it belongs there for a compliance reason rather than
    convenience: when validation fails there, `handler_authorize.go:150-155` already renders an
    error UI and returns without redirecting, which is exactly what RFC 6749 section 4.1.2.1
    requires ("SHOULD inform the resource owner of the error and MUST NOT automatically redirect
    the user-agent to the invalid redirection URI"). Enforcing at emission instead would mean
    hand-writing that error path.

    Tracked as #122 because it is a distinct vulnerability with a different mechanism, it is not
    DCR-specific, and it touches the authorization path rather than registration intake.

    **This covers the fragment item for the registration path**, which was previously listed as out
    of scope. Verified that the fragment case malfunctions today rather than leaking:
    `http://127.0.0.1/cb#frag` emits `http://127.0.0.1/cb%23frag?code=...`, because
    `url.ParseRequestURI` puts `#frag` in the path and `String()` escapes it, so the code is
    delivered to a path the client is not listening on. The authorization-time half stays with
    #122, so stored and admin-registered rows carrying a fragment are not covered by this spec.

    **Rejected:** adding only the registration gate and calling the issue closed, which would
    leave every stored row exploitable while the release note implied otherwise. **Also
    rejected:** doing the whole thing here, which would put an authorization-path change with its
    own error-handling and compliance questions inside a registration-validation fix.

---

## 5. Implementation plan

Four stages.

**Landing strategy, decided with the maintainer.** Commits go **directly to `main`**, no branch
and no pull request, one commit per stage so each is reviewable in isolation. Stage 3 touches
`adminconsole` while the others touch `authserver` and `core`, which is a reason to keep it as its
own commit rather than a reason to defer it.

**#105 lands before #122.** The `IsAbsoluteRedirectURI` predicate is created here, in stage 2 step
1, and #122 consumes it at the authorization layer. That ordering was chosen deliberately: this
spec exists and #122 is not yet specified, so creating the shared predicate on the path that is
ready avoids #122 having to invent it and then reconcile. Nothing in #122 is blocked beyond the
predicate itself.

Line references point at the current code, which is also the pre-change code, since nothing here
has been implemented yet.

### Stage 1: exact host matching
Status: **Done**

**Verified when this landed.** 31 subtests pass, each with a distinct name. Non-vacuousness was
proved by temporarily restoring the prefix check: exactly 11 rows failed, the 9 bug rows plus the
2 case-folding rows, and the file was restored from a byte-for-byte backup afterwards. The 14-row
`TestDCR_RedirectURI_Validation` integration table passes on sqlite, including the two new rows.
`gofmt` clean, `go vet` clean, whole `internal/handlers` package green.

Note for anyone running this outside the devcontainer: `go build` in the container needs
`-buildvcs=false`, because the mounted repo trips git's dubious-ownership check. `go test` and
`run-tests.sh` are unaffected.

1. Replace both prefix blocks in
   `src/authserver/internal/handlers/handler_dynamic_client_registration.go`.
   Status: **Done**

   `:233-238` and `:259-264` each become `if urlutil.IsLoopbackHost(parsed.Host) {`. Add the
   `github.com/leodip/goiabada/core/urlutil` import. Both branches must change: the defect is
   duplicated, and fixing one is how a predicate ends up disagreeing with itself.

   The comment above the public branch currently claims the check prevents phishing via DCR.
   Keep the intent, and cite `urlutil` so the next reader finds the predicate rather than
   reimplementing it.

2. Create `src/authserver/internal/handlers/handler_dynamic_client_registration_test.go`.
   Status: **Done**

   No test file exists for this handler. `validateRedirectURI` is unexported and pure, so this
   is a plain table in package `handlers` with no mocks and no container. Table-driven with
   `t.Run` per case, `assert` for the boolean outcome, matching the neighbouring handler tests.

   This table owns the validator's decisions exhaustively. 31 cases, all executed against a
   working implementation of section 3 before being written here, all passing:

   | URI | `isPublic` | Expect | Rejecting gate |
   |---|---|---|---|
   | `http://localhost:3000/callback` | true | accept | none |
   | `http://127.0.0.1:8080/callback` | true | accept | none |
   | `http://[::1]:9000/callback` | true | accept | none |
   | `http://localhost/cb` | true | accept | none |
   | `http://127.0.0.1/cb` | true | accept | none |
   | `http://[::1]/cb` | true | accept | none |
   | `myapp://callback` | true | accept | none, pins decision 5 |
   | `com.example.app:/oauth` | true | accept | none |
   | `http://LOCALHOST/cb` | true | accept | none, **pins decision 3** |
   | `http://LocalHost:3000/cb` | true | accept | none, **pins decision 3** |
   | `http://user@localhost/cb` | true | accept | none, `Host` excludes userinfo |
   | `https://app.example.com/callback` | false | accept | none |
   | `http://localhost:3000/callback` | false | accept | none |
   | `http://[::1]:9000/cb` | false | accept | none |
   | `http://localhost.attacker.com/callback` | true | reject | host gate, **the bug** |
   | `http://localhost.attacker.com/callback` | false | reject | host gate, sibling branch |
   | `http://127.0.0.1.attacker.com/callback` | true | reject | host gate |
   | `http://127.0.0.1.attacker.com/callback` | false | reject | host gate, sibling branch |
   | `http://localhost-evil.example.net/cb` | true | reject | host gate |
   | `http://localhost-evil.example.net/cb` | false | reject | host gate, sibling branch |
   | `http://localhost.evil.tld:8080/cb` | true | reject | host gate, with port |
   | `http://127.0.0.1x/cb` | true | reject | host gate, no separator |
   | `http://127.0.0.1.evil.tld/cb` | false | reject | host gate |
   | `https://app.example.com/callback` | true | reject | https gate, **pins decision 7** |
   | `http://example.com/callback` | true | reject | host gate |
   | `http://example.com/callback` | false | reject | host gate, sibling branch |
   | `myapp://callback` | false | reject | confidential fallthrough, pins decision 9's message |
   | `not a valid uri` | true | reject | `ParseRequestURI` |
   | `http:///cb` | true | reject | host gate, empty host |
   | `http://localhost:evil/cb` | true | reject | `ParseRequestURI`, not the host gate |
   | `http://127.0.0.1:80@evil.com/cb` | true | reject | host gate, `Host` is `evil.com` |

   Every negative case names the gate meant to reject it, verified by instrumenting the
   implementation to report which gate fires first rather than only the accept or reject
   outcome. The four rows run against both `isPublic` values exist because the bug was
   duplicated across the branches, so a single-branch table would pass with half the fix.

   Two rows deserve a "keep this" comment:

   - `http://LOCALHOST/cb` reverses the current behaviour, so it looks like a mistake without a
     note pointing at decision 3.
   - `http://127.0.0.1x/cb` is the row proving the prefix test needed no separator to be fooled,
     which is the sharpest statement of the bug.

   **`urlutil`'s bracket and port hardening is unreachable from this call site, and the table
   says so rather than pretending otherwise.** An earlier draft of this spec claimed
   `http://localhost:evil/cb` pins `urlutil` decision 15 (non-numeric ports) and that
   `http://[localhost]:3000/cb` would pin decision 14. Verified false: `url.ParseRequestURI`
   rejects a non-numeric port outright, so the predicate never sees it, and `parsed.Host` from a
   successfully parsed URL can never carry a bracketed hostname either. #41's decisions 14 and
   15 protect a caller that passes a raw unparsed host string; this caller does not. Those two
   rows are kept as documentation of where the rejection actually happens, and `urlutil`'s own
   test file remains the only place that pins its hardening.

   **What this cannot prove:** that the HTTP endpoint reaches this function, or that the
   registered client is stored with the URI it validated. That is step 3.

3. Add two rows to `TestDCR_RedirectURI_Validation`
   (`src/authserver/tests/integration/dynamic_client_registration_test.go:180`).
   Status: **Done**

   `http://localhost.attacker.com/callback` with `authMethod: "none"`, expecting
   `http.StatusBadRequest` and `api.DCRErrorInvalidRedirectURI`, and the same URI with
   `authMethod: "client_secret_post"`. The existing 12 rows already cover the legitimate forms
   through the real endpoint.

   Deliberately thin. Step 2 owns the exhaustive table, and duplicating it here would give two
   tables that drift on the first edit. This table runs only inside
   `goiabada-devcontainer-1`, so it is the expensive layer.

   **What this cannot prove:** the rare input shapes. That is step 2's job.

### Stage 2: reject malformed and executable redirect URIs
Status: **Done**

**Verified when this landed.** `urlutil` is at 97 subtests (38 host, 38 match, 21 absolute-URI).
The handler table is at 67, all passing. Each gate was disabled in turn to prove its rows are
load-bearing: absolute-URI 7 rows, character 11, scheme 11. `run-tests.sh --type modules` and
`--type integration --db sqlite` both green, the latter in full rather than filtered.

1. Add `IsAbsoluteRedirectURI` to `src/core/urlutil/redirect_uri.go`. Status: **Done**

   `url.Parse` plus `u.IsAbs() && u.Fragment == ""`, as sketched in section 3. It lives in `core`
   beside `IsLoopbackHost` because #122 needs the identical rule at the authorization layer, and
   the whole point of #41's shared predicate was to stop two notions of the same rule diverging.

   The doc comment must say that `url.ParseRequestURI` is **not** interchangeable here, since it
   keeps a literal `#frag` in the path and reports an empty `Fragment`. That sentence is the only
   thing stopping a future reader from "unifying" the two parsers and silently reopening the
   fragment hole. See decision 12.

   Extend `src/core/urlutil/redirect_uri_test.go` with the accept and reject forms:
   `http://127.0.0.1/cb`, `myapp://callback` and `com.example.app:/oauth` accepted;
   `//evil.example/cb`, `/relative/cb`, `relative/cb`, `http://127.0.0.1/cb#frag` and
   `http://127.0.0.1/cb?a=1#f` rejected; `http://127.0.0.1/cb%23frag` accepted, pinning that an
   encoded `%23` is not a fragment. That file owns the predicate's exhaustive table, per decision
   8, so the handler table below stays thin on this rule.

2. Add the three gates to `validateRedirectURI`. Status: **Done**

   All three ahead of the `isPublic` branch, in the order shown in section 3, with
   `deniedRedirectURISchemes` as a package-level map. Placement is load-bearing per decision 4:
   inside the custom-scheme branch, neither gate would see the confidential `https` case or the
   loopback `http` case.

   The absolute-URI gate calls `urlutil.IsAbsoluteRedirectURI(uri)` on the raw string, not on the
   already-parsed value, per decision 12. Its comment must cite RFC 6749 section 3.1.2 and note
   that this is the registration-side half only. Without that note the next reader will reasonably
   assume the scheme-relative leak is closed.

   The comment must record that the denylist cannot be the primary defence, because the verified
   payload uses the scheme `x`. Without that note the character gate looks redundant next to a
   denylist and is a candidate for "simplification".

3. Extend stage 1's table with 36 more cases. Status: **Done**

   All executed against the same implementation, with both the outcome and the first rejecting
   gate asserted. Total for the file: 67 cases, re-run in full after the predicate was corrected
   to `url.Parse` plus `IsAbs()` plus `Fragment == ""` and again after the denylist was extended,
   with zero mismatches and no change to any stage 1 row.

   | URI | `isPublic` | Expect | Rejecting gate |
   |---|---|---|---|
   | `x:<svg/onload=alert(1)>` | true | reject | character, **the verified payload** |
   | `myapp://x<img/src=x/onerror=alert(1)>` | true | reject | character, `<` |
   | `myapp://cb">alert` | true | reject | character, `"` |
   | `http://127.0.0.1/cb with space` | true | reject | character, space |
   | ``http://127.0.0.1/cb`x` `` | true | reject | character, backtick |
   | `http://127.0.0.1/cb{x}` | true | reject | character, braces |
   | `http://127.0.0.1/cb\|x` | true | reject | character, pipe |
   | `http://127.0.0.1/cb\x` | true | reject | character, backslash |
   | `http://127.0.0.1/cb^x` | true | reject | character, caret |
   | `https://app.example.com/<svg/onload=alert(1)>` | false | reject | character, **pins the placement** |
   | `http://127.0.0.1/<svg/onload=alert(1)>` | true | reject | character, **pins the placement** |
   | `myapp://cb with space` | true | reject | `ParseRequestURI`, **not** the character gate |
   | `//evil.example/cb` | true | reject | absolute-URI, **the code exfiltration case** |
   | `//evil.example/cb` | false | reject | absolute-URI, but see the note: not load-bearing |
   | `//evil.example:8443/cb` | true | reject | absolute-URI, with a port |
   | `/relative/cb` | true | reject | absolute-URI, path-absolute |
   | `relative/cb` | true | reject | `ParseRequestURI`, not the absolute-URI gate |
   | `http://127.0.0.1/cb#frag` | true | reject | absolute-URI, **fragment; passes a scheme-only test** |
   | `https://app.example.com/cb#frag` | false | reject | absolute-URI, fragment on the sibling branch |
   | `http://127.0.0.1/cb?a=1#f` | true | reject | absolute-URI, fragment after a query |
   | `http://127.0.0.1/cb#` | true | reject | absolute-URI, **a bare `#` is still a fragment** |
   | `http://127.0.0.1/cb%23frag` | true | accept | none, `%23` is not a fragment delimiter |
   | `javascript:alert(1)` | true | reject | scheme, no excluded characters |
   | `JavaScript:alert(1)` | true | reject | scheme, folds case |
   | `vbscript:msgbox(1)` | true | reject | scheme |
   | `file:///etc/passwd` | true | reject | scheme |
   | `about:blank` | true | reject | scheme |
   | `data:text/plain,hello` | true | reject | scheme, no excluded characters |
   | `ftp://evil.example/cb` | true | reject | scheme, **the row that prompted the extension** |
   | `FTP://evil.example/cb` | true | reject | scheme, folds case |
   | `ws://localhost/cb` | true | reject | scheme, network protocol |
   | `chrome://settings` | true | reject | scheme, browser internal |
   | `view-source:http://x` | true | reject | scheme, browser internal |
   | `mailto:a@b.c` | true | accept | none, inert and deliberately allowed |
   | `org.example.app.oauth://redirect` | true | accept | none, a real private-use scheme shape |
   | `myapp://cb/%3Cscript%3E` | true | accept | none, percent-encoded is inert |

   **The excluded character must sit in the path, not the authority.** An earlier draft of this
   spec put space, backtick and braces in the host (`myapp://cb with space` and friends).
   Verified worthless: `url.ParseRequestURI` rejects those characters in the authority component,
   so all three passed for the wrong reason and would still pass with the character gate deleted.
   The `myapp://cb with space` row is retained deliberately, labelled as parse-rejected, so
   nobody "improves" it back into a character-gate row.

   **Gate attribution is not the same as being load-bearing, and one row differs.** Each gate was
   disabled in turn against the finished table: removing the absolute-URI gate fails 7 rows, the
   character gate 11, the scheme gate 11. The confidential `//evil.example/cb` row is the one
   exception, because an empty scheme is neither `https` nor `http` and the confidential branch
   falls through to an error regardless. It is kept, labelled in the test, because it documents
   that the confidential branch was never exposed to this.

   Six rows carry the weight:

   - `//evil.example/cb` is the only row that fails if the absolute-URI gate is omitted, and it is
     the one whose absence leaks an authorization code. Keep it verbatim, and keep the comment
     explaining that the emitted `Location` would be protocol-relative, because the row looks
     merely malformed rather than dangerous.

   - `x:<svg/onload=alert(1)>` is the only row that fails if the denylist ships without the
     character gate. It is the reproduction, so keep it verbatim.
   - `javascript:alert(1)` is the mirror image: the only class that fails if the character gate
     ships without the denylist.
   - The two placement rows (`https://...` confidential and `http://127.0.0.1/...`) fail if
     either gate is moved inside the custom-scheme branch. They are the regression guard for
     decision 4's placement and their value is invisible once the placement is right.
   - `myapp://cb/%3Cscript%3E` is the accept row that stops the character gate from being
     tightened into rejecting encoded data.
   - `myapp://cb with space` is the row that documents its own uselessness as a gate test, per
     the note above.

   **What this cannot prove:** that the payload would have executed. No Go test can establish
   that, see stage 3 step 3.

### Stage 3: stop the admin console rendering redirect URIs as markup
Status: **In progress** (steps 1 to 3 done, step 4 needs a running admin console)

Independent of stages 1 and 2. It fixes the sink rather than the source, so it holds even for
URIs that arrive through the unvalidated admin endpoint.

**The writer and the reader must change together.** Both templates also *read* the cell back
when deleting a row: `deleteRedirectURI` does
`row.getElementsByTagName("td")[0].innerHTML` (`admin_clients_redirect_uris.html:139`) and
`deleteWebOrigin` does the same (`admin_clients_web_origins.html:141`), then locates the value
with `indexOf` against the raw array. Changing only the writer silently breaks deletion, because
`innerHTML` returns a serialised, entity-escaped form that no longer equals the raw string.

Verified in a browser across four values, comparing the round trip:

| Stored value | write `innerHTML`, read `innerHTML` (today) | write `textContent`, read `innerHTML` (writer only) | write and read `textContent` |
|---|---|---|---|
| `http://127.0.0.1/plain` | matches | matches | matches |
| `http://127.0.0.1/cb?q=a%20b` | matches | matches | matches |
| `http://127.0.0.1/cb?a=1&b=2` | **mismatch** | **mismatch** | matches |
| `x:<svg/onload=1>` | **mismatch** | **mismatch** | matches |

Two things follow. Changing only the writer would regress deletion for hostile values, as
reported. And the `&` row shows **deletion is already broken today** for any redirect URI
carrying two query parameters, because `innerHTML` re-serialises `&` as `&amp;`. Fixing both
sides fixes that pre-existing bug as a side effect, which is a further argument for doing both
rather than only the display.

1. Change the writer and reader in
   `src/adminconsole/web/template/admin_clients_redirect_uris.html`. Status: **Done**

   `cell1.innerHTML = uri` becomes `cell1.textContent = uri` at `:89`, and the read at `:139`
   becomes `...getElementsByTagName("td")[0].textContent`. The adjacent
   `cell2.innerHTML = getTrashCanMarkup(...)` at `:92` legitimately renders markup and stays.

2. Change the writer and reader in
   `src/adminconsole/web/template/admin_clients_web_origins.html`. Status: **Done**

   Same two edits, at `:89` and `:141`. Not anonymously reachable, since DCR never creates web
   origins, but included per decision 6 so the two files do not diverge.

3. Add a lint case to `src/adminconsole/web/template_lint_test.go`. Status: **Done**

   Landed as `TestTemplates_RedirectURIAndWebOriginCellsAreText`. It bans `innerHTML = uri` and
   `getElementsByTagName("td")[0].innerHTML` in the two guarded files, and asserts it actually
   visited both, so renaming a file cannot silently reduce it to a no-op. Proved non-vacuous by
   reverting each side in turn and by renaming one file: all three fail the lint.

   That file already walks every template via `walkHTMLTemplates` and asserts patterns, and each
   existing case is written as a guard against a specific past bug
   (`TestTemplates_NoHTMLInTitle` guards "the admin_users_* bug"). Follow that shape: assert that
   neither of the two files above contains `innerHTML = uri` **or**
   `getElementsByTagName("td")[0].innerHTML`. Both halves matter: a future edit that restores
   either one reintroduces a defect, and the reader half fails silently rather than visibly.

   Keep it scoped to these two files. A blanket `innerHTML` lint fails immediately on the 21
   other data-bearing sites, and the allowlist-based general version belongs to #120, which
   explicitly proposes replacing this narrow case rather than adding a second lint.

   **What this cannot prove, and it is the important limit of this stage:** nothing here
   executes a browser, so no automated test establishes that the payload fired before the change
   or fails to fire after it, nor that deletion still works after it. The lint proves the sink was
   changed, not that changing it is sufficient. The evidence for sufficiency is the manual
   reproduction recorded in section 1, and re-verifying it after the change is a manual step.

4. Manually verify deletion, not only display. Status: **Not started**

   **Left for the maintainer, because it needs the admin console running** (`make server`), which
   the automated suites do not start. The evidence gathered so far is the browser round trip in
   decision 6's table, which replicates the template's exact write and read but not the real page.

   Because step 3's lint cannot exercise the round trip, and because the round trip is where the
   writer-only change would have broken: add a redirect URI containing `&` (for example
   `http://127.0.0.1:9000/cb?a=1&b=2`), confirm it displays correctly, delete it, and confirm the
   row actually disappears and the save persists. That case fails before this stage and passes
   after it, so it is the cheapest proof that both halves were changed.

### Stage 4: document the rules and fix the messages
Status: **Done**

1. Add a `### Redirect URI rules` subsection to the DCR section of
   `site/src/content/docs/concepts/clients.mdx`. Status: **Done**

   After "Security considerations" (`:209`) and before "Registration endpoint" (`:220`). Nothing
   there documents redirect URI validation today, so this is new material rather than a
   correction.

   | Client type | Allowed | Not allowed |
   |---|---|---|
   | Public (`token_endpoint_auth_method: none`) | `http` on `127.0.0.1`, `::1`, `localhost`, any port; custom schemes | `https`; `http` on any other host |
   | Confidential | `https` on any host; `http` on the three loopback hosts | custom schemes; `http` elsewhere |

   Plus the five things a reader cannot infer from that table:

   - Host matching is exact after case folding, never a prefix. This is the bug, and stating the
     rule is what stops it being reintroduced.
   - A redirect URI must be an absolute URI with a scheme, per RFC 6749 section 3.1.2, so
     `//host/cb` and `/path/cb` are rejected. Also note that a fragment is not permitted, since
     `absolute-URI` excludes one.
   - Characters RFC 3986 excludes from URIs are rejected, and so are the `javascript`, `data`,
     `vbscript`, `file`, `blob` and `about` schemes.
   - The `https` refusal for public clients is a Goiabada restriction, stricter than OIDC
     Dynamic Client Registration section 2's Native Client rule and conditioned differently,
     since `application_type` is not read. Per decision 7 it must be presented with its reason
     (the server cannot verify a claimed domain) and with both of its costs: **a browser-based SPA
     cannot self-register through DCR at all**, and a public native app cannot use the
     claimed-`https` pattern RFC 8252 section 7.2 recommends. Do not describe it as spec
     conformance.
   - Confidential clients cannot use custom schemes, which today's error message contradicts.

2. Cross-link the loopback subsection at `clients.mdx:139`. Status: **Done**

   Linked in both directions: the new DCR subsection points at the loopback section for port
   flexibility, and the loopback section points at the DCR rules for the extra restrictions that
   apply to self-registered clients.

   #41 added `### Loopback redirect URIs for native apps` under `## Redirect URIs`, which
   carries the port-flexibility rule. A native app developer arriving at the DCR section needs
   it, and it is currently a separate island.

3. Rewrite the error messages. Status: **Done**

   Per decision 9. The three pre-existing messages were rewritten in **stage 1** rather than here,
   because they sit on the exact lines that stage changed and splitting them would have meant
   touching the same statements twice. Done: both loopback messages now name all three hosts, and
   the confidential fallthrough no longer offers custom schemes it rejects.

   Completed here for the messages stage 2 introduced (absolute-URI, character, scheme). One
   consistency change beyond what was specified: every validator message now ends with the
   offending URI. The three new gates named it and the four older messages did not, which matters
   because a registration request may carry several redirect URIs and the error identifies only
   one of them. All are quoted verbatim to the registrant at `:56`.

4. Add the release note. Status: **Done** (drafted here; publishing is a release-time action)

   **There is no CHANGELOG in the repo.** Verified: release notes are published as GitHub Release
   bodies, in the style `- **Title** ([#N](link)):` followed by the explanation, under `### Features` and
   `### Bug Fixes` headings (see v1.5.1 and v1.5.2). So this text cannot be committed anywhere
   useful; it goes into the next release body, which is the maintainer's action at tag time.

   Drafted here rather than left to the writer, because decision 2 constrains what it may claim
   and decision 1 constrains what it must include. Written in the house style:

   > ### Bug Fixes
   >
   > - **Redirect URI validation for dynamic client registration**
   >   ([#105](https://github.com/leodip/goiabada/issues/105)): the loopback rule for `http`
   >   redirect URIs compared the host with a prefix match, so any host beginning with `localhost`,
   >   `127.0.0.1` or `[::1]` was accepted, including `localhost.attacker.com`. The comparison is
   >   now exact against `localhost`, `127.0.0.1` and `::1`, and is case-insensitive, so `LOCALHOST`
   >   is now accepted where it previously was not. Registration additionally rejects redirect URIs
   >   that are not absolute (`//example.com/cb`, `/cb`), that carry a fragment
   >   (`http://127.0.0.1/cb#frag`, which never worked since the code was delivered to `/cb%23frag`),
   >   that contain characters RFC 3986 excludes from URIs, or that use a scheme which cannot receive
   >   an authorization response or can execute script (`javascript`, `data`, `vbscript`, `file`,
   >   `blob`, `about`, `chrome`, `chrome-extension`, `moz-extension`, `view-source`, `filesystem`,
   >   `resource`, `ftp`, `ftps`, `ws`, `wss`, `gopher`, `telnet`). Custom private-use schemes such
   >   as `myapp://callback` are unaffected; Android `intent://…#Intent;…` URIs are now rejected by
   >   the fragment rule. Per RFC 6749 §3.1.2.
   >
   > - **Admin console renders redirect URIs and web origins as text**
   >   ([#105](https://github.com/leodip/goiabada/issues/105)): both pages wrote stored values into
   >   the page with `innerHTML`, so markup in a value was parsed rather than displayed. They also
   >   read the value back with `innerHTML` when deleting a row, which meant deleting a redirect URI
   >   containing `&` silently did nothing. Both sides now use `textContent`.
   >
   > **If you enabled Dynamic Client Registration before this release**, existing redirect URIs are
   > not re-validated and there is no automatic cleanup, so a URI registered through the old prefix
   > match remains usable. If DCR has never been enabled, there is nothing to check. Otherwise:
   >
   > ```sql
   > SELECT c.client_identifier, r.uri
   > FROM redirect_uris r
   > JOIN clients c ON c.id = r.client_id
   > WHERE LOWER(r.uri) LIKE 'http://%';
   > ```
   >
   > `LOWER` matters: the stored value keeps the scheme as it was sent, so `HTTP://` rows exist and a
   > case-sensitive comparison would miss them. Review any host that is not `localhost`, `127.0.0.1`
   > or `::1`. Before deleting one, identify who owns the client: re-registering issues a **new**
   > client ID and secret rather than repairing the existing client, and removing the callback breaks
   > that client's authorization flow immediately.
   >
   > This removes one route to an attacker-controlled callback. It does not by itself stop an
   > anonymous caller registering a client with a callback it controls, since a confidential
   > registration may use any `https` host by design. The control for that is the consent screen,
   > tracked in [#108](https://github.com/leodip/goiabada/issues/108).

   The final paragraph is required, not optional. Per decision 2, a release note implying this closes
   DCR phishing would be wrong.

5. Verify. Status: **Done**, with two stated exceptions

   | Command | Covers |
   |---|---|
   | `go test ./urlutil/...` in `src/core` (host) | stage 2 step 1, `IsAbsoluteRedirectURI` |
   | `go test ./internal/handlers/...` in `src/authserver` (host) | stages 1 and 2, the 67-case table |
   | `go test ./...` in `src/adminconsole` (host) | stage 3 step 3, the template lint |
   | `run-tests.sh --type integration --db sqlite --run TestDCR_RedirectURI_Validation` (container) | stage 1 step 3 |
   | `run-tests.sh --type integration --db sqlite` (container) | no regressions elsewhere |
   | Manual: register the payload through DCR, open the client's redirect URIs page as an administrator | stage 3, the only evidence the sink fix works |
   | Manual: add, display and delete a redirect URI containing `&` | stage 3 step 4, the writer and reader round trip |

   Everything above was run in `goiabada-devcontainer-1`, per the maintainer's instruction, not on
   the host. All green. Integration on sqlite alone is sufficient: nothing here touches a query or
   the schema.

   **Two things this did not verify, both stated rather than glossed.** The docs site was not
   built: there is no `node`, `npm` or `site/node_modules` on the host or in the devcontainer, so
   the mdx edit rests on being plain markdown plus `<Aside>`, which that file already imports. And
   stage 3 step 4 remains open, since proving the sink fix end to end needs a running admin console.

   Unrelated pre-existing findings, deliberately untouched: `src/core/i18n/error_codes.go` and
   `src/core/i18n/middleware_test.go` are not `gofmt` clean, and the test run regenerates
   `src/authserver/web/static/main.css` with two utility classes unrelated to this work, so it was
   left unstaged.
