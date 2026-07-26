# Issue 41: RFC 8252 loopback redirect URI port flexibility for native apps

**Issue:** [#41](https://github.com/leodip/goiabada/issues/41)
**Issue state:** open (labels: enhancement, go)
**Spec written:** 2026-07-25
**Last synced:** 2026-07-25 (through comment IC_kwDOKE37NM8AAAABLsiWsg)
**Revised:** 2026-07-25 after spec review. The matcher permitted more than the port, see decision 6.
**Implemented:** 2026-07-25. All three stages. See the verification table in section 5, stage
3 step 5. Section 1 below describes the state **before** this change and is kept as the
record of what was wrong.
**Related:** [#105](https://github.com/leodip/goiabada/issues/105) (open, bug + security). Independent of this work: it acts on a different call site (DCR registration) while this acts on authorization-time matching. Not a prerequisite, see decision 2.

---

## 1. Context

*State before this change. Line numbers are the pre-change ones.*

Redirect URI matching **was** exact string equality. `ValidateClientAndRedirectURI`
(`src/core/validators/authorize_validator.go:120`) looped the client's registered URIs and
compared with `input.RedirectURI == r.URI` (`:163`). Verified by reading lines 161 to 166.
There was no normalisation of any kind, and the loop had no `break`, so it kept scanning
after a match.

That broke the standard native app callback pattern. A native or MCP app binds an
OS-assigned port, starts a temporary HTTP server on it, and cannot know the port at
registration time. RFC 8252 section 7.3 addresses exactly this:

> The authorization server MUST allow any port to be specified at the time of the request
> for loopback IP redirect URIs

So Goiabada **was** non-compliant with a MUST. Registered `http://127.0.0.1/callback`,
requested `http://127.0.0.1:54321/callback`, rejected.

**The mismatch was reachable in practice**, not theoretical. The reason still holds, since
this part was left alone: the admin redirect URI endpoint
(`src/authserver/internal/handlers/apihandlers/handler_api_clients.go:724`) validates each
entry with `url.ParseRequestURI` plus a trim and a duplicate check, and applies **no scheme
or host validation at all**. Verified by reading lines 715 to 735. A portless loopback URI
therefore stores successfully.

**The failure mode was fail-closed.** Being stricter than the RFC cost functionality, not
security. There was no urgency, only a real functional gap for native apps.

**The token endpoint was already correct and was not changed.**
`src/core/validators/token_validator.go:148` compares `codeEntity.RedirectURI !=
input.RedirectURI`. The stored value originates from the authorization request itself
(`handler_authorize.go:93` reads `r.FormValue("redirect_uri")`, which reaches the code
entity via `src/core/oauth/code_issuer.go:79`). That is requested against requested, not
requested against registered, which is what RFC 6749 section 4.1.3 asks for. The ephemeral
port flows through end to end, including the final redirect, which uses `code.RedirectURI`
(`handler_auth_issue.go:271`). See decision 8.

**No loopback helper existed anywhere in `src/core`.** A grep for `loopback`, `127.0.0.1` and
`::1` across the module returned zero non-test hits, confirmed again immediately before
implementing. The predicate was built from nothing.

**Three places asserted the opposite of what this change makes true.** All three were
amended in stage 3:

| Location | Text before this change |
|---|---|
| `site/src/content/docs/concepts/clients.mdx:137` | "only exact matches are accepted (no wildcards)" |
| `src/core/i18n/catalogs/active.en.toml:655-657` | "We only accept **exact matches** for redirect URIs; wildcards are not permitted." |
| `src/core/i18n/catalogs/active.pt-BR.toml:632-634` | the same sentence in Portuguese |

The last two are the admin console's own intro prose on the redirect URIs page
(`src/adminconsole/web/template/admin_clients_redirect_uris.html:179`). Shipping the
feature without amending them would have shipped a known-false statement in two languages.

> **Assumed:** that native and MCP clients in practice register `localhost` at least as
> often as the IP literals. Not confirmed, and it could not be confirmed from this repo:
> nothing under `site/src/content/docs/` gave redirect URI guidance for native apps or MCP
> (`concepts/clients.mdx:172` mentioned MCP servers only in the context of DCR). Decision 1
> is deliberately built so that this assumption does not need to hold.

---

## 2. Goal

A client that registers an **`http` loopback** redirect URI can present any port on it at
authorization time and be accepted, **when requesting `response_type=code`**. Both of those
qualifiers are load-bearing, see decisions 11 and 12.

**The port is the only thing permitted to differ.** Every other component, including scheme
case and path escaping, is compared byte for byte, per RFC 6749 section 3.1.2.3. Non-loopback
clients are compared byte for byte throughout, so no existing client's behaviour changes.

Concretely, all of these become true:

| Registered | Requested | `response_type` | Result |
|---|---|---|---|
| `http://127.0.0.1/callback` | `http://127.0.0.1:12345/callback` | `code` | accept |
| `http://127.0.0.1:8080/callback` | `http://127.0.0.1:54321/callback` | `code` | accept |
| `http://[::1]/callback` | `http://[::1]:9999/callback` | `code` | accept |
| `http://localhost/cb` | `http://localhost:3000/cb` | `code` | accept |
| `https://example.com/callback` | `https://example.com:8080/callback` | `code` | reject |
| `http://127.0.0.1/cb` | `http://127.0.0.1:9/cb?injected=evil` | `code` | reject |
| `http://127.0.0.1/cb` | `HTTP://127.0.0.1:9000/cb` | `code` | reject |
| `https://127.0.0.1/cb` | `https://127.0.0.1:9000/cb` | `code` | reject (not `http`) |
| `http://127.0.0.1/cb` | `http://127.0.0.1:9000/cb` | `token` | reject (not code flow) |

### Out of scope

- **Fixing #105.** Separate issue, separate call site. This spec does not touch
  `handler_dynamic_client_registration.go`. Decision 9 records that #105 should adopt the
  predicate introduced here when it is fixed.
- **Rejecting fragments in redirect URIs.** RFC 6749 section 3.1.2 forbids a fragment, and
  neither the registration path nor the authorization path rejects one today. Real, and
  separate.
- **Adding scheme or host validation to the admin redirect URI endpoint.** It has none
  (`apihandlers/handler_api_clients.go:724`). That absence is why the portless form is
  registrable at all, so it is load-bearing for this feature, but tightening it is its own
  decision with its own migration questions about already-stored rows.
- **Changing the token endpoint.** Already correct. See decision 8.
- **Tightening `response_type` validation.** Found while verifying decision 12 and worth its own
  issue: `ValidateRequest` counts recognised flags rather than validating the token list, so
  `response_type=code foo` and `response_type=code code` are **accepted as valid**
  (`authorize_validator.go:229-247`, verified). RFC 6749 section 3.1.1 defines `response_type` as
  a space-delimited list of values, and an unrecognised value should yield
  `unsupported_response_type`. Out of scope here, and decision 12's gate is written so that this
  spec does not depend on it being fixed.
- **Cleaning up rows registered through the #105 prefix-match bug.** Those remain matchable
  by exact equality regardless of what happens here.

---

## 3. Proposed solution

A new dependency-free package `src/core/urlutil` with two exported functions, consumed by
the existing authorization validator.

```go
package urlutil

// IsLoopbackHost reports whether host targets the loopback interface. It accepts a bare
// host, a host:port pair, and IPv6 forms with or without brackets, so callers may pass
// either url.URL.Host or url.URL.Hostname().
//
// The set is 127.0.0.1, ::1 and localhost. RFC 8252 section 7.3 mandates port flexibility
// for the two IP literals only; section 8.3 marks the localhost hostname NOT RECOMMENDED.
// localhost is included here as a deliberate convenience for native and MCP clients, not
// as RFC compliance. See decision 1 in docs/issue-41-loopback-redirect-uri.md.
//
// Host matching is exact after case folding. A prefix match would accept
// localhost.attacker.com; RFC 3986 section 6.2.2.1 makes the host case-insensitive, so
// LOCALHOST is folded in. See decision 10.
func IsLoopbackHost(host string) bool {
	h := strings.ToLower(host)

	// Brackets belong to IPv6 literals only, so handle them as their own case. Do not
	// strings.Trim them: the cutset strips any number from either end, so "[[::1]]" would
	// pass. Do not defer to net.SplitHostPort either, which accepts "[localhost]:3000" and
	// returns "localhost". See decision 14.
	if strings.HasPrefix(h, "[") {
		if !strings.HasPrefix(h, "[::1]") {
			return false
		}
		suffix := h[len("[::1]"):]
		return suffix == "" || (strings.HasPrefix(suffix, ":") && isDigits(suffix[1:]))
	}
	if strings.ContainsRune(h, ']') {
		return false
	}

	// Strip only a numeric port. net.SplitHostPort is happy with service names and any
	// other junk, so "localhost:evil" and "127.0.0.1:http" would otherwise reduce to a
	// loopback host. An empty port is kept, matching the bracket branch above and
	// stripPortRaw. See decision 15.
	if hp, port, err := net.SplitHostPort(h); err == nil && isDigits(port) {
		h = hp
	}
	switch h {
	case "127.0.0.1", "::1", "localhost":
		return true
	}
	return false
}

// stripPortRaw removes the port from raw's authority, operating on the raw string so that
// no other component is normalised. Returns false if raw has no authority.
//
// Deliberately textual. Parsing and re-rendering through url.URL.String() would lowercase
// the scheme and re-escape the path, which silently permits differences beyond the port.
// See decision 6.
func stripPortRaw(raw string) (string, bool) {
	i := strings.Index(raw, "://")
	if i < 0 {
		return "", false
	}
	authStart := i + 3
	authEnd := len(raw)
	if n := strings.IndexAny(raw[authStart:], "/?#"); n >= 0 {
		authEnd = authStart + n
	}
	auth := raw[authStart:authEnd]

	hostStart := 0
	if at := strings.LastIndex(auth, "@"); at >= 0 {
		hostStart = at + 1 // userinfo stays put
	}
	host := auth[hostStart:]

	var stripped string
	if strings.HasPrefix(host, "[") {
		b := strings.Index(host, "]")
		if b < 0 {
			return "", false
		}
		// Only an empty suffix or ":digits" may follow the closing bracket. Dropping
		// whatever is there would accept [::1]:evil and [::1].attacker. See decision 13.
		if suffix := host[b+1:]; suffix != "" && !(strings.HasPrefix(suffix, ":") && isDigits(suffix[1:])) {
			return "", false
		}
		stripped = host[:b+1]
	} else if c := strings.LastIndex(host, ":"); c >= 0 && isDigits(host[c+1:]) {
		stripped = host[:c]
	} else {
		stripped = host
	}
	return raw[:authStart] + auth[:hostStart] + stripped + raw[authEnd:], true
}

func isDigits(s string) bool {
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// RedirectURIMatches reports whether requested matches registered. Exact equality always
// matches. Beyond that, RFC 8252 section 7.3 port flexibility applies only when the
// registered URI is an http loopback URI, and only the port may differ: everything else is
// compared byte for byte, per RFC 6749 section 3.1.2.3.
//
// This function is flow agnostic. Callers gate it on the authorization code flow, see
// decision 12.
func RedirectURIMatches(registered, requested string) bool {
	if registered == requested {
		return true
	}
	reg, err := url.Parse(registered)
	if err != nil {
		return false
	}
	// RFC 8252 section 7.3 scopes loopback redirects to the http scheme. See decision 11.
	if reg.Scheme != "http" {
		return false
	}
	if !IsLoopbackHost(reg.Hostname()) {
		return false
	}
	a, ok1 := stripPortRaw(registered)
	b, ok2 := stripPortRaw(requested)
	return ok1 && ok2 && a == b
}
```

The call site keeps the flow decision, so `urlutil` stays free of OAuth concepts:

```go
// in ValidateClientAndRedirectURI, after rtInfo is computed at line 140

// RFC 8252 section 7.3 port flexibility is for the authorization code flow only.
//
// Tested on the token sequence rather than on rtInfo's booleans: ParseResponseType
// ignores unrecognised values and collapses duplicates, so HasCode && !HasToken &&
// !HasIdToken is also true for "code foo" and "code code". And not as
// !rtInfo.IsImplicitFlow(), because response_type is not validated until
// ValidateRequest, which runs after this check. See decision 12.
responseTypes := strings.Fields(input.ResponseType)
allowLoopbackPortFlexibility := len(responseTypes) == 1 && responseTypes[0] == "code"

clientHasRedirectURI := false
for _, r := range client.RedirectURIs {
	if r.URI == input.RedirectURI {
		clientHasRedirectURI = true
		break
	}
	if allowLoopbackPortFlexibility && urlutil.RedirectURIMatches(r.URI, input.RedirectURI) {
		clientHasRedirectURI = true
		break
	}
}
```

**Two rejected approaches, both verified broken.** See decisions 6 and 7.

The issue's own `loopbackURIsMatch` compares `Scheme`, `Hostname()` and `Path` field by
field. Verified by running it: `http://127.0.0.1/callback` and
`http://127.0.0.1:9/callback?injected=evil` compare **equal**, because `url.Parse` puts the
query in `RawQuery`, not `Path`. `Fragment` and `User` are likewise unchecked, and RFC 6749
section 3.1.2 permits a query in a registered redirect URI, so that is a real deviation from
"only the port varies" in both directions.

Comparing **canonical re-rendered forms** was the first replacement, and review found it
leaks in a subtler way: it fixes the enumeration problem but inherits every normalisation
`url.URL` performs. Verified, both accepted when they should not be:

| Registered | Requested | Why it wrongly matched |
|---|---|---|
| `http://127.0.0.1/cb` | `HTTP://127.0.0.1:9000/cb` | `url.Parse` lowercases the scheme |
| `http://127.0.0.1/c b` | `http://127.0.0.1:9/c%20b` | `String()` re-escapes the path |

And inconsistently so: `%2F` against `%2f` correctly rejected, because hex case survives in
`RawPath`. So the tolerance depended on which characters happened to be involved.

Operating on the raw strings and removing only the port is what actually delivers "only the
port may differ". Nothing is parsed for comparison purposes; `url.Parse` is used solely to
extract the host for the loopback gate.

**Why this is safe:** the exact-equality fast path makes the change strictly additive. It
can only cause previously rejected requests to succeed, and only when the registered URI is
a loopback host. Every other client keeps byte-for-byte matching, and loopback clients now
keep it too for every component except the port. Gating on the **registered** side alone is
sufficient, because the raw comparison then rejects any requested URI whose host differs,
verified for `127.0.0.1` against `[::1]` and against a non-loopback host.

Custom-scheme redirect URIs used by native apps, for example `com.example.app:/oauth`, are
untouched: they have no host, so the loopback gate rejects them before `stripPortRaw` runs
and the exact-equality path continues to govern them. Verified.

Every case in stage 1's tables was run against a working implementation before this spec was
written, and re-verified after each review revision: 38 host cases and 38 match cases, all
passing. Flow gating is verified separately, in stage 2.

---

## 4. Open questions and decisions

All items are settled. Kept as a running log so a reviewer can see what was decided, why,
and what was rejected.

1. **`localhost` gets port flexibility alongside `127.0.0.1` and `::1`.** Status: **Decided**

   One set, three hosts, documented in the code as a deliberate extension beyond the
   section 7.3 MUST rather than as compliance.

   **Rejected:** the RFC-pure reading of IP literals only. Section 8.3 does mark the
   `localhost` hostname NOT RECOMMENDED, so excluding it is defensible, but DCR exists here
   for MCP clients and those are precisely the clients needing ephemeral ports. If they
   register `localhost`, an IP-only implementation leaves the motivating gap wide open.
   **Also rejected:** putting `localhost` behind a Settings flag, which adds a migration, an
   admin control, and a knob most operators cannot reason about.

   **Residual risk, stated honestly** (this paragraph replaces an earlier claim that the
   security cost was "nil", which review correctly called too strong):

   - Relaxing the port turns a single fixed target into any port an attacker can bind. That
     applies to the IP literals as much as to `localhost`, and it is the inherent trade of
     RFC 8252 section 7.3 rather than something this decision introduces.
   - The cost specific to `localhost` is what section 8.3 warns about and the IP literals
     avoid: resolution of the name is not guaranteed to reach the loopback interface, since
     it depends on the host's name resolution, and binding by hostname can inadvertently
     listen on a non-loopback interface.
   - What is genuinely bounded: `localhost` is already accepted today under exact matching,
     so this widens the port only, and because the host comparison is exact after case
     folding, `localhost.attacker.com` gains nothing (verified).

   The mitigation is PKCE, which the docs subsection in stage 3 must require for public
   native clients rather than merely mention.

   **Consequence:** the two predicates proposed during issue review (`IsLoopbackHost` and
   `IsLoopbackIPHost`) collapse into one, since both call sites now need the identical set.
   That removes the divergence risk the review was guarding against.

2. **This work ships independently of #105. No gate.** Status: **Decided**

   The two issues touch different call sites: #105 changes registration intake in
   `handler_dynamic_client_registration.go`, this changes authorization-time matching in
   `authorize_validator.go`. Neither needs the other's code.

   Verified that this change does not amplify #105. A `localhost.attacker.com` registration
   smuggled in through the prefix-match bug gets no port flexibility, because
   `IsLoopbackHost(reg.Hostname())` returns false for it and the matcher therefore returns
   before comparing anything. Exact equality still governs such a row, exactly as it does today.
   The `localhost.attacker.com` row in stage 1's match table pins that.

   (This paragraph previously credited the outcome to the matcher "comparing `Hostname()`
   exactly", which described the canonical-form design discarded in decision 6. The conclusion
   was unchanged, the mechanism was not.)

   **Rejected:** treating "land #105 first" as a prerequisite stage. It was a hygiene
   preference, not a technical dependency, and enforcing it would block a functional fix on
   an unrelated security fix's timeline.

3. **The predicate lives in a new package `src/core/urlutil`.** Status: **Decided**

   **Rejected:** `src/core/validators`. It is already imported by authserver
   (`apihandlers/handler_api_clients.go:22`) so reuse would have worked, but every file in
   that package is a constructor-plus-methods validator type and it has no exported free
   functions. A pure string predicate does not fit that shape. **Also rejected:** making
   them methods on `AuthorizeValidator`, which would force any other caller to construct a
   validator, and therefore supply a `data.Database`, just to test a string. That defeats
   decision 9.

4. **The docs page is corrected in this change.** Status: **Decided**

   `clients.mdx:137` would have become false the moment this shipped, so amending it was part
   of the change, not follow-up polish. A short subsection is added for the native app audience,
   which had no redirect URI guidance anywhere under `site/` before this change.

   **Rejected:** correcting the one clause and adding nothing, which leaves a native app
   developer with no way to discover the capability.

5. **Both i18n catalogs are updated.** Status: **Decided**

   English is the source of truth and pt-BR is edited in-repo through the normal PR flow,
   per the project's established i18n convention.

   **Rejected:** English now with pt-BR deferred to a translator, which would knowingly
   ship a false Portuguese string. **Also rejected:** rewording to sidestep the claim
   entirely (for example "Wildcards are not permitted" plus a docs link), which stays true
   with no new translation but removes the loopback hint from the point of use.

6. **Compare the raw strings with only the port removed. Never parse and re-render.**
   Status: **Decided** (revised after review)

   `stripPortRaw` removes the port textually and the two results are compared with `==`.
   RFC 6749 section 3.1.2.3 requires simple string comparison per RFC 3986 section 6.2.1,
   and this is that comparison with exactly one exemption.

   **Rejected:** the issue's field-by-field comparison of `Scheme`, `Hostname()` and `Path`.
   Verified broken: it returns true for `http://127.0.0.1/callback` against
   `http://127.0.0.1:9/callback?injected=evil`, because the query lives in `RawQuery`. It
   also ignores `Fragment` and `User`, and the next field added to `url.URL` would be missed
   too.

   **Also rejected, and this spec originally specified it:** comparing canonical forms
   rendered by `url.URL.String()` with the port stripped. Review found it permits more than
   the port, because it inherits `url.URL`'s normalisations. Verified: `url.Parse` lowercases
   the scheme, so `HTTP://127.0.0.1:9000/cb` matched registered `http://127.0.0.1/cb`; and
   `String()` re-escapes the path, so a literal space matched `%20`. Inconsistently, too,
   since `%2F` against `%2f` correctly rejected because hex case survives in `RawPath`. The
   lesson generalises: any approach that round-trips through `url.URL` silently adopts
   whatever that type decides to normalise, now and in future Go versions.

   Not a security hole in itself. A case-different scheme is semantically the same URI under
   RFC 3986 section 6.2.2.1, and the gate already requires a loopback host, so the target is
   the user's own machine either way. It was fixed because the spec asserted an invariant its
   own implementation broke.

7. **Both functions take strings and parse internally.** Status: **Decided**
   (rationale strengthened by the decision 6 revision)

   **Rejected:** accepting a `*url.URL`. Originally this was a risk argument: the DCR path
   parses with `url.ParseRequestURI` while a matcher naturally uses `url.Parse`, and the two
   disagree on fragments. Verified: `http://127.0.0.1/cb#frag` yields `Path="/cb"`,
   `Fragment="frag"` under the former but `Path="/cb#frag"`, `Fragment=""` under the latter.

   After decision 6 it is no longer a preference but a **requirement**. `RedirectURIMatches`
   compares raw strings, and the raw form cannot be faithfully recovered from a `*url.URL`:
   recovering it means calling `String()`, which is precisely the normalisation decision 6
   exists to avoid. A caller therefore cannot hand over a parsed URL without destroying the
   information the comparison depends on.

   `IsLoopbackHost` alone would have been safe either way, since `Host` and `Hostname()`
   agree across both parsers in every case tested, but it takes a string for consistency and
   so the DCR call site in #105 can pass either field.

8. **The token endpoint is not modified.** Status: **Decided**

   `token_validator.go:148` compares the code's stored URI against the token request's URI,
   and the stored value came from the authorization request. Requested against requested is
   correct per RFC 6749 section 4.1.3 and needs no port flexibility. Recorded explicitly
   because it looks like a second call site that was missed, and "fixing" it to compare
   against registered URIs would be a regression.

9. **#105 adopts `urlutil.IsLoopbackHost` when it is fixed.** Status: **Decided**

   Confirmed with the maintainer. #105's own proposal used `net.SplitHostPort` plus
   `strings.Trim(host, "[]")` on `parsed.Host`, which is the same logic; it should call the
   shared predicate instead so the codebase carries one notion of "is loopback" rather than
   one at registration and one at authorization. The predicate is exported and accepts
   either `Host` or `Hostname()` specifically so that call site can use it unchanged.

   No work in this spec. Recorded so whoever fixes #105 finds it.

10. **`IsLoopbackHost` folds host case. The matcher does not.** Status: **Decided**

    `strings.ToLower` in the predicate's switch, so `http://LOCALHOST/cb` is recognised as a
    loopback registration and gets port flexibility. RFC 3986 section 6.2.2.1 makes the host
    case-insensitive, so this is normalisation rather than laxity, and denying it silently
    would be a dead end for whoever typed it.

    Verified that folding only widens the gate and never weakens it:
    `LOCALHOST.ATTACKER.COM` still returns false, because the comparison after folding is
    still exact rather than a prefix.

    The asymmetry with decision 6 is deliberate. The gate asks "is this host loopback", where
    case is not meaningful. The comparison asks "is this the same URI but for the port", where
    it is. So `LOCALHOST` registered against `LOCALHOST:3000` requested matches, while
    `LOCALHOST` against `localhost:3000` does not. Both verified.

    **Rejected:** a case-sensitive predicate. Smaller, but an admin who registers `Localhost`
    gets exact matching with nothing in the UI or the docs explaining why.

11. **Port flexibility requires the `http` scheme.** Status: **Decided** (added by review)

    `RedirectURIMatches` returns false unless the registered URI's scheme is `http`.

    Verified that without this gate the exception leaked to every scheme:
    `https://127.0.0.1/cb`, `custom://127.0.0.1/cb` and even `ftp://127.0.0.1/cb` all gained
    variable-port matching, because only the hostname was gated. RFC 8252 section 7.3 defines
    loopback redirects as using the `http` scheme, so anything beyond that is unjustified
    scope creep.

    Nothing regresses. There was no port flexibility to withdraw, and `https://127.0.0.1:8443/cb`
    against itself still matches through the exact-equality path (verified). The cost is that
    a native app serving TLS on an ephemeral loopback port does not get flexibility, which is
    both rare and outside the mandate.

    The gate reads the **parsed** scheme, which `url.Parse` lowercases, so a registration of
    `HTTP://127.0.0.1/cb` passes it while the raw comparison still requires the request to
    spell the scheme identically. Same split as decision 10: the gate normalises, the
    comparison does not.

12. **Port flexibility applies to the authorization code flow only.** Status: **Decided**
    (added by review)

    The call site requires `strings.Fields(input.ResponseType)` to be exactly `["code"]`, and
    only consults the matcher when that holds.

    `ValidateClientAndRedirectURI` serves implicit requests as well as authorization code
    requests: `rtInfo.IsImplicitFlow()` is branched on at `authorize_validator.go:142`, and
    the redirect URI check below it is common to both. So without a gate, the relaxation would
    permit arbitrary loopback ports for responses that carry tokens directly in the fragment,
    where interception cannot be mitigated by PKCE. RFC 8252 section 8.2 discourages implicit
    for native apps outright.

    **Rejected:** `!rtInfo.IsImplicitFlow()`. `ValidateClientAndRedirectURI` runs at
    `handler_authorize.go:143` while `ValidateRequest`, which validates `response_type`
    combinations, runs at `:205`. Verified: **the redirect URI check sees an unvalidated
    `response_type`.** So the negative test returns true for `code token` (hybrid sets
    `HasCode`) and for garbage such as `response_type=foo` (all flags false).

    **Also rejected, and this spec originally specified it:**
    `rtInfo.HasCode && !rtInfo.HasToken && !rtInfo.HasIdToken`. Review found it is not
    equivalent to "code only", because `ParseResponseType`
    (`src/core/oauth/response_type.go:16`) ignores unrecognised values and collapses
    duplicates into booleans. Verified: `code foo` and `code code` both satisfy it. Testing the
    token sequence instead cannot be fooled by either. Whitespace tolerance is retained via
    `strings.Fields`, matching how the rest of the server reads the parameter, so `" code "`
    keeps flexibility rather than losing it to padding.

    Zero plumbing cost: `ValidateClientAndRedirectURIInput` already carries `ResponseType`.

13. **A bracketed IPv6 authority may be followed only by an empty suffix or `:digits`.**
    Status: **Decided** (added by review)

    `stripPortRaw` returns false for anything else rather than discarding it.

    **Rejected, and this spec originally specified it:** dropping everything after the closing
    bracket. Verified that it accepted four malformed authorities as equal to registered
    `http://[::1]/cb`:

    | Requested | Stripped to |
    |---|---|
    | `http://[::1]:evil/cb` | `http://[::1]/cb` |
    | `http://[::1].attacker/cb` | `http://[::1]/cb` |
    | `http://[::1]::443/cb` | `http://[::1]/cb` |
    | `http://[::1]x/cb` | `http://[::1]/cb` |

    Not exploitable as an open redirect: verified that all four fail **both** `url.Parse` and
    `url.ParseRequestURI`, so the flow errors out downstream rather than redirecting anywhere.
    Verified too that userinfo smuggling does not get through, since `http://[::1]:80@evil.com/cb`
    strips to itself and does not match.

    Fixed anyway, on two grounds. Redirect URI validation accepting an unregistered URI and
    relying on a later parser to reject it is exactly the layered assumption that breaks when
    the later layer changes. And it contradicts decision 6's invariant, which is the whole
    point of comparing raw strings.

14. **Bracketed hosts are matched explicitly, not by trimming brackets.**
    Status: **Decided** (added by review)

    `IsLoopbackHost` handles a leading `[` as its own case, requiring exactly `[::1]` optionally
    followed by `:` and digits, and rejects any host containing `]` otherwise.

    **Rejected, and this spec originally specified it:** `strings.Trim(h, "[]")`. Trim treats
    the brackets as a cutset, so it strips any number from either end. Verified that six
    malformed hosts returned true: `[[::1]]`, `[localhost]`, `[[localhost]]`,
    `[localhost]:3000`, `[127.0.0.1]` and `]::1[`.

    **Also insufficient:** switching to exact cases for `::1` and `[::1]` while keeping
    `net.SplitHostPort`. Verified that it fixes five of the six but not `[localhost]:3000`,
    because `SplitHostPort` strips the brackets itself and hands back `localhost`, which then
    matches legitimately. The bracket check has to happen before that call, not after it.

    Today's matcher is unaffected either way: it calls `IsLoopbackHost(reg.Hostname())`, and
    `url.Parse` never returns brackets from `Hostname()` (verified). This is fixed because
    decision 9 exports the predicate for reuse in #105's DCR validation, which is
    security-sensitive and where the caller may pass `parsed.Host` rather than `Hostname()`.
    An exported predicate whose doc comment promises it tolerates bracketed IPv6 forms must not
    also accept `[localhost]`.

15. **The non-bracketed branch strips only a numeric port.** Status: **Decided**
    (added by review)

    `net.SplitHostPort`'s result is accepted only when the port component passes `isDigits`.

    **Rejected, and this spec originally specified it:** accepting `hp` whenever
    `SplitHostPort` returns no error. It validates bracket balance and colon count but not the
    port's contents, because service names are legal for `net.Dial`. Verified that six hosts
    returned true: `localhost:evil`, `127.0.0.1:http`, `127.0.0.1:https`, `localhost:+80`,
    `localhost:-1` and `localhost:80x`.

    This is the same defect as decision 14, in the sibling branch. Decision 14 fixed the
    bracketed path and left the non-bracketed path trusting a helper that is more permissive
    than URL syntax, which is also why the two branches disagreed: `[::1]:evil` rejected while
    `localhost:evil` was accepted. Recorded as its own decision rather than folded into 14 so
    the sequence stays legible.

    An empty port stays accepted (`localhost:`), consistent with `[::1]:` in decision 14 and
    with `stripPortRaw`, which also treats an empty port as a port.

    Defense-in-depth again, on the same reasoning as decision 14. `stripPortRaw`'s
    non-bracketed branch already required `isDigits` (verified), and today's matcher only ever
    passes `Hostname()`, which carries no port at all, so no match result changes. Confirmed by
    re-running the full matcher table against the fixed predicate.

---

## 5. Implementation plan

Three stages. All land together as one PR unless review velocity suggests otherwise.

*Unlike section 1, the line references in this section point at where the code landed rather
than at the pre-change locations, unless a reference is explicitly identified as pre-change.
Stage 3's citations happen to be unchanged by the edits.*

### Stage 1: the `urlutil` package
Status: **Done**

1. Create `src/core/urlutil/redirect_uri.go` with `IsLoopbackHost`, `stripPortRaw` and
   `isDigits` (both unexported), and `RedirectURIMatches`, as sketched in section 3.
   Status: **Done**

   `RedirectURIMatches` gates on `reg.Scheme != "http"` before the host check, per decision 11.

   Doc comments state which RFC section each rule serves, that `localhost` is a deliberate
   extension rather than compliance, that the `http` gate is the section 7.3 scope, and that
   `stripPortRaw` is textual on purpose, so decisions 1, 6, 10 and 11 survive future edits.
   The comment on `stripPortRaw` matters most: without it, a future reader will "simplify" it
   back into a parse-and-render and silently reintroduce the scheme-case bug.

2. Create `src/core/urlutil/redirect_uri_test.go` with the canonical host table.
   Status: **Done**

   This table is the single source of truth for loopback host cases. All 38 verified
   passing against a working implementation:

   | Host | Expect |
   |---|---|
   | `127.0.0.1`, `127.0.0.1:8080` | true |
   | `::1`, `[::1]`, `[::1]:9999`, `[::1]:`, `[::1]:80` | true |
   | `localhost`, `localhost:3000`, `localhost:` | true (pins decision 1) |
   | `LOCALHOST`, `LocalHost:3000` | true (pins decision 10) |
   | `localhost.attacker.com`, `localhost.attacker.com:9` | false |
   | `LOCALHOST.ATTACKER.COM` | false (folding does not weaken the gate) |
   | `127.0.0.1.evil.tld`, `localhost-evil.example.net` | false |
   | `example.com`, `127.0.0.2`, `127.0.0.1.`, `""` | false |
   | `[[::1]]`, `[[localhost]]` | false (**pins decision 14**, doubled brackets) |
   | `[localhost]`, `[localhost]:3000` | false (brackets are for IP literals only) |
   | `[127.0.0.1]` | false (IPv4 is not bracketed) |
   | `]::1[`, `[::1` | false (unbalanced) |
   | `[::1]x`, `[::1]:evil` | false (bad suffix after the bracket) |
   | `[::2]` | false (a different address) |
   | `localhost:evil`, `localhost:80x` | false (**pins decision 15**, non-numeric port) |
   | `127.0.0.1:http`, `127.0.0.1:https` | false (service names are legal to `net.Dial`) |
   | `localhost:+80`, `localhost:-1` | false (signed is not numeric) |
   | `::1:80` | false (unbracketed IPv6 cannot carry a port) |

   Two rows carry most of the weight:

   - `[localhost]:3000` survives the obvious fix to decision 14, because `net.SplitHostPort`
     strips the brackets before any later check can see them.
   - `localhost:evil` is the mirror image, and the pair is why decisions 14 and 15 exist
     separately. Fixing only one leaves the two branches disagreeing about the same input
     shape.

3. Add the match table to the same test file. Status: **Done**

   Consolidated and deduplicated from the issue body (6 cases), both review comments (6
   more), and the spec reviews that produced decisions 6, 11, 13 and 15 (26 more). All 38
   verified passing. Flow gating is not covered here, because `RedirectURIMatches` is flow
   agnostic; those cases live in stage 2:

   | Registered | Requested | Expect | Guards |
   |---|---|---|---|
   | `http://127.0.0.1/callback` | same | accept | identical |
   | `http://127.0.0.1/callback` | `http://127.0.0.1:12345/callback` | accept | port added |
   | `http://127.0.0.1:8080/callback` | `http://127.0.0.1:54321/callback` | accept | port changed |
   | `http://127.0.0.1:8080/cb` | `http://127.0.0.1/cb` | accept | port removed |
   | `http://[::1]/callback` | `http://[::1]:9999/callback` | accept | IPv6 |
   | `http://localhost/cb` | `http://localhost:3000/cb` | accept | pins decision 1 |
   | `http://127.0.0.1/cb` | `http://127.0.0.1:80/cb` | accept | default port is still port variance |
   | `http://LOCALHOST/cb` | `http://LOCALHOST:3000/cb` | accept | pins decision 10 |
   | `com.example.app:/oauth` | same | accept | custom scheme, exact path |
   | `http://127.0.0.1/cb` | `http://127.0.0.1:9/other` | reject | path differs |
   | `http://127.0.0.1:8080/cb` | `https://127.0.0.1:8080/cb` | reject | scheme differs |
   | `http://127.0.0.1/cb` | `HTTP://127.0.0.1:9000/cb` | reject | **scheme case, pins decision 6** |
   | `http://127.0.0.1/cb` | `HtTp://127.0.0.1/cb` | reject | scheme case with no port change |
   | `http://127.0.0.1/c b` | `http://127.0.0.1:9/c%20b` | reject | escaping must not be normalised |
   | `http://127.0.0.1/c%2Fb` | `http://127.0.0.1:9/c%2fb` | reject | hex case |
   | `https://example.com/cb` | `https://example.com:8080/cb` | reject | not loopback |
   | `http://127.0.0.1/cb` | `http://127.0.0.1:9/cb?injected=evil` | reject | query added |
   | `http://127.0.0.1/cb?a=1` | `http://127.0.0.1:9/cb` | reject | query dropped |
   | `http://127.0.0.1/cb` | `http://127.0.0.1:9/cb?` | reject | empty query added |
   | `http://127.0.0.1/cb` | `http://127.0.0.1:9/cb#f` | reject | fragment added |
   | `http://127.0.0.1/cb` | `http://user@127.0.0.1:9/cb` | reject | userinfo added |
   | `http://127.0.0.1/cb` | `http://127.0.0.1:9//cb` | reject | double slash |
   | `http://localhost.attacker.com/cb` | `http://localhost.attacker.com:9/cb` | reject | #105 interaction |
   | `http://LOCALHOST/cb` | `http://localhost:3000/cb` | reject | host case differs between the two |
   | `http://127.0.0.1/cb` | `http://[::1]:9/cb` | reject | v4 is not v6 |
   | `https://127.0.0.1/cb` | `https://127.0.0.1:9000/cb` | reject | **pins decision 11** |
   | `https://localhost/cb` | `https://localhost:8443/cb` | reject | https localhost |
   | `custom://127.0.0.1/cb` | `custom://127.0.0.1:9000/cb` | reject | custom scheme on a loopback host |
   | `ftp://127.0.0.1/cb` | `ftp://127.0.0.1:2121/cb` | reject | any other scheme |
   | `https://127.0.0.1:8443/cb` | same | accept | https still matches exactly |
   | `http://[::1]/cb` | `http://[::1]:/cb` | accept | empty port is still a port |
   | `http://[::1]/cb` | `http://[::1]:evil/cb` | reject | **pins decision 13** |
   | `http://[::1]/cb` | `http://[::1].attacker/cb` | reject | suffix after the bracket |
   | `http://[::1]/cb` | `http://[::1]::443/cb` | reject | double colon |
   | `http://[::1]/cb` | `http://[::1]x/cb` | reject | trailing character |
   | `http://[::1]/cb` | `http://[::1]:80@evil.com/cb` | reject | userinfo smuggling |
   | `http://localhost/cb` | `http://localhost:evil/cb` | reject | decision 15 through the matcher |
   | `http://127.0.0.1/cb` | `http://127.0.0.1:http/cb` | reject | service name as a port |

   Two rows deserve attention because they contradict earlier positions:

   - The `localhost` accept row **reverses the first review comment**, which assumed the
     IP-only reading. Decision 1 chose otherwise and this row pins it.
   - The `HTTP://` reject row is the one that **failed under this spec's original design**.
     Keep it. It is the regression test for decision 6, and it fails the moment anyone
     reintroduces parse-and-render.

### Stage 2: consume it in the authorization validator
Status: **Done**

1. Compute the flow gate in `ValidateClientAndRedirectURI`, after `rtInfo` is assigned
   (`src/core/validators/authorize_validator.go:140`). Status: **Done**

   Landed at `:165-166`, after the `rtInfo.IsImplicitFlow()` branch rather than immediately
   after the assignment, so all three flow-related reads sit together without splitting
   `rtInfo` from its first use.

   `strings.Fields(input.ResponseType)` must be exactly `["code"]`, per decision 12. Note this
   reads `input.ResponseType` directly rather than `rtInfo`, so it did not strictly need to sit
   after the assignment, but keeping it adjacent to `rtInfo` keeps the flow reasoning in one place.

   The comment must record both rejected forms and why, because each looks tidier than what is
   specified: `!rtInfo.IsImplicitFlow()` reads more naturally, and the boolean triple looks
   like it means "code only" when it also accepts `code foo` and `code code`.

2. Replace the comparison in the loop, adding the `break` the loop lacked. Status: **Done**

   The loop is now at `authorize_validator.go:178-189`; it was at `:161-166` before this change.

   Exact equality first, then `allowLoopbackPortFlexibility && urlutil.RedirectURIMatches(...)`,
   as sketched in section 3. Argument order matters: registered first, requested second, since
   the scheme and host gates read the registered side.

3. Extend `src/core/validators/authorize_validator_test.go`. Status: **Done**

   Both tests became table-driven to carry the new rows, and the reject test switched from
   `assert.Error` to `require.Error` plus a checked type assertion. Not cosmetic: with
   `assert`, a regression leaves `err` nil and the existing
   `err.(*customerrors.ErrorDetail)` panics, which aborts the whole table. Verified, that is
   exactly what happened when the gate was disabled to confirm the rows were not vacuous:
   only the first of the five flow rows reported before the panic. With `require`, all five
   report.

   Extend the existing `TestValidateClientAndRedirectURI_ValidClientAndRedirectURI` (now
   `:168`) and `_InvalidRedirectURI` (now `:218`) rather than adding a parallel suite; they
   already set up the `mocks_data.Database` and `ClientLoadRedirectURIs` stub this needs.

   Seven cases, covering only what stage 1 cannot, which is the wiring and the flow gate. Every
   registered and requested URI is written out, because a case whose two URIs are unrelated
   passes for the wrong reason:

   | Registered | Requested | `response_type` | Expect | Pins |
   |---|---|---|---|---|
   | `http://127.0.0.1/cb` | `http://127.0.0.1:54321/cb` | `code` | accept | the wiring |
   | `https://example.com/cb` | `https://example.com:8443/cb` | `code` | reject | non-loopback, port-only difference |
   | `http://127.0.0.1/cb` | `http://127.0.0.1:54321/cb` | `token` | reject | decision 12, implicit |
   | `http://127.0.0.1/cb` | `http://127.0.0.1:54321/cb` | `id_token` | reject | decision 12, implicit |
   | `http://127.0.0.1/cb` | `http://127.0.0.1:54321/cb` | `code token` | reject | decision 12, hybrid on an unvalidated parameter |
   | `http://127.0.0.1/cb` | `http://127.0.0.1:54321/cb` | `code foo` | reject | decision 12, unrecognised token |
   | `http://127.0.0.1/cb` | `http://127.0.0.1:54321/cb` | `code code` | reject | decision 12, duplicate token |

   The non-loopback row must differ **only** in port. An earlier draft paired
   `https://example.com/cb` with the default requested `http://127.0.0.1:54321/cb`, which
   compares two entirely unrelated URIs and would pass even if the scheme and host gates were
   deleted.

   The last three matter most, and none of them would fail under a naive gate:

   - `code token` is rejected by `ValidateRequest` later, so this row asserts that **this**
     function does not grant flexibility on a parameter it has not validated.
   - `code foo` and `code code` are **accepted as valid** by `ValidateRequest`
     (`authorize_validator.go:229-247` counts recognised flags and reaches 1), so these two are
     the only thing standing between the gate and the looseness described in decision 12.

   Otherwise deliberately thin. The exhaustive matcher tables live with the helper in stage 1;
   duplicating them here would give two tables that drift on the first edit.

4. Add an end-to-end integration test in `src/authserver/tests/integration/`.
   Status: **Done**

   `token_authcode_loopback_port_test.go`, one test:
   `TestToken_AuthCode_LoopbackEphemeralPort`. The port comes from `net.Listen` on
   `127.0.0.1:0`, released immediately, so the test carries a genuinely OS-assigned number
   that could not have been known at registration time rather than a hardcoded one. Nothing
   connects to the callback, so releasing the port is harmless. The wrong-port attempt uses
   `port+1`.

   Nothing above proves the advertised behaviour actually works: stage 1 tests a pure function
   and step 3 above exercises a mocked database, so neither shows a real ephemeral-port callback
   completing. Follow the existing full-flow tests, for example
   `token_authcode_basicauth_test.go` and `token_authcode_concurrent_test.go`.

   One test, asserting the whole chain. **The order of the last two steps is load-bearing:**

   1. register a client with the portless `http://127.0.0.1/callback`
   2. authorize with `redirect_uri=http://127.0.0.1:<ephemeral>/callback` and
      `response_type=code`
   3. assert the `Location` header redirects to the **requested** port, not the registered one,
      since `handler_auth_issue.go:271` redirects using `code.RedirectURI`
   4. **first**, attempt the exchange at `/auth/token` with a **different** port and assert it
      fails with `invalid_grant` and description `Invalid redirect_uri.`
      (`token_validator.go:148-149`)
   5. **then** exchange the same still-unused code with the correct ephemeral URI and assert
      success

   Steps 4 and 5 must be in that order. Redeeming first would consume the code, so a subsequent
   wrong-port attempt would fail because the code was already used, and the assertion would pass
   even if `token_validator.go:148` had been switched to flexible matching. Testing the wrong
   port first is what actually pins decision 8.

   Verified that this ordering works: `ValidateTokenRequest` runs at `handler_token.go:54` and
   `MarkCodeAsUsed` only at `:93`, so a validation failure returns at `:77` without consuming
   the code. Revocation at `:64` fires only for `AuthCodeReusedError`, which requires
   authenticating against an already-used code, so a plain redirect URI mismatch does not
   trigger it. Two independent codes would also work, but are unnecessary given this ordering.

### Stage 3: correct the three false statements
Status: **Done**

1. Amend `site/src/content/docs/concepts/clients.mdx:137`. Status: **Done**

   "only exact matches are accepted (no wildcards)" gains the loopback exception and a
   pointer to the new subsection.

2. Add a loopback subsection under `## Redirect URIs` (`clients.mdx:131`).
   Status: **Done**

   `### Loopback redirect URIs for native apps`. The `localhost` warning became an
   `<Aside type="caution">`, since `Aside` is already imported in the file.

   Covers: why native apps cannot know the port at registration time, that registering
   `http://127.0.0.1/callback` accepts any port at authorization time, that the set is
   `127.0.0.1`, `::1` and `localhost`, and that everything except the port must still match
   byte for byte.

   Must also state the three limits explicitly, since each is a decision someone will
   otherwise trip over:

   - **`http` only** (decision 11). An `https` loopback URI still requires an exact match.
   - **`response_type=code` only** (decision 12). Implicit gets no flexibility.
   - **PKCE is required for public native clients**, not merely recommended. This is the
     mitigation the relaxation depends on, per decision 1's residual risk, and it is why the
     wording is a requirement rather than a suggestion. Point readers at
     `site/src/content/docs/concepts/pkce.mdx` and the per-client `PKCERequired` setting.

   Recommend the IP literals over `localhost`, per RFC 8252 section 8.3, and say why: name
   resolution for `localhost` is not guaranteed to reach the loopback interface, and binding
   by hostname can inadvertently listen on a non-loopback interface.

3. Update `src/core/i18n/catalogs/active.en.toml:655-657`. Status: **Done**

   `intro_suffix` is now `" for redirect URIs; wildcards are not permitted. One exception:
   for http loopback addresses, any port is accepted on authorization code requests."`
   No new keys, so no template change.

   Both qualifiers are required. The earlier wording said only "Loopback addresses are an
   exception: any port is accepted", which review correctly called false for `https` loopback
   (decision 11) and for implicit requests (decision 12). Point-of-use copy that overstates the
   rule is worse than no copy, because an admin will register an `https` loopback URI and expect
   flexibility they do not get.

4. Update `src/core/i18n/catalogs/active.pt-BR.toml:632-634`. Status: **Done**

   Both catalogs confirmed to need no template change: the intro renders as
   `intro_prefix` + `intro_em` + `intro_suffix` at
   `src/adminconsole/web/template/admin_clients_redirect_uris.html:179`.

   `intro_suffix` is now `" para URIs de redirecionamento; curingas não são permitidos. Uma
   exceção: para endereços de loopback http, qualquer porta é aceita em solicitações de código
   de autorização."`

5. Verify. Status: **Done**

   `go test ./...` in `src/core` covers stages 1 and 2 steps 1 to 3, which are all pure or
   mock-backed. Stage 2 step 4 is an integration test and will **not** run on the host: it
   needs `./run-tests.sh` from `src/authserver` inside `goiabada-devcontainer-1`, where the
   database hostnames and tailwindcss exist. Both were run.

   What was actually run:

   | Command | Result |
   |---|---|
   | `go test ./urlutil/...` (host) | pass, 76 subtests (38 host + 38 match), no duplicate names |
   | `go test ./validators/...` (host) | pass, including the 7 new rows (9 total, with the two pre-existing cases folded into the tables) |
   | `run-tests.sh --type modules` (container) | pass, internal + core + adminconsole |
   | `run-tests.sh --type integration --db sqlite --run TestToken_AuthCode_LoopbackEphemeralPort` | pass |
   | `run-tests.sh --type integration --db sqlite` (full suite) | pass, no regressions |

   `core/communication.TestSendEmail` fails on the host with `lookup mailpit: no such host`.
   Pre-existing and environmental, and it passes in the container.

   **Two things this did not verify.** The docs site was not built: there is no `node`,
   `npm` or `site/node_modules` on the host or in the devcontainer, so the mdx edit rests on
   it being plain markdown plus the already-imported `<Aside>`. And integration ran on sqlite
   only; the change touches no query or schema, so the other three engines add nothing here.
