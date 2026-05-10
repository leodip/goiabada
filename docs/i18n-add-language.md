# Adding a new language to Goiabada

Goiabada's UI is fully localized. Adding a new language is mechanical and
requires no Go code changes. This guide assumes you are adding a language
identified by a BCP 47 tag — for example `pt-BR`, `es-ES`, `fr`, `ja`.

The same instructions apply whether you build the language into Goiabada
itself (file goes in the embedded catalog directory) or ship it as a
runtime override (file goes in `GOIABADA_I18N_OVERRIDES_DIR`).

## 1. Translate the message catalog

The English source of truth is `src/core/i18n/catalogs/active.en.toml`.
Copy it to `active.<your-tag>.toml` and translate every value, keeping
keys, placeholders (`{{.var}}`, `{{name}}`), and inline HTML markup
(`<span class='text-accent'>...</span>`, `<br />`) verbatim.

```bash
cp src/core/i18n/catalogs/active.en.toml \
   src/core/i18n/catalogs/active.pt-BR.toml
```

Translate the values. Keys missing from your file fall back to English at
lookup time, so a partial translation is valid — keys can be filled in
incrementally.

## 2. Translate the email bodies

Each email template under `src/authserver/web/template/emails/` is a
self-contained HTML file. Localized copies are sibling files named
`<original>.<locale>.html`:

```
emails/
  email_forgot_password.html         # English baseline
  email_forgot_password.pt-BR.html   # Portuguese (Brazilian) translation
  email_register_activate.html
  email_register_activate.pt-BR.html
  ...
```

The renderer looks for `<name>.<locale>.html` first and falls back to
`<name>.html` when no locale-specific copy exists. Translate the **body
text** but keep the template structure (Go template directives, `<a
href>` links, `{{.appName}}`, `{{.link}}`, etc.) unchanged.

Email **subjects** live in the catalog (`email.<template>.subject` keys)
and follow the regular catalog translation flow above; they do not have
separate template files.

## 3. (Optional) Add reference-data translations

`src/core/i18n/reference/<your-tag>/` holds per-locale labels for
country names, timezones, and phone-country dropdowns. Each file is a
flat `<key> = <localized label>` TOML map keyed by:

- `countries.toml` — ISO 3166-1 alpha-2 (`"BR"`, `"US"`, ...)
- `phone_countries.toml` — same alpha-2; value is `<emoji> - <country
  name> (+<dialing code>)`
- `timezones.toml` — IANA zone ID (`"America/Sao_Paulo"`, ...)

When a key is absent, the English bundle is consulted; when that's
absent too, the existing English struct field is used as fallback. So
reference-data translations can also be added incrementally.

A future generator script (`scripts/i18n/gen-reference.sh`) will be able
to emit these files from CLDR data; for now, copy the English baseline
under `reference/en/*.toml` and translate the values by hand.

## 4. (Optional, future) Locale picker native name

The locale picker in account / admin-user profile pages currently shows
the locale ID and English description. CLDR-derived **native names** (so
that `pt-BR` shows up as "Português (Brasil)" rather than "Portuguese
(Brazil)") are not yet wired up — when they are, no per-language work is
required, the data comes from CLDR.

## 5. Loading the catalog

Embedded catalogs and reference bundles live under
`src/core/i18n/catalogs/` and `src/core/i18n/reference/<locale>/`. Files
placed there are picked up automatically at startup via `//go:embed` and
require a rebuild.

For runtime overrides without a rebuild, set
`GOIABADA_I18N_OVERRIDES_DIR=/path/to/overrides`. Goiabada loads
`<dir>/catalogs/active.<locale>.toml` and `<dir>/reference/<locale>/...`
on top of the embedded files; override values win on conflict.

## 6. Verifying

After the language is in place:

1. Restart Goiabada (or reload the override directory).
2. Open any page in your browser with `Accept-Language: <your-tag>`,
   or pass `?ui_locales=<your-tag>` on the URL, or set the locale on a
   user profile and log in as that user.
3. Walk through registration, login, account management, admin
   operations, error scenarios, and incoming emails.

Any missing key shows up as the literal key string (e.g.
`auth.pwd.title`) — that's the visible-miss policy and lets you spot
gaps quickly.

## 7. The lint script

`scripts/i18n/lint-error-codes.sh` checks that every `validator.*` and
`handler.*` code constant in `error_codes.go` has a matching catalog
entry, and vice versa. It runs against `active.en.toml` (the source of
truth) and is not affected by other language files. Run it whenever you
add a new code in the Go side.
