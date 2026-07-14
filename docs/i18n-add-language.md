# Adding a new language to Goiabada

Goiabada's UI is fully localized. Adding a new language is mechanical and
requires no Go code changes. This guide assumes you are adding a language
identified by a BCP 47 tag — for example `pt-BR`, `es-ES`, `fr`, `ja`.

The same instructions apply whether you build the language into Goiabada
itself (file goes in the embedded catalog directory) or ship it as a
runtime override (file goes in `GOIABADA_I18N_OVERRIDES_DIR`).

> **Dropdown labels need no per-language work.** Country and phone-country
> **names** in the profile dropdowns are derived from Unicode CLDR
> automatically for the active locale, and **timezone labels** are assembled
> at runtime as *CLDR-localized country name + IANA zone ID + optional English
> comment*. None of them require per-language data files.

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

## 3. Locale picker native name

Locale-picker entries are rendered automatically from CLDR as
`<native name> (<English name>)` (so `pt-BR` shows up as
"português (Brasil) (Portuguese (Brazil))"). No per-language work is required.

## 4. Loading the catalog

Embedded catalogs live under `src/core/i18n/catalogs/`. Files placed there
are picked up automatically at startup via `//go:embed` and require a
rebuild.

For runtime overrides without a rebuild, set
`GOIABADA_I18N_OVERRIDES_DIR=/path/to/overrides`. Goiabada loads
`<dir>/catalogs/active.<locale>.toml` on top of the embedded files;
override values win on conflict. Only the `catalogs/` subdirectory is
consulted.

## 5. Verifying

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

## 6. The lint script

`scripts/i18n/lint-error-codes.sh` checks that every `validator.*` and
`handler.*` code constant in `error_codes.go` has a matching catalog
entry, and vice versa. It runs against `active.en.toml` (the source of
truth) and is not affected by other language files. Run it whenever you
add a new code in the Go side.
