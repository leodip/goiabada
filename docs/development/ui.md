# UI development

Change templates, static scripts and translations using the existing design system.

Paths in backticks are relative to the repository root unless a module directory is named. Read the
sections relevant to the change; [AGENTS.md](../../AGENTS.md) lists the common commands.

Both servers draw their pages with `ui.css`, Goiabada's design tokens and components, and Tailwind
utilities for layout (#617). The file is one copy in each application's `web/tailwindcss/`, which
`TestUICSS_IsTheAuthServersCopy` holds byte-identical; edit one, copy it over the other, and
regenerate both `main.css`. Every class a page names has a rule in the served `main.css`
(`core/guard.AssertClassesAreDrawn`), so a misspelt or leftover class fails the unit tier.

- **Themes**: a page is drawn in a brand (#810): its appearance, `auto` (each
  visitor's device decides), `light` or `dark`, and its theme, one of the eight presets in
  `authserver/internal/brandthemes`. The layouts write `data-theme` for light and dark alone, and
  link the brand's stylesheet after `main.css`: the auth server's pages by
  `brandthemes.StylesheetPath`, the console's by the `stylesheetUrl` `/api/public/settings` answers,
  which the console never builds. An auth server page takes the brand of the client its request
  names in `reqctx.PageClient`, its own or the default, and every other page the default (#812):
  `middleware.PageClient` puts an empty one on every page request, `middleware.SignInPageClient`
  names the client of the sign-in a step's request names on the step routes, ahead of their guards
  and limiters, and `/auth/authorize` names its client once the request reaches the client check.
  `/auth/logout` names the client of a confirmed hint or, with no hint, `client_id`, and none for a
  rejected hint; its declining link carries that `client_id` to `/auth/logout/declined`, which
  names it for the look alone. The no-longer-active page forgets it. `render.RequestPageBrand` reads it for both layouts and the
  form_post page. A page with no readable brand links none and is drawn automatic in the built-in
  colors. The stylesheet sets the 23 `--color-*` tokens, the dark ones under the two
  selectors `ui.css`'s dark variant uses, so a change to that variant changes `stylesheetCSS` too.
  Blueberry's declares no colors, since `ui.css` holds its values, which
  `TestThemeContrast_BlueberryIsBothCopiesOfUICSS` keeps equal to its preset; a token added to
  `ui.css` is added to every preset. A color is a token, `bg-surface`, `text-ink-muted`,
  `border-line`, never a raw value, and every pair a component draws text or a boundary on is in
  `TestThemeContrast_EveryPairMeetsWCAGAA`, at WCAG AA in both modes of every preset and 7:1 for
  High contrast's text.
- **Brand preview**: the brand editor (`admin_settings_branding_brand.html`) is two panes (#811),
  `brand-editor`: the form, and outside it the `brand-preview`, held in view beside the form from
  75rem and below it in a narrower window. The `brand_sample` partial draws a refused sign-in, once
  per mode, with the auth server's card components and, wherever the sign-in page has one, its own
  message; its fields, buttons and link are spans, and each sample is `inert`, `aria-hidden` and
  drawn `hidden`. `static/pages/brand-preview.js` reads every theme's palettes from the
  `brand-palettes` data block, sets the chosen theme's 23 tokens, the mode's `--shadow-panel` and
  `color-scheme` on each sample alone through the CSSOM (never a `style` attribute or the page's
  root), on every input and `pageshow`. The appearance decides what shows: Light or Dark its one
  sample with the Light/Dark switch hidden, Automatic (or no appearance it knows) the switch and
  the sample it names, and one `data-brand-preview-note` sentence saying which applies; the
  template draws the switch and sentences for the form's appearance. The switch on the heading's
  line, the sentences sharing one paragraph, the column's width and close spacing keep the whole
  preview on a 1280×800 screen beneath the header in every built-in language;
  `preview.spec.ts` measures it at 1280×800 and 1440×900, so check it there after adding to the
  preview. The script also redraws the
  three Appearance cards' swatches in the chosen theme: each `data-appearance-swatch` names its
  modes, one SVG each in order, and `brand_swatch`'s shapes name their tokens in `data-fill` and
  `data-stroke`; the theme cards' swatches keep their own theme. A form holding a theme the list
  lacks is previewed in the first listed one. The script keeps its own copy
  of `ui.css`'s two panel shadows, which `TestBrandPreviewJS_ShadowsAreUICSSs` holds equal, and
  `brand_preview_script_test.go` runs it under Node against a stand-in of the editor. The samples'
  colors are the theme's, under a forced palette too; the editor's own controls are held to the
  page's contrast requirement.
- **Components**: `page-header` with `page-eyebrow`, `page-title`, `page-lead` and `page-actions`;
  `panel`, `panel-body` (several, each under a `panel-title`, for a panel in sections),
  `panel-footer`; `button`, with `-primary` for a form's one main action, `-danger`, `-quiet`,
  `-sm`, `-icon` and `-block`; `field`, holding `field-label`, a `control`, `field-hint` and
  `field-error`; `input-row` for a control and the button acting on it; `choice`, `switch`,
  `option-card`, in an `option-grid` where cards reflow to their column's width, `check-list` of
  `check-row`; `detail-list`, a `dl` of a record's facts; `notice`
  with `-danger`, `-positive`, `-caution` or `-note`; `tag`; `table-scroll` around a `data-table`;
  `tab-bar` and `tab-item`, one underlined row while the tabs fit and rows of pills where they do
  not, which `shell.js` decides, so a bar never scrolls sideways; `pager`; `dialog`; `empty-state`;
  `spinner`; `text-link`. The auth server's card adds `auth-title`, `auth-lead`, `auth-status` with
  a `status-icon` (`-danger`, `-positive`, `-caution`, `-note`), `auth-actions` for two answers side
  by side, `auth-steps`, `auth-qr`, `secret-key` with `secret-key-row`, `code-hint`, `auth-address`,
  `auth-section-title`, `identity-row` and `link-list` of `link-row`; the console's pages without a
  menu (home, the error pages, sign-out) draw the same card. An uploaded image is an `image-upload`
  with an `image-preview` (`-square` for a logo), cropped in the `crop_dialog` partial: a
  `crop-area` the cropper draws in, and `crop-controls` whose `crop-slider`s do what dragging does,
  so a crop needs neither a pointer nor a drag.
- **Markup**: `core/guard.AssertWellFormedTemplates` holds every page to well-formed HTML and to the
  accessibility rules readable from a template: every element closed explicitly and in order, what a
  branch opens closed in it, quoted attributes, no nesting a browser repairs, a label for every
  control, alt on every image, a name on every link and button, one `<h1>`, no skipped heading
  level.
- **Scripts**: no executable script in a template, no `on…` attribute, no `javascript:` URL. The
  browser enforces it: both servers send `Content-Security-Policy: script-src 'self'; object-src
  'none'; base-uri 'none'; frame-ancestors 'none'` (`core/httpmw.SecurityHeaders`), which refuses
  inline code, `eval`, `<object>`/`<embed>` and `<base>`, so a page needing any of them breaks
  rather than being given a nonce, a hash or an exception. The one origin admitted beside `'self'`
  is Cloudflare's, for the Turnstile challenge (#642): while it is on, the auth server's sign-in,
  forgot-password and registration forms carry its widget, and each response drawing one of them
  through `turnstile.WithWidget` adds the constant `https://challenges.cloudflare.com` to
  `script-src` (`core/httpmw.SetContentSecurityPolicy`). Every other page, those three with the
  challenge off, and an error page replacing one of them, keep the policy above. Page
  behaviour lives in static files, `static/utils.js`, the console's `static/shell.js` and
  `static/pages/<page>.js`, attached with `addEventListener`. A template hands a script data in a
  JSON data block, `<script type="application/json" id="…">{{ . }}</script>`, or in `data-`
  attributes, and text by message ID: through `T`, except the console's `js.*` strings, which carry
  client-side placeholders and go through `i18n.Raw` in `JSBootstrap`. ES2020 at most, with no build
  step, for the declared floor: Chrome and Edge 111, Safari 16.4, Firefox 128.
  `core/guard.AssertScriptSyntax` parses every static script with acorn under Node, both pinned in
  `versions.yaml`, so each module's unit tier needs `node` on the path, as the dev container and the
  test jobs have it. The auth server's pages work with JavaScript off, except those three forms while the challenge
  is on, whose submission needs the token the widget's script writes; the console says it needs it.
  In both servers a button marked `data-password-toggle` shows and hides the password field its
  `aria-controls` names (each `utils.js`'s `passwordToggle`), and with JavaScript off it never shows.
  In the console a script answers an action in a live region the page draws empty, through
  `showNotice`, not in a dialog, its failures too (`sendAjaxRequest`'s `statusRegion`); a removal
  asks first in a `modal_dialog` of type `confirm`, whose second button names the action; a button
  marked `data-copy-target` copies, a page script may call `passwordToggle` on a show/hide button it
  reaches by id, so an operator's older template keeps working, a long `select` marked `data-searchable` becomes a `combobox`
  that filters as the person types, the select kept hidden to post the value, its field taking the
  select's `autocomplete` (`off` where it has none), turning `autocorrect` off, since a keyboard's
  correction fires the input event Firefox's fill does, and committing a browser's fill to the select,
  by option value, case aside, then by name, flag aside, or for `tel-country-code` by the one
  option whose `data-calling-code` it is, a fill naming nothing in a field without the focus
  putting the choice back, and leaving the field keeping the option its text names, an element marked
  `data-duration-for` says the seconds typed in a field as a duration, and a form marked
  `data-confirm-dialog` asks before a save whose consequences need saying, every one in one
  `modal_dialog` of type `confirm_change`, each from a control marked `data-confirm` against the
  value stored when the page was drawn (`data-stored-value`, `data-stored-checked`), as `shell.js`
  wires them; a form a script saves calls `confirmChanges`. A script that shows something following
  a control's value shows it again on `pageshow`, since a browser restoring the form, as on Back,
  fires no change, and a script asking the server about a choice drops an answer to any request but
  its latest, a failure included, through `sendAjaxRequest`'s `current`; one asking the server to
  validate values applies the values it sent, never the fields as they are when the answer arrives,
  and drops the answer once the person has typed past them. A row's own action, a removal or an
  addition saved at once, is a button marked `data-action-url`, which `static/pages/row-actions.js`
  posts, asking first when the button carries `data-confirm`; a search that finds users to add is
  `#userSearchForm`, which `static/pages/user-search.js` turns into a search as the person types and
  never lets submit.
- **Accessibility**: WCAG 2.2 AA on every page, in every state, appearance and theme. An error is a
  `notice-danger` with `role="alert"`, a success a `notice-positive` with `role="status"`; a table
  wider than its place scrolls inside `table-scroll`, a labelled region with `tabindex="0"`; an icon
  is `aria-hidden="true"`, and a button showing one alone carries `sr-only` text; targets are at
  least 24 pixels. The console's sticky header is `--app-header-height` tall, and
  `html:has(.app-header)` reserves that height plus 1.25rem as `scroll-padding-top`, so Tab,
  `focus()`, `scrollIntoView` and in-page links leave the element, focus ring included, below the
  header (SC 2.4.11). The gap is that wide because WebKit lines up a text field's caret, not its box,
  with the edge; change the header's height only through the property, and give anything else
  pinned over the page a scroll offset of its own. `focus-not-obscured.spec.ts` checks it in
  Chromium, Firefox and WebKit. A field collecting the person's own data declares its purpose
  (SC 1.3.5) with a token the HTML Standard allows on its control (Autofill, 4.10.19.7.1), and a
  control a script draws in place of another keeps the purpose of the one it replaces; a page about
  another user declares none, since autofill would fill in the administrator's own data. Every
  password field, in both servers, carries `spellcheck="false"`, `autocapitalize="none"` and
  `autocorrect="off"`, so a shown password reaches no spell-check service and no keyboard rewrites
  it (HTML Standard 6.8.5, 6.8.7, 6.8.8), and sits in an `input-row` beside its show/hide button: a
  `button type="button"`, drawn `hidden` so it never shows without JavaScript, marked
  `data-password-toggle`, with `aria-controls` naming the field. Its visible word is
  `adminconsole.password_toggle.show` in the console and `common.password_toggle.show` in the auth
  server, and, in `data-hide-label`, `hide`; its name, in `aria-label`
  and `data-hide-name`, is the `show_<kind>` and `hide_<kind>` pair of the field's kind, such as
  "Show new password", which contains the visible word in every catalog (SC 2.5.3); and
  `data-shown-status` and `data-hidden-status` carry the words the script writes into the
  `role="status"` region it adds beside the field. The name changes with the state, so the button
  has no `aria-pressed`. `ui.css` hides Edge's own reveal control beside a shown button. A refusal
  about one field marks it `aria-invalid="true"` and names the notice in its `aria-describedby`, under the same `{{if .error}}` the notice renders under, which the guard
  reads as one branch; a handler whose form has several fields says which in `errorField`, and in
  the console reads it off the admin API's error code through `render.ErrorField`, or, for the API's
  `VALIDATION_ERROR`, which names no field, the first required field sent blank through
  `render.ErrorFieldOrBlank`. No template rebinds `$`, which the guard refuses, since it reads `$`
  as the data the template was called with.
- **Page patterns**: every page is one of a few shapes, built the same way each time, and the first
  page of each shape is its reference. A list (`admin_users.html`): the page header with the main
  action, a GET search form if the list searches, a `data-table-stack` table whose first cell links
  to the record and whose last holds the row's other actions as links, a `notice` or `empty-state`
  for nothing found, and the paginator only past one page. A settings form
  (`admin_settings_sessions.html`): eyebrow, title and lead, one `panel` holding the notices at its
  top and the fields in a `form-grid`, each field's help visible under it, and Save in the
  `panel-footer`; a longer one (`admin_settings_general.html`) in sections, each a `panel-body`
  under a `panel-title`, and the settings a switch governs hidden while it is off rather than
  disabled (`admin_settings_email.html`). An action on the whole page that changes what is stored
  (`admin_settings_keys.html`, Rotate keys) is a form posted from `page-actions`, asked first in a
  `confirm_change` dialog, which answers with the page again. A choice among a few options
  (`admin_settings_branding_brand.html`, its appearance): `option-card`s in a fieldset with a legend; several of many
  (`consent.html`): a `check-list` of `check-row`s in a fieldset with a legend. A confirmation that
  deletes or removes says so on its buttons: "Cancel", and the action in `button-danger`. On the
  auth server, a form (`auth_pwd.html`): the title, an `auth-lead` saying what the page asks when
  the title does not, the notice at the top of the form, the fields, and one `button-block` primary
  button; a page that reports (`auth_error.html`): an `auth-status` with a `status-icon` in the
  outcome's tone, the title and the icon centered, the message left-aligned, an address it names in
  an `auth-address`, and at most one action, a `button-block`. A list whose rows a person ends or
  revokes (`account_user_sessions.html`): each row's button asks in a `confirm` dialog with the
  row's own sentence in `data-confirm`, and on success gives way to a `tag` saying so, which takes
  its focus unless the person moved it elsewhere meanwhile, while the page's live region says it
  too; a row added the same way from a search (`admin_groups_members_add.html`) acts at once, with
  no dialog, since one Remove undoes it. A home of destinations (the console's `index.html`): a
  `link-list`. A record with tabs (`admin_clients_settings.html`): a header linking back to the list
  in the eyebrow, the record's identifier as the title, the `tab-bar`, one partial per kind of
  record (`client_header`, `user_header`, `group_header`, `resource_header`), then each tab one
  `panel`, its sections `panel-body`s under a `panel-title`, its yes or no settings a `check-list`
  whose rows say what each does, and Save in the `panel-footer`. A create form
  (`admin_clients_new.html`): the same back link, title and lead, one `panel`, and Cancel beside the
  create action. A delete confirmation page (`admin_clients_delete.html`): a lead saying what the
  deletion takes with it, the record in a `detail-list`, its identifier typed to confirm, and Cancel
  beside the action in `button-danger`. A list edited in the page and saved whole
  (`admin_clients_redirect_uris.html`): a field and its Add in an `input-row`, refused at the field,
  the rows drawn as stored, each with a Remove naming its row, a change announced, and Save sending
  the list beside the list as drawn; where a row's Edit loads it into those fields
  (`admin_resources_permissions.html`), the row is marked `data-editing` while the edit lasts, its
  Edit giving way to a `tag` saying so. A new shape gets its reference page and a line here when its
  first page is built.
- **Wording**: the glossary's terms (`site/src/content/docs/concepts/glossary.mdx`): sign in and
  sign out, client, one-time code, two-factor authentication, auth server. Client and application
  are one thing with a name per reader. Wherever an administrator or a developer reads, the
  console's admin pages, the admin API's messages and the docs, it is a client, which is OAuth's
  word and the API's. Wherever the person signing in reads, the auth server's pages and the
  console's account pages, it is an application, since that person never registered one; a page
  quoting such a screen quotes it as it reads. No page calls it both, though a parameter's name,
  such as `client_id`, stays as it is. On an administrator's page "app" names a kind of software,
  such as a single-page app or a mobile app, and never a client: a sentence about what uses a client
  says that ("anything that signs in with this client"). Every sentence is true when it is read, its
  tense included: a question asked before an action says what will happen ("The key will be
  deleted"), a notice after it what was done, and help about standing behaviour the present.
  Sentence case; a button says what it does ("Save", "New user"); a page title reads "Page – app
  name". All built-in catalogs change together, a message ID is kept, and a renamed one goes in the
  release notes, since operators' override catalogs are keyed by it.
