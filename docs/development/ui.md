# UI development

Change templates, static scripts and translations using the existing design system.

Paths in backticks are relative to the repository root unless a module directory is named. Read the
sections relevant to the change; [AGENTS.md](../../AGENTS.md) lists the common commands.

Both servers draw their pages with `ui.css`, Goiabada's design tokens and components, and Tailwind
utilities for layout (#617). The file is one copy in each application's `web/tailwindcss/`, which
`TestUICSS_IsTheAuthServersCopy` holds byte-identical; edit one, copy it over the other, and
regenerate both `main.css`. Every class a page names has a rule in the served `main.css`
(`core/guard.AssertClassesAreDrawn`), so a misspelt or leftover class fails the unit tier.

- **Themes**: automatic (the settings' empty value: each visitor's device decides), light and dark.
  The layouts write `data-theme` for light and dark alone. A color is a token, `bg-surface`,
  `text-ink-muted`, `border-line`, never a raw value, and every pair a component draws text or a
  boundary on is in `TestThemeContrast_EveryPairMeetsWCAGAA`, at WCAG AA in both themes.
- **Components**: `page-header` with `page-eyebrow`, `page-title`, `page-lead` and `page-actions`;
  `panel`, `panel-body` (several, each under a `panel-title`, for a panel in sections),
  `panel-footer`; `button`, with `-primary` for a form's one main action, `-danger`, `-quiet`,
  `-sm`, `-icon` and `-block`; `field`, holding `field-label`, a `control`, `field-hint` and
  `field-error`; `input-row` for a control and the button acting on it; `choice`, `switch`,
  `option-card`, `check-list` of `check-row`; `detail-list`, a `dl` of a record's facts; `notice`
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
  rather than being given a nonce, a hash or an exception. Page
  behaviour lives in static files, `static/utils.js`, the console's `static/shell.js` and
  `static/pages/<page>.js`, attached with `addEventListener`. A template hands a script data in a
  JSON data block, `<script type="application/json" id="…">{{ . }}</script>`, or in `data-`
  attributes, and text by message ID: through `T`, except the console's `js.*` strings, which carry
  client-side placeholders and go through `i18n.Raw` in `JSBootstrap`. ES2020 at most, with no build
  step, for the declared floor: Chrome and Edge 111, Safari 16.4, Firefox 128.
  `core/guard.AssertScriptSyntax` parses every static script with acorn under Node, both pinned in
  `versions.yaml`, so each module's unit tier needs `node` on the path, as the dev container and the
  test jobs have it. The auth server's pages work with JavaScript off; the console says it needs it.
  In the console a script answers an action in a live region the page draws empty, through
  `showNotice`, not in a dialog, its failures too (`sendAjaxRequest`'s `statusRegion`); a removal
  asks first in a `modal_dialog` of type `confirm`, whose second button names the action; a button
  marked `data-copy-target` copies, a long `select` marked `data-searchable` becomes a `combobox`
  that filters as the person types, the select kept hidden to post the value, an element marked
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
- **Accessibility**: WCAG 2.2 AA on every page, in every state and both themes. An error is a
  `notice-danger` with `role="alert"`, a success a `notice-positive` with `role="status"`; a table
  wider than its place scrolls inside `table-scroll`, a labelled region with `tabindex="0"`; an icon
  is `aria-hidden="true"`, and a button showing one alone carries `sr-only` text; targets are at
  least 24 pixels. A refusal about one field marks it `aria-invalid="true"` and names the notice in
  its `aria-describedby`, under the same `{{if .error}}` the notice renders under, which the guard
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
  (`admin_settings_ui_theme.html`): `option-card`s in a fieldset with a legend; several of many
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
