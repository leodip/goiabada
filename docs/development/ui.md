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
  `authserver/internal/brandthemes` or `custom`, the brand's own palette (#815). The layouts write `data-theme` for light and dark alone, and
  link the brand's stylesheet after `main.css`: the auth server's pages by
  `brandthemes.StylesheetPath`, the console's by the `stylesheetUrl` `/api/public/settings` answers,
  which the console never builds. An auth server page takes the brand of the client its request
  names in `reqctx.PageClient`, its own or the default, and every other page the default (#812):
  `middleware.PageClient` puts an empty one on every page request, `middleware.SignInPageClient`
  names the client of the sign-in a step's request names on the step routes, ahead of their guards
  and limiters, and `/auth/authorize` names its client once the request reaches the client check.
  `middleware.LinkedSignInPageClient` does the same on forgot password, registration, activation
  and password reset, from the well-formed `ceremony` parameter of their URL on a GET and a POST
  alike, while the browser holds that sign-in; the password page's links to the first two carry it,
  the activation and reset links mailed from them carry it through their first hop, and a refused
  reset link's Request a new link carries it back to forgot password.
  `/auth/logout` names the client of a confirmed hint or, with no hint, `client_id`, and none for a
  rejected hint; its declining link carries that `client_id` to `/auth/logout/declined`, which
  names it for the look alone. The no-longer-active page forgets it. `render.RequestPageBrand` reads it for both layouts and the
  form_post page. Every console page takes the brand of the console's own client, its own or the
  default, which `/api/public/settings` answers through `render.ClientPageBrand`. The console drops
  its cached copy when its client's Brand select is saved and on every Branding write, so its pages
  change at once; a change made through the admin API alone reaches them when the cache expires. A page with no readable brand links none and is drawn automatic in the built-in
  colors. A brand has two stylesheets (#813 decision 9): the full one, which the auth server's pages
  link, and the colors-only one at `brandthemes.ColorsStylesheetRoute`, which
  `/api/public/settings` names as `colorsStylesheetUrl`. Both set the 23 `--color-*` tokens, the
  dark ones under the two selectors `ui.css`'s dark variant uses, so a change to that variant
  changes `stylesheetCSS` too. A custom brand's two stylesheets set its stored palette's 23 colors
  of each mode as a preset's are (`brandthemes.ColorsStylesheet`), built on each request with no
  color math: a basic palette's other 19 are worked out once, at the save, and stored, so a page
  draws exactly what the warnings describe (#815 decision 1). A stored palette missing a token or
  holding a value that is not `#rrggbb` names no stylesheet and is logged, as an unknown theme is,
  so no value reaches a stylesheet unless it is a color. The full one then sets the tokens the brand's corners and system
  family change, `--radius-control`, `--radius-panel` and `--font-sans`, and none for rounded and
  System UI, which are `ui.css`'s. A box that may hold more than one line is rounded by
  `--radius-box`, `--radius-control` capped at 1rem, so pill corners round a single-line control
  fully and leave such a box's content unclipped; draw a new multi-line component with it. The
  radii and family lists are `core/brandkit`'s, which the console's editor sample draws from too.
  The full one also draws the kit's files, read from the brand's six asset slots without their
  bytes (`brandasset.ReadSlots`): the uploaded font as `brandkit.UploadedFontFamily`, one
  `@font-face` per file with `font-display: swap`, followed by System UI, and the background image
  on `.auth-page`, the card pages' box around their `<main>` (`.auth-main`) and their footer, over
  the theme's background color at the brand's fit.
  A card page draws the brand's logo in `.auth-logo` above the app name (the auth server's two
  layouts and `form_post.html`, the console's `partials/brand_logo.html`), the dark logo on a
  dark page and in a `<picture>` switching to it under `prefers-color-scheme: dark` on an automatic
  one, and its alt is empty while the name shows as text
  and the app name while `hideAppName` hides it, so a screen reader says the name once. A page
  whose brand has a favicon links it as `icon` and `apple-touch-icon` and drops `favicon.ico` and
  the manifest. The console tells an admin page, one whose `menu` template calls `admin_menu`
  (`render.drawsAdminMenu`), from an end-user page: an admin page links `colorsStylesheetUrl` and
  keeps Goiabada's icons, and every other console page, Account, home and every card page, links
  `stylesheetUrl` and the brand's favicon. Both draw the logo, in the header's and the sidebar's
  link to home on a menu page.
  Blueberry's declares no colors, since `ui.css` holds its values, which
  `TestThemeContrast_BlueberryIsBothCopiesOfUICSS` keeps equal to its preset; a token added to
  `ui.css` is added to every preset, to `core/palette`'s `Tokens` and `Derive`, and to the brand
  editor's Colors groups and their catalog labels. A color is a token, `bg-surface`,
  `text-ink-muted`, `border-line`, never a raw value, and every pair a component draws text, a
  boundary or the focus ring in is in `core/palette`'s shared list (`palette.Pairs`), once, at its
  minimum: 4.5:1 for text (WCAG 2.2 SC 1.4.3) and 3:1 for a boundary or the focus ring (SC 1.4.11).
  `TestThemeContrast_EveryPairMeetsWCAGAA` holds every preset to the list in both modes, and High
  contrast's text to 7:1 besides. A custom brand's `contrastWarnings` and the editor's live list are
  `palette.Check` against the same list, for the modes the appearance draws, so a pair added for a
  new component reaches every saved brand's warnings without a save.
  `TestThemeContrast_BasicPaletteRebuildsTheBuiltInThemes` rebuilds each preset but High contrast
  from its four colors with `palette.Derive` and holds the result to no failing pair and to within
  0.05 in OKLab of the hand-made colors, so a change to the derivation is measured against them.
- **Outside the card**: the card is opaque, and the brand's background image sits behind it
  (#813 decision 6). What is drawn outside the card, today the brand's footer (#814), is small
  `text-ink-muted` and link text straight on the page's `bg-canvas`, and sits on its own opaque
  panel in `bg-surface` only while the brand has a background image, whatever its fit and whether
  or not the image loads (`.brand-footer-panel`): an uploaded image's colors are unknown, so text on
  it, or on a translucent layer over it, has no contrast a test can hold, while both backgrounds
  are pairs `TestThemeContrast_EveryPairMeetsWCAGAA` checks. Draw nothing else outside the card
  without one of those two backgrounds. The footer is the page's `footer` landmark after `main`
  (`.auth-main`), straight under the card: the links in a `ul`, then "Need help?" and the contact
  in a `p`, each link underlined and a 24-pixel target, wrapping rather than clipping. The auth
  server's two layouts and `form_post.html` draw it from `render.FooterOf`, bound as `brandFooter`
  only for a brand with links or a contact, so a brand with neither is drawn as it was;
  `form_post.html`, parsed without template functions, takes its words in its data. The console
  draws it from the public settings' brand on every end-user page through the `brand_footer`
  partial: under the card on a card page, panel included from `hasBackground`, and on an Account
  page after `main` as `.app-footer`, in the content column's gutters and never on a panel; an
  admin page binds no `brandFooter`. Each link's label is picked by `brandkit.FooterLinkLabel`
  for the catalog the page's `lang` names, the support address linked through
  `brandkit.MailtoAddress`.
- **Brand preview**: the brand editor (`admin_settings_branding_brand.html`) is two panes (#811),
  `brand-editor`: the form, and outside it the `brand-preview`, held in view beside the form from
  75rem and below it in a narrower window. The `brand_sample` partial draws a refused sign-in, once
  per mode, with the auth server's card components and, wherever the sign-in page has one, its own
  message; its fields, buttons and link are spans, and each sample is `inert`, `aria-hidden` and
  drawn `hidden`. Each sample holds two views (#815 decision 10), named by `data-brand-sample-view`:
  the sign-in card with the footer under it, and the Messages card (`brand-sample-messages`), which
  draws the positive, caution and note notices with a link in the last two, a hovered link row, a
  selected item, a focused field, and the primary and danger buttons at rest and hovered, so
  between them the two views draw all 23 colors. Nothing in an inert sample can be hovered or
  focused, so `brand-sample-hover` and `brand-sample-focus` mark those states and `ui.css` draws
  them as the components' `:hover` and `:focus-visible`; a change to either rule changes both. The
  Sign-in/Messages switch (`brandPreviewView`) sits on the heading's line, outside the form, for
  every theme and appearance, and the Messages card is no taller than the sign-in one.
  `static/pages/brand-preview.js` reads every theme's palettes from the
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
  lacks is previewed in the first listed one. Custom is drawn from the Colors section's fields, each
  a token itself, so an entered color shows at once with no request; a value that is not `#rrggbb`
  is never set on a sample, which keeps the color it was drawn in. Editing a Colors field puts the
  switch on that field's mode under Automatic, and the Custom card's swatch draws the palette being
  edited. The script keeps its own copy
  of `ui.css`'s two panel shadows, which `TestBrandPreviewJS_ShadowsAreUICSSs` holds equal, and
  `brand_preview_script_test.go` runs it under Node against a stand-in of the editor. The samples'
  colors are the theme's, under a forced palette too; the editor's own controls are held to the
  page's contrast requirement. The samples take the kit as the form holds it too (#813): the
  corners' radius tokens, the family's `--font-sans`, each fit's background layout and the two
  font files' weights from the `brand-kit-styles` data block, which the page writes from `core/brandkit`, so a sample never draws
  a shape, family or fit the saved brand would draw otherwise; Rounded and System UI are handed
  nothing and keep the console's tokens. `ui.css` reads `--radius-box` and the font on
  `.brand-sample`, as `:root` does on a page. The files come from each slot's two hidden fields,
  its asset's id and URL, which `static/pages/brand-assets.js` fills as a file is uploaded to the
  console's route of its kind and empties on Remove; Save names the held ids in their slots. The
  sample draws the logo of its mode, the background at its fit and the uploaded font, whose
  `@font-face` rules the script writes as the auth server's stylesheet does into a stylesheet the
  page adopts: a `FontFace` cannot leave the weight automatic, so a variable font would be pinned to
  400. The favicon is a thumbnail beside its field. Under its card the sample draws the footer from
  the form's footer fields (#814 decision 12), as `FooterOf` would: each row's label in the
  language of the console page, the phone number without its separators, "Support page" for the
  URL and the panel while a background is held, with the links as spans since the sample is inert.
  To keep the preview on a 1280×800 screen with a logo, the app name and a footer of three links
  and the whole contact in it, in WebKit too, the sample's card takes closer padding and spacing
  and caps its logo at 2rem, and then the whole sample is drawn at `zoom: 0.9`, which keeps every
  length the brand sets in proportion; none of the parts #811 lists is left out to make room. A
  footer with very long values may still wrap past the screen. The footer fields are the form's
  last and the footer the sample's last, so the part being edited is the part kept in view.
- **Colors section**: picking the Custom card shows `brand-palette` under the theme cards (#815
  decisions 7 and 8): Basic and Advanced (`paletteMode`), and a row per color with a Light and a
  Dark cell, each a color well beside the text field the form submits, `palette-<mode>-<token>`.
  The wells and Copy colors from need the script and are drawn hidden; everything else works with
  scripts off. Basic shows the four rows of `palette.BasicTokens`, Advanced all 23 in four groups
  with their token names. Both columns are always submitted, and the one the appearance does not
  draw is hidden with a line saying its colors are kept, except while one of its fields holds a
  value that is not a color: it then stays shown with a line saying its colors must be valid, and
  the server applies the same rule when it redraws a refused form, so a refusal is never on a
  hidden field. `static/pages/brand-palette.js` keeps the section in step with the form, and posts
  it to the console's `/admin/settings/branding/palette-check` (`HandleBrandPaletteCheckPost`),
  which answers each mode's 23 colors and the failing pairs from `core/palette`, the code the auth
  server saves with (#815 decision 6). Never copy the color math into a script: two languages'
  floating point need not agree at a contrast threshold, and the preview would list pairs the save
  does not. A typed edit waits for a pause, a choice asks at once, and only the answer to the
  latest request is drawn; a basic palette's answer fills the other 19 fields and fires `input` on
  the section, which `brand-preview.js` draws. When the route cannot be reached the count line says
  the colors could not be checked, and the save is unaffected. The list at the section's foot
  (`palette-warnings`) is a count line, the one `role="status"` part, so an edit announces the
  count and not the list, over an item per pair with a swatch of the pair. After a save the server
  draws it from the brand's `contrastWarnings`, and the saved notice links to it. The script notes
  the form a list describes, the one the page was drawn with (`defaultValue`, `defaultChecked`)
  when the server drew a list, then each answer's; on load and on `pageshow` it asks at once for a
  custom form that is not that one, a refused form or one a browser restored. A basic palette is
  sent as one, as its save works it out, unless its other 19 are known to be worked out from its
  four as they stand: a saved basic palette's while its four are the ones drawn, or an answer's.
  Then the check sends the 23 fields as they stand and draws only the list, so a saved basic
  palette's stored worked-out colors are kept. A refused form's other 19 are never known, since
  an edit the check could not reach leaves them worked out from earlier colors.
  `brand_palette_script_test.go` runs the script under Node. Page text about the check says what it
  establishes, which pairs meet the two minimums, and never that a palette or a page meets WCAG
  (decision 11).
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
  menu (home, the error pages, sign-out) draw the same card. Under it, `brand-footer` (with
  `-panel` over a background image, and `app-footer` on an Account page) holds `brand-footer-links`
  and `brand-footer-contact` of `brand-footer-link`s. A form's group among several of its kind is a
  `footer-link` fieldset, and what it holds out of sight a `details` `disclosure`. An uploaded image is an `image-upload`
  with an `image-preview` (`-square` for a logo), cropped in the `crop_dialog` partial: a
  `crop-area` the cropper draws in, and `crop-controls` whose `crop-slider`s do what dragging does,
  so a crop needs neither a pointer nor a drag.
- **Styling contract**: what CSS written for the pages can rely on from release to release (#816),
  published on the docs' Styling contract page, which `stylingcontract_docs_test.go` holds to the
  lists in `core/stylingcontract`: 28 variables, a `data-page` value per page and 45 hook classes,
  each promised on the server whose pages draw it. Every auth server page and every console
  end-user page (the Account pages, and the cards: home, the error pages and sign-out) defines `{{define "data-page"}}<value>{{end}}` beside its title, one value per template whatever
  state it is drawn in, a console one beginning `account-` or `console-`. The renderers read it
  through `stylingcontract.PageName` and bind `dataPage`, which all four layouts write on `<body>`;
  `form_post.html`, parsed alone, writes its own. The admin pages and `settings_unavailable.html`
  define none and carry none. `core/guard.AssertStylingContract` holds both servers' templates to
  the lists in their unit tiers, so a new end-user page needs a value added to the list and to the
  reference page, and removing or renaming a listed variable, value or hook class, or no longer
  drawing a hook class on a server it is promised on, needs the list, the page and the release
  notes changed with it. Tailwind utilities and a class one page draws are never promised.
- **Markup**: `core/guard.AssertWellFormedTemplates` holds every page to well-formed HTML and to the
  accessibility rules readable from a template: every element closed explicitly and in order, what a
  branch opens closed in it, quoted attributes, no nesting a browser repairs, a label for every
  control, alt on every image, a name on every link and button, one `<h1>`, no skipped heading
  level. A link that opens a new tab says so to assistive technology (WCAG technique G201, #814
  decision 13): `target="_blank"` with `rel="noopener noreferrer"`, and
  `<span class="sr-only"> {{ T $.ctx "common.link.opens_in_new_tab" }}</span>` after its text,
  inside the link, so it is part of the link's name and nothing visible moves;
  `core/guard.AssertTemplatesNewTabLinksSaySo` refuses a template whose `target="_blank"` link
  lacks it. `form_post.html` carries the text in its data, as `$.page.NewTabNotice`.
- **Scripts and styles**: no executable script in a template, no `on…` attribute, no
  `javascript:` URL, no `<style>` element and no `style` attribute. The browser enforces it: the
  auth server sends `Content-Security-Policy: script-src 'self'; style-src 'self'; img-src 'self'
  data:; font-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'`
  (`core/httpmw.SecurityHeaders`), which refuses inline code, `eval`, inline styles,
  `<object>`/`<embed>`, `<base>`, and any stylesheet, image or font from another site, so a page
  needing any of them breaks rather than being given a nonce, a hash or an exception. The console
  sends the same policy with the auth server's public origin, from `GOIABADA_AUTHSERVER_BASEURL`,
  beside `'self'` in `style-src`, `img-src` and `font-src`, for the brand's stylesheets, pictures
  and font, the client logos and the user pictures it loads from there (#816 decision 5). A
  script sets a style through the CSSOM (`element.style`, a constructed stylesheet), which the
  policy admits; never with `setAttribute("style", …)` or a script-made `<style>`, which it
  refuses. An image the page makes itself, such as the QR code or the picture being cropped, is a
  `data:` URL. The one origin admitted beside `'self'`
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
  `render.ErrorFieldOrBlank`. A refusal about one member of a list item carries the admin API's
  `error_field` (see the conventions guide), which `render.ErrorPointer` reads into reference
  tokens and the handler maps to the input's id, such as `footerLinks-1-url`. No template rebinds `$`, which the guard refuses, since it reads `$`
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
  Edit giving way to a `tag` saying so. A short list of items with several fields each, saved
  with its form (the brand editor's footer links, #814 decision 11): as many fixed rows as the
  list's cap, each a `footer-link` fieldset whose legend numbers it, its fields named
  `<list>-<index>-<field>`, and what most rows leave empty, such as a label per language, in a
  closed `disclosure` drawn open while it holds the refused field. An empty row is no item, the
  items keep the rows' order with the empty ones skipped, and a refused form is drawn again in
  that order. It needs no script or focus handling, and is restored by
  the browser on Back; use Add and Remove only for a list too long to draw whole. A new shape gets its reference page and a line here when its
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
