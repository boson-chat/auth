# Network branding and emails

auth publishes the network's theme (boson-theme/1) for clients, and renders
its emails with the network's logo, colour, sender name, footer and wording.
Both come from the [stack config file](../README.md#stack-config-file)
(`BOSON_CONFIG`) and reload live. Without the file, or without the sections
below, there is no branding (`GET /v1/branding` → 404) and the emails are
Boson's built-in ones, byte for byte.

## Config file

```yaml
version: 1
branding:
  theme:                          # boson-theme/1, without image URLs
    base: dark                    # dark | light (default dark)
    colors: { accent: "#7c3aed", bg: "#0b0b10" }   # THEME_TOKENS keys, #rrggbb
    nick: { saturation: 62, lightness: 64 }        # integers 0–100
    radius: 2                     # integer 0–12
    font: boson                   # boson | system
    panes:                        # servers | channels | messages | members
      servers:  { bg: "#0b0b10" }
      channels: { bg: "#111118", dim: 0.6, blur: 0 }
      messages: { dim: 0.7, blur: 8, position: center }   # dim 0–1, blur 0–24 px
  images:                         # files in the branding directory
    logo: logo-3f2a.svg           # square-ish mark
    logo_wide: wordmark-91bc.png  # optional wordmark (headers, emails)
    login_background: login-77de.webp
    panes.messages.image: messages-0a1b.webp       # panes.<pane>.image
auth:
  email:                          # present (even {}) = branded layout
    sender_name: "Example Chat"   # display name of SMTP_FROM; header text without a logo
    accent: "#7c3aed"             # the button and links (default #d97706, Boson amber)
    footer: "Example Chat · example.com"           # small print under the card; URLs linkified
    logo: true                    # show the branding logo (logo_wide, else logo; raster before SVG)
    templates:                    # any subset; absent = Boson's wording
      verification:   { subject: "Confirm your {{network}} account", body: "Hi {{username}},\n\n{{link}}\n\nExpires in {{expires}}." }
      password_reset: { subject: "…", body: "…" }
      account_setup:  { subject: "…", body: "…" }
      invite:         { subject: "…", body: "…" }
    layout:                       # optional: your own MJML layout (raw MJML editing)
      mjml: emails/layout-5e6f.mjml   # MJML source, kept for re-editing (optional)
      html: emails/layout-5e6f.html   # compiled HTML: what auth renders
    # A template can be replaced as a whole document, too:
    #   invite: { subject: "…", mjml: emails/invite-7a8b.mjml, html: emails/invite-7a8b.html }
```

**Branding directory.** `BOSON_BRANDING_DIR`, by default `branding` next to
the config file (`/config/branding` in the stack). The admin panel writes
the images there as `<slot>-<hash>.<ext>` *before* it writes the config file
that names them, and removes old files afterwards. auth reads only the files
the config names, through `os.Root` (no `..`, absolute paths or symlinks out
of the directory), when the config is loaded. Replacing a file's bytes under
the same name is not picked up until the config file itself changes, so
always use a new name.

**Validation** (the boson-theme/1 rules; errors carry line and column and
keep the last good config, like every other key):

- colours are `#rrggbb` (stored lower case); `base` dark|light; `font`
  boson|system; `radius` 0–12; `nick.*` 0–100; `dim` 0–1; `blur` 0–24;
  `position` center|top|bottom|left|right.
- unknown keys (colour tokens, panes, fields, templates) are dropped and
  logged.
- image URL keys in the theme (`logo`, `panes.*.image`, …) are errors: images
  are files listed in `branding.images`.
- image file names are plain names (`[A-Za-z0-9][A-Za-z0-9._-]*`, ≤ 128) with
  a .png .jpg .jpeg .webp .gif or .svg extension. The file must exist, be at
  most 2 MB, have the type its extension says (sniffed, not trusted), and
  rasters at most 4096 px on a side. An SVG must be XML with an `<svg>` root.
- the rendered document is at most 16 KB.
- `sender_name` one line ≤ 100; `footer` ≤ 500; `subject` one line ≤ 200;
  `body` ≤ 10 000, not blank.

Audited as `config_reloaded` with the changed keys: `branding.theme`,
`branding.images.<slot>`, `auth.email.<field>`,
`auth.email.templates.<name>.subject|body|mjml|html`,
`auth.email.layout.mjml|html`.

## `GET /v1/branding`

Public, `Access-Control-Allow-Origin: *` (no credentials; preflights for
`If-None-Match` are answered), `Cache-Control: public, max-age=60`, `ETag`
(changes whenever the theme or any image's bytes change) and
`If-None-Match` → 304. 404 `no_branding` when nothing is configured.

```json
{
  "version": 1,
  "base": "dark",
  "colors": { "accent": "#7c3aed", "bg": "#0b0b10" },
  "nick": { "saturation": 62, "lightness": 64 },
  "radius": 2,
  "font": "boson",
  "panes": {
    "messages": { "image": "https://auth.example.com/v1/branding/assets/messages-0a1b.webp?v=1f2e3d4c5b6a7980", "dim": 0.7, "blur": 8, "position": "center" },
    "servers": { "bg": "#0b0b10" }
  },
  "logo": "https://auth.example.com/v1/branding/assets/logo-3f2a.svg?v=0a1b2c3d4e5f6071",
  "logo_wide": "https://auth.example.com/v1/branding/assets/wordmark-91bc.png?v=…",
  "login_background": "https://auth.example.com/v1/branding/assets/login-77de.webp?v=…"
}
```

`version` and `base` are always present; every other field only when set.
Image URLs are absolute (`PUBLIC_URL`) with `?v=` = the first 16 hex digits
of the file's SHA-256. `GET /v1/config` has `branding_url` (this URL, or
`null` without branding).

## `GET /v1/branding/assets/{file}`

Only files the current branding references, served from memory. `ETag` =
the hash; `Cache-Control: public, max-age=31536000, immutable` when `?v=`
matches, `public, max-age=300` otherwise. `Content-Type` from the
extension, `X-Content-Type-Options: nosniff`,
`Cross-Origin-Resource-Policy: cross-origin`, CORS `*`. SVGs get
`Content-Security-Policy: default-src 'none'; style-src 'unsafe-inline'`.
Anything else is 404.

## Emails

Templates: `verification`, `password_reset`, `account_setup`, `invite`
(auth itself sends no invite emails yet; the template exists for previews
and tests, and for when it does).

Variables: `{{network}}` (network.name / SITE_NAME), `{{username}}`,
`{{link}}`, `{{expires}}` ("24 hours"), `{{inviter}}`. Spaces inside the
braces are allowed (`{{ link }}`); anything else in braces stays as typed.

The body is plain text: blank lines separate paragraphs, single line breaks
are kept, `http(s)://` URLs become links (no other scheme is ever a link),
and a paragraph that is only `{{link}}` becomes the action button ("Confirm
email", "Choose a new password", …). Paragraphs after the button are set
as small print (the expiry line). All template text and every value is
HTML-escaped, so a template can't inject markup. The plain-text part is the
prompt line (`$ verify --email`), the body with the variables filled in
(the action link under the button's label, `Confirm email:` then the URL),
then `-- ` and the footer.

### Layout (MJML)

With `auth.email` present, the HTML part is built from
[`templates/layout.mjml`](../internal/services/email/templates/layout.mjml)
with [MJML](https://mjml.io/). It is compiled at build time, not by the
server: `go generate ./internal/services/email` runs
[`gen`](../internal/services/email/gen/main.go), which compiles it with
[mjml-go](https://github.com/Boostport/mjml-go) (MJML as WebAssembly on
wazero: pure Go, no Node), into `templates/compiled/layout.html` and
`layout-footer.html`. Those are committed and embedded. CI regenerates them
and fails on any difference, and checks that the server binary doesn't
link mjml-go. MJML produces the table layout and Outlook conditional
comments that Gmail, Outlook and Apple Mail need.

After editing `layout.mjml` (or the palette in `layout.go`), run
`go generate ./internal/services/email` and commit the compiled files with
it.

- Boson's terminal look: a 600 px card (1 px border, 2 px radius) on a
  near-black page; above it the logo (40 px high, at most 240 px wide,
  with explicit `width`/`height` for Outlook) or the sender name in
  monospace; in the card a prompt line (`$ verify --email`,
  `$ reset --password`, `$ setup --account`, `$ join --invite`; not
  configurable), the subject as the heading, the body, the button, the
  small print after it, and under a hairline the link as a fallback
  ("Button not working? Paste this link into your browser"); under the
  card the footer and a quiet "Powered by Boson" line.
- The accent is used only where it means something: the button (its label
  `#ffffff` or `#070709`, whichever contrasts more) and links (the accent
  when it reads at 4.5:1 on the dark card, else the heading colour). There
  is no decorative accent bar.
- Fonts: JetBrains Mono for the prompt, heading, button and links' URLs,
  Inter for the body, each followed by system fonts (`ui-monospace,
  SFMono-Regular, Menlo, Consolas, monospace`; `-apple-system, Segoe UI,
  Roboto, Helvetica, Arial, sans-serif`), as web fonts can't be relied on;
  Outlook for Windows gets Consolas and Segoe UI. No web fonts are loaded.
  A hidden inbox preview line (the start of the body, without the link).
- Dark first: the inline colours are Boson's Terminal theme (page
  `#070709`, card `#0d0d11`), which clients without media queries show.
  `color-scheme: dark light` and `prefers-color-scheme: light` rules (Apple
  Mail, iOS Mail, Outlook for Mac) switch to the Daylight theme;
  `[data-ogsc]` / `[data-ogsb]` rules keep the dark colours when
  Outlook.com recolours for its dark mode. Every text colour reads at
  4.5:1 or better on its page and card in both (`TestPaletteContrast`), and
  stays readable when a client inverts the email.
- The logo is the wordmark, else the mark; PNG / JPEG / GIF before WebP
  (Outlook for Windows shows no WebP) before SVG (Gmail and Outlook show
  no SVG).

**Performance.** When the email service starts, the two compiled variants
(with and without a footer) are cut into an HTML skeleton with slots (under
1 ms). Sending or previewing an email only fills the slots: about 10 µs per
email (`go test -bench Preview ./internal/services/email`). Config reloads
change nothing in the skeleton: the accent, logo, sender name, footer and
wording are all slot values.

**Escaping.** Nothing user-supplied is ever given to MJML. Each slot has
one rule, applied when it is filled: text (subject, button label, preview
line) is HTML-escaped; URLs (button, logo) must be `http(s)` and are escaped
(anything else becomes `#` / no logo); colours must be `#rrggbb`; and the
body, header and footer slots take only HTML this package built from
escaped text.

**Goldens.** `internal/services/email/testdata/legacy` is the built-in
emails (byte for byte); `testdata/branded` is the MJML layout. After an
intended layout change: `go test ./internal/services/email -run Golden
-update`, and look at the samples (`EMAIL_SAMPLES_DIR=/tmp/x go test
./internal/services/email -run WriteSamples` writes them as HTML files).

### Custom MJML (layout and whole emails)

An admin can replace Boson's layout with their own MJML, and replace any
email as a whole document. The admin panel compiles the MJML in the
browser (`mjml-browser`); auth never runs MJML on it, it only renders the
compiled HTML.

**Files.** `auth.email.layout.{mjml,html}` and
`auth.email.templates.<name>.{mjml,html}` name files in the emails
directory: `BOSON_EMAILS_DIR`, by default `emails` next to the config file
(`/config/emails` in the stack). A name is a plain file name
(`[A-Za-z0-9][A-Za-z0-9._-]*`, ≤ 128, `.mjml` / `.html`), optionally
written with the `emails/` prefix; `html` is required, `mjml` is the source
kept for re-editing. Files are read through `os.Root` (no `..`, absolute
paths or symlinks out of the directory) when the config is loaded, must be
regular files of at most 512 KB, and are reloaded with the config file;
as with images, write new files under new (hashed) names, then the config.
A missing, oversized or invalid file is a config error at the file name's
line and column (placeholder errors also give the line and column inside
the HTML file) and the last good config stays.

**Placeholders**, written `{{name}}` (spaces inside the braces allowed):

| Placeholder | Where | Filled with |
|---|---|---|
| `{{content}}` | layout only, exactly once, in body text | the body: paragraphs and the button, HTML auth builds from escaped text |
| `{{subject}}` `{{network}}` `{{username}}` `{{inviter}}` `{{expires}}` `{{footer}}` `{{sender_name}}` | anywhere | text |
| `{{link}}` | anywhere; a whole email must contain it | the action URL (http(s) only, else `#`) |
| `{{logo_url}}` | anywhere | the email logo's URL (http(s); empty without a logo or with `logo: false`) |
| `{{accent}}` | anywhere | the accent, always `#rrggbb` |
| `{{accent_text}}` | anywhere | text on the accent (a button label): `#ffffff` or `#070709`, whichever contrasts more |

In a whole-email override the document is the admin's: it is not wrapped in
the layout, and `{{content}}` is not available (it stays as written, with a
warning). An unknown `{{x}}` stays as written, with a warning in the
preview (and in auth's log on reload).

**Escaping.** The placeholders are found once, when the file is loaded,
with an HTML tokenizer that notes each one's context, and filled in a
single pass (a value is never scanned for placeholders, so a username of
`{{content}}` is just text):

- body text, `<title>`, comments and ordinary attributes: HTML-escaped,
  quotes included; unquoted attribute values also escape spaces, `=` and
  `` ` ``. Outlook's conditional comments (`<!--[if mso]>…<![endif]-->`) are
  scanned as the markup they are.
- URL attributes (`href`, `src`, `background`, …): `{{link}}` /
  `{{logo_url}}` at the start of the value as they are (http(s) only),
  attribute-escaped; anything else in a URL (a text placeholder, or a URL
  inside a query string) is percent-encoded, so it can't add a scheme.
- CSS (`style` attributes and `<style>`): `{{accent}}`; URLs
  percent-encoded except URL characters that can't end a string, `url()`
  or declaration; text placeholders keep only letters, digits, spaces and
  `. , - _ # %` (with a warning).
- `<script>` and `on*` attributes, and inside a tag outside any attribute
  value: left out (with a warning); `{{accent}}` only in scripts.
- `{{content}}` must be in body text (not in an attribute, `<title>`,
  CSS, a script or a comment), or the file is rejected.

**Plain-text part.** With a custom layout: the body with the variables
filled in, then `-- ` and the footer (no prompt line). With a whole-email override: the template's body if
one is set; otherwise text generated from the HTML (head, styles, scripts
and hidden elements such as the preview line left out; block elements and
`<br>` as line breaks; links as `text (url)`).

**Default MJML.** `GET /internal/email/default-mjml?part=…` (below) is the
starting point: `templates/layout.mjml` with its build-time slots as
placeholders (`{{subject}}` title and heading, `{{sender_name}}` header,
`{{accent}}` link colour, `{{content}}` body, `{{footer}}` footer, and
`$ mail` as the prompt line; no inbox preview line, as there is no
placeholder for it). In `{{content}}` each button is followed by its link
as a fallback. For a template it is that layout with the template's prompt
line, its default text in place of `{{content}}`, a raw-HTML `{{link}}`
button in `{{accent}}` / `{{accent_text}}` (MJML's validator rejects them
as `mj-button` colours), the small print and the fallback link. `go generate` compiles every default with strict
validation into `testdata/default-mjml/*.html` and checks auth accepts it;
CI fails when they are stale.

## Admin endpoints (internal listener)

All three need `Authorization: Bearer <access token>` of a user with
`settings.manage` (like `PATCH /v1/admin/settings`), on the internal
listener (`AUTH_INTERNAL_URL`); they are not on the public listener.

`POST /internal/email/preview` renders an email as it would be sent now,
with sample values (the caller's username as `username` and `inviter`, a
placeholder link, the real TTL), and lets the admin panel try unsaved
values while the admin types:

```json
{
  "template": "verification",
  "subject": "Confirm your {{network}} account",
  "body": "Hi {{username}},\n\n{{link}}\n\nExpires in {{expires}}.",
  "email": { "sender_name": "Example Chat", "accent": "#7c3aed", "footer": "Example Chat · https://example.com", "logo": true },
  "layout_html": "<!doctype html>… {{content}} …",
  "html": "<!doctype html>… {{link}} …"
}
```

Only `template` is required. Every other field, and every field of
`email`, is optional: a missing one is the saved value (`auth.email`, or
Boson's default). In `email`, `""` means the default (no sender name, the
default accent, no footer), like leaving the key out of the file. Without
`auth.email` and without any override it is the built-in email; any
override (wording or `email`) uses the branded layout.

`layout_html` and `html` are compiled MJML the admin panel has not saved:
a layout (with `{{content}}`) and this template's whole-email override
(with `{{link}}`), each at most 512 KB. `""` previews without one (Boson's
layout; no override); absent is the saved file. The request body may be up
to 2 MB + 64 KB (64 KB for every other endpoint).

```json
{
  "subject": "Confirm your Example Chat account",
  "html": "<!doctype html>…",
  "text": "$ verify --email\n\nHi alice,\n\nConfirm email:\nhttps://…\n\nExpires in 24 hours.\n\n-- \nExample Chat · https://example.com\n",
  "from": "\"Example Chat\" <no-reply@example.com>",
  "warnings": []
}
```

`from` is the From: header the email gets (`SMTP_FROM` with `sender_name`
as display name). `warnings` is always a list: the custom HTML's unknown
placeholders, placeholders left out (scripts, tag positions) and text
reduced in CSS, each with its line and column, e.g.
`"unknown placeholder {{nmae}} at line 12, column 5 is left as written"`.

Values are checked with the config file's rules and normalised the same
way (`sender_name` / `footer` trimmed, `accent` lower case). An invalid one
is 400 `invalid_request` naming the field:

```json
{ "error": "invalid_request", "code": "invalid_request", "field": "email.accent", "message": "email.accent must be a #rrggbb colour, got \"blue\"" }
```

(`field` is one of `subject`, `body`, `email.sender_name`, `email.accent`,
`email.footer`, `layout_html`, `html`; an unknown template is a 400
without `field`.) For the custom HTML:

```json
{ "error": "invalid_request", "field": "layout_html", "message": "layout_html must contain {{content}} (where the email's text and button go)" }
{ "error": "invalid_request", "field": "layout_html", "message": "layout_html must contain {{content}} exactly once, found 2 (line 3, column 9; line 7, column 9)" }
{ "error": "invalid_request", "field": "layout_html", "message": "layout_html {{content}} at line 3, column 20 must be in the body text, not in an attribute" }
{ "error": "invalid_request", "field": "html", "message": "html must contain {{link}} (the email's action link)" }
{ "error": "invalid_request", "field": "html", "message": "html must be at most 512 KB, got 513 KB" }
```

Meant to be called on every (debounced) keystroke: rate-limited per admin
at a burst of 60, then 5 a second (429 with `Retry-After`), and answers for
identical inputs (template, wording, effective settings, network name,
logo, sender address, username, custom HTML) come from a small in-memory
cache (previews over 64 KB of HTML are not cached). A
preview takes about 10 µs to render (under 1 µs from the cache); the
request as a whole is a few milliseconds, mostly the access-token check.

`POST /internal/email/test` `{template, to}` → `{status, to, subject}`
sends that email (subject prefixed `[Test] `) with the same sample values
and waits for the SMTP server. `status` is `sent`, or `logged` without
`SMTP_HOST`. `to` must be one bare address. 502 `email_send_failed` (with
the server's reply) when SMTP rejects it. Rate-limited per admin (burst 5,
then one per 6 minutes; 429 with `Retry-After`) and audited as
`email_test_sent` (`meta: {template, to, outcome, logged_only}`).

`GET /internal/email/default-mjml?part=layout|verification|password_reset|account_setup|invite`
→ `{"mjml": "<mjml lang=\"en\" dir=\"ltr\">…</mjml>"}`: Boson's default MJML
source for the editor's "Reset to default". `layout` contains `{{content}}`
once; a template's is a full MJML document (the same layout with the
template's default text, its variables as placeholders, and the `{{link}}`
button). Any other `part` is 400 `invalid_request` with `field: "part"`.
