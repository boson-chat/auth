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
    accent: "#7c3aed"             # top border, buttons, links (default #3b5bdb)
    footer: "Example Chat · example.com"           # small print under the card; URLs linkified
    logo: true                    # show the branding logo (logo_wide, else logo; raster before SVG)
    templates:                    # any subset; absent = Boson's wording
      verification:   { subject: "Confirm your {{network}} account", body: "Hi {{username}},\n\n{{link}}\n\nExpires in {{expires}}." }
      password_reset: { subject: "…", body: "…" }
      account_setup:  { subject: "…", body: "…" }
      invite:         { subject: "…", body: "…" }
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
`auth.email.templates.<name>.subject|body`.

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
and a paragraph that is only `{{link}}` becomes the action button ("Verify
email", "Choose a new password", …). All template text and every value is
HTML-escaped, so a template can't inject markup. The plain-text part is the
body with the variables filled in, then `-- ` and the footer.

### Layout (MJML)

With `auth.email` present, the HTML part is built from
[`templates/layout.mjml`](../internal/services/email/templates/layout.mjml)
with [MJML](https://mjml.io/), compiled in-process by
[mjml-go](https://github.com/Boostport/mjml-go) (MJML as WebAssembly on
wazero: pure Go, no Node, no CGO). MJML produces the table layout and
Outlook conditional comments that Gmail, Outlook and Apple Mail need.

- 600 px wide card on a soft grey page; 4 px accent bar on top; logo
  (40 px high, at most 240 px wide, with explicit `width`/`height` for
  Outlook) or the sender name as text; the button in the accent colour,
  its label white or near-black, whichever contrasts more; small centred
  footer; system font stack (no web fonts); a hidden inbox preview line
  (the start of the body, without the link).
- Dark mode: `color-scheme: light dark`, and `prefers-color-scheme: dark`
  rules (Apple Mail, iOS Mail; `[data-ogsc]` / `[data-ogsb]` for
  Outlook.com) switch to a dark page and card with light text. Gmail's
  apps invert on their own; the light colours are chosen to survive that.
- The logo is the wordmark, else the mark; PNG / JPEG / GIF before WebP
  (Outlook for Windows shows no WebP) before SVG (Gmail and Outlook show
  no SVG).

**Performance.** The layout is compiled once per process, when the email
service starts (two variants: with and without a footer, about 35 ms
each), into an HTML skeleton with slots. Sending or previewing an email only
fills the slots: about 10 µs per email (`go test -bench Preview
./internal/services/email`), no MJML at request time. Config reloads don't
recompile: the accent, logo, sender name, footer and wording are all slot
values. The MJML runtime costs about 0.4 s and ~130 MB of memory when the
process starts (the wasm module stays loaded).

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

## Admin endpoints (internal listener)

Both need `Authorization: Bearer <access token>` of a user with
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
  "email": { "sender_name": "Example Chat", "accent": "#7c3aed", "footer": "Example Chat · https://example.com", "logo": true }
}
```

Only `template` is required. Every other field, and every field of
`email`, is optional: a missing one is the saved value (`auth.email`, or
Boson's default). In `email`, `""` means the default (no sender name, the
default accent, no footer), like leaving the key out of the file. Without
`auth.email` and without any override it is the built-in email; any
override (wording or `email`) uses the branded layout.

```json
{
  "subject": "Confirm your Example Chat account",
  "html": "<!doctype html>…",
  "text": "Hi alice,\n\nhttps://…\n\nExpires in 24 hours.\n\n-- \nExample Chat · https://example.com\n",
  "from": "\"Example Chat\" <no-reply@example.com>"
}
```

`from` is the From: header the email gets (`SMTP_FROM` with `sender_name`
as display name).

Values are checked with the config file's rules and normalised the same
way (`sender_name` / `footer` trimmed, `accent` lower case). An invalid one
is 400 `invalid_request` naming the field:

```json
{ "error": "invalid_request", "code": "invalid_request", "field": "email.accent", "message": "email.accent must be a #rrggbb colour, got \"blue\"" }
```

(`field` is one of `subject`, `body`, `email.sender_name`, `email.accent`,
`email.footer`; an unknown template is a 400 without `field`.)

Meant to be called on every (debounced) keystroke: rate-limited per admin
at a burst of 60, then 5 a second (429 with `Retry-After`), and answers for
identical inputs (template, wording, effective settings, network name,
logo, sender address, username) come from a small in-memory cache. A
preview takes about 10 µs to render (under 1 µs from the cache); the
request as a whole is a few milliseconds, mostly the access-token check.

`POST /internal/email/test` `{template, to}` → `{status, to, subject}`
sends that email (subject prefixed `[Test] `) with the same sample values
and waits for the SMTP server. `status` is `sent`, or `logged` without
`SMTP_HOST`. `to` must be one bare address. 502 `email_send_failed` (with
the server's reply) when SMTP rejects it. Rate-limited per admin (burst 5,
then one per 6 minutes; 429 with `Retry-After`) and audited as
`email_test_sent` (`meta: {template, to, outcome, logged_only}`).
