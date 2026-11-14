package email

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"maps"
	"strings"
	"sync"

	"github.com/boson-chat/auth/config"
	"github.com/boson-chat/auth/internal/apperr"
	"github.com/boson-chat/auth/internal/mailer"
)

// PreviewInput is one POST /internal/email/preview: the template, and
// unsaved wording and email settings to try. nil fields keep what is saved.
type PreviewInput struct {
	Template string
	Subject  *string
	Body     *string
	Email    *EmailOverrides
	// LayoutHTML and HTML are unsaved compiled MJML: a layout, and this
	// template's whole-email override. "" previews without (Boson's layout,
	// no override).
	LayoutHTML *string
	HTML       *string
}

// EmailOverrides are unsaved auth.email settings.
type EmailOverrides struct {
	SenderName *string
	Accent     *string
	Footer     *string
	Logo       *bool
}

func (o *EmailOverrides) empty() bool {
	return o == nil || o.SenderName == nil && o.Accent == nil && o.Footer == nil && o.Logo == nil
}

// check validates and normalises the overrides like the config file's
// auth.email (same rules, same trimming and lower-casing).
func (o *EmailOverrides) check() (*EmailOverrides, error) {
	if o.empty() {
		return nil, nil
	}
	out := &EmailOverrides{Logo: o.Logo}
	for _, f := range []struct {
		field string
		src   *string
		dst   **string
		check func(string) string
		norm  func(string) string
	}{
		{"email.sender_name", o.SenderName, &out.SenderName, config.CheckSenderName, strings.TrimSpace},
		{"email.accent", o.Accent, &out.Accent, config.CheckAccent, strings.ToLower},
		{"email.footer", o.Footer, &out.Footer, config.CheckFooter, strings.TrimSpace},
	} {
		if f.src == nil {
			continue
		}
		v := *f.src
		// "" is the default, as when the key is absent from the file.
		if v != "" {
			if msg := f.check(v); msg != "" {
				return nil, apperr.InvalidField(f.field, msg)
			}
		}
		v = f.norm(v)
		*f.dst = &v
	}
	return out, nil
}

// apply returns cfg (nil: none saved) with the overrides on top; cfg is
// not modified.
func (o *EmailOverrides) apply(cfg *config.EmailConfig) *config.EmailConfig {
	c := config.EmailConfig{}
	if cfg != nil {
		c = *cfg
		c.Templates = maps.Clone(cfg.Templates)
	}
	if o.SenderName != nil {
		c.SenderName = *o.SenderName
	}
	if o.Accent != nil {
		c.Accent = *o.Accent
	}
	if o.Footer != nil {
		c.Footer = *o.Footer
	}
	if o.Logo != nil {
		c.Logo = *o.Logo
	}
	return &c
}

func checkWording(in PreviewInput) (*config.EmailTemplate, error) {
	for _, f := range []struct {
		field string
		v     *string
		check func(string) string
	}{{"subject", in.Subject, config.CheckSubject}, {"body", in.Body, config.CheckBody}} {
		if f.v != nil {
			if msg := f.check(*f.v); msg != "" {
				return nil, apperr.InvalidField(f.field, msg)
			}
		}
	}
	if in.Subject == nil && in.Body == nil {
		return nil, nil
	}
	return &config.EmailTemplate{Subject: in.Subject, Body: in.Body}, nil
}

// Preview renders the email as it would be sent with the saved settings
// and in's overrides on top. Without auth.email and without overrides it
// is the built-in email. Identical inputs are answered from a small cache
// (the admin panel previews on every keystroke).
func (s *EmailService) Preview(_ context.Context, username string, in PreviewInput) (Rendered, error) {
	tpl, v, err := s.sample(in.Template, username)
	if err != nil {
		return Rendered{}, err
	}
	over, err := checkWording(in)
	if err != nil {
		return Rendered{}, err
	}
	email, err := in.Email.check()
	if err != nil {
		return Rendered{}, err
	}
	cfg := s.cfg.Load()
	cu := s.customFor(cfg, tpl.name)
	for _, f := range []struct {
		field  string
		src    *string
		dst    **customDoc
		layout bool
	}{{"layout_html", in.LayoutHTML, &cu.layout, true}, {"html", in.HTML, &cu.tpl, false}} {
		if f.src == nil {
			continue
		}
		*f.dst = nil
		if *f.src == "" {
			continue
		}
		d, err := compileDoc(*f.src, f.layout)
		if err != nil {
			return Rendered{}, apperr.InvalidField(f.field, err.Error())
		}
		*f.dst = d
	}
	if email != nil {
		cfg = email.apply(cfg)
	}
	logo := s.opts.Logo()
	from := mailer.FromAddress(s.Mailer)
	if from == "" {
		from = s.opts.From
	}
	key := previewKey(tpl.name, v, cfg, over, logo, from, cu)
	if r, ok := s.previews.get(key); ok {
		return r, nil
	}
	r, err := s.render(tpl, v, cfg, over, cu)
	if err != nil {
		return Rendered{}, err
	}
	var name string
	if cfg != nil {
		name = cfg.SenderName
	}
	r.From = mailer.FromHeader(from, name)
	if r.Warnings == nil {
		r.Warnings = []string{}
	}
	if len(r.HTML) <= maxCachedPreview {
		s.previews.put(key, r)
	}
	return r, nil
}

// previewKey hashes everything a preview depends on.
func previewKey(name string, v Vars, cfg *config.EmailConfig, over *config.EmailTemplate, logo Logo, from string, cu custom) [32]byte {
	h := sha256.New()
	var n [8]byte
	str := func(s string) {
		binary.LittleEndian.PutUint64(n[:], uint64(len(s)))
		h.Write(n[:])
		h.Write([]byte(s))
	}
	opt := func(p *string) {
		if p == nil {
			str("\x00nil")
			return
		}
		str(*p)
	}
	for _, s := range []string{name, v.Network, v.Username, v.Link, v.Expires, v.Inviter, logo.URL, from} {
		str(s)
	}
	binary.LittleEndian.PutUint32(n[:4], uint32(logo.Width))
	binary.LittleEndian.PutUint32(n[4:], uint32(logo.Height))
	h.Write(n[:])
	for i, d := range []*customDoc{cu.layout, cu.tpl} {
		if d != nil {
			str([]string{"layout", "tpl"}[i])
			h.Write(d.hash[:])
		}
	}
	if over != nil {
		str("over")
		opt(over.Subject)
		opt(over.Body)
	}
	if cfg != nil {
		str("cfg")
		str(cfg.SenderName)
		str(cfg.Accent)
		str(cfg.Footer)
		if cfg.Logo {
			str("logo")
		}
		// Only this template's saved wording matters.
		if t, ok := cfg.Templates[name]; ok {
			opt(t.Subject)
			opt(t.Body)
		}
	}
	var k [32]byte
	h.Sum(k[:0])
	return k
}

// previewCacheSize bounds the cache: a few admins typing, a few hundred
// recent states each at most ~20 KB.
const previewCacheSize = 256

// maxCachedPreview: larger previews (custom HTML) aren't cached, so the
// cache stays a few MB.
const maxCachedPreview = 64 << 10

// previewCache is a fixed-size map with first-in-first-out eviction.
type previewCache struct {
	mu   sync.Mutex
	m    map[[32]byte]Rendered
	ring [][32]byte
	next int
}

func newPreviewCache(size int) *previewCache {
	return &previewCache{m: make(map[[32]byte]Rendered, size), ring: make([][32]byte, 0, size)}
}

func (c *previewCache) get(k [32]byte) (Rendered, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	r, ok := c.m[k]
	return r, ok
}

func (c *previewCache) put(k [32]byte, r Rendered) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, ok := c.m[k]; ok {
		return
	}
	if len(c.ring) < cap(c.ring) {
		c.ring = append(c.ring, k)
	} else {
		delete(c.m, c.ring[c.next])
		c.ring[c.next] = k
		c.next = (c.next + 1) % len(c.ring)
	}
	c.m[k] = r
}

func (c *previewCache) len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.m)
}
