package roles

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"time"
	"unicode"

	"github.com/boson-chat/auth/internal/apperr"
	"github.com/boson-chat/auth/internal/db/repositories/role"
	"github.com/boson-chat/auth/internal/nick"
	"github.com/boson-chat/auth/internal/perm"
	"github.com/boson-chat/auth/internal/textutil"
)

const (
	MaxNameLen      = 32
	MaxWhoisLineLen = 64
	// VhostMaxLen is Ergo's default accounts.vhosts.max-length.
	VhostMaxLen = 64
	// MinPosition and MaxPosition bound every role but Owner (1000) and Member (0).
	MinPosition = 1
	MaxPosition = 999
	// UsernamePlaceholder is replaced by the vhost form of the account name.
	UsernamePlaceholder = "{username}"
)

var (
	nameRe  = regexp.MustCompile(`^[A-Za-z0-9 _-]+$`)
	colorRe = regexp.MustCompile(`^#[0-9a-fA-F]{6}$`)
	// vhostRe is Ergo's default accounts.vhosts.valid-regexp (irc/hostserv.go).
	vhostRe = regexp.MustCompile(`^[0-9A-Za-z.\-_/]+$`)
)

// Nullable is a JSON field that tells "absent" (Set false) from null
// (Set true, Value nil).
type Nullable[T any] struct {
	Set   bool
	Value *T
}

func (n *Nullable[T]) UnmarshalJSON(b []byte) error {
	n.Set = true
	if string(b) == "null" {
		n.Value = nil
		return nil
	}
	var v T
	if err := json.Unmarshal(b, &v); err != nil {
		return err
	}
	n.Value = &v
	return nil
}

// Some makes a set, non-null Nullable.
func Some[T any](v T) Nullable[T] { return Nullable[T]{Set: true, Value: &v} }

// IRCInput is the irc block of a create/patch body.
type IRCInput struct {
	WhoisLine Nullable[string] `json:"whois_line"`
	Vhost     Nullable[string] `json:"vhost"`
	Oper      *bool            `json:"oper"`
}

// Input is POST /v1/admin/roles and (all fields optional) PATCH.
type Input struct {
	Name        *string          `json:"name"`
	Color       Nullable[string] `json:"color"`
	Position    *int             `json:"position"`
	Permissions *[]string        `json:"permissions"`
	IRC         *IRCInput        `json:"irc"`
	Hoist       *bool            `json:"hoist"`
	Mentionable *bool            `json:"mentionable"`
	// IfMatch (PATCH only, from the If-Match header): fail with 412 unless
	// the role's updated_at is still this.
	IfMatch *time.Time `json:"-"`
}

func (in Input) empty() bool {
	return in.Name == nil && !in.Color.Set && in.Position == nil && in.Permissions == nil &&
		(in.IRC == nil || (!in.IRC.WhoisLine.Set && !in.IRC.Vhost.Set && in.IRC.Oper == nil)) &&
		in.Hoist == nil && in.Mentionable == nil
}

// NormalizeName trims and validates a role name.
func NormalizeName(s string) (string, error) {
	s = strings.TrimSpace(s)
	if s == "" || len(s) > MaxNameLen || !nameRe.MatchString(s) {
		return "", apperr.Invalid("name must be 1-32 characters: letters, digits, spaces, - and _")
	}
	return s, nil
}

// Slug is the Ergo oper-class name of a role: lower case, spaces as '-'.
func Slug(name string) string {
	return strings.ReplaceAll(strings.ToLower(strings.TrimSpace(name)), " ", "-")
}

// NormalizeColor validates #rrggbb and lower-cases it.
func NormalizeColor(s string) (string, error) {
	if !colorRe.MatchString(s) {
		return "", apperr.Invalid("color must be #rrggbb")
	}
	return strings.ToLower(s), nil
}

// NormalizeWhoisLine trims a WHOIS line; "" means the default.
func NormalizeWhoisLine(s string) (string, error) {
	s = strings.TrimSpace(s)
	if len(s) > MaxWhoisLineLen || !textutil.Storable(s) || strings.ContainsFunc(s, unicode.IsControl) {
		return "", apperr.Invalid(fmt.Sprintf("irc.whois_line must be at most %d characters without control characters", MaxWhoisLineLen))
	}
	return s, nil
}

// ValidateVhostTemplate accepts templates whose every rendering is a vhost
// Ergo accepts (valid-regexp ^[0-9A-Za-z.\-_/]+$, max-length 64): static
// characters from that set plus any number of {username}, at most 64 bytes
// with a 30-character username, not starting or ending with '.' or '/', and
// no empty labels ("..", "//").
func ValidateVhostTemplate(t string) error {
	bad := func(msg string) error { return apperr.Invalid("irc.vhost: " + msg) }
	n := strings.Count(t, UsernamePlaceholder)
	static := strings.ReplaceAll(t, UsernamePlaceholder, "")
	if static != "" && !vhostRe.MatchString(static) {
		return bad("only letters, digits, . - _ / and {username} are allowed")
	}
	if len(static)+n*nick.MaxLen > VhostMaxLen {
		return bad(fmt.Sprintf("too long: at most %d characters with a %d-character username", VhostMaxLen, nick.MaxLen))
	}
	sample := strings.ReplaceAll(t, UsernamePlaceholder, "u")
	if sample == "" || strings.ContainsAny(sample[:1], "./") || strings.ContainsAny(sample[len(sample)-1:], "./") ||
		strings.Contains(sample, "..") || strings.Contains(sample, "//") {
		return bad("must not start or end with . or / or contain empty labels")
	}
	return nil
}

// VhostUsername is the {username} value: the account name lower-cased
// (ASCII), with the nick characters Ergo rejects in vhosts ([]\`^{|}) as '-'.
func VhostUsername(username string) string {
	b := []byte(strings.ToLower(username))
	for i, c := range b {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
			b[i] = '-'
		}
	}
	return string(b)
}

// RenderVhost fills a template for username; "" if the result isn't a
// valid Ergo vhost (can't happen for templates that passed validation).
func RenderVhost(template, username string) string {
	out := strings.ReplaceAll(template, UsernamePlaceholder, VhostUsername(username))
	if out == "" || len(out) > VhostMaxLen || !vhostRe.MatchString(out) {
		return ""
	}
	return out
}

// apply validates in and writes it to r. Built-in rules: no renames; Owner
// and Member keep their positions; Owner's permissions are fixed.
func apply(r *role.Role, in Input) error {
	if in.Name != nil {
		name, err := NormalizeName(*in.Name)
		if err != nil {
			return err
		}
		if r.IsBuiltin() && name != r.Name {
			return apperr.Invalid("built-in roles can't be renamed")
		}
		r.Name, r.Slug = name, Slug(name)
	}
	if in.Color.Set {
		r.Color = nil
		if in.Color.Value != nil && *in.Color.Value != "" {
			c, err := NormalizeColor(*in.Color.Value)
			if err != nil {
				return err
			}
			r.Color = &c
		}
	}
	if in.Position != nil {
		p := *in.Position
		switch {
		case r.Is(role.BuiltinOwner) || r.Is(role.BuiltinMember):
			if p != r.Position {
				return apperr.Invalid("the Owner and Member positions are fixed")
			}
		case p < MinPosition || p > MaxPosition:
			return apperr.Invalid(fmt.Sprintf("position must be %d-%d", MinPosition, MaxPosition))
		}
		r.Position = p
	}
	if in.Permissions != nil {
		if r.Is(role.BuiltinOwner) {
			return apperr.Invalid("the Owner role always has every permission")
		}
		ps, err := perm.Normalize(*in.Permissions)
		if err != nil {
			return apperr.Invalid(err.Error())
		}
		r.Permissions = ps
	}
	if in.IRC != nil {
		if in.IRC.WhoisLine.Set {
			r.IRCWhoisLine = nil
			if v := in.IRC.WhoisLine.Value; v != nil {
				w, err := NormalizeWhoisLine(*v)
				if err != nil {
					return err
				}
				if w != "" {
					r.IRCWhoisLine = &w
				}
			}
		}
		if in.IRC.Vhost.Set {
			r.IRCVhost = nil
			if v := in.IRC.Vhost.Value; v != nil && strings.TrimSpace(*v) != "" {
				t := strings.TrimSpace(*v)
				if err := ValidateVhostTemplate(t); err != nil {
					return err
				}
				r.IRCVhost = &t
			}
		}
		if in.IRC.Oper != nil {
			r.IRCOper = *in.IRC.Oper
		}
	}
	if in.Hoist != nil {
		r.Hoist = *in.Hoist
	}
	if in.Mentionable != nil {
		r.Mentionable = *in.Mentionable
	}
	return nil
}
