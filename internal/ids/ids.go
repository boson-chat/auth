// Package ids makes prefixed ULID identifiers like usr_01HZY....
package ids

import (
	"strings"

	"github.com/oklog/ulid/v2"
)

const (
	User         = "usr"
	Session      = "ses"
	RefreshToken = "rtk"
	TokenFamily  = "rtf"
	EmailToken   = "etk"
	Provider     = "idp"
	Identity     = "uid"
	Invite       = "inv"
	Audit        = "aud"
	Role         = "rol"
	SigningKey   = "key"
	TokenID      = "jti"
	SSOCode      = "ssc"
)

// New returns prefix_ULID. ulid.Make is safe for concurrent use and
// monotonic within a millisecond.
func New(prefix string) string {
	return prefix + "_" + ulid.Make().String()
}

// HasPrefix reports whether id looks like prefix_<ULID>.
func HasPrefix(id, prefix string) bool {
	rest, ok := strings.CutPrefix(id, prefix+"_")
	if !ok {
		return false
	}
	_, err := ulid.ParseStrict(rest)
	return err == nil
}
