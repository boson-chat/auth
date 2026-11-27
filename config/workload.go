package config

import (
	"errors"
	"fmt"
	"os"
	"regexp"
	"slices"
	"strings"
	"time"
)

// WorkloadConfig is the workload issuer (<ISSUER>/workload): short-lived
// ES256 JWTs for this stack's own services (sub "service:<name>"), minted
// on the internal listener and verifiable with the issuer's own JWKS, e.g.
// as the subject token of Google Workload Identity Federation, so the push
// relay needs no Google service-account key. README "Workload identity".
type WorkloadConfig struct {
	// Comma-separated name:audience pairs that may be minted, e.g.
	// "pushrelay:boson-pushrelay". A name may appear more than once (one
	// pair per audience). Empty: the feature is off and /workload/* and
	// /internal/v1/workload/* are 404.
	Identities string `env:"WORKLOAD_IDENTITIES"`
	// Lifetime of a minted token (at most MaxWorkloadTokenTTL).
	TokenTTL time.Duration `default:"5m" env:"WORKLOAD_TOKEN_TTL"`
	// How often the workload signing key is replaced.
	KeyRotation time.Duration `default:"720h" env:"WORKLOAD_KEY_ROTATION"`
	// How long a new workload key is in the JWKS before it signs; also how
	// long a retired one stays there after its last token expired. Keep it
	// above the verifiers' JWKS cache time.
	KeyPublishLead time.Duration `default:"1h" env:"WORKLOAD_KEY_PUBLISH_LEAD"`

	// Getenv reads the per-workload tokens (tests; nil: os.Getenv).
	Getenv func(string) string `env:"-" json:"-" yaml:"-"`
}

// MaxWorkloadTokenTTL bounds WORKLOAD_TOKEN_TTL.
const MaxWorkloadTokenTTL = 10 * time.Minute

// WorkloadSubjectPrefix prefixes the workload name in the sub claim.
const WorkloadSubjectPrefix = "service:"

// WorkloadIdentity is one workload allowed to mint tokens.
type WorkloadIdentity struct {
	Name      string
	Audiences []string
	// Token is WORKLOAD_TOKEN_<NAME>: the secret the workload sends as
	// X-Workload-Token. Every workload has its own.
	Token string
}

// Subject is the sub claim: service:<name>.
func (w WorkloadIdentity) Subject() string { return WorkloadSubjectPrefix + w.Name }

var (
	workloadNameRe     = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,31}$`)
	workloadAudienceRe = regexp.MustCompile(`^[\x21-\x7e]{1,256}$`) // printable, no spaces
)

// Enabled reports whether any workload identity is configured.
func (c WorkloadConfig) Enabled() bool { return strings.TrimSpace(c.Identities) != "" }

// TokenEnv is the environment variable holding name's token:
// WORKLOAD_TOKEN_ + the name upper-cased, "-" as "_".
func TokenEnv(name string) string {
	return "WORKLOAD_TOKEN_" + strings.ToUpper(strings.ReplaceAll(name, "-", "_"))
}

// Workloads parses WORKLOAD_IDENTITIES and reads each workload's token.
func (c WorkloadConfig) Workloads() ([]WorkloadIdentity, error) {
	getenv := c.Getenv
	if getenv == nil {
		getenv = os.Getenv
	}
	var out []WorkloadIdentity
	idx := map[string]int{}
	for _, pair := range SplitList(c.Identities) {
		name, aud, ok := strings.Cut(pair, ":")
		if !ok || !workloadNameRe.MatchString(name) || !workloadAudienceRe.MatchString(aud) {
			return nil, fmt.Errorf("WORKLOAD_IDENTITIES: %q must be name:audience (name: a-z 0-9 _ -, up to 32)", pair)
		}
		i, seen := idx[name]
		if !seen {
			i = len(out)
			idx[name] = i
			out = append(out, WorkloadIdentity{Name: name, Token: strings.TrimSpace(getenv(TokenEnv(name)))})
		}
		if !slices.Contains(out[i].Audiences, aud) {
			out[i].Audiences = append(out[i].Audiences, aud)
		}
	}
	// TokenEnv folds "-" into "_": two names may not share a variable.
	envs := map[string]string{}
	for _, w := range out {
		if other, dup := envs[TokenEnv(w.Name)]; dup {
			return nil, fmt.Errorf("WORKLOAD_IDENTITIES: %q and %q would share %s", other, w.Name, TokenEnv(w.Name))
		}
		envs[TokenEnv(w.Name)] = w.Name
	}
	return out, nil
}

// Validate checks the workload settings; reserved are secrets no workload
// token may equal (INTERNAL_API_TOKEN, INTERNAL_ACTING_TOKEN).
func (c WorkloadConfig) Validate(reserved ...string) error {
	if !c.Enabled() {
		return nil
	}
	if c.TokenTTL <= 0 || c.TokenTTL > MaxWorkloadTokenTTL {
		return fmt.Errorf("WORKLOAD_TOKEN_TTL must be positive and at most %s", MaxWorkloadTokenTTL)
	}
	if c.KeyRotation <= 0 || c.KeyPublishLead < 0 {
		return errors.New("WORKLOAD_KEY_ROTATION must be positive and WORKLOAD_KEY_PUBLISH_LEAD not negative")
	}
	list, err := c.Workloads()
	if err != nil {
		return err
	}
	tokens := map[string]string{}
	for _, w := range list {
		env := TokenEnv(w.Name)
		switch {
		case len(w.Token) < 16:
			return fmt.Errorf("%s must be set (at least 16 characters; e.g. openssl rand -hex 32) for workload %q", env, w.Name)
		case slices.Contains(reserved, w.Token):
			return fmt.Errorf("%s must differ from INTERNAL_API_TOKEN and INTERNAL_ACTING_TOKEN", env)
		}
		if other, dup := tokens[w.Token]; dup {
			return fmt.Errorf("%s and %s must differ", TokenEnv(other), env)
		}
		tokens[w.Token] = w.Name
	}
	return nil
}
