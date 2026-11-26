package federation

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/boson-chat/auth/config"
	"github.com/boson-chat/auth/internal/apperr"
	"github.com/boson-chat/auth/internal/db"
	"github.com/boson-chat/auth/internal/db/repositories"
	fedrepo "github.com/boson-chat/auth/internal/db/repositories/federation"
	"github.com/boson-chat/auth/internal/services/audit"
)

// Settings are the effective federation settings (GET /v1/admin/federation).
//
// With the stack config file (BOSON_CONFIG) present they are its
// auth.federation keys over the FEDERATION_* env values (file > env >
// default) and read-only here (Editable false, PATCH answers 409
// settings_managed). Without it, values stored through PATCH
// (federation_settings) override the env.
type Settings struct {
	Mode         string   `json:"mode"`
	Allow        []string `json:"allow"`
	Block        []string `json:"block"`
	DirectoryURL string   `json:"directory_url"`
	// RemoteUploadQuota is remote users' upload quota per rolling window
	// ("1GB"; "" = the files service's account quota).
	RemoteUploadQuota string `json:"remote_upload_quota"`
	RemoteVoice       bool   `json:"remote_voice"`
	// Sources per field: file | database | env | default.
	Sources map[string]string `json:"sources"`
	// Editable: PATCH /v1/admin/federation works (no stack config file).
	Editable bool `json:"editable"`
	// Issuer is this server's token issuer (boson.json federation.issuer),
	// Domain its boson_domain.
	Issuer string `json:"issuer"`
	Domain string `json:"domain"`
	// RemoteUsers is the number of federated accounts here.
	RemoteUsers int64 `json:"remote_users"`
	// RemoteRole is FEDERATION_REMOTE_ROLE (read-only).
	RemoteRole string     `json:"remote_role"`
	UpdatedAt  *time.Time `json:"updated_at"`
	UpdatedBy  *string    `json:"updated_by"`

	// remoteUploadBytes is RemoteUploadQuota parsed (0 = default).
	remoteUploadBytes int64
}

// Sources.
const (
	SourceFile     = "file"
	SourceDatabase = "database"
	SourceEnv      = "env"
	SourceDefault  = "default"
)

// Field names (JSON, PATCH).
const (
	FieldMode              = "mode"
	FieldAllow             = "allow"
	FieldBlock             = "block"
	FieldDirectoryURL      = "directory_url"
	FieldRemoteUploadQuota = "remote_upload_quota"
	FieldRemoteVoice       = "remote_voice"
)

var patchFields = []string{FieldMode, FieldAllow, FieldBlock, FieldDirectoryURL, FieldRemoteUploadQuota, FieldRemoteVoice}

var fieldEnv = map[string]string{
	FieldMode: "FEDERATION_MODE", FieldAllow: "FEDERATION_ALLOW", FieldBlock: "FEDERATION_BLOCK",
	FieldDirectoryURL: "FEDERATION_DIRECTORY_URL", FieldRemoteUploadQuota: "FEDERATION_REMOTE_UPLOAD_QUOTA",
	FieldRemoteVoice: "FEDERATION_REMOTE_VOICE",
}

// ErrSettingsManaged: the stack config file manages the settings.
var ErrSettingsManaged = apperr.New(http.StatusConflict, "settings_managed",
	"federation settings come from the stack config file (auth.federation); edit the file or the admin panel instead")

// fileState is file mode: the effective federation config and the fields
// the file sets.
type fileState struct {
	cfg    config.FederationConfig
	fields []string
}

// settingsStore reads and writes the settings with a short cache.
type settingsStore struct {
	repo  fedrepo.FederationRepositoryImpl
	tx    db.TxManagerImpl
	audit audit.AuditServiceImpl
	env   config.Config
	// envSet: fields whose FEDERATION_* variable is set.
	envSet map[string]bool
	ttl    time.Duration
	now    func() time.Time

	file atomic.Pointer[fileState]

	mu       sync.Mutex
	cached   Settings
	cachedAt time.Time
	valid    bool
}

func newSettingsStore(repo fedrepo.FederationRepositoryImpl, tx db.TxManagerImpl, a audit.AuditServiceImpl, cfg config.Config, now func() time.Time) *settingsStore {
	envSet := map[string]bool{}
	for f, name := range fieldEnv {
		if _, ok := os.LookupEnv(name); ok {
			envSet[f] = true
		}
	}
	return &settingsStore{repo: repo, tx: tx, audit: a, env: cfg, envSet: envSet, ttl: cfg.AccountConfig.SettingsCacheTTL, now: now}
}

// fromConfig renders f (env, or env with the file applied).
func (s *settingsStore) fromConfig(f config.FederationConfig) Settings {
	allow, _ := config.ParseDomainList(config.SplitList(f.Allow))
	block, _ := config.ParseDomainList(config.SplitList(f.Block))
	out := Settings{
		Mode: f.Mode, Allow: allow, Block: block, DirectoryURL: strings.TrimRight(strings.TrimSpace(f.DirectoryURL), "/"),
		RemoteUploadQuota: strings.TrimSpace(f.RemoteUploadQuota), RemoteVoice: f.RemoteVoice,
		Issuer: s.env.TokenConfig.Issuer, Domain: s.env.FederationDomain(), RemoteRole: strings.TrimSpace(s.env.FederationConfig.RemoteRole),
		Sources: map[string]string{},
	}
	if out.Mode == "" {
		out.Mode = config.FederationDirectory
	}
	if out.DirectoryURL == "" {
		out.DirectoryURL = config.DefaultDirectoryURL
	}
	for _, name := range patchFields {
		out.Sources[name] = SourceDefault
		if s.envSet[name] {
			out.Sources[name] = SourceEnv
		}
	}
	return out
}

func (s *settingsStore) finish(out Settings) Settings {
	if out.Allow == nil {
		out.Allow = []string{}
	}
	if out.Block == nil {
		out.Block = []string{}
	}
	out.remoteUploadBytes, _ = config.ParseSize(out.RemoteUploadQuota)
	return out
}

func (s *settingsStore) effective(r *fedrepo.SettingsRow) Settings {
	out := s.fromConfig(s.env.FederationConfig)
	out.Editable = true
	set := func(name string) { out.Sources[name] = SourceDatabase }
	if r.Mode != nil {
		out.Mode = *r.Mode
		set(FieldMode)
	}
	if r.Allow != nil {
		out.Allow = slices.Clone([]string(*r.Allow))
		set(FieldAllow)
	}
	if r.Block != nil {
		out.Block = slices.Clone([]string(*r.Block))
		set(FieldBlock)
	}
	if r.DirectoryURL != nil {
		out.DirectoryURL = *r.DirectoryURL
		set(FieldDirectoryURL)
	}
	if r.RemoteUploadQuota != nil {
		out.RemoteUploadQuota = *r.RemoteUploadQuota
		set(FieldRemoteUploadQuota)
	}
	if r.RemoteVoice != nil {
		out.RemoteVoice = *r.RemoteVoice
		set(FieldRemoteVoice)
	}
	out.UpdatedAt, out.UpdatedBy = r.UpdatedAt, r.UpdatedBy
	return s.finish(out)
}

func (s *settingsStore) fromFile(f *fileState) Settings {
	out := s.fromConfig(f.cfg)
	for _, name := range f.fields {
		out.Sources[name] = SourceFile
	}
	return s.finish(out)
}

// setFile switches to file mode (nil: back to the database).
func (s *settingsStore) setFile(cfg *config.FederationConfig, fields []string) {
	if cfg == nil {
		s.file.Store(nil)
	} else {
		s.file.Store(&fileState{cfg: *cfg, fields: slices.Clone(fields)})
	}
	s.mu.Lock()
	s.valid = false
	s.mu.Unlock()
}

func (s *settingsStore) get(ctx context.Context) (Settings, error) {
	if f := s.file.Load(); f != nil {
		return s.fromFile(f), nil
	}
	s.mu.Lock()
	if s.valid && s.now().Sub(s.cachedAt) < s.ttl {
		v := s.cached
		s.mu.Unlock()
		return v, nil
	}
	s.mu.Unlock()
	row, err := s.repo.GetSettings(ctx)
	if err != nil {
		return Settings{}, err
	}
	v := s.effective(row)
	s.store(v)
	return v, nil
}

func (s *settingsStore) store(v Settings) {
	s.mu.Lock()
	s.cached, s.cachedAt, s.valid = v, s.now(), true
	s.mu.Unlock()
}

// Patch is PATCH /v1/admin/federation: any subset of mode, allow, block,
// directory_url, remote_upload_quota and remote_voice. A JSON null resets
// that field to its env default.
type Patch map[string]json.RawMessage

func isNull(raw json.RawMessage) bool { return bytes.Equal(bytes.TrimSpace(raw), []byte("null")) }

func badField(field, msg string) error { return apperr.InvalidField(field, msg) }

// apply validates p and writes it onto row.
func (s *settingsStore) apply(row *fedrepo.SettingsRow, p Patch) error {
	if len(p) == 0 {
		return apperr.Invalid("nothing to update")
	}
	for k := range p {
		if !slices.Contains(patchFields, k) {
			return badField(k, "is not a federation setting (read-only or unknown)")
		}
	}
	strField := func(name string, dst **string, check func(string) (string, error)) error {
		raw, ok := p[name]
		if !ok {
			return nil
		}
		if isNull(raw) {
			*dst = nil
			return nil
		}
		var v string
		if err := json.Unmarshal(raw, &v); err != nil {
			return badField(name, "must be a string")
		}
		v, err := check(v)
		if err != nil {
			return err
		}
		*dst = &v
		return nil
	}
	if err := strField(FieldMode, &row.Mode, func(v string) (string, error) {
		if !config.ValidFederationMode(v) {
			return "", badField(FieldMode, "must be off, allowlist, directory or open")
		}
		return v, nil
	}); err != nil {
		return err
	}
	if err := strField(FieldDirectoryURL, &row.DirectoryURL, func(v string) (string, error) {
		v = strings.TrimRight(strings.TrimSpace(v), "/")
		if err := config.ValidateServiceURL(v, s.env.FederationConfig.AllowHTTP); err != nil {
			return "", badField(FieldDirectoryURL, "must be an https URL such as https://directory.boson.chat")
		}
		return v, nil
	}); err != nil {
		return err
	}
	if err := strField(FieldRemoteUploadQuota, &row.RemoteUploadQuota, func(v string) (string, error) {
		v = strings.TrimSpace(v)
		if v == "" {
			return v, nil
		}
		if n, err := config.ParseSize(v); err != nil || n <= 0 {
			return "", badField(FieldRemoteUploadQuota, "must be a size such as 1GB or 500MB (\"\" = the account quota)")
		}
		return v, nil
	}); err != nil {
		return err
	}
	listField := func(name string, dst **repositories.StringList) error {
		raw, ok := p[name]
		if !ok {
			return nil
		}
		if isNull(raw) {
			*dst = nil
			return nil
		}
		var v []string
		if err := json.Unmarshal(raw, &v); err != nil {
			return badField(name, "must be an array of domains")
		}
		if len(v) > config.MaxFederationDomains {
			return badField(name, fmt.Sprintf("may have at most %d entries", config.MaxFederationDomains))
		}
		list, err := config.ParseDomainList(v)
		if err != nil {
			return badField(name, err.Error())
		}
		l := repositories.StringList(list)
		*dst = &l
		return nil
	}
	if err := listField(FieldAllow, &row.Allow); err != nil {
		return err
	}
	if err := listField(FieldBlock, &row.Block); err != nil {
		return err
	}
	if raw, ok := p[FieldRemoteVoice]; ok {
		if isNull(raw) {
			row.RemoteVoice = nil
		} else {
			var v bool
			if err := json.Unmarshal(raw, &v); err != nil {
				return badField(FieldRemoteVoice, "must be a boolean")
			}
			row.RemoteVoice = &v
		}
	}
	return nil
}

// update applies p and returns the new settings.
func (s *settingsStore) update(ctx context.Context, actorID string, p Patch) (Settings, error) {
	if s.file.Load() != nil {
		return Settings{}, ErrSettingsManaged
	}
	var before, after Settings
	err := s.tx.WithTx(ctx, func(ctx context.Context) error {
		row, err := s.repo.GetSettingsForUpdate(ctx)
		if err != nil {
			return err
		}
		before = s.effective(row)
		if err := s.apply(row, p); err != nil {
			return err
		}
		now := s.now().UTC()
		row.UpdatedAt = &now
		row.UpdatedBy = nil
		if actorID != "" {
			row.UpdatedBy = &actorID
		}
		if err := s.repo.SaveSettings(ctx, row); err != nil {
			return err
		}
		after = s.effective(row)
		return nil
	})
	if err != nil {
		return Settings{}, err
	}
	s.store(after)
	oldV, newV := diffSettings(before, after)
	if len(newV) > 0 {
		s.audit.Record(ctx, actorID, audit.EventFederationSettingsUpdated, map[string]any{"old": oldV, "new": newV})
	}
	return after, nil
}

func diffSettings(a, b Settings) (map[string]any, map[string]any) {
	oldV, newV := map[string]any{}, map[string]any{}
	add := func(name string, x, y any) {
		if fmt.Sprint(x) != fmt.Sprint(y) {
			oldV[name], newV[name] = x, y
		}
	}
	add(FieldMode, a.Mode, b.Mode)
	add(FieldAllow, a.Allow, b.Allow)
	add(FieldBlock, a.Block, b.Block)
	add(FieldDirectoryURL, a.DirectoryURL, b.DirectoryURL)
	add(FieldRemoteUploadQuota, a.RemoteUploadQuota, b.RemoteUploadQuota)
	add(FieldRemoteVoice, a.RemoteVoice, b.RemoteVoice)
	return oldV, newV
}
