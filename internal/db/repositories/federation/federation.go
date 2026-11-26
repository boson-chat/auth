// Package federation is the repository for federated accounts, banned
// identities, the assertion replay cache and the federation settings row.
package federation

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/boson-chat/auth/internal/db"
	"github.com/boson-chat/auth/internal/db/repositories"
	"github.com/boson-chat/auth/internal/db/repositories/accountremoval"
	"gorm.io/gorm/clause"
)

// SuspendedBan: a federation ban disabled the local user (federated_accounts.suspended_by).
const SuspendedBan = "ban"

// ErrIdentityTaken: (issuer, subject) already has a local account.
var ErrIdentityTaken = errors.New("federated identity already has an account")

// Account links a local user to a home server identity.
type Account struct {
	UserID        string
	Issuer        string
	Subject       string
	HomeDomain    string
	HomeUsername  string
	Picture       *string
	EmailVerified bool
	SuspendedBy   *string
	QuotaApplied  *string
	// DomainBlockedAt: set while the home domain is blocked (and the IRC
	// disconnect was queued); see MarkDomainBlocked.
	DomainBlockedAt *time.Time
	CreatedAt       time.Time
	LastLoginAt     time.Time
}

func (Account) TableName() string { return "federated_accounts" }

// Identity is the user@domain form shown to people.
func (a *Account) Identity() string { return a.HomeUsername + "@" + a.HomeDomain }

// AccountView is an account with its local user's fields, for admin lists.
type AccountView struct {
	Account      `gorm:"embedded"`
	Username     string
	DisplayName  string
	DisabledAt   *time.Time
	LastActiveAt *time.Time
	Banned       bool
	BannedAt     *time.Time
	BanReason    *string
	// Sessions is the number of active sessions.
	Sessions int
}

// Ban is a banned identity.
type Ban struct {
	Issuer    string
	Subject   string
	Identity  string
	Reason    string
	CreatedBy *string
	CreatedAt time.Time
}

func (Ban) TableName() string { return "federation_bans" }

// SettingsRow holds the stored overrides; nil follows the env default.
type SettingsRow struct {
	ID                bool `gorm:"primaryKey"`
	Mode              *string
	Allow             *repositories.StringList
	Block             *repositories.StringList
	DirectoryURL      *string
	RemoteUploadQuota *string
	RemoteVoice       *bool
	UpdatedAt         *time.Time
	UpdatedBy         *string
}

func (SettingsRow) TableName() string { return "federation_settings" }

type replayRow struct {
	Key       string
	ExpiresAt time.Time
}

func (replayRow) TableName() string { return "federation_replay" }

// ListFilter selects federated accounts for the admin list.
type ListFilter struct {
	Query  string // substring of handle, home username or home domain
	Domain string // exact home domain
	Limit  int
	Offset int
}

type FederationRepositoryImpl interface {
	Create(ctx context.Context, a *Account) error
	FindByIdentity(ctx context.Context, issuer, subject string) (*Account, error)
	FindByUserID(ctx context.Context, userID string) (*Account, error)
	// IsFederated reports whether userID is a federated account.
	IsFederated(ctx context.Context, userID string) (bool, error)
	// Touch records a login and refreshes the home profile.
	Touch(ctx context.Context, userID, homeUsername string, picture *string, emailVerified bool, at time.Time) error
	SetSuspendedBy(ctx context.Context, userID string, by *string) error
	SetQuotaApplied(ctx context.Context, userID, applied string) error
	List(ctx context.Context, f ListFilter) ([]*AccountView, int64, error)
	View(ctx context.Context, userID string) (*AccountView, error)
	Count(ctx context.Context) (int64, error)
	// ByUsernames maps folded usernames to the federated accounts behind
	// them (local users are absent).
	ByUsernames(ctx context.Context, folded []string) (map[string]*Account, error)
	// ByDomain returns the accounts whose home domain matches (see
	// config.DomainListMatches): "*.x" matches x and its subdomains.
	ByDomain(ctx context.Context, entry string) ([]*Account, error)
	// HomeDomains lists the distinct home domains of all federated accounts.
	HomeDomains(ctx context.Context) ([]string, error)
	// MarkDomainBlocked sets domain_blocked_at on the accounts from domains
	// (exact home domains) that don't have it yet, queues a
	// "domain_blocked" IRC disconnect for each (irc_account_removals) and
	// returns their user ids.
	MarkDomainBlocked(ctx context.Context, domains []string, at time.Time) ([]string, error)
	// ClearDomainBlocked clears domain_blocked_at on the accounts whose home
	// domain is not in domains (no longer blocked); their queued
	// "domain_blocked" disconnects stop applying.
	ClearDomainBlocked(ctx context.Context, domains []string) (int64, error)
	// QueueIRCDisconnect writes a "sessions_revoked" IRC disconnect for
	// each of userIDs (federated accounts only).
	QueueIRCDisconnect(ctx context.Context, userIDs []string, at time.Time) error

	Ban(ctx context.Context, b *Ban) error
	Unban(ctx context.Context, issuer, subject string) error
	IsBanned(ctx context.Context, issuer, subject string) (bool, error)
	ListBans(ctx context.Context) ([]*Ban, error)

	// MarkSeen stores key until expires; false when it was already there
	// (a replay).
	MarkSeen(ctx context.Context, key string, expires time.Time) (bool, error)
	PruneSeen(ctx context.Context, now time.Time) error

	GetSettings(ctx context.Context) (*SettingsRow, error)
	GetSettingsForUpdate(ctx context.Context) (*SettingsRow, error)
	SaveSettings(ctx context.Context, r *SettingsRow) error
}

type FederationRepository struct {
	db *db.DB
}

func NewFederationRepository(d *db.DB) FederationRepositoryImpl {
	return &FederationRepository{db: d}
}

func (r *FederationRepository) Create(ctx context.Context, a *Account) error {
	err := r.db.Conn(ctx).Create(a).Error
	if repositories.UniqueViolation(err) != "" {
		return ErrIdentityTaken
	}
	return err
}

func (r *FederationRepository) FindByIdentity(ctx context.Context, issuer, subject string) (*Account, error) {
	var a Account
	err := r.db.Conn(ctx).Where("issuer = ? AND subject = ?", issuer, subject).First(&a).Error
	if err != nil {
		return nil, repositories.NotFound(err)
	}
	return &a, nil
}

func (r *FederationRepository) FindByUserID(ctx context.Context, userID string) (*Account, error) {
	if userID == "" {
		return nil, repositories.ErrNotFound
	}
	var a Account
	if err := r.db.Conn(ctx).Where("user_id = ?", userID).First(&a).Error; err != nil {
		return nil, repositories.NotFound(err)
	}
	return &a, nil
}

func (r *FederationRepository) IsFederated(ctx context.Context, userID string) (bool, error) {
	var n int64
	err := r.db.Conn(ctx).Model(&Account{}).Where("user_id = ?", userID).Count(&n).Error
	return n > 0, err
}

func (r *FederationRepository) Touch(ctx context.Context, userID, homeUsername string, picture *string, emailVerified bool, at time.Time) error {
	return r.db.Conn(ctx).Model(&Account{}).Where("user_id = ?", userID).Updates(map[string]any{
		"home_username": homeUsername, "picture": picture, "email_verified": emailVerified, "last_login_at": at,
	}).Error
}

func (r *FederationRepository) SetSuspendedBy(ctx context.Context, userID string, by *string) error {
	return r.db.Conn(ctx).Model(&Account{}).Where("user_id = ?", userID).Update("suspended_by", by).Error
}

func (r *FederationRepository) SetQuotaApplied(ctx context.Context, userID, applied string) error {
	return r.db.Conn(ctx).Model(&Account{}).Where("user_id = ?", userID).Update("quota_applied", applied).Error
}

func likePattern(s string) string {
	return "%" + strings.NewReplacer(`\`, `\\`, "%", `\%`, "_", `\_`).Replace(s) + "%"
}

func (r *FederationRepository) List(ctx context.Context, f ListFilter) ([]*AccountView, int64, error) {
	q := r.db.Conn(ctx).Table("federated_accounts AS f").Joins("JOIN users u ON u.id = f.user_id")
	if s := strings.TrimSpace(f.Query); s != "" {
		like := likePattern(s)
		q = q.Where("u.username ILIKE ? OR f.home_username ILIKE ? OR f.home_domain ILIKE ? OR u.display_name ILIKE ?", like, like, like, like)
	}
	if d := strings.ToLower(strings.TrimSpace(f.Domain)); d != "" {
		q = q.Where("f.home_domain = ?", d)
	}
	var total int64
	if err := q.Count(&total).Error; err != nil {
		return nil, 0, err
	}
	var out []*AccountView
	err := q.Select(viewColumns).Joins(banJoin).
		Order("GREATEST(f.last_login_at, COALESCE(u.last_active_at, f.last_login_at)) DESC, f.user_id DESC").
		Limit(f.Limit).Offset(f.Offset).Scan(&out).Error
	return out, total, err
}

const (
	viewColumns = `f.*, u.username, u.display_name, u.disabled_at, u.last_active_at,
		b.issuer IS NOT NULL AS banned, b.created_at AS banned_at, b.reason AS ban_reason,
		(SELECT count(*) FROM sessions s WHERE s.user_id = f.user_id AND s.revoked_at IS NULL AND s.expires_at > now()) AS sessions`
	banJoin = "LEFT JOIN federation_bans b ON b.issuer = f.issuer AND b.subject = f.subject"
)

// View is one account with its user's fields (ErrNotFound for a local user).
func (r *FederationRepository) View(ctx context.Context, userID string) (*AccountView, error) {
	var out []*AccountView
	err := r.db.Conn(ctx).Table("federated_accounts AS f").Joins("JOIN users u ON u.id = f.user_id").Joins(banJoin).
		Select(viewColumns).Where("f.user_id = ?", userID).Scan(&out).Error
	if err != nil {
		return nil, err
	}
	if len(out) == 0 {
		return nil, repositories.ErrNotFound
	}
	return out[0], nil
}

func (r *FederationRepository) ByDomain(ctx context.Context, entry string) ([]*Account, error) {
	q := r.db.Conn(ctx).Model(&Account{})
	if base, ok := strings.CutPrefix(entry, "*."); ok {
		q = q.Where("home_domain = ? OR home_domain LIKE ?", base, "%."+strings.NewReplacer(`\`, `\\`, "%", `\%`, "_", `\_`).Replace(base))
	} else {
		q = q.Where("home_domain = ?", entry)
	}
	var out []*Account
	return out, q.Find(&out).Error
}

func (r *FederationRepository) HomeDomains(ctx context.Context) ([]string, error) {
	var out []string
	return out, r.db.Conn(ctx).Model(&Account{}).Distinct("home_domain").Order("home_domain").Pluck("home_domain", &out).Error
}

func (r *FederationRepository) MarkDomainBlocked(ctx context.Context, domains []string, at time.Time) ([]string, error) {
	if len(domains) == 0 {
		return nil, nil
	}
	var ids []string
	err := r.db.Conn(ctx).Raw(`
WITH marked AS (
    UPDATE federated_accounts SET domain_blocked_at = ?
    WHERE domain_blocked_at IS NULL AND home_domain IN ?
    RETURNING user_id
), queued AS (
    INSERT INTO irc_account_removals (user_id, username, username_folded, reason, at)
    SELECT u.id, u.username, u.username_folded, ?, ? FROM users u JOIN marked m ON m.user_id = u.id ORDER BY u.id
    RETURNING user_id
)
SELECT user_id FROM queued ORDER BY user_id`, at, domains, accountremoval.ReasonDomainBlocked, at).Scan(&ids).Error
	return ids, err
}

func (r *FederationRepository) ClearDomainBlocked(ctx context.Context, domains []string) (int64, error) {
	q := r.db.Conn(ctx).Model(&Account{}).Where("domain_blocked_at IS NOT NULL")
	if len(domains) > 0 {
		q = q.Where("home_domain NOT IN ?", domains)
	}
	res := q.Update("domain_blocked_at", nil)
	return res.RowsAffected, res.Error
}

func (r *FederationRepository) QueueIRCDisconnect(ctx context.Context, userIDs []string, at time.Time) error {
	if len(userIDs) == 0 {
		return nil
	}
	return r.db.Conn(ctx).Exec(`
INSERT INTO irc_account_removals (user_id, username, username_folded, reason, at)
SELECT u.id, u.username, u.username_folded, ?, ?
FROM users u JOIN federated_accounts f ON f.user_id = u.id
WHERE u.id IN ?
ORDER BY u.id`, accountremoval.ReasonSessionsRevoked, at, userIDs).Error
}

func (r *FederationRepository) Ban(ctx context.Context, b *Ban) error {
	return r.db.Conn(ctx).Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "issuer"}, {Name: "subject"}},
		DoUpdates: clause.AssignmentColumns([]string{"identity", "reason", "created_by", "created_at"}),
	}).Create(b).Error
}

func (r *FederationRepository) Unban(ctx context.Context, issuer, subject string) error {
	return r.db.Conn(ctx).Where("issuer = ? AND subject = ?", issuer, subject).Delete(&Ban{}).Error
}

func (r *FederationRepository) IsBanned(ctx context.Context, issuer, subject string) (bool, error) {
	var n int64
	err := r.db.Conn(ctx).Model(&Ban{}).Where("issuer = ? AND subject = ?", issuer, subject).Count(&n).Error
	return n > 0, err
}

func (r *FederationRepository) ListBans(ctx context.Context) ([]*Ban, error) {
	var out []*Ban
	return out, r.db.Conn(ctx).Order("created_at DESC").Find(&out).Error
}

func (r *FederationRepository) MarkSeen(ctx context.Context, key string, expires time.Time) (bool, error) {
	res := r.db.Conn(ctx).Clauses(clause.OnConflict{DoNothing: true}).Create(&replayRow{Key: key, ExpiresAt: expires})
	if res.Error != nil {
		return false, res.Error
	}
	return res.RowsAffected == 1, nil
}

func (r *FederationRepository) PruneSeen(ctx context.Context, now time.Time) error {
	return r.db.Conn(ctx).Where("expires_at < ?", now).Delete(&replayRow{}).Error
}

func (r *FederationRepository) getSettings(ctx context.Context, lock bool) (*SettingsRow, error) {
	var row SettingsRow
	q := r.db.Conn(ctx).Where("id")
	if lock {
		q = q.Clauses(clause.Locking{Strength: "UPDATE"})
	}
	err := repositories.NotFound(q.First(&row).Error)
	if errors.Is(err, repositories.ErrNotFound) {
		return &SettingsRow{ID: true}, nil
	}
	if err != nil {
		return nil, err
	}
	return &row, nil
}

func (r *FederationRepository) GetSettings(ctx context.Context) (*SettingsRow, error) {
	return r.getSettings(ctx, false)
}

func (r *FederationRepository) GetSettingsForUpdate(ctx context.Context) (*SettingsRow, error) {
	return r.getSettings(ctx, true)
}

func (r *FederationRepository) SaveSettings(ctx context.Context, row *SettingsRow) error {
	row.ID = true
	return r.db.Conn(ctx).Clauses(clause.OnConflict{UpdateAll: true}).Create(row).Error
}

func (r *FederationRepository) Count(ctx context.Context) (int64, error) {
	var n int64
	return n, r.db.Conn(ctx).Model(&Account{}).Count(&n).Error
}

func (r *FederationRepository) ByUsernames(ctx context.Context, folded []string) (map[string]*Account, error) {
	out := map[string]*Account{}
	if len(folded) == 0 {
		return out, nil
	}
	var rows []struct {
		Account        `gorm:"embedded"`
		UsernameFolded string
	}
	err := r.db.Conn(ctx).Table("federated_accounts AS f").Joins("JOIN users u ON u.id = f.user_id").
		Select("f.*, u.username_folded").Where("u.username_folded IN ?", folded).Scan(&rows).Error
	for i := range rows {
		out[rows[i].UsernameFolded] = &rows[i].Account
	}
	return out, err
}
