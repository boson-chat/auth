// Package social is the friendships / friend_requests / user_blocks /
// privacy_settings / calls repository (migration 12).
package social

import (
	"context"
	"errors"
	"time"

	"github.com/boson-chat/auth/internal/db"
	"github.com/boson-chat/auth/internal/db/repositories"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// Who can call me.
const (
	CallsNobody   = "nobody"
	CallsFriends  = "friends"
	CallsEveryone = "everyone"
)

// Who can send me friend requests.
const (
	RequestsNobody   = "nobody"
	RequestsServers  = "servers"
	RequestsEveryone = "everyone"
)

// Call states.
const (
	CallRinging     = "ringing"
	CallAnswered    = "answered"
	CallDeclined    = "declined"
	CallMissed      = "missed"
	CallEnded       = "ended"
	CallUnavailable = "unavailable"
)

// Privacy is a privacy_settings row (defaults when the user has none).
type Privacy struct {
	UserID         string
	Calls          string
	DoNotDisturb   bool
	FriendRequests string
	UpdatedAt      time.Time
}

func (Privacy) TableName() string { return "privacy_settings" }

// DefaultPrivacy is what a user without a row has.
func DefaultPrivacy(userID string) *Privacy {
	return &Privacy{UserID: userID, Calls: CallsFriends, FriendRequests: RequestsEveryone}
}

// Friendship is one direction of a friendship: Friend as seen by User.
type Friendship struct {
	UserID         string
	FriendID       string
	CanCallAnytime bool
	CreatedAt      time.Time
}

func (Friendship) TableName() string { return "friendships" }

type Request struct {
	FromID    string
	ToID      string
	Hidden    bool
	CreatedAt time.Time
}

func (Request) TableName() string { return "friend_requests" }

type Block struct {
	UserID    string
	BlockedID string
	CreatedAt time.Time
}

func (Block) TableName() string { return "user_blocks" }

type Call struct {
	ID         string
	CallerID   string
	CalleeID   string
	Video      bool
	State      string
	MissedSeen bool
	CreatedAt  time.Time
	AnsweredAt *time.Time
	EndedAt    *time.Time
}

func (Call) TableName() string { return "calls" }

// Person is another user in a list, with when the relation started.
type Person struct {
	UserID         string    `gorm:"column:user_id"`
	Username       string    `gorm:"column:username"`
	DisplayName    string    `gorm:"column:display_name"`
	CanCallAnytime bool      `gorm:"column:can_call_anytime"`
	Since          time.Time `gorm:"column:since"`
}

// Relation is how two users stand, from one side.
type Relation struct {
	// Friends both ways (a friendship is always symmetric).
	Friends bool
	// MineAnytime: the other may call me anytime. TheirsAnytime: I may call
	// them anytime (their switch for me).
	MineAnytime, TheirsAnytime bool
	// IBlocked: I blocked them. TheyBlocked: they blocked me.
	IBlocked, TheyBlocked bool
	// Outgoing: I sent them a request (hidden or not). Incoming: they sent
	// me a visible one.
	Outgoing, Incoming bool
	// IncomingHidden: they sent me one I'll never see.
	IncomingHidden bool
}

var ErrStateChanged = errors.New("call state changed")

type SocialRepositoryImpl interface {
	Privacy(ctx context.Context, userID string) (*Privacy, error)
	SavePrivacy(ctx context.Context, p *Privacy) error

	Relation(ctx context.Context, me, other string) (*Relation, error)
	Friends(ctx context.Context, userID string) ([]*Person, error)
	// IncomingRequests are visible requests to userID; OutgoingRequests all
	// of userID's (hidden ones look sent).
	IncomingRequests(ctx context.Context, userID string) ([]*Person, error)
	OutgoingRequests(ctx context.Context, userID string) ([]*Person, error)
	Blocked(ctx context.Context, userID string) ([]*Person, error)

	// AddFriends makes a and b friends (both rows) and drops requests
	// between them.
	AddFriends(ctx context.Context, a, b string, at time.Time) error
	// RemoveFriends drops the friendship both ways. Reports whether there was one.
	RemoveFriends(ctx context.Context, a, b string) (bool, error)
	SetAnytime(ctx context.Context, userID, friendID string, on bool) (bool, error)
	PutRequest(ctx context.Context, r *Request) error
	// DeleteRequest drops the from → to request. Reports whether there was one.
	DeleteRequest(ctx context.Context, from, to string) (bool, error)
	// Block records it and drops the friendship and requests both ways.
	Block(ctx context.Context, userID, blockedID string, at time.Time) error
	Unblock(ctx context.Context, userID, blockedID string) (bool, error)

	CreateCall(ctx context.Context, c *Call) error
	FindCall(ctx context.Context, id string) (*Call, error)
	// TransitionCall moves a call from one of `from` to `to` (setting the
	// answered / ended time), or returns ErrStateChanged.
	TransitionCall(ctx context.Context, id string, from []string, to string, at time.Time) (*Call, error)
	// RingingFor are calls ringing for callee created after since.
	RingingFor(ctx context.Context, calleeID string, since time.Time) ([]*Call, error)
	// RingingFrom are caller's calls still ringing.
	RingingFrom(ctx context.Context, callerID string) ([]*Call, error)
	// ExpireRinging turns calls ringing since before cutoff into missed ones
	// and returns them.
	ExpireRinging(ctx context.Context, cutoff, at time.Time) ([]*Call, error)
	// EndStale ends answered calls answered before cutoff.
	EndStale(ctx context.Context, cutoff, at time.Time) (int64, error)
	// Missed are the callee's unseen missed calls, newest first.
	Missed(ctx context.Context, calleeID string, limit int) ([]*Call, int64, error)
	MarkMissedSeen(ctx context.Context, calleeID string) error
	// DeleteOldCalls drops finished calls created before cutoff.
	DeleteOldCalls(ctx context.Context, cutoff time.Time) error
}

type SocialRepository struct {
	db *db.DB
}

func NewSocialRepository(d *db.DB) SocialRepositoryImpl {
	return &SocialRepository{db: d}
}

func (r *SocialRepository) Privacy(ctx context.Context, userID string) (*Privacy, error) {
	var p Privacy
	err := r.db.Conn(ctx).Where("user_id = ?", userID).First(&p).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return DefaultPrivacy(userID), nil
	}
	if err != nil {
		return nil, err
	}
	return &p, nil
}

func (r *SocialRepository) SavePrivacy(ctx context.Context, p *Privacy) error {
	return r.db.Conn(ctx).Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "user_id"}},
		DoUpdates: clause.AssignmentColumns([]string{"calls", "do_not_disturb", "friend_requests", "updated_at"}),
	}).Create(p).Error
}

func (r *SocialRepository) Relation(ctx context.Context, me, other string) (*Relation, error) {
	var row struct {
		Mine         *bool `gorm:"column:mine"`
		Theirs       *bool `gorm:"column:theirs"`
		IBlocked     bool  `gorm:"column:i_blocked"`
		TheyBlocked  bool  `gorm:"column:they_blocked"`
		Outgoing     bool  `gorm:"column:outgoing"`
		Incoming     *bool `gorm:"column:incoming"`
		IncomingHide *bool `gorm:"column:incoming_hide"`
	}
	err := r.db.Conn(ctx).Raw(`SELECT
		(SELECT can_call_anytime FROM friendships WHERE user_id = @me AND friend_id = @other) AS mine,
		(SELECT can_call_anytime FROM friendships WHERE user_id = @other AND friend_id = @me) AS theirs,
		EXISTS (SELECT 1 FROM user_blocks WHERE user_id = @me AND blocked_id = @other) AS i_blocked,
		EXISTS (SELECT 1 FROM user_blocks WHERE user_id = @other AND blocked_id = @me) AS they_blocked,
		EXISTS (SELECT 1 FROM friend_requests WHERE from_id = @me AND to_id = @other) AS outgoing,
		(SELECT NOT hidden FROM friend_requests WHERE from_id = @other AND to_id = @me) AS incoming,
		(SELECT hidden FROM friend_requests WHERE from_id = @other AND to_id = @me) AS incoming_hide`,
		map[string]any{"me": me, "other": other}).Scan(&row).Error
	if err != nil {
		return nil, err
	}
	rel := &Relation{IBlocked: row.IBlocked, TheyBlocked: row.TheyBlocked, Outgoing: row.Outgoing}
	if row.Mine != nil && row.Theirs != nil {
		rel.Friends, rel.MineAnytime, rel.TheirsAnytime = true, *row.Mine, *row.Theirs
	}
	rel.Incoming = row.Incoming != nil && *row.Incoming
	rel.IncomingHidden = row.IncomingHide != nil && *row.IncomingHide
	return rel, nil
}

func (r *SocialRepository) people(ctx context.Context, query string, userID string) ([]*Person, error) {
	var out []*Person
	err := r.db.Conn(ctx).Raw(query, map[string]any{"me": userID}).Scan(&out).Error
	return out, err
}

func (r *SocialRepository) Friends(ctx context.Context, userID string) ([]*Person, error) {
	return r.people(ctx, `SELECT u.id AS user_id, u.username, u.display_name, f.can_call_anytime, f.created_at AS since
		FROM friendships f JOIN users u ON u.id = f.friend_id
		WHERE f.user_id = @me AND u.disabled_at IS NULL ORDER BY u.username_folded`, userID)
}

func (r *SocialRepository) IncomingRequests(ctx context.Context, userID string) ([]*Person, error) {
	return r.people(ctx, `SELECT u.id AS user_id, u.username, u.display_name, q.created_at AS since
		FROM friend_requests q JOIN users u ON u.id = q.from_id
		WHERE q.to_id = @me AND NOT q.hidden AND u.disabled_at IS NULL ORDER BY q.created_at DESC`, userID)
}

func (r *SocialRepository) OutgoingRequests(ctx context.Context, userID string) ([]*Person, error) {
	return r.people(ctx, `SELECT u.id AS user_id, u.username, u.display_name, q.created_at AS since
		FROM friend_requests q JOIN users u ON u.id = q.to_id
		WHERE q.from_id = @me ORDER BY q.created_at DESC`, userID)
}

func (r *SocialRepository) Blocked(ctx context.Context, userID string) ([]*Person, error) {
	return r.people(ctx, `SELECT u.id AS user_id, u.username, u.display_name, b.created_at AS since
		FROM user_blocks b JOIN users u ON u.id = b.blocked_id
		WHERE b.user_id = @me ORDER BY u.username_folded`, userID)
}

func (r *SocialRepository) dropRequests(ctx context.Context, a, b string) error {
	return r.db.Conn(ctx).Where("(from_id = ? AND to_id = ?) OR (from_id = ? AND to_id = ?)", a, b, b, a).Delete(&Request{}).Error
}

func (r *SocialRepository) AddFriends(ctx context.Context, a, b string, at time.Time) error {
	return r.db.WithTx(ctx, func(ctx context.Context) error {
		if err := r.dropRequests(ctx, a, b); err != nil {
			return err
		}
		rows := []*Friendship{{UserID: a, FriendID: b, CreatedAt: at}, {UserID: b, FriendID: a, CreatedAt: at}}
		return r.db.Conn(ctx).Clauses(clause.OnConflict{DoNothing: true}).Create(&rows).Error
	})
}

func (r *SocialRepository) RemoveFriends(ctx context.Context, a, b string) (bool, error) {
	res := r.db.Conn(ctx).Where("(user_id = ? AND friend_id = ?) OR (user_id = ? AND friend_id = ?)", a, b, b, a).Delete(&Friendship{})
	return res.RowsAffected > 0, res.Error
}

func (r *SocialRepository) SetAnytime(ctx context.Context, userID, friendID string, on bool) (bool, error) {
	res := r.db.Conn(ctx).Model(&Friendship{}).Where("user_id = ? AND friend_id = ?", userID, friendID).Update("can_call_anytime", on)
	return res.RowsAffected > 0, res.Error
}

func (r *SocialRepository) PutRequest(ctx context.Context, q *Request) error {
	return r.db.Conn(ctx).Clauses(clause.OnConflict{DoNothing: true}).Create(q).Error
}

func (r *SocialRepository) DeleteRequest(ctx context.Context, from, to string) (bool, error) {
	res := r.db.Conn(ctx).Where("from_id = ? AND to_id = ?", from, to).Delete(&Request{})
	return res.RowsAffected > 0, res.Error
}

func (r *SocialRepository) Block(ctx context.Context, userID, blockedID string, at time.Time) error {
	return r.db.WithTx(ctx, func(ctx context.Context) error {
		if _, err := r.RemoveFriends(ctx, userID, blockedID); err != nil {
			return err
		}
		// Their request to me goes; mine to them too.
		if err := r.dropRequests(ctx, userID, blockedID); err != nil {
			return err
		}
		return r.db.Conn(ctx).Clauses(clause.OnConflict{DoNothing: true}).
			Create(&Block{UserID: userID, BlockedID: blockedID, CreatedAt: at}).Error
	})
}

func (r *SocialRepository) Unblock(ctx context.Context, userID, blockedID string) (bool, error) {
	res := r.db.Conn(ctx).Where("user_id = ? AND blocked_id = ?", userID, blockedID).Delete(&Block{})
	return res.RowsAffected > 0, res.Error
}

func (r *SocialRepository) CreateCall(ctx context.Context, c *Call) error {
	return r.db.Conn(ctx).Create(c).Error
}

func (r *SocialRepository) FindCall(ctx context.Context, id string) (*Call, error) {
	var c Call
	if err := r.db.Conn(ctx).Where("id = ?", id).First(&c).Error; err != nil {
		return nil, repositories.NotFound(err)
	}
	return &c, nil
}

func (r *SocialRepository) TransitionCall(ctx context.Context, id string, from []string, to string, at time.Time) (*Call, error) {
	set := map[string]any{"state": to}
	switch to {
	case CallAnswered:
		set["answered_at"] = at
	default:
		set["ended_at"] = at
	}
	var out []*Call
	res := r.db.Conn(ctx).Model(&out).Clauses(clause.Returning{}).
		Where("id = ? AND state IN ?", id, from).Updates(set)
	if res.Error != nil {
		return nil, res.Error
	}
	if len(out) == 0 {
		return nil, ErrStateChanged
	}
	return out[0], nil
}

func (r *SocialRepository) RingingFor(ctx context.Context, calleeID string, since time.Time) ([]*Call, error) {
	var out []*Call
	err := r.db.Conn(ctx).Where("callee_id = ? AND state = ? AND created_at > ?", calleeID, CallRinging, since).
		Order("created_at").Find(&out).Error
	return out, err
}

func (r *SocialRepository) RingingFrom(ctx context.Context, callerID string) ([]*Call, error) {
	var out []*Call
	err := r.db.Conn(ctx).Where("caller_id = ? AND state = ?", callerID, CallRinging).Find(&out).Error
	return out, err
}

func (r *SocialRepository) ExpireRinging(ctx context.Context, cutoff, at time.Time) ([]*Call, error) {
	var out []*Call
	err := r.db.Conn(ctx).Model(&out).Clauses(clause.Returning{}).
		Where("state = ? AND created_at < ?", CallRinging, cutoff).
		Updates(map[string]any{"state": CallMissed, "ended_at": at}).Error
	return out, err
}

func (r *SocialRepository) EndStale(ctx context.Context, cutoff, at time.Time) (int64, error) {
	res := r.db.Conn(ctx).Model(&Call{}).Where("state = ? AND answered_at < ?", CallAnswered, cutoff).
		Updates(map[string]any{"state": CallEnded, "ended_at": at})
	return res.RowsAffected, res.Error
}

func (r *SocialRepository) Missed(ctx context.Context, calleeID string, limit int) ([]*Call, int64, error) {
	q := r.db.Conn(ctx).Model(&Call{}).Where("callee_id = ? AND state = ? AND NOT missed_seen", calleeID, CallMissed)
	var n int64
	if err := q.Count(&n).Error; err != nil {
		return nil, 0, err
	}
	if limit <= 0 {
		return nil, n, nil
	}
	var out []*Call
	err := r.db.Conn(ctx).Where("callee_id = ? AND state = ? AND NOT missed_seen", calleeID, CallMissed).
		Order("created_at DESC").Limit(limit).Find(&out).Error
	return out, n, err
}

func (r *SocialRepository) MarkMissedSeen(ctx context.Context, calleeID string) error {
	return r.db.Conn(ctx).Model(&Call{}).Where("callee_id = ? AND state = ? AND NOT missed_seen", calleeID, CallMissed).
		Update("missed_seen", true).Error
}

func (r *SocialRepository) DeleteOldCalls(ctx context.Context, cutoff time.Time) error {
	return r.db.Conn(ctx).Where("created_at < ? AND state NOT IN ?", cutoff, []string{CallRinging, CallAnswered}).Delete(&Call{}).Error
}
