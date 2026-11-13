// Package invite mints and redeems registration invite codes.
package invite

import (
	"context"
	"errors"
	"time"

	"github.com/boson-chat/auth/internal/apperr"
	"github.com/boson-chat/auth/internal/db/repositories"
	inviterepo "github.com/boson-chat/auth/internal/db/repositories/invite"
	"github.com/boson-chat/auth/internal/ids"
	"github.com/boson-chat/auth/internal/opaque"
)

const CodePrefix = "inv_"

type InviteServiceImpl interface {
	// Create returns the plaintext code (shown once) and the stored invite.
	Create(ctx context.Context, createdBy string, maxUses int, ttl time.Duration, note string) (string, *inviterepo.Invite, error)
	// Redeem consumes one use. Call inside the registration transaction.
	Redeem(ctx context.Context, code string) error
	List(ctx context.Context, limit int) ([]*inviterepo.Invite, error)
	Revoke(ctx context.Context, id string) error
}

type InviteService struct {
	Repository inviterepo.InviteRepositoryImpl
	Now        func() time.Time
}

func NewInviteService(repo inviterepo.InviteRepositoryImpl, now func() time.Time) InviteServiceImpl {
	if now == nil {
		now = time.Now
	}
	return &InviteService{Repository: repo, Now: now}
}

func (s *InviteService) Create(ctx context.Context, createdBy string, maxUses int, ttl time.Duration, note string) (string, *inviterepo.Invite, error) {
	if maxUses < 1 || maxUses > 10000 {
		return "", nil, apperr.Invalid("max_uses must be between 1 and 10000")
	}
	if len(note) > 200 {
		return "", nil, apperr.Invalid("note must be at most 200 characters")
	}
	now := s.Now().UTC()
	code := opaque.New(CodePrefix)
	inv := &inviterepo.Invite{
		ID: ids.New(ids.Invite), CodeHash: opaque.Hash(code), Note: note, MaxUses: maxUses, CreatedAt: now,
	}
	if createdBy != "" {
		inv.CreatedBy = &createdBy
	}
	if ttl > 0 {
		exp := now.Add(ttl)
		inv.ExpiresAt = &exp
	}
	if err := s.Repository.Create(ctx, inv); err != nil {
		return "", nil, err
	}
	return code, inv, nil
}

func (s *InviteService) Redeem(ctx context.Context, code string) error {
	if code == "" {
		return apperr.ErrInviteRequired
	}
	inv, err := s.Repository.FindByHashForUpdate(ctx, opaque.Hash(code))
	if errors.Is(err, repositories.ErrNotFound) {
		return apperr.ErrInviteRequired
	}
	if err != nil {
		return err
	}
	if !inv.Usable(s.Now().UTC()) {
		return apperr.ErrInviteRequired
	}
	return s.Repository.IncrementUses(ctx, inv.ID)
}

func (s *InviteService) List(ctx context.Context, limit int) ([]*inviterepo.Invite, error) {
	return s.Repository.List(ctx, limit)
}

func (s *InviteService) Revoke(ctx context.Context, id string) error {
	err := s.Repository.Revoke(ctx, id, s.Now().UTC())
	if errors.Is(err, repositories.ErrNotFound) {
		return apperr.ErrNotFound
	}
	return err
}
