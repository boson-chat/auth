// Package signingkeytest provides an in-memory SigningKeyRepositoryImpl for tests.
package signingkeytest

import (
	"context"
	"slices"
	"sync"
	"time"

	"github.com/boson-chat/auth/internal/db/repositories"
	"github.com/boson-chat/auth/internal/db/repositories/signingkey"
)

type MemRepository struct {
	mu   sync.Mutex
	keys map[string]*signingkey.SigningKey
}

func New() *MemRepository {
	return &MemRepository{keys: map[string]*signingkey.SigningKey{}}
}

func (m *MemRepository) LockRotation(context.Context) error { return nil }

func (m *MemRepository) Create(_ context.Context, k *signingkey.SigningKey) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	c := *k
	m.keys[k.KID] = &c
	return nil
}

func (m *MemRepository) list(keep func(*signingkey.SigningKey) bool) []*signingkey.SigningKey {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []*signingkey.SigningKey
	for _, k := range m.keys {
		if keep(k) {
			c := *k
			out = append(out, &c)
		}
	}
	slices.SortFunc(out, func(a, b *signingkey.SigningKey) int { return a.ActivatedAt.Compare(b.ActivatedAt) })
	return out
}

func (m *MemRepository) ListUsable(_ context.Context, after time.Time) ([]*signingkey.SigningKey, error) {
	return m.list(func(k *signingkey.SigningKey) bool { return k.RetiredAt == nil || k.RetiredAt.After(after) }), nil
}

func (m *MemRepository) ListAll(context.Context) ([]*signingkey.SigningKey, error) {
	return m.list(func(*signingkey.SigningKey) bool { return true }), nil
}

func (m *MemRepository) Retire(_ context.Context, kid string, at time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	k, ok := m.keys[kid]
	if !ok {
		return repositories.ErrNotFound
	}
	k.RetiredAt = &at
	return nil
}

// Len is the number of stored keys.
func (m *MemRepository) Len() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.keys)
}
