package audit

import (
	"context"
	"testing"

	auditrepo "github.com/boson-chat/auth/internal/db/repositories/audit"
	"github.com/boson-chat/auth/internal/reqmeta"
)

type memRepo struct{ entries []*auditrepo.Entry }

func (m *memRepo) Create(_ context.Context, e *auditrepo.Entry) error {
	m.entries = append(m.entries, e)
	return nil
}

func (m *memRepo) List(context.Context, auditrepo.Filter) ([]*auditrepo.EntryView, error) {
	return nil, nil
}

// Acting-API requests (reqmeta.Via) record meta.via without touching the
// caller's map; other requests record meta as given.
func TestRecordAddsVia(t *testing.T) {
	repo := &memRepo{}
	s := NewAuditService(repo)
	meta := map[string]any{"role_id": "rol_x"}
	s.Record(reqmeta.With(context.Background(), reqmeta.Meta{IP: "192.0.2.1", Via: "roleserv"}), "usr_a", EventRoleCreated, meta)
	s.Record(context.Background(), "usr_a", EventRoleCreated, meta)
	s.RecordTarget(reqmeta.With(context.Background(), reqmeta.Meta{Via: "roleserv"}), "usr_a", "usr_b", EventUserRolesChanged, nil)
	if got := repo.entries[0].Meta; got["via"] != "roleserv" || got["role_id"] != "rol_x" || repo.entries[0].IP != "192.0.2.1" {
		t.Fatalf("acting entry: %+v", repo.entries[0])
	}
	if _, ok := repo.entries[1].Meta["via"]; ok || len(meta) != 1 {
		t.Fatalf("plain entry has via (or meta was mutated): %v %v", repo.entries[1].Meta, meta)
	}
	if repo.entries[2].Meta["via"] != "roleserv" || *repo.entries[2].TargetUserID != "usr_b" {
		t.Fatalf("nil meta: %+v", repo.entries[2])
	}
}
