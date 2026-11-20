package authn

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/boson-chat/auth/config"
	"github.com/boson-chat/auth/internal/apperr"
	"github.com/boson-chat/auth/internal/db/repositories"
	"github.com/boson-chat/auth/internal/db/repositories/user"
	"github.com/boson-chat/auth/internal/services/settings"
	"github.com/boson-chat/auth/internal/services/token"
	"github.com/boson-chat/auth/metrics"
)

type fakeSettings struct{ st settings.Settings }

func (f *fakeSettings) Get(context.Context) (settings.Settings, error) { return f.st, nil }
func (f *fakeSettings) Update(context.Context, string, settings.Patch) (settings.Settings, error) {
	return f.st, nil
}
func (f *fakeSettings) SetFile(*config.AccountConfig) {}

// fakeUsers holds accounts by folded username; the embedded interface
// panics on anything else.
type fakeUsers struct {
	user.UserRepositoryImpl
	byFold map[string]*user.User
	err    error
}

func (f *fakeUsers) FindByUsernameFolded(_ context.Context, folded string) (*user.User, error) {
	if f.err != nil {
		return nil, f.err
	}
	if u, ok := f.byFold[folded]; ok {
		return u, nil
	}
	return nil, repositories.ErrNotFound
}

type mint struct {
	guestID, nick string
	rooms         []string
}

type fakeTokens struct {
	token.TokenServiceImpl
	minted []mint
}

func (f *fakeTokens) MintGuestVoice(_ context.Context, guestID, nick string, rooms []string) (string, time.Time, error) {
	f.minted = append(f.minted, mint{guestID, nick, rooms})
	return "tok", time.Now().Add(5 * time.Minute), nil
}

func newGuestSvc(access, voice bool) (*AuthnService, *fakeUsers, *fakeTokens) {
	users := &fakeUsers{byFold: map[string]*user.User{"alice": {ID: "usr_1", Username: "alice"}, "b{o}b": {ID: "usr_2", Username: "b[o]b"}}}
	toks := &fakeTokens{}
	s := &AuthnService{Deps: Deps{
		Users: users, Tokens: toks, Metrics: metrics.Noop(),
		Settings: &fakeSettings{st: settings.Settings{GuestAccess: access, GuestVoice: voice}},
	}}
	return s, users, toks
}

const gid = "Gx7_k2-Qm9vT4pLw"

func wantErr(t *testing.T, err error, status int, code string) {
	t.Helper()
	e, ok := apperr.As(err)
	if !ok || e.Status != status || e.Code != code {
		t.Fatalf("want %d %s, got %v", status, code, err)
	}
}

func TestGuestVoiceTokenDisabled(t *testing.T) {
	for _, c := range []struct{ access, voice bool }{{true, false}, {false, true}, {false, false}} {
		s, _, toks := newGuestSvc(c.access, c.voice)
		_, _, err := s.GuestVoiceToken(t.Context(), "Wanderer", gid, nil)
		wantErr(t, err, 403, "guest_voice_disabled")
		if len(toks.minted) != 0 {
			t.Fatal("minted while disabled")
		}
	}
}

func TestGuestVoiceTokenInvalid(t *testing.T) {
	s, _, toks := newGuestSvc(true, true)
	many := make([]string, 33)
	for i := range many {
		many[i] = "r"
	}
	for name, c := range map[string]struct {
		nick, id string
		rooms    []string
		field    string
	}{
		"empty nick":     {"", gid, nil, "nick"},
		"digit first":    {"1abc", gid, nil, "nick"},
		"space":          {"a b", gid, nil, "nick"},
		"too long":       {strings.Repeat("a", 31), gid, nil, "nick"},
		"non-ascii":      {"wänderer", gid, nil, "nick"},
		"empty id":       {"Wanderer", "", nil, "guest_id"},
		"short id":       {"Wanderer", strings.Repeat("a", 15), nil, "guest_id"},
		"long id":        {"Wanderer", strings.Repeat("a", 65), nil, "guest_id"},
		"bad id char":    {"Wanderer", "Gx7_k2-Qm9vT4pL!", nil, "guest_id"},
		"id with dot":    {"Wanderer", "Gx7_k2-Qm9vT4p.w", nil, "guest_id"},
		"empty room":     {"Wanderer", gid, []string{""}, ""},
		"too many rooms": {"Wanderer", gid, many, ""},
		"long room":      {"Wanderer", gid, []string{strings.Repeat("r", 129)}, ""},
	} {
		_, _, err := s.GuestVoiceToken(t.Context(), c.nick, c.id, c.rooms)
		e, ok := apperr.As(err)
		if !ok || e.Status != 400 || e.Code != "invalid_request" || e.Field != c.field {
			t.Errorf("%s: got %v (field %q)", name, err, func() string {
				if ok {
					return e.Field
				}
				return ""
			}())
		}
	}
	if len(toks.minted) != 0 {
		t.Fatal("minted for an invalid request")
	}
}

func TestGuestVoiceTokenNickRegistered(t *testing.T) {
	s, users, toks := newGuestSvc(true, true)
	for _, n := range []string{"alice", "ALICE", "B[O]B", "b{o}b", "NickServ", "chanserv", "Global"} {
		_, _, err := s.GuestVoiceToken(t.Context(), n, gid, nil)
		wantErr(t, err, 409, "nick_registered")
	}
	if len(toks.minted) != 0 {
		t.Fatal("minted for a registered nick")
	}
	// A database error is not a free name.
	users.err = errors.New("db down")
	if _, _, err := s.GuestVoiceToken(t.Context(), "Wanderer", gid, nil); err == nil || err.Error() != "db down" {
		t.Fatalf("want the db error, got %v", err)
	}
}

func TestGuestVoiceTokenSuccess(t *testing.T) {
	s, _, toks := newGuestSvc(true, true)
	tok, exp, err := s.GuestVoiceToken(t.Context(), "Wand[er]er", gid, []string{"lobby"})
	if err != nil || tok != "tok" || time.Until(exp) <= 0 {
		t.Fatalf("got %q %v %v", tok, exp, err)
	}
	if len(toks.minted) != 1 || toks.minted[0].guestID != gid || toks.minted[0].nick != "Wand[er]er" ||
		len(toks.minted[0].rooms) != 1 || toks.minted[0].rooms[0] != "lobby" {
		t.Fatalf("minted %+v", toks.minted)
	}
	// Exactly 16 and 64 characters are fine.
	for _, id := range []string{strings.Repeat("A", 16), strings.Repeat("z_-9", 16)} {
		if _, _, err := s.GuestVoiceToken(t.Context(), "Wanderer", id, nil); err != nil {
			t.Fatalf("%s: %v", id, err)
		}
	}
}
