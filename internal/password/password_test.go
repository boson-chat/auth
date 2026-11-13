package password

import (
	"strings"
	"testing"

	"golang.org/x/crypto/bcrypt"
)

var fast = Params{MemoryKiB: 1024, Iterations: 1, Parallelism: 1}

func TestHashVerify(t *testing.T) {
	h, err := NewHasher(fast)
	if err != nil {
		t.Fatal(err)
	}
	phc, err := h.Hash("correct horse battery")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(phc, "$argon2id$v=19$m=1024,t=1,p=1$") {
		t.Fatalf("unexpected PHC %q", phc)
	}
	ok, rehash, err := h.Verify("correct horse battery", phc)
	if err != nil || !ok || rehash {
		t.Fatalf("Verify(correct) = %v, %v, %v", ok, rehash, err)
	}
	ok, _, err = h.Verify("wrong horse battery", phc)
	if err != nil || ok {
		t.Fatalf("Verify(wrong) = %v, %v", ok, err)
	}
	phc2, _ := h.Hash("correct horse battery")
	if phc == phc2 {
		t.Fatal("salt not random")
	}
}

func TestParamsChangeNeedsRehash(t *testing.T) {
	old, _ := NewHasher(fast)
	phc, _ := old.Hash("correct horse battery")
	newer, _ := NewHasher(Params{MemoryKiB: 2048, Iterations: 2, Parallelism: 1})
	ok, rehash, err := newer.Verify("correct horse battery", phc)
	if err != nil || !ok || !rehash {
		t.Fatalf("old hash under new params: ok=%v rehash=%v err=%v", ok, rehash, err)
	}
	ok, rehash, _ = newer.Verify("nope nope nope", phc)
	if ok || rehash {
		t.Fatal("wrong password must not ask for rehash")
	}
}

func TestDefaultParamsHash(t *testing.T) {
	if testing.Short() {
		t.Skip("64 MiB hash")
	}
	h, err := NewHasher(DefaultParams)
	if err != nil {
		t.Fatal(err)
	}
	phc, _ := h.Hash("a long enough password")
	if !strings.Contains(phc, "m=65536,t=3,p=2") {
		t.Fatalf("PHC %q does not carry default params", phc)
	}
}

func TestInvalidHashes(t *testing.T) {
	h, _ := NewHasher(fast)
	for _, bad := range []string{
		"", "plain", "$argon2i$v=19$m=1024,t=1,p=1$c2FsdHNhbHQ$aGFzaGhhc2hoYXNoaGFzaA",
		"$argon2id$v=18$m=1024,t=1,p=1$c2FsdHNhbHQ$aGFzaGhhc2hoYXNoaGFzaA",
		"$argon2id$v=19$m=1024,t=0,p=1$c2FsdHNhbHQ$aGFzaGhhc2hoYXNoaGFzaA",
		"$argon2id$v=19$m=99999999,t=1,p=1$c2FsdHNhbHQ$aGFzaGhhc2hoYXNoaGFzaA",
		"$argon2id$v=19$m=1024,t=1,p=1$!!$aGFzaGhhc2hoYXNoaGFzaA",
	} {
		if _, _, err := h.Verify("x", bad); err == nil {
			t.Errorf("Verify accepted %q", bad)
		}
	}
	h.VerifyDummy("anything") // must not panic
}

func TestCheckPolicy(t *testing.T) {
	cases := []struct {
		pw, user, email string
		want            error
	}{
		{"short", "u", "", ErrTooShort},
		{"ééééééééé", "u", "", ErrTooShort}, // 9 runes, 18 bytes
		{strings.Repeat("x", 257), "u", "", ErrTooLong},
		{strings.Repeat("x", 256), "u", "", nil},
		{"AliceAlice1", "alicealice1", "", ErrMatchesIdentity},
		{"me@example.com", "bob", "ME@example.com", ErrMatchesIdentity},
		{"a fine password", "alice", "alice@example.com", nil},
	}
	for _, c := range cases {
		if got := CheckPolicy(c.pw, c.user, c.email); got != c.want {
			t.Errorf("CheckPolicy(%q) = %v, want %v", c.pw, got, c.want)
		}
	}
}

func TestVerifyImportedBcrypt(t *testing.T) {
	h, _ := NewHasher(fast)
	for _, prefix := range []string{"$2a$", "$2b$", "$2y$"} {
		raw, err := bcrypt.GenerateFromPassword([]byte("supabase password"), bcrypt.MinCost)
		if err != nil {
			t.Fatal(err)
		}
		hash := prefix + string(raw[4:])
		if !IsBcrypt(hash) {
			t.Fatalf("IsBcrypt(%q) = false", hash)
		}
		ok, rehash, err := h.Verify("supabase password", hash)
		if err != nil || !ok || !rehash {
			t.Fatalf("%s correct: ok=%v rehash=%v err=%v", prefix, ok, rehash, err)
		}
		ok, rehash, err = h.Verify("wrong password", hash)
		if err != nil || ok || rehash {
			t.Fatalf("%s wrong: ok=%v rehash=%v err=%v", prefix, ok, rehash, err)
		}
	}
	if _, _, err := h.Verify("x", "$2a$10$tooshort"); err == nil {
		t.Fatal("accepted a truncated bcrypt hash")
	}
	phc, _ := h.Hash("whatever password")
	if IsBcrypt(phc) {
		t.Fatal("argon2id PHC detected as bcrypt")
	}
}
