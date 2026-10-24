package store

import (
	"context"
	"path/filepath"
	"slices"
	"testing"
)

func open(t *testing.T, url string) *Store {
	t.Helper()
	s, err := Open(context.Background(), url)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func TestMarks(t *testing.T) {
	ctx := context.Background()
	url := "sqlite:" + filepath.Join(t.TempDir(), "test.db")
	s := open(t, url)
	uid := s.Anonymous()
	if uid == 0 {
		t.Fatal("no anonymous user")
	}

	m := &Mark{UserID: uid, Kind: "image", Key: "registry.example.com/shop/web", State: Hidden, Note: "checked", Findings: []string{"a", "b"}}
	if err := s.PutMark(ctx, m); err != nil {
		t.Fatal(err)
	}
	v := s.Version()
	// Same kind and key: replaced, ID and Created kept.
	again := &Mark{UserID: uid, Kind: "image", Key: "registry.example.com/shop/web", State: Flagged, Note: "rechecked", Findings: []string{"a", "b", "c"}}
	if err := s.PutMark(ctx, again); err != nil {
		t.Fatal(err)
	}
	if again.ID != m.ID || !again.Created.Equal(m.Created) || s.Version() == v {
		t.Errorf("upsert: id %d/%d created %v/%v version %d/%d", again.ID, m.ID, again.Created, m.Created, s.Version(), v)
	}
	if err := s.PutMark(ctx, &Mark{UserID: uid, Kind: "cve", Key: "CVE-2024-0001", State: Hidden}); err != nil {
		t.Fatal(err)
	}

	other, err := s.User(ctx, "someone")
	if err != nil {
		t.Fatal(err)
	}
	if again, _ := s.User(ctx, "someone"); again != other || other == uid {
		t.Errorf("user ids: %d, %d, anonymous %d", other, again, uid)
	}
	if err := s.PutMark(ctx, &Mark{UserID: other, Kind: "cve", Key: "CVE-2024-0001", State: Flagged}); err != nil {
		t.Fatal(err)
	}

	// Survives a reopen.
	_ = s.Close()
	s = open(t, url)
	if s.Anonymous() != uid {
		t.Errorf("anonymous user changed: %d, was %d", s.Anonymous(), uid)
	}
	list, err := s.Marks(ctx, uid)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 2 || list[1].Note != "rechecked" || list[1].State != Flagged || list[0].State != Hidden || !slices.Equal(list[1].Findings, []string{"a", "b", "c"}) || list[0].Findings == nil {
		t.Fatalf("marks = %+v", list)
	}

	if ok, err := s.DeleteMark(ctx, other, m.ID); ok || err != nil {
		t.Errorf("deleted another user's mark: %v %v", ok, err)
	}
	if ok, err := s.DeleteMark(ctx, uid, m.ID); !ok || err != nil {
		t.Errorf("delete: %v %v", ok, err)
	}
	if list, _ := s.Marks(ctx, uid); len(list) != 1 {
		t.Errorf("after delete: %d marks", len(list))
	}
}

func TestOpenURL(t *testing.T) {
	open(t, "")
	for _, url := range []string{"postgres://localhost/trivyal", "sqlite:"} {
		if _, err := Open(context.Background(), url); err == nil {
			t.Errorf("Open(%q) did not fail", url)
		}
	}
}

// Marks saved before marks had a state are hides.
func TestStateDefault(t *testing.T) {
	ctx := context.Background()
	s := open(t, "")
	if _, err := s.db.ExecContext(ctx, `INSERT INTO marks (user_id, kind, key, note, findings, created, updated)
		VALUES (?, 'cve', 'CVE-2024-0001', '', '[]', ?, ?)`, s.Anonymous(), now(), now()); err != nil {
		t.Fatal(err)
	}
	list, err := s.Marks(ctx, s.Anonymous())
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 || list[0].State != Hidden {
		t.Errorf("marks = %+v", list)
	}
}
