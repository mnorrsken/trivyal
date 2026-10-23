// Package store keeps what users mark in the UI (hidden findings) in a SQL
// database. It goes through bun, so the same code can run on PostgreSQL
// later; only SQLite is wired up for now.
package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"sync/atomic"
	"time"

	"github.com/uptrace/bun"
	"github.com/uptrace/bun/dialect/sqlitedialect"
	"github.com/uptrace/bun/migrate"
	_ "modernc.org/sqlite" // pure Go, so builds stay CGO_ENABLED=0

	"github.com/mnorrsken/trivyal/internal/store/migrations"
)

// AnonymousSubject is the user everyone is until marks are tied to logins.
const AnonymousSubject = "anonymous"

// User owns marks. Subject is the login's stable ID.
type User struct {
	bun.BaseModel `bun:"table:users"`

	ID      int64     `bun:",pk,autoincrement"`
	Subject string    `bun:",unique,notnull"`
	Created time.Time `bun:",notnull"`
}

// Mark hides one target (an image, a CVE, a workload...) for one user.
// Kind and Key name the target; Findings are the finding IDs it had when it
// was hidden, so findings that turn up later show again.
type Mark struct {
	bun.BaseModel `bun:"table:marks"`

	ID       int64     `bun:",pk,autoincrement"`
	UserID   int64     `bun:",notnull"`
	Kind     string    `bun:",notnull"`
	Key      string    `bun:",notnull"`
	Note     string    `bun:",notnull"`
	Findings []string  `bun:",notnull"`
	Created  time.Time `bun:",notnull"`
	Updated  time.Time `bun:",notnull"`
}

// Store is the database.
type Store struct {
	db   *bun.DB
	ver  atomic.Uint64
	anon int64
}

// Open connects to url and applies the migrations. url is "sqlite:<path>";
// an empty url keeps everything in memory until the process exits.
func Open(ctx context.Context, url string) (*Store, error) {
	dsn, err := sqliteDSN(url)
	if err != nil {
		return nil, err
	}
	sqldb, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("opening database: %w", err)
	}
	// SQLite has one writer; one connection avoids "database is locked" and
	// keeps an in-memory database alive.
	sqldb.SetMaxOpenConns(1)
	s := &Store{db: bun.NewDB(sqldb, sqlitedialect.New())}
	if err := s.migrate(ctx); err != nil {
		_ = s.db.Close()
		return nil, err
	}
	if s.anon, err = s.User(ctx, AnonymousSubject); err != nil {
		_ = s.db.Close()
		return nil, err
	}
	return s, nil
}

func sqliteDSN(url string) (string, error) {
	if url == "" {
		return "file::memory:", nil
	}
	path, ok := strings.CutPrefix(url, "sqlite:")
	if !ok {
		return "", fmt.Errorf("unsupported database url %q: only sqlite:<path> is supported", url)
	}
	path = strings.TrimPrefix(path, "//")
	if path == "" {
		return "", errors.New("database url has no path")
	}
	return "file:" + path + "?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=foreign_keys(1)", nil
}

func (s *Store) migrate(ctx context.Context) error {
	m := migrate.NewMigrator(s.db, migrations.Migrations)
	if err := m.Init(ctx); err != nil {
		return fmt.Errorf("preparing migrations: %w", err)
	}
	if err := m.Lock(ctx); err != nil {
		return fmt.Errorf("locking migrations: %w", err)
	}
	defer func() { _ = m.Unlock(ctx) }()
	if _, err := m.Migrate(ctx); err != nil {
		return fmt.Errorf("migrating database: %w", err)
	}
	return nil
}

// Close closes the database.
func (s *Store) Close() error { return s.db.Close() }

// Version changes on every write, so callers can cache what they read.
func (s *Store) Version() uint64 { return s.ver.Load() }

// Anonymous returns the ID of the anonymous user.
func (s *Store) Anonymous() int64 { return s.anon }

// User returns the ID of the user with subject, creating the user if needed.
func (s *Store) User(ctx context.Context, subject string) (int64, error) {
	u := &User{Subject: subject, Created: time.Now().UTC()}
	if _, err := s.db.NewInsert().Model(u).On("CONFLICT (subject) DO NOTHING").Exec(ctx); err != nil {
		return 0, fmt.Errorf("creating user: %w", err)
	}
	if err := s.db.NewSelect().Model(u).Where("subject = ?", subject).Scan(ctx); err != nil {
		return 0, fmt.Errorf("loading user: %w", err)
	}
	return u.ID, nil
}

// Marks returns a user's marks, most recently changed first.
func (s *Store) Marks(ctx context.Context, userID int64) ([]Mark, error) {
	var out []Mark
	if err := s.db.NewSelect().Model(&out).Where("user_id = ?", userID).OrderExpr("updated DESC, id DESC").Scan(ctx); err != nil {
		return nil, fmt.Errorf("loading marks: %w", err)
	}
	return out, nil
}

// PutMark saves m, replacing the user's mark of the same kind and key. ID
// and Created are kept from the mark it replaces.
func (s *Store) PutMark(ctx context.Context, m *Mark) error {
	now := time.Now().UTC()
	m.Updated = now
	if m.Findings == nil {
		m.Findings = []string{}
	}
	err := s.db.RunInTx(ctx, nil, func(ctx context.Context, tx bun.Tx) error {
		var old Mark
		err := tx.NewSelect().Model(&old).Where("user_id = ? AND kind = ? AND key = ?", m.UserID, m.Kind, m.Key).Scan(ctx)
		switch {
		case errors.Is(err, sql.ErrNoRows):
			m.ID, m.Created = 0, now
			_, err = tx.NewInsert().Model(m).Exec(ctx)
		case err == nil:
			m.ID, m.Created = old.ID, old.Created
			_, err = tx.NewUpdate().Model(m).Column("note", "findings", "updated").WherePK().Exec(ctx)
		}
		return err
	})
	if err != nil {
		return fmt.Errorf("saving mark: %w", err)
	}
	s.ver.Add(1)
	return nil
}

// DeleteMark removes one of a user's marks; false when there was none.
func (s *Store) DeleteMark(ctx context.Context, userID, id int64) (bool, error) {
	res, err := s.db.NewDelete().Model((*Mark)(nil)).Where("id = ? AND user_id = ?", id, userID).Exec(ctx)
	if err != nil {
		return false, fmt.Errorf("deleting mark: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("deleting mark: %w", err)
	}
	if n > 0 {
		s.ver.Add(1)
	}
	return n > 0, nil
}
