package migrations

import (
	"context"
	"fmt"
	"time"

	"github.com/uptrace/bun"
)

// The tables as they were created here; later migrations change them, so
// these types stay as they are and are not the store's models.
type user struct {
	bun.BaseModel `bun:"table:users"`

	ID      int64     `bun:",pk,autoincrement"`
	Subject string    `bun:",unique,notnull"`
	Created time.Time `bun:",notnull"`
}

type mark struct {
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

func init() {
	Migrations.MustRegister(func(ctx context.Context, db *bun.DB) error {
		return db.RunInTx(ctx, nil, func(ctx context.Context, tx bun.Tx) error {
			if _, err := tx.NewCreateTable().Model((*user)(nil)).Exec(ctx); err != nil {
				return fmt.Errorf("creating users: %w", err)
			}
			if _, err := tx.NewCreateTable().Model((*mark)(nil)).
				ForeignKey(`("user_id") REFERENCES "users" ("id") ON DELETE CASCADE`).Exec(ctx); err != nil {
				return fmt.Errorf("creating marks: %w", err)
			}
			if _, err := tx.NewCreateIndex().Model((*mark)(nil)).Index("marks_user_kind_key").
				Unique().Column("user_id", "kind", "key").Exec(ctx); err != nil {
				return fmt.Errorf("creating marks index: %w", err)
			}
			return nil
		})
	}, func(ctx context.Context, db *bun.DB) error {
		for _, m := range []any{(*mark)(nil), (*user)(nil)} {
			if _, err := db.NewDropTable().Model(m).IfExists().Exec(ctx); err != nil {
				return fmt.Errorf("dropping table: %w", err)
			}
		}
		return nil
	})
}
