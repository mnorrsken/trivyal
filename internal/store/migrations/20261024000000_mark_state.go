package migrations

import (
	"context"
	"fmt"

	"github.com/uptrace/bun"
)

// A mark either hides or flags its target. Marks made before this were all
// hides.
func init() {
	Migrations.MustRegister(func(ctx context.Context, db *bun.DB) error {
		if _, err := db.NewAddColumn().Model((*mark)(nil)).
			ColumnExpr("state VARCHAR NOT NULL DEFAULT 'hidden'").Exec(ctx); err != nil {
			return fmt.Errorf("adding marks.state: %w", err)
		}
		return nil
	}, func(ctx context.Context, db *bun.DB) error {
		if _, err := db.NewDropColumn().Model((*mark)(nil)).Column("state").Exec(ctx); err != nil {
			return fmt.Errorf("dropping marks.state: %w", err)
		}
		return nil
	})
}
