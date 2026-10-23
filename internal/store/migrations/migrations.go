// Package migrations holds the database schema changes, one file per
// change named <timestamp>_<name>.go (bun takes the name from the file).
// They use bun's query builder, not raw SQL, so they run on SQLite and
// PostgreSQL alike.
package migrations

import "github.com/uptrace/bun/migrate"

// Migrations are applied in file name order.
var Migrations = migrate.NewMigrations()
