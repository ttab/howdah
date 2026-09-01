package pgstore

import (
	"context"
	"fmt"
	"io/fs"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/tern/v2/migrate"
	"github.com/ttab/howdah/tokenstore/pgstore/schema"
)

// SchemaVersionTable is the table howdah tracks its own schema version in.
// It is howdah's own rather than the tern default, so that howdah's
// migration numbering cannot collide with the numbering of the migrations
// the application already has in the same database.
const SchemaVersionTable = "howdah_session_version"

// Migrations are the tern migrations that build what pgstore reads and
// writes. They are here for an application that runs its migrations through
// tooling of its own; Migrate is the shorter path.
var Migrations fs.FS = schema.Migrations

// Migrate applies howdah's migrations, using a connection from the pool.
//
// **Call it from a deliberate step, never from the service's startup path.**
// A migration can be expensive, and one that runs at startup turns every
// restart, scale-up and rollback into a schema change that blocks the process
// from serving for as long as it takes. Put it behind a subcommand, or behind
// whatever the application already uses to migrate.
func Migrate(ctx context.Context, pool *pgxpool.Pool) error {
	conn, err := pool.Acquire(ctx)
	if err != nil {
		return fmt.Errorf("acquire a connection for the migration: %w", err)
	}

	defer conn.Release()

	return MigrateConn(ctx, conn.Conn())
}

// MigrateConn applies howdah's migrations over a connection of the caller's
// own. It is Migrate for an application that has a *pgx.Conn rather than a
// pool — see there for when to call it.
func MigrateConn(ctx context.Context, conn *pgx.Conn) error {
	m, err := migrate.NewMigrator(ctx, conn, SchemaVersionTable)
	if err != nil {
		return fmt.Errorf("create the migrator: %w", err)
	}

	err = m.LoadMigrations(Migrations)
	if err != nil {
		return fmt.Errorf("load howdah's migrations: %w", err)
	}

	err = m.Migrate(ctx)
	if err != nil {
		return fmt.Errorf("apply howdah's migrations: %w", err)
	}

	return nil
}
