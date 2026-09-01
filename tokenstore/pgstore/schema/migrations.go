// Package schema holds howdah's own tern migrations, embedded so that an
// application can apply them from wherever it runs its migrations.
//
// They are applied against a version table of howdah's own — see
// pgstore.SchemaVersionTable — so that howdah's numbering cannot collide
// with the numbering of the migrations the application already has.
package schema

import "embed"

// Migrations holds the migrations that build the tables pgstore reads and
// writes. Nothing in howdah applies them: a migration turns every restart,
// scale-up and rollback into a schema change, so it is a deliberate step the
// application takes.
//
//go:embed *.sql
var Migrations embed.FS
