// Package migrations embeds the SQL migrations and applies them at hub
// startup (beta: the container must boot on an empty volume; psql is NOT
// available inside the runtime image).
//
// Idempotence: every migration file is written with IF NOT EXISTS / ADD
// COLUMN IF NOT EXISTS, so re-applying on boot is safe. A settings row
// marks the last applied version for reporting (and later: a real
// sequential migrator with forward-only rules).
package migrations

import (
	"embed"
	"fmt"
	"log"
	"sort"
	"strings"

	"git.dpnac.cloud/dpnac/central/internal/store"
)

//go:embed sql/hub/*.sql
var hubFS embed.FS

// ApplyHub runs every embedded hub migration in filename order (001 → N).
// Errors are fatal on purpose: a half-migrated hub must not serve.
func ApplyHub(db *store.DB) error {
	entries, err := hubFS.ReadDir("sql/hub")
	if err != nil {
		return err
	}
	var names []string
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".sql") {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)
	for _, name := range names {
		raw, err := hubFS.ReadFile("sql/hub/" + name)
		if err != nil {
			return err
		}
		if _, err := db.Exec(string(raw)); err != nil {
			return fmt.Errorf("migration %s: %w", name, err)
		}
		log.Printf("migrations: applied %s", name)
	}
	_, _ = db.Exec(`INSERT INTO settings (key, value) VALUES ('schema_version', $1)
		ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value`, latest(names))
	return nil
}

func latest(names []string) string {
	if len(names) == 0 {
		return "?"
	}
	return strings.TrimSuffix(names[len(names)-1], ".sql")
}