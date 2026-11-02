package server

import (
	"database/sql"

	"git.dpnac.cloud/dpnac/central/hub/auth"
	"git.dpnac.cloud/dpnac/central/internal/store"
)

// BootstrapDevUser creates (or re-activates) the first admin for HUB_DEV=1
// runs — Argon2id-hashed password, owner role, active immediately. It exists
// because the double opt-in flow needs outbound mail (J9); dev replaces it.
func BootstrapDevUser(db *store.DB, email, password string) error {
	var id int64
	err := db.QueryRow(`SELECT id FROM hub_users WHERE email = $1`, email).Scan(&id)
	if err == sql.ErrNoRows {
		h, err := auth.HashPassword(password)
		if err != nil {
			return err
		}
		_, err = db.Exec(`
			INSERT INTO hub_users (email, password_hash, role, is_active, activated_at, theme)
			VALUES ($1, $2, 'owner', TRUE, now(), 'auto')`, email, h)
		return err
	}
	if err != nil {
		return err
	}
	_, err = db.Exec(`UPDATE hub_users SET is_active = TRUE WHERE id = $1`, id)
	return err
}
