package sample

import (
	"crypto/tls"
	"database/sql"
)

func SecureOperations(db *sql.DB, param string) {
	db.Query("SELECT * FROM users WHERE name = ?", param)

	_ = &tls.Config{
		MinVersion: tls.VersionTLS13,
	}
}
