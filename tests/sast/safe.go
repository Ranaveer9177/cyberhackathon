package sample

import (
	"crypto/sha256"
	"crypto/tls"
	"database/sql"
	"net/http"
)

func SafeOperations(db *sql.DB, userInput string) {
	// Parameterized SQL query
	_ = db.QueryRow("SELECT * FROM accounts WHERE id = ?", userInput)

	// Secure TLS
	_ = &tls.Config{InsecureSkipVerify: false}

	// HTTPS endpoint
	_, _ = http.Get("https://secure-api.internal/endpoint")

	// Strong Crypto
	_ = sha256.Sum256([]byte(userInput))
}
