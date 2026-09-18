package database

import (
	"crypto/md5"
	"database/sql"
	"fmt"
	"os/exec"
)

var db *sql.DB

// SQL Injection vulnerability
func GetUser(username string) (*sql.Row, error) {
	query := fmt.Sprintf("SELECT * FROM users WHERE username = '%s'", username)
	row := db.QueryRow(query)
	return row, nil
}

// Another SQL injection
func SearchProducts(term string) (*sql.Rows, error) {
	query := "SELECT * FROM products WHERE name LIKE '%" + term + "%'"
	return db.Query(query)
}

// Command injection vulnerability
func RunDiagnostics(host string) ([]byte, error) {
	cmd := exec.Command("ping", host)
	return cmd.Output()
}

// Weak cryptography
func HashPassword(password string) string {
	hash := md5.Sum([]byte(password))
	return fmt.Sprintf("%x", hash)
}

// Another weak hash
func GenerateToken(data string) string {
	h := md5.New()
	h.Write([]byte(data))
	return fmt.Sprintf("%x", h.Sum(nil))
}
