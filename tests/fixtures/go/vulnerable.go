package sample

import (
	"crypto/tls"
	"database/sql"
	"fmt"
	"os/exec"
)

func InsecureOperations(db *sql.DB, param string) {
	q := fmt.Sprintf("SELECT * FROM users WHERE name = '%s'", param)
	db.Query(q)

	exec.Command("sh", "-c", param)

	_ = &tls.Config{
		InsecureSkipVerify: true,
	}
}
