package sample

import (
	"crypto/md5"
	"crypto/tls"
	"fmt"
	"net/http"
	"os/exec"
)

func VulnerableOperations(userInput string) {
	// SQL Injection pattern
	_ = fmt.Sprintf("SELECT * FROM accounts WHERE id = '%s'", userInput)

	// Command injection pattern
	_ = exec.Command("sh", "-c", userInput)

	// Disabled TLS verification
	_ = &tls.Config{InsecureSkipVerify: true}

	// Insecure HTTP
	_, _ = http.Get("http://insecure-api.internal/endpoint")

	// Weak Crypto
	_ = md5.Sum([]byte(userInput))
}
