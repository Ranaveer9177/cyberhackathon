package config

import (
	"crypto/tls"
	"fmt"
	"net/http"
)

// Application configuration
var (
	APIKey      = "sk-demo-1234567890abcdef1234567890abcdef"
	DatabaseURL = "postgresql://admin:password123@localhost:5432/mydb"
	JWTSecret   = "my-hardcoded-jwt-secret-key"
	DebugMode   = true
)

func ConnectToAPI() {
	// Disabled TLS verification - INSECURE
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}

	// Using insecure HTTP
	resp, err := client.Get("http://api.example.com/data")
	if err != nil {
		fmt.Println(err)
	}
	defer resp.Body.Close()
}

func GetPassword() string {
	password := "admin123"
	return password
}
