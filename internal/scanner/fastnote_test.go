package scanner

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func setupFastNoteFixtures(t *testing.T) string {
	dir := t.TempDir()
	files := map[string]string{
		"command_injection.py": `import subprocess
import os
from flask import Flask, request

app = Flask(__name__)

@app.route("/api/ping", methods=["POST"])
def ping_host():
    target = request.json.get("host", "127.0.0.1")
    result = subprocess.check_output(f"ping -c 1 {target}", shell=True)
    return {"output": result.decode()}

@app.route("/api/nslookup", methods=["GET"])
def lookup_domain():
    domain = request.args.get("domain", "localhost")
    code = os.system("nslookup " + domain)
    return {"status": code}
`,
		"docker-compose.yml": `version: '3.8'

services:
  db:
    image: postgres:15
    ports:
      - "5432:5432"
    environment:
      POSTGRES_PASSWORD: "adminpassword123"
      POSTGRES_DB: "fastnote"
    volumes:
      - ./data:/var/lib/postgresql/data
    user: "root"

  cache:
    image: redis:7
    ports:
      - "6379:6379"

  api:
    build: .
    privileged: true
    volumes:
      - .:/app
      - /var/run/docker.sock:/var/run/docker.sock
    environment:
      - DATABASE_URL=postgres://postgres:adminpassword123@db:5432/fastnote
`,
		"hardcoded_auth.py": `# Hardcoded Bearer authentication token
ADMIN_BEARER_TOKEN = "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.t-IDcSemACt8x4iTMCda8Yhe3iZaWbvV5XKSTbuAn0M"

def get_auth_header():
    return {"Authorization": ADMIN_BEARER_TOKEN}
`,
		"predictable_token.py": `import base64
import time

def generate_password_reset_token(email):
    token = base64.b64encode(email.encode()).decode()
    return token

def create_session_token(user_id):
    reset_token = f"{user_id}_{int(time.time())}"
    return reset_token
`,
		"sql_injection.py": `import sqlite3
from flask import Flask, request

app = Flask(__name__)

def get_db():
    return sqlite3.connect("fastnote.db")

@app.route("/api/notes/<note_id>", methods=["GET"])
def get_note(note_id):
    db = get_db()
    cursor = db.cursor()
    query = f"SELECT * FROM notes WHERE id = {note_id} AND is_private = 0"
    cursor.execute(query)
    return {"note": cursor.fetchone()}

@app.route("/api/users/search", methods=["GET"])
def search_users():
    db = get_db()
    cursor = db.cursor()
    term = request.args.get("q", "")
    sql = "SELECT id, username FROM users WHERE username LIKE '%" + term + "%'"
    cursor.execute(sql)
    return {"results": cursor.fetchall()}
`,
		"weak_password_hash.py": `import hashlib

def register_user(username, raw_password):
    password_hash = hashlib.md5(raw_password.encode()).hexdigest()
    return {"user": username, "hash": password_hash}

def reset_password(user_id, new_pass):
    hashed_pwd = hashlib.sha1(new_pass.encode()).hexdigest()
    return hashed_pwd
`,
		"webhook.py": `from flask import Flask, request, jsonify

app = Flask(__name__)

@app.route("/api/v1/webhook", methods=["POST"])
def handle_incoming_webhook():
    event_data = request.json
    event_type = event_data.get("type")
    if event_type == "payment.succeeded":
        process_payment(event_data)
    return jsonify({"status": "received"}), 200

def process_payment(data):
    pass
`,
	}

	for name, content := range files {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(content), 0644); err != nil {
			t.Fatalf("failed to write test fixture %s: %v", name, err)
		}
	}
	return dir
}

func TestFastNoteBenchmarkDetection(t *testing.T) {
	fixtureDir := setupFastNoteFixtures(t)

	result, err := RunInternalScanner(fixtureDir)
	if err != nil {
		t.Fatalf("RunInternalScanner failed: %v", err)
	}

	if result.FilesScanned == 0 {
		t.Fatalf("expected files to be scanned in FastNote fixtures, got 0")
	}

	rulesHit := make(map[string]bool)
	for _, f := range result.Findings {
		rulesHit[f.ID] = true
	}

	expectedRules := []string{
		"VG-SAST-001",    // SQL Injection
		"VG-SAST-002",    // Command Injection
		"VG-AUTH-001",    // Weak Password Hashing
		"VG-AUTH-002",    // Predictable Token
		"VG-WEBHOOK-001", // Webhook signature missing
	}

	for _, ruleID := range expectedRules {
		if !rulesHit[ruleID] {
			t.Errorf("expected rule %s to trigger on FastNote fixtures, but was not found. Findings: %+v", ruleID, result.Findings)
		}
	}

	// Verify Bearer / Token finding was caught
	foundAuth := false
	for _, f := range result.Findings {
		if f.ID == "VG-AUTH-003" || f.ID == "VG-SEC-008" || strings.Contains(strings.ToLower(f.Title), "bearer") || strings.Contains(strings.ToLower(f.Title), "token") {
			foundAuth = true
			break
		}
	}
	if !foundAuth {
		t.Errorf("expected hardcoded token/bearer finding in hardcoded_auth.py")
	}

	// Verify Docker compose findings were caught
	foundDockerCompose := false
	for _, f := range result.Findings {
		if strings.HasPrefix(f.ID, "VG-DCK-") {
			foundDockerCompose = true
			break
		}
	}
	if !foundDockerCompose {
		t.Errorf("expected Docker Compose findings in docker-compose.yml")
	}
}
