package dependencies

import (
	"testing"
)

func TestParseGoMod(t *testing.T) {
	content := `module example.com/app

go 1.21

require (
	golang.org/x/crypto v0.1.0
	github.com/gin-gonic/gin v1.9.0 // indirect
)
`
	deps := ParseGoMod(content, "go.mod")
	if len(deps) < 2 {
		t.Fatalf("expected at least 2 dependencies, got %d", len(deps))
	}

	foundCrypto := false
	for _, d := range deps {
		if d.Name == "golang.org/x/crypto" && d.Version == "v0.1.0" && d.Ecosystem == "Go" {
			foundCrypto = true
		}
	}
	if !foundCrypto {
		t.Errorf("expected to find golang.org/x/crypto v0.1.0")
	}
}

func TestParsePackageJSON(t *testing.T) {
	content := `{
  "dependencies": {
    "lodash": "^4.17.20",
    "express": "~4.17.1"
  },
  "devDependencies": {
    "jest": "26.6.3"
  }
}`
	deps := ParsePackageJSON(content, "package.json")
	if len(deps) != 3 {
		t.Fatalf("expected 3 dependencies, got %d", len(deps))
	}

	foundLodash := false
	for _, d := range deps {
		if d.Name == "lodash" && d.Version == "4.17.20" && d.Ecosystem == "npm" {
			foundLodash = true
		}
	}
	if !foundLodash {
		t.Errorf("expected to find sanitized lodash 4.17.20")
	}
}

func TestParseRequirementsTxt(t *testing.T) {
	content := `
# Comment
Flask==2.0.1
requests>=2.25.1
django==3.2.0
`
	deps := ParseRequirementsTxt(content, "requirements.txt")
	if len(deps) != 3 {
		t.Fatalf("expected 3 dependencies, got %d", len(deps))
	}

	foundFlask := false
	for _, d := range deps {
		if d.Name == "Flask" && d.Version == "2.0.1" && d.Ecosystem == "PyPI" {
			foundFlask = true
		}
	}
	if !foundFlask {
		t.Errorf("expected to find Flask 2.0.1")
	}
}

func TestParseCargoToml(t *testing.T) {
	content := `[package]
name = "myapp"
version = "0.1.0"

[dependencies]
serde = "1.0.104"
tokio = { version = "1.0", features = ["full"] }
`
	deps := ParseCargoToml(content, "Cargo.toml")
	if len(deps) != 2 {
		t.Fatalf("expected 2 dependencies, got %d", len(deps))
	}

	foundSerde := false
	for _, d := range deps {
		if d.Name == "serde" && d.Version == "1.0.104" && d.Ecosystem == "crates.io" {
			foundSerde = true
		}
	}
	if !foundSerde {
		t.Errorf("expected to find serde 1.0.104")
	}
}

func TestDetectDependenciesExclusions(t *testing.T) {
	root := "../../"
	deps, err := DetectDependencies(root)
	if err != nil {
		t.Fatalf("DetectDependencies failed: %v", err)
	}

	for _, d := range deps {
		cleanSource := d.SourceFile
		if cleanSource != "" && (containsSubstr(cleanSource, "tests/dependencies") || containsSubstr(cleanSource, "tests\\dependencies")) {
			t.Errorf("dependency from excluded tests/ was detected: %s (%s)", d.Name, d.SourceFile)
		}
	}
}

func containsSubstr(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

