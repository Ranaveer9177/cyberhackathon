package dependencies

import (
	"io/fs"
	"os"
	"path/filepath"
)

type Dependency struct {
	Name       string
	Version    string
	Ecosystem  string
	SourceFile string
}

func DetectDependencies(projectPath string) ([]Dependency, error) {
	var deps []Dependency

	err := filepath.WalkDir(projectPath, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		
		if d.IsDir() {
			if d.Name() == "node_modules" || d.Name() == ".git" || d.Name() == "vendor" {
				return filepath.SkipDir
			}
			return nil
		}

		contentBytes, err := os.ReadFile(path)
		if err != nil {
			return nil // skip unreadable files
		}
		content := string(contentBytes)

		var fileDeps []Dependency
		switch d.Name() {
		case "go.mod":
			fileDeps = ParseGoMod(content, path)
		case "package-lock.json":
			fileDeps = ParsePackageLockJSON(content, path)
		case "package.json":
			// If package-lock.json exists in same dir, prefer the lockfile for exact installed versions
			lockFile := filepath.Join(filepath.Dir(path), "package-lock.json")
			if _, err := os.Stat(lockFile); os.IsNotExist(err) {
				fileDeps = ParsePackageJSON(content, path)
			}
		case "requirements.txt":
			fileDeps = ParseRequirementsTxt(content, path)
		case "Cargo.lock":
			fileDeps = ParseCargoLock(content, path)
		case "Cargo.toml":
			// If Cargo.lock exists in same dir, prefer the lockfile
			lockFile := filepath.Join(filepath.Dir(path), "Cargo.lock")
			if _, err := os.Stat(lockFile); os.IsNotExist(err) {
				fileDeps = ParseCargoToml(content, path)
			}
		}
		deps = append(deps, fileDeps...)

		return nil
	})

	if err != nil {
		return nil, err
	}

	return deps, nil
}
