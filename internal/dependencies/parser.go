package dependencies

import (
	"encoding/json"
	"regexp"
	"strings"
)

func ParseGoMod(content string, sourceFile string) []Dependency {
	var deps []Dependency
	re := regexp.MustCompile(`(?m)^\s*([a-zA-Z0-9.\-_/]+)\s+(v[a-zA-Z0-9.\-_+]+)(?:\s+//.*)?$`)
	matches := re.FindAllStringSubmatch(content, -1)
	for _, match := range matches {
		if len(match) == 3 && match[1] != "module" && match[1] != "go" {
			deps = append(deps, Dependency{
				Name:       match[1],
				Version:    match[2],
				Ecosystem:  "Go",
				SourceFile: sourceFile,
			})
		}
	}
	return deps
}

func ParsePackageJSON(content string, sourceFile string) []Dependency {
	var deps []Dependency
	var pkg struct {
		Dependencies    map[string]string `json:"dependencies"`
		DevDependencies map[string]string `json:"devDependencies"`
	}
	if err := json.Unmarshal([]byte(content), &pkg); err != nil {
		return deps
	}

	addDeps := func(m map[string]string) {
		for name, version := range m {
			version = strings.TrimPrefix(version, "^")
			version = strings.TrimPrefix(version, "~")
			version = strings.TrimPrefix(version, ">=")
			version = strings.TrimSpace(version)
			deps = append(deps, Dependency{
				Name:       name,
				Version:    version,
				Ecosystem:  "npm",
				SourceFile: sourceFile,
			})
		}
	}
	addDeps(pkg.Dependencies)
	addDeps(pkg.DevDependencies)
	return deps
}

func ParseRequirementsTxt(content string, sourceFile string) []Dependency {
	var deps []Dependency
	lines := strings.Split(content, "\n")
	re := regexp.MustCompile(`^([a-zA-Z0-9\-_.]+)(?:==|>=)(.*)$`)
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		matches := re.FindStringSubmatch(line)
		if len(matches) == 3 {
			deps = append(deps, Dependency{
				Name:       matches[1],
				Version:    strings.TrimSpace(matches[2]),
				Ecosystem:  "PyPI",
				SourceFile: sourceFile,
			})
		} else {
			name := strings.Split(line, " ")[0]
			name = strings.Split(name, "=")[0]
			name = strings.Split(name, "<")[0]
			name = strings.Split(name, ">")[0]
			if name != "" && !strings.HasPrefix(name, "-") {
				deps = append(deps, Dependency{
					Name:       name,
					Version:    "unknown",
					Ecosystem:  "PyPI",
					SourceFile: sourceFile,
				})
			}
		}
	}
	return deps
}

func ParseCargoToml(content string, sourceFile string) []Dependency {
	var deps []Dependency
	lines := strings.Split(content, "\n")
	inDeps := false
	re1 := regexp.MustCompile(`^([a-zA-Z0-9\-_]+)\s*=\s*"([^"]+)"`)
	re2 := regexp.MustCompile(`^([a-zA-Z0-9\-_]+)\s*=\s*\{.*version\s*=\s*"([^"]+)".*}`)

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			inDeps = strings.Contains(line, "dependencies")
			continue
		}
		if !inDeps || line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if matches := re1.FindStringSubmatch(line); len(matches) == 3 {
			deps = append(deps, Dependency{
				Name:       matches[1],
				Version:    matches[2],
				Ecosystem:  "crates.io",
				SourceFile: sourceFile,
			})
		} else if matches := re2.FindStringSubmatch(line); len(matches) == 3 {
			deps = append(deps, Dependency{
				Name:       matches[1],
				Version:    matches[2],
				Ecosystem:  "crates.io",
				SourceFile: sourceFile,
			})
		}
	}
	return deps
}

// ParsePackageLockJSON parses npm package-lock.json for exact installed dependency versions.
func ParsePackageLockJSON(content string, sourceFile string) []Dependency {
	var deps []Dependency
	var lock struct {
		Packages     map[string]struct {
			Version string `json:"version"`
		} `json:"packages"`
		Dependencies map[string]struct {
			Version string `json:"version"`
		} `json:"dependencies"`
	}
	if err := json.Unmarshal([]byte(content), &lock); err != nil {
		return deps
	}

	seen := make(map[string]bool)
	// Check npm v2/v3 packages object
	for pkgPath, info := range lock.Packages {
		if info.Version == "" {
			continue
		}
		name := strings.TrimPrefix(pkgPath, "node_modules/")
		if name != "" && name != pkgPath && !seen[name] {
			seen[name] = true
			deps = append(deps, Dependency{
				Name:       name,
				Version:    info.Version,
				Ecosystem:  "npm",
				SourceFile: sourceFile,
			})
		}
	}

	// Check npm v1 dependencies object
	for name, info := range lock.Dependencies {
		if info.Version != "" && !seen[name] {
			seen[name] = true
			deps = append(deps, Dependency{
				Name:       name,
				Version:    info.Version,
				Ecosystem:  "npm",
				SourceFile: sourceFile,
			})
		}
	}

	return deps
}

// ParseGoSum extracts dependency versions from go.sum.
func ParseGoSum(content string, sourceFile string) []Dependency {
	var deps []Dependency
	seen := make(map[string]bool)
	lines := strings.Split(content, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) >= 2 {
			pkg := parts[0]
			ver := strings.TrimSuffix(parts[1], "/go.mod")
			key := pkg + "@" + ver
			if !seen[key] {
				seen[key] = true
				deps = append(deps, Dependency{
					Name:       pkg,
					Version:    ver,
					Ecosystem:  "Go",
					SourceFile: sourceFile,
				})
			}
		}
	}
	return deps
}

// ParseCargoLock parses Cargo.lock for exact locked crate versions.
func ParseCargoLock(content string, sourceFile string) []Dependency {
	var deps []Dependency
	lines := strings.Split(content, "\n")
	var currName, currVersion string
	inPackage := false

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "[[package]]" {
			if inPackage && currName != "" && currVersion != "" {
				deps = append(deps, Dependency{
					Name:       currName,
					Version:    currVersion,
					Ecosystem:  "crates.io",
					SourceFile: sourceFile,
				})
			}
			inPackage = true
			currName = ""
			currVersion = ""
			continue
		}
		if inPackage {
			if strings.HasPrefix(line, "name = ") {
				currName = strings.Trim(strings.TrimPrefix(line, "name = "), "\"")
			} else if strings.HasPrefix(line, "version = ") {
				currVersion = strings.Trim(strings.TrimPrefix(line, "version = "), "\"")
			}
		}
	}
	if inPackage && currName != "" && currVersion != "" {
		deps = append(deps, Dependency{
			Name:       currName,
			Version:    currVersion,
			Ecosystem:  "crates.io",
			SourceFile: sourceFile,
		})
	}
	return deps
}
