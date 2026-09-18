package osv

type QueryRequest struct {
	Version string  `json:"version,omitempty"`
	Package Package `json:"package"`
}

type Package struct {
	Name      string `json:"name"`
	Ecosystem string `json:"ecosystem"`
}

type QueryResponse struct {
	Vulns []Vulnerability `json:"vulns"`
}

type Vulnerability struct {
	ID         string          `json:"id"`
	Summary    string          `json:"summary"`
	Details    string          `json:"details"`
	Aliases          []string               `json:"aliases"`
	Severity         []SeverityEntry        `json:"severity"`
	Affected         []AffectedEntry        `json:"affected"`
	References       []Reference            `json:"references"`
	DatabaseSpecific map[string]interface{} `json:"database_specific,omitempty"`
}

type SeverityEntry struct {
	Type  string `json:"type"`
	Score string `json:"score"`
}

type AffectedEntry struct {
	Package  AffectedPackage `json:"package"`
	Ranges   []Range         `json:"ranges"`
	Versions []string        `json:"versions"`
}

type AffectedPackage struct {
	Name      string `json:"name"`
	Ecosystem string `json:"ecosystem"`
	Purl      string `json:"purl"`
}

type Range struct {
	Type   string  `json:"type"`
	Events []Event `json:"events"`
}

type Event struct {
	Introduced   string `json:"introduced,omitempty"`
	Fixed        string `json:"fixed,omitempty"`
	LastAffected string `json:"last_affected,omitempty"`
}

type Reference struct {
	Type string `json:"type"`
	Url  string `json:"url"`
}
