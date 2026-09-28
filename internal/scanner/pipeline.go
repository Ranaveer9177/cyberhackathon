package scanner

// PipelineMeta contains the v7.0 Deep Offline Security Engine pipeline metadata
// produced by the Rust scanner's pipeline post-processor.
// It is deserialized from the `pipeline_meta` field of the JSON ScanResult.
type PipelineMeta struct {
	EngineVersion      string              `json:"engine_version"`
	StagesExecuted     []string            `json:"stages_executed"`
	RawFindingCount    int                 `json:"raw_finding_count"`
	DeduplicatedCount  int                 `json:"deduplicated_count"`
	SuppressedCount    int                 `json:"suppressed_count"`
	CorrelationChains  []CorrelationChain  `json:"correlation_chains"`
	ConfidenceBreakdown ConfidenceBreakdown `json:"confidence_breakdown"`
	AnalysisScope      AnalysisScopeStats  `json:"analysis_scope"`
	OfflineCapable     bool                `json:"offline_capable"`
}

// CorrelationChain groups related findings that share the same underlying vulnerability.
type CorrelationChain struct {
	ID              string   `json:"id"`
	VulnClass       string   `json:"vuln_class"`
	CWE             string   `json:"cwe"`
	FindingIDs      []string `json:"finding_ids"`
	Severity        string   `json:"severity"`
	Confidence      string   `json:"confidence"`
	ConfidenceScore uint8    `json:"confidence_score"`
	Rationale       string   `json:"rationale"`
	CrossFile       bool     `json:"cross_file"`
	CrossFunction   bool     `json:"cross_function"`
}

// ConfidenceBreakdown counts findings by confidence level.
type ConfidenceBreakdown struct {
	High   int `json:"high"`
	Medium int `json:"medium"`
	Low    int `json:"low"`
}

// AnalysisScopeStats counts findings by the scope of analysis that detected them.
type AnalysisScopeStats struct {
	IntraFunction      int `json:"intra_function"`
	CrossFunction      int `json:"cross_function"`
	CrossFile          int `json:"cross_file"`
	FrameworkAware     int `json:"framework_aware"`
	ConfigurationAware int `json:"configuration_aware"`
}

// PipelineMetaRaw is the raw JSON representation received from the Rust scanner.
// It is embedded in ScanResult as a json.RawMessage to allow lazy decoding.
// Access it via ScanResult.RawMeta().
type PipelineMetaRaw struct {
	present bool
	meta    PipelineMeta
}
