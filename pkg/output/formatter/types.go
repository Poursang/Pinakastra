package formatter

import "time"

// ScanResult contains all results from a complete scan
type ScanResult struct {
	Metadata       ScanMetadata     `json:"metadata"`
	Subdomains     SubdomainResults `json:"subdomains"`
	HTTPProbe      HTTPProbeResults `json:"http_probe"`
	Findings       []Finding        `json:"findings"`
	TerminalOutput []string         `json:"terminal_output"`
}

// Finding is one confirmed vulnerability from the active-verification phase.
// It mirrors the fields a reader needs without depending on the exploit
// package's internal type, so the report is self-contained.
type Finding struct {
	Subdomain string `json:"subdomain,omitempty"`
	URL       string `json:"url"`
	Type      string `json:"type"`
	Severity  string `json:"severity"`
	Verified  bool   `json:"verified"`
	Evidence  string `json:"evidence,omitempty"`
	Payload   string `json:"payload,omitempty"`
	Impact    string `json:"impact,omitempty"`
}

// ScanMetadata contains scan metadata
type ScanMetadata struct {
	Domain    string    `json:"domain"`
	ScanID    string    `json:"scan_id"`
	StartTime time.Time `json:"start_time"`
	EndTime   time.Time `json:"end_time"`
	Duration  string    `json:"duration"`
	Mode      string    `json:"mode"`
	EnableAI  bool      `json:"enable_ai"`
	UseTor    bool      `json:"use_tor"`
	Version   string    `json:"version"`
}

// SubdomainResults contains subdomain enumeration results
type SubdomainResults struct {
	TotalFound  int            `json:"total_found"`
	Duplicates  int            `json:"duplicates"`
	UniqueCount int            `json:"unique_count"`
	Subdomains  []string       `json:"subdomains"`
	APICount    int            `json:"api_count"`
	APIs        []string       `json:"apis"`
	ToolResults map[string]int `json:"tool_results"`
	Duration    string         `json:"duration"`
}

// HTTPProbeResults contains HTTP probing results
type HTTPProbeResults struct {
	TotalProbed int       `json:"total_probed"`
	LiveCount   int       `json:"live_count"`
	LiveURLs    []LiveURL `json:"live_urls"`
	Duration    string    `json:"duration"`
}

// LiveURL contains details about a live URL
type LiveURL struct {
	URL          string   `json:"url"`
	StatusCode   int      `json:"status_code,omitempty"`
	Title        string   `json:"title,omitempty"`
	ContentType  string   `json:"content_type,omitempty"`
	Technologies []string `json:"technologies,omitempty"`
}
