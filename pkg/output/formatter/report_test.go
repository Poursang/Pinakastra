package formatter

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A confirmed finding must appear in the primary report. If it only reached the
// separate exploits/ files, a consumer of scan_results.json would never see the
// vulnerabilities the scan confirmed.
func TestJSONReportIncludesFindings(t *testing.T) {
	dir := t.TempDir()
	res := &ScanResult{
		Findings: []Finding{{
			URL:      "https://target/x?id=1",
			Type:     "SQL Injection",
			Severity: "critical",
			Verified: true,
			Evidence: "boolean differential held",
		}},
	}
	if err := NewJSONFormatter(dir).Format(res); err != nil {
		t.Fatal(err)
	}

	data, err := os.ReadFile(filepath.Join(dir, "scan_results.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "SQL Injection") || !strings.Contains(string(data), "boolean differential held") {
		t.Fatalf("finding missing from report:\n%s", data)
	}

	var rr ScanResult
	if err := json.Unmarshal(data, &rr); err != nil {
		t.Fatal(err)
	}
	if len(rr.Findings) != 1 || !rr.Findings[0].Verified {
		t.Fatalf("finding did not round-trip: %+v", rr.Findings)
	}
}
