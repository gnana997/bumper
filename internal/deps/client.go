package deps

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// DefaultAdvisorURL is the hosted, public, read-only Advisor. Override with
// --advisor-url or $BUMPER_ADVISOR_URL to point at a self-hosted instance.
const DefaultAdvisorURL = "https://advisor.bumper.sh"

// scanChunk caps deps per /scan request (the API's per-request bound). The CLI
// chunks to this for FULL coverage of big trees (the web tool caps at 3,000).
const scanChunk = 5000

// ErrRateLimited is returned when the Advisor replies 429 (the /scan limiter).
var ErrRateLimited = errors.New("rate limited by the Advisor (HTTP 429)")

// ResolveAdvisorURL applies precedence: explicit flag > $BUMPER_ADVISOR_URL > default.
func ResolveAdvisorURL(flagVal string) string {
	if flagVal != "" {
		return strings.TrimRight(flagVal, "/")
	}
	if env := os.Getenv("BUMPER_ADVISOR_URL"); env != "" {
		return strings.TrimRight(env, "/")
	}
	return DefaultAdvisorURL
}

// Client is a thin Advisor REST client.
type Client struct {
	BaseURL string
	HTTP    *http.Client
}

// NewClient builds a client for an already-resolved base URL.
func NewClient(baseURL string) *Client {
	return &Client{BaseURL: strings.TrimRight(baseURL, "/"), HTTP: &http.Client{Timeout: 30 * time.Second}}
}

// --- /scan -------------------------------------------------------------------

type Ref struct {
	URL  string `json:"url"`
	Type string `json:"type"`
}

type ScanVuln struct {
	ID           string `json:"id"`
	Severity     string `json:"severity"`
	FixedVersion string `json:"fixed_version"`
	HasAIInsight bool   `json:"has_ai_insight"`
}

type ScanMalware struct {
	ID      string `json:"id"`
	Summary string `json:"summary"`
}

type ScanFinding struct {
	Ecosystem string        `json:"ecosystem"`
	Package   string        `json:"package"`
	Version   string        `json:"version"`
	Vulns     []ScanVuln    `json:"vulns"`
	Malware   []ScanMalware `json:"malware"`
}

type ScanResult struct {
	Status          string        `json:"status"`
	Scanned         int           `json:"scanned"`
	VulnerableCount int           `json:"vulnerable_count"`
	MalwareCount    int           `json:"malware_count"`
	Skipped         int           `json:"skipped"`
	Truncated       bool          `json:"truncated"`
	Findings        []ScanFinding `json:"findings"`
}

// Scan runs a version-aware vulnerability scan (+ malware) over deps, chunked so
// big lockfiles fully cover under the API's per-request cap.
func (c *Client) Scan(deps []Dep, includeMalware bool) (*ScanResult, error) {
	agg := &ScanResult{Status: "ok"}
	for i := 0; i < len(deps); i += scanChunk {
		end := i + scanChunk
		if end > len(deps) {
			end = len(deps)
		}
		var res ScanResult
		if err := c.post("/scan", map[string]any{"deps": deps[i:end], "include_malware": includeMalware}, &res); err != nil {
			return nil, err
		}
		agg.Scanned += res.Scanned
		agg.Skipped += res.Skipped
		if res.Truncated {
			agg.Truncated = true
		}
		if res.Status == "unavailable" {
			agg.Status = "unavailable"
		}
		agg.Findings = append(agg.Findings, res.Findings...)
	}
	for _, f := range agg.Findings {
		if len(f.Vulns) > 0 {
			agg.VulnerableCount++
		}
		if len(f.Malware) > 0 {
			agg.MalwareCount++
		}
	}
	return agg, nil
}

// --- /malware-check ----------------------------------------------------------

type MalwareAdvisory struct {
	ID      string `json:"id"`
	Summary string `json:"summary"`
	Details string `json:"details"`
	Refs    []Ref  `json:"refs"`
}

type MalwareHit struct {
	Ecosystem  string            `json:"ecosystem"`
	Package    string            `json:"package"`
	Malicious  bool              `json:"malicious"`
	Advisories []MalwareAdvisory `json:"advisories"`
}

type MalwareResult struct {
	Status         string       `json:"status"`
	Checked        int          `json:"checked"`
	MaliciousCount int          `json:"malicious_count"`
	Skipped        int          `json:"skipped"`
	Results        []MalwareHit `json:"results"`
}

// MalwareCheck runs a name-level known-malicious check on the named packages.
func (c *Client) MalwareCheck(deps []Dep) (*MalwareResult, error) {
	var res MalwareResult
	if err := c.post("/malware-check", map[string]any{"deps": deps}, &res); err != nil {
		return nil, err
	}
	return &res, nil
}

func (c *Client) post(path string, body, out any) error {
	b, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, err := http.NewRequest(http.MethodPost, c.BaseURL+path, bytes.NewReader(b))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusTooManyRequests {
		return ErrRateLimited
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("advisor returned HTTP %d", resp.StatusCode)
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

// CollectLockfileDeps parses every known lockfile present in dir and returns the
// merged, deduped coordinates. Used by `bumper deps` (no path) and `deps watch`.
func CollectLockfileDeps(dir string) []Dep {
	var all []Dep
	for _, name := range LockfileCandidates {
		b, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			continue
		}
		res, err := ParseLockfile(name, string(b))
		if err != nil {
			continue
		}
		all = append(all, res.Deps...)
	}
	return dedupe(all)
}
