// Package nuclei shells out to projectdiscovery/nuclei and converts its JSONL
// output into ngehe findings. Nuclei brings thousands of community-maintained
// templates (CVEs, default configs, exposures, takeovers) that complement
// ngehe's hand-written detectors.
//
// We only invoke nuclei if it is on PATH; otherwise Scan returns an empty
// slice. Findings emitted here carry Source="nuclei" so users can filter
// native findings vs upstream findings.
package nuclei

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/chud-lori/ngehe/internal/finding"
)

// Options configures a nuclei run.
type Options struct {
	Targets    []string      // URLs to scan; required
	Severity   string        // comma-separated min severities, e.g. "low,medium,high,critical"
	Tags       string        // comma-separated tags to include
	Concurrent int           // nuclei -c
	Timeout    time.Duration // overall command timeout (0 = no limit)
	RateLimit  int           // nuclei -rl (requests/sec)
	ExtraArgs  []string      // pass-through, e.g. ["-disable-update-check"]
}

// nucleiResult mirrors the subset of nuclei's -jsonl schema we consume.
type nucleiResult struct {
	TemplateID string `json:"template-id"`
	Info       struct {
		Name        string   `json:"name"`
		Severity    string   `json:"severity"`
		Description string   `json:"description"`
		Tags        []string `json:"tags"`
	} `json:"info"`
	Type          string `json:"type"`
	Host          string `json:"host"`
	MatchedAt     string `json:"matched-at"`
	ExtractedRes  []any  `json:"extracted-results"`
	CurlCommand   string `json:"curl-command"`
}

// Available reports whether nuclei is on PATH.
func Available() bool {
	_, err := exec.LookPath("nuclei")
	return err == nil
}

// Scan runs nuclei against the given targets and returns findings.
// If nuclei is missing, it returns nil and no error.
func Scan(opts Options) ([]finding.Finding, error) {
	if !Available() {
		return nil, nil
	}
	if len(opts.Targets) == 0 {
		return nil, nil
	}

	args := []string{"-jsonl", "-silent", "-disable-update-check", "-no-color"}
	for _, t := range opts.Targets {
		args = append(args, "-u", t)
	}
	if opts.Severity != "" {
		args = append(args, "-s", opts.Severity)
	} else {
		// Skip info-only templates by default — they're noisy.
		args = append(args, "-s", "low,medium,high,critical")
	}
	if opts.Tags != "" {
		args = append(args, "-tags", opts.Tags)
	}
	if opts.Concurrent > 0 {
		args = append(args, "-c", fmt.Sprintf("%d", opts.Concurrent))
	}
	if opts.RateLimit > 0 {
		args = append(args, "-rl", fmt.Sprintf("%d", opts.RateLimit))
	}
	args = append(args, opts.ExtraArgs...)

	ctx := context.Background()
	if opts.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, opts.Timeout)
		defer cancel()
	}

	cmd := exec.CommandContext(ctx, "nuclei", args...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("nuclei pipe: %w", err)
	}
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("nuclei start: %w", err)
	}

	var out []finding.Finding
	scanner := bufio.NewScanner(stdout)
	scanner.Buffer(make([]byte, 1024*1024), 8*1024*1024)
	for scanner.Scan() {
		line := scanner.Bytes()
		var r nucleiResult
		if err := json.Unmarshal(line, &r); err != nil {
			continue
		}
		out = append(out, convert(r))
	}
	// Drain — nuclei exits non-zero on no-matches in some versions; don't fail on that.
	_ = cmd.Wait()
	return out, nil
}

func convert(r nucleiResult) finding.Finding {
	rule := "nuclei-" + strings.ReplaceAll(r.TemplateID, "/", "-")
	url := r.MatchedAt
	if url == "" {
		url = r.Host
	}
	evidence := r.Info.Description
	if len(r.ExtractedRes) > 0 {
		parts := make([]string, 0, len(r.ExtractedRes))
		for _, e := range r.ExtractedRes {
			parts = append(parts, fmt.Sprintf("%v", e))
		}
		if evidence != "" {
			evidence += " — extracted: " + strings.Join(parts, ", ")
		} else {
			evidence = "extracted: " + strings.Join(parts, ", ")
		}
	}
	if len(evidence) > 600 {
		evidence = evidence[:600] + "…"
	}
	next := ""
	if r.CurlCommand != "" {
		next = "Reproduce: " + r.CurlCommand
	}
	return finding.Finding{
		Rule:     rule,
		Severity: mapSeverity(r.Info.Severity),
		Method:   "GET",
		URL:      url,
		Path:     pathOf(url),
		Evidence: evidence,
		Why:      fmt.Sprintf("nuclei template %q (%s) matched", r.Info.Name, r.TemplateID),
		Next:     next,
		Source:   "nuclei",
	}
}

func mapSeverity(s string) finding.Severity {
	switch strings.ToLower(s) {
	case "critical":
		return finding.SevCritical
	case "high":
		return finding.SevHigh
	case "medium":
		return finding.SevMedium
	case "low":
		return finding.SevLow
	default:
		return finding.SevInfo
	}
}

func pathOf(rawURL string) string {
	i := strings.Index(rawURL, "://")
	if i < 0 {
		return rawURL
	}
	rest := rawURL[i+3:]
	if j := strings.Index(rest, "/"); j >= 0 {
		return rest[j:]
	}
	return "/"
}
