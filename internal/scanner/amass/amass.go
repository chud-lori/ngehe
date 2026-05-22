// Package amass shells out to OWASP amass for passive subdomain enumeration.
// We deliberately use passive mode only — active mode is slow and noisy and
// the subfinder package covers the cheap-and-fast pass.
package amass

import (
	"bufio"
	"context"
	"encoding/json"
	"os/exec"
	"strings"
	"time"

	"github.com/chud-lori/ngehe/internal/finding"
)

// Options configures an amass enum run.
type Options struct {
	Domain  string
	Timeout time.Duration // overall command timeout (0 = 5 minutes)
}

// amassRecord — amass enum -json one-line schema (subset).
type amassRecord struct {
	Name string `json:"name"`
	Addr string `json:"addr"`
	Tag  string `json:"tag"`
}

// Available reports whether amass is on PATH.
func Available() bool {
	_, err := exec.LookPath("amass")
	return err == nil
}

// SmokeTest verifies amass is callable. Note: amass works without API keys
// but with reduced coverage — we deliberately don't warn about that because
// many passive sources are free-tier and the tool is still useful as-is.
func SmokeTest() (ok bool, hint string) {
	if !Available() {
		return false, "binary not on PATH — install: ./install.sh --with-extras"
	}
	cmd := exec.Command("amass", "-version")
	cmd.Stdout, cmd.Stderr = nil, nil
	if err := cmd.Run(); err != nil {
		return false, "binary present but '-version' failed — check architecture / corrupted install"
	}
	return true, ""
}

// Enumerate runs `amass enum -passive -d <domain>` and returns the discovered
// subdomains plus one finding-per-host (severity info) for the JSONL report.
// If amass is missing, returns nil and no error so callers can chain it.
func Enumerate(opts Options) (hosts []string, findings []finding.Finding, err error) {
	if !Available() || opts.Domain == "" {
		return nil, nil, nil
	}
	timeout := opts.Timeout
	if timeout == 0 {
		timeout = 5 * time.Minute
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, "amass", "enum", "-passive", "-d", opts.Domain, "-json", "/dev/stdout", "-nocolor")
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, nil, err
	}

	seen := map[string]bool{}
	scanner := bufio.NewScanner(stdout)
	scanner.Buffer(make([]byte, 1024*1024), 4*1024*1024)
	for scanner.Scan() {
		line := scanner.Bytes()
		var r amassRecord
		if err := json.Unmarshal(line, &r); err != nil {
			continue
		}
		name := strings.TrimSuffix(strings.ToLower(r.Name), ".")
		if name == "" || seen[name] {
			continue
		}
		seen[name] = true
		hosts = append(hosts, name)
		findings = append(findings, finding.Finding{
			Rule:     "amass-subdomain",
			Severity: finding.SevInfo,
			Method:   "DNS",
			URL:      "dns://" + name,
			Path:     "/",
			Evidence: r.Addr,
			Why:      "amass passive discovery surfaced subdomain " + name,
			Source:   "amass",
		})
	}
	_ = cmd.Wait()
	return hosts, findings, nil
}
