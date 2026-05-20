package recon

import (
	"bytes"
	"fmt"
	"strings"
	"sync"

	"github.com/chud-lori/ngehe/internal/finding"
)

// fileFingerprint maps the path suffix → content marker that, when present,
// upgrades a 200 to a real positive (defeats catch-all routers that return
// 200 for anything).
type fileFingerprint struct {
	pathSuffix string
	marker     string
	severity   finding.Severity
	why        string
}

var fileFingerprints = []fileFingerprint{
	{".git/HEAD", "ref: refs/heads/", finding.SevHigh, "exposed .git/HEAD — git history accessible, source-code leak likely"},
	{".git/config", "[core]", finding.SevHigh, "exposed .git/config — git history accessible"},
	{".env", "=", finding.SevHigh, "exposed .env — application secrets likely included"},
	{".env.local", "=", finding.SevHigh, "exposed .env.local — application secrets likely included"},
	{".env.production", "=", finding.SevHigh, "exposed .env.production — production secrets likely included"},
	{".htpasswd", ":", finding.SevHigh, "exposed .htpasswd — hashed credentials"},
	{".aws/credentials", "aws_access_key_id", finding.SevHigh, "exposed AWS credentials file"},
	{".DS_Store", "Bud1", finding.SevLow, "exposed .DS_Store — leaks file listing"},
	{".bash_history", "", finding.SevHigh, "exposed shell history"},
	{".npmrc", "//registry", finding.SevMedium, "exposed npm config — may include auth tokens"},
	{"server-status", "Apache Server Status", finding.SevMedium, "Apache mod_status enabled — exposes request data"},
	{"phpinfo.php", "PHP Version", finding.SevHigh, "phpinfo() exposed — full server config leak"},
	{"info.php", "PHP Version", finding.SevHigh, "phpinfo() exposed — full server config leak"},
}

// SensitiveFiles probes the target for known sensitive paths. Default scan
// uses ngehe's curated fileFingerprints (high-signal); --top widens the
// probe to use the full SecLists quickhits wordlist.
func SensitiveFiles(client *httpClient, target string, concurrency int, fullWordlist []string) []finding.Finding {
	var (
		mu       sync.Mutex
		findings []finding.Finding
	)

	// First pass: curated high-signal probes with content fingerprinting.
	curated := make([]string, 0, len(fileFingerprints))
	curatedIdx := map[string]fileFingerprint{}
	for _, fp := range fileFingerprints {
		path := "/" + strings.TrimLeft(fp.pathSuffix, "/")
		curated = append(curated, path)
		curatedIdx[path] = fp
	}

	fanout(curated, concurrency, func(path string) {
		resp := client.get(target + path)
		if resp.Status < 200 || resp.Status >= 300 {
			return
		}
		fp := curatedIdx[path]
		if fp.marker != "" && !bytes.Contains(resp.Body, []byte(fp.marker)) {
			return
		}
		mu.Lock()
		findings = append(findings, pathFinding("sensitive-file", target, path, resp, fp.severity, fp.why))
		mu.Unlock()
	})

	// Second pass (only if a wordlist was provided): generic 200-detection.
	// Severity stays low because we don't fingerprint the content.
	if len(fullWordlist) == 0 {
		return findings
	}
	seen := map[string]bool{}
	for _, p := range curated {
		seen[p] = true
	}
	var rest []string
	for _, p := range fullWordlist {
		full := "/" + strings.TrimLeft(p, "/")
		if !seen[full] {
			rest = append(rest, full)
		}
	}
	fanout(rest, concurrency, func(path string) {
		resp := client.get(target + path)
		if resp.Status < 200 || resp.Status >= 300 {
			return
		}
		mu.Lock()
		findings = append(findings, pathFinding(
			"sensitive-path",
			target, path, resp,
			finding.SevLow,
			fmt.Sprintf("path returned %d; manual review needed", resp.Status),
		))
		mu.Unlock()
	})
	return findings
}
