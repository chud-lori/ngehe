package recon

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/chud-lori/ngehe/internal/finding"
)

// nginxVerRe extracts the "X.Y.Z" portion of a "nginx/X.Y.Z" Server header.
var nginxVerRe = regexp.MustCompile(`(?i)nginx/(\d+)\.(\d+)\.(\d+)`)

// KnownCVEs checks the target's response banner against ngehe's small list of
// hardcoded high-impact CVEs. Currently covers:
//   - CVE-2026-42945 (NGINX Rift) — heap buffer overflow in
//     ngx_http_rewrite_module, NGINX 0.6.27 through 1.30.0.
//
// Detection is banner-only (one GET on /). We deliberately do not send a
// crafted rewrite-trigger payload — the vuln symptom is a worker crash, which
// would amount to a DoS on the target. Confirm exploitability with the
// published PoC out-of-band on authorized targets only.
func KnownCVEs(client *httpClient, target string) []finding.Finding {
	resp := client.get(target)
	if resp.Status == 0 {
		return nil
	}
	server := resp.Headers.Get("Server")
	if server == "" {
		return nil
	}
	var out []finding.Finding
	if f, ok := checkNginxRift(target, server); ok {
		out = append(out, f)
	}
	return out
}

// checkNginxRift returns a CVE-2026-42945 finding if the Server header
// advertises an nginx version in the vulnerable range (0.6.27 ≤ v ≤ 1.30.0).
func checkNginxRift(target, server string) (finding.Finding, bool) {
	m := nginxVerRe.FindStringSubmatch(server)
	if m == nil {
		return finding.Finding{}, false
	}
	major, _ := strconv.Atoi(m[1])
	minor, _ := strconv.Atoi(m[2])
	patch, _ := strconv.Atoi(m[3])
	ver := [3]int{major, minor, patch}
	lo := [3]int{0, 6, 27}
	hi := [3]int{1, 30, 0}
	if cmp3(ver, lo) < 0 || cmp3(ver, hi) > 0 {
		return finding.Finding{}, false
	}
	verStr := fmt.Sprintf("%d.%d.%d", major, minor, patch)
	return finding.Finding{
		Rule:     "cve-2026-42945-nginx-rift",
		Severity: finding.SevCritical,
		Method:   "GET",
		URL:      target,
		Path:     "/",
		Evidence: "Server: " + strings.TrimSpace(server) + " (vulnerable range 0.6.27–1.30.0)",
		Why: "NGINX " + verStr + " — heap buffer overflow in ngx_http_rewrite_module " +
			"(CVE-2026-42945, CVSS 9.2). Triggerable by unauthenticated HTTP if config " +
			"uses rewrite + unnamed PCRE captures with '?' in the replacement. Crashes " +
			"workers; RCE possible when ASLR is disabled.",
	}, true
}

// cmp3 compares two 3-component version tuples lexicographically.
// Returns -1, 0, 1.
func cmp3(a, b [3]int) int {
	for i := 0; i < 3; i++ {
		if a[i] < b[i] {
			return -1
		}
		if a[i] > b[i] {
			return 1
		}
	}
	return 0
}
