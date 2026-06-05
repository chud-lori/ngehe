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

// cpanelVersionRe extracts visible cPanel / WHM / cpsrvd versions from common
// management-plane login pages and Server banners.
var cpanelVersionRe = regexp.MustCompile(`(?i)(?:cpanel|whm|cpsrvd|wp\s*squared)[^0-9]{0,32}((?:\d+\.){2,3}\d+)`)

// KnownCVEs checks the target's response banner against ngehe's small list of
// hardcoded high-impact CVEs. Currently covers:
//   - CVE-2026-42945 (NGINX Rift) — heap buffer overflow in
//     ngx_http_rewrite_module, NGINX 0.6.27 through 1.30.0.
//   - CVE-2026-41940 (cPanel & WHM / WP Squared auth bypass) — flags
//     exposed cPanel management surfaces and vulnerable visible versions.
//
// Detection is non-invasive (one GET on /). We deliberately do not send
// exploit payloads: NGINX Rift can crash workers, and CVE-2026-41940 exploit
// probes can create unauthorized sessions on vulnerable servers.
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
	if f, ok := checkCPanelAuthBypass(target, server, resp.Headers.Values("Set-Cookie"), string(resp.Body)); ok {
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

// checkCPanelAuthBypass returns a CVE-2026-41940 finding when the response
// looks like an exposed cPanel / WHM / Webmail / WP Squared management surface.
// If the visible version is in an affected branch, severity is critical. If no
// version is exposed, severity is informational so the report prompts manual
// patch verification without claiming exploitability.
func checkCPanelAuthBypass(target, server string, cookies []string, body string) (finding.Finding, bool) {
	evidence := cpanelEvidence(server, cookies, body)
	if evidence == "" {
		return finding.Finding{}, false
	}
	ver := extractCPanelVersion(server + "\n" + body)
	if ver != "" {
		if isCPanelVulnerableVersion(ver) {
			return finding.Finding{
				Rule:     "cve-2026-41940-cpanel-whm-auth-bypass",
				Severity: finding.SevCritical,
				Method:   "GET",
				URL:      target,
				Path:     "/",
				Evidence: strings.TrimSpace(evidence + "; version " + ver + " is below the fixed release for its branch"),
				Why: "cPanel & WHM / WP Squared version " + ver + " is in a branch affected by CVE-2026-41940, " +
					"a pre-authentication authentication bypass in the login/session flow.",
			}, true
		}
		return finding.Finding{
			Rule:     "cpanel-whm-management-plane",
			Severity: finding.SevInfo,
			Method:   "GET",
			URL:      target,
			Path:     "/",
			Evidence: strings.TrimSpace(evidence + "; visible version " + ver + " is not below the known fixed release for its branch"),
			Why:      "exposed cPanel / WHM management surface; visible version does not match the known vulnerable CVE-2026-41940 ranges",
		}, true
	}
	return finding.Finding{
		Rule:     "cpanel-whm-management-plane",
		Severity: finding.SevInfo,
		Method:   "GET",
		URL:      target,
		Path:     "/",
		Evidence: evidence,
		Why: "exposed cPanel / WHM management surface; verify CVE-2026-41940 patch level manually " +
			"because the response did not expose a version",
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

func cpanelEvidence(server string, cookies []string, body string) string {
	var parts []string
	if strings.Contains(strings.ToLower(server), "cpsrvd") {
		parts = append(parts, "Server: "+strings.TrimSpace(server))
	}
	for _, c := range cookies {
		lc := strings.ToLower(c)
		switch {
		case strings.HasPrefix(lc, "cpsession="):
			parts = append(parts, "Set-Cookie: cpsession")
		case strings.HasPrefix(lc, "cprelogin="):
			parts = append(parts, "Set-Cookie: cprelogin")
		}
	}
	bodyLC := strings.ToLower(body)
	switch {
	case strings.Contains(bodyLC, "whm login"):
		parts = append(parts, "body: WHM login")
	case strings.Contains(bodyLC, "cpanel login"):
		parts = append(parts, "body: cPanel login")
	case strings.Contains(bodyLC, "webmail login"):
		parts = append(parts, "body: Webmail login")
	case strings.Contains(bodyLC, "cpsrvd"):
		parts = append(parts, "body: cpsrvd")
	}
	return strings.Join(dedupe(parts), "; ")
}

func extractCPanelVersion(s string) string {
	m := cpanelVersionRe.FindStringSubmatch(s)
	if len(m) < 2 {
		return ""
	}
	return m[1]
}

func isCPanelVulnerableVersion(ver string) bool {
	v, ok := parseDottedVersion(ver)
	if !ok {
		return false
	}
	ranges := [][2]string{
		{"11.40.0.1", "11.86.0.41"},
		{"11.88.0.0", "11.110.0.97"},
		{"11.112.0.0", "11.118.0.63"},
		{"11.120.0.0", "11.124.0.35"},
		{"11.126.0.0", "11.126.0.54"},
		{"11.128.0.0", "11.130.0.19"},
		{"11.132.0.0", "11.132.0.29"},
		{"11.134.0.0", "11.134.0.20"},
		{"11.136.0.0", "11.136.0.5"},
	}
	for _, r := range ranges {
		lo, _ := parseDottedVersion(r[0])
		fixed, _ := parseDottedVersion(r[1])
		if cmpVersion(v, lo) >= 0 && cmpVersion(v, fixed) < 0 {
			return true
		}
	}
	return false
}

func parseDottedVersion(s string) ([]int, bool) {
	parts := strings.Split(s, ".")
	if len(parts) < 2 {
		return nil, false
	}
	out := make([]int, len(parts))
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil {
			return nil, false
		}
		out[i] = n
	}
	return out, true
}

func cmpVersion(a, b []int) int {
	n := len(a)
	if len(b) > n {
		n = len(b)
	}
	for i := 0; i < n; i++ {
		av, bv := 0, 0
		if i < len(a) {
			av = a[i]
		}
		if i < len(b) {
			bv = b[i]
		}
		if av < bv {
			return -1
		}
		if av > bv {
			return 1
		}
	}
	return 0
}

func dedupe(xs []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, x := range xs {
		if x == "" || seen[x] {
			continue
		}
		seen[x] = true
		out = append(out, x)
	}
	return out
}
