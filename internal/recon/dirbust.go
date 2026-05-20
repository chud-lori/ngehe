package recon

import (
	"strings"
	"sync"

	"github.com/chud-lori/ngehe/internal/finding"
)

// DirBruteforce walks the wordlist against the target and reports each path
// that returns a non-{404, 410, 0} status. A baseline 404 fingerprint is
// captured first so apps that return 200/302 for everything (catch-all
// routers) are detected and the scan is short-circuited.
func DirBruteforce(client *httpClient, target string, concurrency int, paths []string) []finding.Finding {
	if len(paths) == 0 {
		return nil
	}
	baseline := client.get(target + "/ngehe-baseline-" + randomToken())
	if baseline.Status >= 200 && baseline.Status < 400 {
		return []finding.Finding{{
			Rule:     "dir-bruteforce-skipped",
			Severity: finding.SevInfo,
			Method:   "GET",
			URL:      target,
			Path:     "/",
			Why:      "target returns success for nonexistent paths (catch-all SPA?); dir bruteforce skipped",
		}}
	}

	var (
		mu       sync.Mutex
		findings []finding.Finding
	)
	fanout(paths, concurrency, func(p string) {
		path := "/" + strings.TrimLeft(p, "/")
		resp := client.get(target + path)
		if resp.Status == 0 || resp.Status == 404 || resp.Status == 410 {
			return
		}
		sev := finding.SevLow
		why := "path returned " + statusName(resp.Status) + "; investigate"
		switch {
		case resp.Status == 401 || resp.Status == 403:
			sev = finding.SevMedium
			why = "path requires auth — likely a real endpoint worth attacking"
		case resp.Status >= 200 && resp.Status < 300:
			sev = finding.SevMedium
			why = "path returned 2xx — accessible endpoint"
		case resp.Status >= 300 && resp.Status < 400:
			sev = finding.SevLow
			why = "path returned redirect — follow the Location header"
		}
		mu.Lock()
		findings = append(findings, pathFinding("dir-discovery", target, path, resp, sev, why))
		mu.Unlock()
	})
	return findings
}

func statusName(s int) string {
	switch {
	case s >= 200 && s < 300:
		return "2xx"
	case s >= 300 && s < 400:
		return "3xx"
	case s >= 400 && s < 500:
		return "4xx"
	case s >= 500:
		return "5xx"
	}
	return "?"
}

// randomToken returns a deterministic-ish string for baseline detection.
// We don't need crypto-random — just something unlikely to exist.
func randomToken() string {
	return "x7zk9q3v1n0p"
}
