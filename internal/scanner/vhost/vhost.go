// Package vhost bruteforces virtual-host names by mutating the HTTP Host
// header against a target IP. Returns mutations whose response differs from
// a control (wildcard / catch-all) response.
package vhost

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/chud-lori/ngehe/internal/finding"
	"github.com/chud-lori/ngehe/internal/httpx"
	"github.com/chud-lori/ngehe/internal/wordlist"
)

// Scan against http://<host>:<port>/ using the given list of vhost candidates.
// `apexDomain` is appended to each candidate, e.g. candidate="admin", apex="htb"
// → Host header "admin.htb". If apexDomain is empty, candidates are used as-is.
func Scan(target, apexDomain string, top int) []finding.Finding {
	client := httpx.NewClient(5000)
	// Establish baseline: a guaranteed-nonexistent vhost.
	baselineHost := "ngehe-baseline-" + randomToken() + suffix(apexDomain)
	baseline := fetch(client, target, baselineHost)
	baselineHash := bodyHash(baseline.Body)

	candidates := wordlist.Subdomains()
	if top > 0 && top < len(candidates) {
		candidates = candidates[:top]
	}

	var mu sync.Mutex
	var out []finding.Finding
	var wg sync.WaitGroup
	sem := make(chan struct{}, 20)
	for _, c := range candidates {
		wg.Add(1)
		sem <- struct{}{}
		go func(sub string) {
			defer wg.Done()
			defer func() { <-sem }()
			host := sub + suffix(apexDomain)
			resp := fetch(client, target, host)
			if resp.Status == 0 {
				return
			}
			if resp.Status == baseline.Status && bodyHash(resp.Body) == baselineHash {
				return
			}
			sev := finding.SevLow
			if resp.Status >= 200 && resp.Status < 400 {
				sev = finding.SevMedium
			}
			mu.Lock()
			out = append(out, finding.Finding{
				Rule: "vhost-discovery", Severity: sev,
				Method:   "GET",
				URL:      target,
				Path:     "/",
				Param:    "Host",
				Payload:  host,
				Evidence: fmt.Sprintf("Host: %s → %d (%d bytes)", host, resp.Status, len(resp.Body)),
				Why:      "Host header returned response distinct from wildcard baseline — virtual host found",
			})
			mu.Unlock()
		}(c)
	}
	wg.Wait()
	return out
}

func fetch(client *http.Client, target, hostHeader string) httpx.Response {
	headers := map[string]string{
		"Host":       hostHeader,
		"User-Agent": "ngehe-vhost/0.2",
	}
	return httpx.Do(client, "GET", target, headers, nil, 64*1024)
}

func bodyHash(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

func suffix(apex string) string {
	if apex == "" {
		return ""
	}
	return "." + apex
}

func randomToken() string {
	return fmt.Sprintf("%d", time.Now().UnixNano()%1000000)
}
