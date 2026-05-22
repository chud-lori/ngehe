// Package recon discovers facts about a target with only its URL: technology
// fingerprint, exposed sensitive files, hidden paths, and (where login forms
// are reachable) default credentials. Designed to be the first command run
// against a fresh HTB box.
package recon

import (
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/chud-lori/ngehe/internal/finding"
	"github.com/chud-lori/ngehe/internal/httpx"
	"github.com/chud-lori/ngehe/internal/wordlist"
)

// Options configures a recon run.
type Options struct {
	Target      string
	Concurrency int
	TimeoutMS   int
	Top         int  // limit how many wordlist entries to test (0 = all)
	SkipDirbust bool
	Verbose     bool // print sub-step progress to stderr
}

// Run executes all recon sub-detectors and returns aggregated findings.
func Run(opts Options) []finding.Finding {
	if opts.Concurrency <= 0 {
		opts.Concurrency = 20
	}
	target := strings.TrimRight(opts.Target, "/")
	client := &httpClient{c: httpx.NewClient(opts.TimeoutMS), maxBody: 64 * 1024}

	logStep := func(name string, n int, t time.Time) {
		if opts.Verbose {
			fmt.Fprintf(os.Stderr, "    recon[%s]: %d findings (%.1fs)\n", name, n, time.Since(t).Seconds())
		}
	}

	var findings []finding.Finding
	t := time.Now()
	fp := Fingerprint(client, target)
	findings = append(findings, fp...)
	logStep("fingerprint", len(fp), t)

	t = time.Now()
	sens := SensitiveFiles(client, target, opts.Concurrency, limit(wordlist.SensitiveFiles(), opts.Top))
	findings = append(findings, sens...)
	logStep("sensitive-files", len(sens), t)

	if !opts.SkipDirbust {
		t = time.Now()
		dirs := DirBruteforce(client, target, opts.Concurrency, limit(wordlist.CommonPaths(), opts.Top))
		findings = append(findings, dirs...)
		logStep("dir-bruteforce", len(dirs), t)
	}
	return findings
}

// httpClient is a tiny adapter used by recon helpers — keeps signatures small.
type httpClient struct {
	c       *http.Client
	maxBody int
}

func (h *httpClient) get(url string) httpx.Response {
	return httpx.Do(h.c, "GET", url, map[string]string{"User-Agent": "ngehe-recon/0.2"}, nil, h.maxBody)
}

func limit(xs []string, n int) []string {
	if n <= 0 || n >= len(xs) {
		return xs
	}
	return xs[:n]
}

// pathFinding turns a discovered path + response into a Finding with severity
// scaled by how interesting the path is.
func pathFinding(rule, target, path string, resp httpx.Response, sev finding.Severity, why string) finding.Finding {
	return finding.Finding{
		Rule:           rule,
		Severity:       sev,
		Method:         "GET",
		URL:            target + path,
		Path:           path,
		BaselineStatus: resp.Status,
		Evidence:       summarizeBody(resp.Body),
		Why:            why,
	}
}

func summarizeBody(body []byte) string {
	if len(body) == 0 {
		return ""
	}
	trimmed := strings.TrimSpace(string(body))
	if len(trimmed) > 200 {
		trimmed = trimmed[:200] + "…"
	}
	return fmt.Sprintf("%d bytes; preview: %q", len(body), trimmed)
}

// fanout runs `work` for each item in `items` with the given concurrency.
func fanout(items []string, concurrency int, work func(string)) {
	if concurrency < 1 {
		concurrency = 1
	}
	ch := make(chan string)
	var wg sync.WaitGroup
	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for s := range ch {
				work(s)
			}
		}()
	}
	for _, s := range items {
		ch <- s
	}
	close(ch)
	wg.Wait()
}
