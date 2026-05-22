// Package httpx shells out to projectdiscovery/httpx to probe a list of
// hostnames for live HTTP services. Returns live URLs (so callers can chain
// into ngehe recon / scan) and a finding per live host with the tech stack
// httpx fingerprinted.
package httpx

import (
	"bufio"
	"context"
	"encoding/json"
	"os/exec"
	"strings"
	"time"

	"github.com/chud-lori/ngehe/internal/finding"
)

type Options struct {
	Hosts       []string
	Timeout     time.Duration
	Concurrency int
}

// httpxResult — httpx -json schema (subset).
type httpxResult struct {
	URL        string   `json:"url"`
	Input      string   `json:"input"`
	Title      string   `json:"title"`
	StatusCode int      `json:"status_code"`
	Tech       []string `json:"tech"`
	Webserver  string   `json:"webserver"`
}

func Available() bool {
	_, err := exec.LookPath("httpx")
	return err == nil
}

// SmokeTest verifies httpx is callable.
func SmokeTest() (ok bool, hint string) {
	if !Available() {
		return false, "binary not on PATH — install: ./install.sh --with-extras"
	}
	cmd := exec.Command("httpx", "-version")
	cmd.Stdout, cmd.Stderr = nil, nil
	if err := cmd.Run(); err != nil {
		return false, "binary present but '-version' failed — check architecture / corrupted install"
	}
	return true, ""
}

// Probe runs `httpx -json` against the provided hosts and returns live URLs
// plus findings (severity info) describing each live host's tech stack.
func Probe(opts Options) (liveURLs []string, findings []finding.Finding, err error) {
	if !Available() || len(opts.Hosts) == 0 {
		return nil, nil, nil
	}
	timeout := opts.Timeout
	if timeout == 0 {
		timeout = 3 * time.Minute
	}
	concurrency := opts.Concurrency
	if concurrency <= 0 {
		concurrency = 50
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, "httpx",
		"-json", "-silent", "-nc",
		"-status-code", "-title", "-tech-detect",
		"-threads", itoa(concurrency),
	)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, nil, err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, nil, err
	}
	go func() {
		defer stdin.Close()
		for _, h := range opts.Hosts {
			_, _ = stdin.Write([]byte(h + "\n"))
		}
	}()

	seen := map[string]bool{}
	scanner := bufio.NewScanner(stdout)
	scanner.Buffer(make([]byte, 1024*1024), 4*1024*1024)
	for scanner.Scan() {
		line := scanner.Bytes()
		var r httpxResult
		if err := json.Unmarshal(line, &r); err != nil {
			continue
		}
		if r.URL == "" || seen[r.URL] {
			continue
		}
		seen[r.URL] = true
		liveURLs = append(liveURLs, r.URL)
		evidence := ""
		if r.Title != "" {
			evidence = "title=" + r.Title
		}
		if r.Webserver != "" {
			if evidence != "" {
				evidence += "; "
			}
			evidence += "server=" + r.Webserver
		}
		if len(r.Tech) > 0 {
			if evidence != "" {
				evidence += "; "
			}
			evidence += "tech=" + strings.Join(r.Tech, ",")
		}
		findings = append(findings, finding.Finding{
			Rule:           "httpx-live",
			Severity:       finding.SevInfo,
			Method:         "GET",
			URL:            r.URL,
			Path:           "/",
			OffenderStatus: r.StatusCode,
			Evidence:       evidence,
			Why:            "httpx probe surfaced a live HTTP endpoint — chain into ngehe recon / scan",
			Source:         "httpx",
		})
	}
	_ = cmd.Wait()
	return liveURLs, findings, nil
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}
