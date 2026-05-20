// Package creds tries default credentials against configured login URLs.
// One spec per URL with an optional `|` modifier for field names / mode.
//
// Example specs (set in ngehe.yaml under detectors.default_creds_urls):
//   http://target/login
//   http://target/api/login|user=email,password=passwd,json
//   http://target/admin/login.php|user=user,password=pass
//
// Success is recognized by a status transition from the baseline (401/403/2xx
// with error body) plus a new session cookie or a meaningfully different body.
package creds

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/chud-lori/ngehe/internal/config"
	"github.com/chud-lori/ngehe/internal/finding"
	"github.com/chud-lori/ngehe/internal/httpx"
	"github.com/chud-lori/ngehe/internal/wordlist"
)

type loginTarget struct {
	URL           string
	UserField     string
	PasswordField string
	JSONMode      bool
}

func Run(cfg *config.Config) []finding.Finding {
	urls := cfg.Detectors.DefaultCredsURLs
	if len(urls) == 0 {
		return nil
	}
	client := httpx.NewClient(cfg.Replay.TimeoutMS)
	maxBody := cfg.Replay.MaxBodyBytes
	if maxBody == 0 {
		maxBody = 64 * 1024
	}

	var out []finding.Finding
	for _, u := range urls {
		target := parseTarget(u)
		baseline := submit(client, target, "ngehe-baseline-user", "ngehe-baseline-pass", maxBody)
		for _, cred := range wordlist.DefaultCreds() {
			resp := submit(client, target, cred[0], cred[1], maxBody)
			if isLikelyAuthSuccess(baseline, resp) {
				out = append(out, finding.Finding{
					Rule: "default-credentials", Severity: finding.SevCritical,
					Method:         "POST",
					URL:            target.URL,
					Path:           pathOf(target.URL),
					BaselineStatus: baseline.Status,
					OffenderStatus: resp.Status,
					Payload:        cred[0] + ":" + cred[1],
					Evidence:       authEvidence(resp),
					Why:            "default credentials accepted",
				})
				break
			}
		}
	}
	return out
}

func parseTarget(spec string) loginTarget {
	t := loginTarget{URL: spec, UserField: "username", PasswordField: "password"}
	i := strings.Index(spec, "|")
	if i < 0 {
		return t
	}
	t.URL = spec[:i]
	for _, kv := range strings.Split(spec[i+1:], ",") {
		kv = strings.TrimSpace(kv)
		if kv == "json" {
			t.JSONMode = true
			continue
		}
		eq := strings.Index(kv, "=")
		if eq <= 0 {
			continue
		}
		k, v := kv[:eq], kv[eq+1:]
		switch k {
		case "user":
			t.UserField = v
		case "password":
			t.PasswordField = v
		}
	}
	return t
}

func submit(client *http.Client, t loginTarget, user, pass string, maxBody int) httpx.Response {
	if t.JSONMode {
		body, _ := json.Marshal(map[string]string{
			t.UserField:     user,
			t.PasswordField: pass,
		})
		return httpx.Do(client, "POST", t.URL,
			map[string]string{"Content-Type": "application/json", "User-Agent": "ngehe/0.2"},
			body, maxBody)
	}
	form := url.Values{}
	form.Set(t.UserField, user)
	form.Set(t.PasswordField, pass)
	return httpx.Do(client, "POST", t.URL,
		map[string]string{"Content-Type": "application/x-www-form-urlencoded", "User-Agent": "ngehe/0.2"},
		[]byte(form.Encode()), maxBody)
}

func isLikelyAuthSuccess(baseline, candidate httpx.Response) bool {
	if candidate.Status == 0 {
		return false
	}
	if baseline.Status == candidate.Status && bodySimilar(baseline.Body, candidate.Body) {
		return false
	}
	successStatus := candidate.Status == 302 || candidate.Status == 303 ||
		(candidate.Status >= 200 && candidate.Status < 300)
	if !successStatus {
		return false
	}
	return hasNewCookie(baseline, candidate) || !bodySimilar(baseline.Body, candidate.Body)
}

func hasNewCookie(baseline, candidate httpx.Response) bool {
	have := map[string]bool{}
	for _, c := range baseline.Headers.Values("Set-Cookie") {
		have[cookieName(c)] = true
	}
	for _, c := range candidate.Headers.Values("Set-Cookie") {
		if !have[cookieName(c)] {
			return true
		}
	}
	return false
}

func cookieName(setCookie string) string {
	if i := strings.Index(setCookie, "="); i > 0 {
		return setCookie[:i]
	}
	return setCookie
}

func bodySimilar(a, b []byte) bool {
	if len(a) == 0 || len(b) == 0 {
		return len(a) == len(b)
	}
	if len(a) > 4096 {
		a = a[:4096]
	}
	if len(b) > 4096 {
		b = b[:4096]
	}
	return string(a) == string(b)
}

func authEvidence(r httpx.Response) string {
	cookies := r.Headers.Values("Set-Cookie")
	if len(cookies) > 0 {
		return fmt.Sprintf("Set-Cookie: %s", cookies[0])
	}
	return fmt.Sprintf("HTTP %d", r.Status)
}

func pathOf(u string) string {
	if i := strings.Index(u, "://"); i >= 0 {
		rest := u[i+3:]
		if s := strings.Index(rest, "/"); s >= 0 {
			return rest[s:]
		}
	}
	return "/"
}
