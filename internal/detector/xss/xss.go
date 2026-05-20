// Package xss detects reflected cross-site scripting by injecting an
// unencoded HTML-context marker and checking the response body verbatim.
//
// We deliberately use a distinctive tag instead of <script> so the
// detector does not need to bypass naive filters; if the server returns
// our exact tag without escaping, the parameter is reflected unsafely.
package xss

import (
	"strings"

	"github.com/chud-lori/ngehe/internal/config"
	"github.com/chud-lori/ngehe/internal/finding"
	"github.com/chud-lori/ngehe/internal/fuzz"
	"github.com/chud-lori/ngehe/internal/har"
	"github.com/chud-lori/ngehe/internal/httpx"
	"github.com/chud-lori/ngehe/internal/session"
)

const marker = "ngehe-xss-7q3v"

var payloads = []string{
	"<kbmr>" + marker + "</kbmr>",
	"\"><kbmr>" + marker + "</kbmr>",
	"'><kbmr>" + marker + "</kbmr>",
	"</script><kbmr>" + marker + "</kbmr>",
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
		for _, p := range payloads {
			done := false
			for _, inj := range injections(r, p) {
				resp := httpx.FireRequest(client, inj.Request, b, maxBody)
				body := string(resp.Body)
				// require the *unescaped* tag (ngehe marker plus our tag) to appear.
				if strings.Contains(body, "<kbmr>"+marker) || strings.Contains(body, "<kbmr>"+marker+"</kbmr>") {
					out = append(out, finding.Finding{
						Rule: "xss-reflected", Severity: finding.SevHigh,
						Method: inj.Request.Method, URL: inj.Request.URL, Path: inj.Request.Path,
						Param: inj.Param, Payload: inj.Payload,
						Evidence: "<kbmr>" + marker + "</kbmr>",
						Why:      "parameter value was reflected into the response body without HTML encoding",
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
