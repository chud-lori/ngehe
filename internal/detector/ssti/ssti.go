// Package ssti detects server-side template injection across major engines
// by injecting math probes per syntax and checking for the evaluated result.
package ssti

import (
	"github.com/chud-lori/ngehe/internal/config"
	"github.com/chud-lori/ngehe/internal/finding"
	"github.com/chud-lori/ngehe/internal/fuzz"
	"github.com/chud-lori/ngehe/internal/har"
	"github.com/chud-lori/ngehe/internal/httpx"
	"github.com/chud-lori/ngehe/internal/oracle"
	"github.com/chud-lori/ngehe/internal/session"
)

// probe pairs a template syntax with the expected evaluation marker.
// The marker is "1763889" = 1337*1331, distinctive enough to avoid
// natural-prose collisions in response bodies.
type probe struct {
	engine  string
	payload string
	marker  string
}

var probes = []probe{
	{"Jinja2/Twig/Liquid", "{{1337*1331}}", "1779547"},
	{"Velocity/Freemarker", "${1337*1331}", "1779547"},
	{"ERB", "<%= 1337*1331 %>", "1779547"},
	{"Smarty/Mako", "{1337*1331}", "1779547"},
	{"Razor", "@(1337*1331)", "1779547"},
	{"Pug", "#{1337*1331}", "1779547"},
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
		baseline := httpx.FireRequest(client, r, b, maxBody)
		baselineHasMarker := oracle.StringOracle(baseline.Body, "1779547") != ""

		for _, p := range probes {
			done := false
			for _, inj := range injections(r, p.payload) {
				resp := httpx.FireRequest(client, inj.Request, b, maxBody)
				if baselineHasMarker {
					continue
				}
				if m := oracle.StringOracle(resp.Body, p.marker); m != "" {
					out = append(out, finding.Finding{
						Rule: "ssti", Severity: finding.SevCritical,
						Method: inj.Request.Method, URL: inj.Request.URL, Path: inj.Request.Path,
						Param: inj.Param, Payload: inj.Payload,
						Evidence: p.engine + " evaluated 1337*1331 → " + m,
						Why:      "template expression was evaluated server-side — SSTI confirmed (RCE chain available)",
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
