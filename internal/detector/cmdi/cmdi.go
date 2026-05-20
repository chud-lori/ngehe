// Package cmdi detects OS command injection. Two oracles: timing (sleep
// payload causes a measurable delay) and marker (echoed value appears in
// response body).
package cmdi

import (
	"fmt"
	"time"

	"github.com/chud-lori/ngehe/internal/config"
	"github.com/chud-lori/ngehe/internal/finding"
	"github.com/chud-lori/ngehe/internal/fuzz"
	"github.com/chud-lori/ngehe/internal/har"
	"github.com/chud-lori/ngehe/internal/httpx"
	"github.com/chud-lori/ngehe/internal/oracle"
	"github.com/chud-lori/ngehe/internal/session"
)

const sleepSec = 5
const marker = "ngehecmdi42"

var timePayloads = []string{
	";sleep 5",
	"|sleep 5",
	"`sleep 5`",
	"$(sleep 5)",
	"&&sleep 5",
	"%0asleep 5",
	"& timeout /t 5",
}

var markerPayloads = []string{
	";echo " + marker,
	"|echo " + marker,
	"`echo " + marker + "`",
	"$(echo " + marker + ")",
	"&&echo " + marker,
}

func Run(reqs []har.Request, sessions []session.Session, cfg *config.Config) []finding.Finding {
	client := httpx.NewClient(cfg.Replay.TimeoutMS + sleepSec*1000 + 2000)
	maxBody := cfg.Replay.MaxBodyBytes
	if maxBody == 0 {
		maxBody = 256 * 1024
	}
	var out []finding.Finding

	for _, r := range reqs {
		b := bearer(r, sessions)
		baseline := httpx.FireRequest(client, r, b, maxBody)

		// Baseline-aware: per parameter, first send the marker *without* shell
		// metacharacters. If the response already contains it, the param is
		// merely reflected and any subsequent marker-hit would be a false
		// positive. Track which params are "reflective" and skip them.
		reflective := map[string]bool{}
		for _, inj := range allInj(r, marker) {
			resp := httpx.FireRequest(client, inj.Request, b, maxBody)
			if oracle.StringOracle(resp.Body, marker) != "" {
				reflective[inj.Param] = true
			}
		}

		for _, payload := range markerPayloads {
			done := false
			for _, inj := range allInj(r, payload) {
				if reflective[inj.Param] {
					continue
				}
				resp := httpx.FireRequest(client, inj.Request, b, maxBody)
				if m := oracle.StringOracle(resp.Body, marker); m != "" {
					out = append(out, finding.Finding{
						Rule: "cmdi-marker", Severity: finding.SevCritical,
						Method: inj.Request.Method, URL: inj.Request.URL, Path: inj.Request.Path,
						Param: inj.Param, Payload: inj.Payload,
						Evidence: m,
						Why:      "shell command output reflected in response — RCE confirmed",
					})
					done = true
					break
				}
			}
			if done {
				break
			}
		}

		for _, payload := range timePayloads {
			done := false
			for _, inj := range allInj(r, payload) {
				start := time.Now()
				resp := httpx.FireRequest(client, inj.Request, b, maxBody)
				elapsed := time.Since(start).Milliseconds()
				if resp.Status == 0 {
					continue
				}
				if oracle.TimingOracle(baseline.MS, elapsed, sleepSec*1000) {
					out = append(out, finding.Finding{
						Rule: "cmdi-time-based", Severity: finding.SevCritical,
						Method: inj.Request.Method, URL: inj.Request.URL, Path: inj.Request.Path,
						Param: inj.Param, Payload: inj.Payload,
						Evidence: fmt.Sprintf("baseline %dms → injected %dms", baseline.MS, elapsed),
						Why:      "sleep payload caused the expected response delay — blind command injection",
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

func allInj(r har.Request, payload string) []fuzz.Injection {
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
