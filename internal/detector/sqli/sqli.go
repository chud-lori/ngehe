// Package sqli detects SQL injection by injecting marker payloads into each
// query/body parameter and checking for DB error strings or time-based delays.
package sqli

import (
	"fmt"
	"regexp"
	"time"

	"github.com/chud-lori/ngehe/internal/config"
	"github.com/chud-lori/ngehe/internal/finding"
	"github.com/chud-lori/ngehe/internal/fuzz"
	"github.com/chud-lori/ngehe/internal/har"
	"github.com/chud-lori/ngehe/internal/httpx"
	"github.com/chud-lori/ngehe/internal/oracle"
	"github.com/chud-lori/ngehe/internal/session"
)

var errorPayloads = []string{`'`, `"`, `')`, `")`, "`"}

var errorPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)you have an error in your sql syntax`),
	regexp.MustCompile(`(?i)warning:\s+mysql`),
	regexp.MustCompile(`(?i)unclosed quotation mark after the character string`),
	regexp.MustCompile(`(?i)quoted string not properly terminated`),
	regexp.MustCompile(`(?i)pg_query|pg::syntaxerror|postgresql query failed`),
	regexp.MustCompile(`(?i)sqlite\s*error|sqlite3::|near ".*": syntax error|sql logic error`),
	regexp.MustCompile(`(?i)unrecognized token`),
	regexp.MustCompile(`(?i)ora-\d{5}`),
	regexp.MustCompile(`(?i)microsoft\s+ole\s+db\s+provider`),
	regexp.MustCompile(`(?i)odbc microsoft access driver`),
	regexp.MustCompile(`(?i)\bsqlstate\[`),
	regexp.MustCompile(`(?i)mysql_fetch_array|mysql_num_rows`),
}

const sleepSec = 5

var timePayloads = []string{
	"' AND SLEEP(5)-- -",
	"\" AND SLEEP(5)-- -",
	"1' AND SLEEP(5)-- -",
	"';WAITFOR DELAY '0:0:5'-- -",
	"';SELECT pg_sleep(5)-- -",
}

func Run(reqs []har.Request, sessions []session.Session, cfg *config.Config) []finding.Finding {
	client := httpx.NewClient(cfg.Replay.TimeoutMS + sleepSec*1000 + 2000)
	maxBody := cfg.Replay.MaxBodyBytes
	if maxBody == 0 {
		maxBody = 256 * 1024
	}
	var out []finding.Finding

	for _, r := range reqs {
		b := pickBearer(r, sessions)

		// Error-based
		for _, payload := range errorPayloads {
			done := false
			for _, inj := range injections(r, payload) {
				resp := httpx.FireRequest(client, inj.Request, b, maxBody)
				if m := oracle.RegexOracle(resp.Body, errorPatterns...); m != "" {
					out = append(out, finding.Finding{
						Rule: "sqli-error-based", Severity: finding.SevHigh,
						Method: inj.Request.Method, URL: inj.Request.URL, Path: inj.Request.Path,
						Param: inj.Param, Payload: inj.Payload,
						Evidence: m,
						Why:      "payload triggered a database error string in the response",
					})
					done = true
					break
				}
			}
			if done {
				break
			}
		}

		// Time-based
		baseline := httpx.FireRequest(client, r, b, maxBody)
		timeFound := false
		for _, payload := range timePayloads {
			if timeFound {
				break
			}
			for _, inj := range injections(r, payload) {
				start := time.Now()
				resp := httpx.FireRequest(client, inj.Request, b, maxBody)
				elapsed := time.Since(start).Milliseconds()
				if resp.Status == 0 {
					continue
				}
				if oracle.TimingOracle(baseline.MS, elapsed, sleepSec*1000) {
					out = append(out, finding.Finding{
						Rule: "sqli-time-based", Severity: finding.SevHigh,
						Method: inj.Request.Method, URL: inj.Request.URL, Path: inj.Request.Path,
						Param: inj.Param, Payload: inj.Payload,
						Evidence: fmt.Sprintf("baseline %dms → injected %dms", baseline.MS, elapsed),
						Why:      "response time grew by the expected sleep duration when sleep payload was injected",
					})
					timeFound = true
					break
				}
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

func pickBearer(r har.Request, sessions []session.Session) httpx.Bearer {
	baseline := session.IdentifyBaseline(r.Headers["Authorization"], sessions)
	for _, s := range sessions {
		if s.Name == baseline {
			return httpx.Bearer{Token: s.Bearer, Headers: s.Headers}
		}
	}
	if len(sessions) > 0 {
		return httpx.Bearer{Token: sessions[0].Bearer, Headers: sessions[0].Headers}
	}
	return httpx.Bearer{}
}
