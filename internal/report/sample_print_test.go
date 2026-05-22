package report

import (
	"os"
	"testing"

	"github.com/chud-lori/ngehe/internal/finding"
)

func TestPrintTerminal_Visual(t *testing.T) {
	if os.Getenv("NGEHE_VISUAL") == "" {
		t.Skip("set NGEHE_VISUAL=1 to render sample output")
	}
	findings := []finding.Finding{
		{Rule: "ssti", Severity: finding.SevCritical, Method: "GET", URL: "http://box.htb/api/render?msg={{1337*1331}}", Path: "/api/render", Param: "query:msg", Payload: "{{1337*1331}}", Evidence: "Jinja2 evaluated 1337*1331 → 1779547", Why: "template expr evaluated"},
		{Rule: "sqli-error-based", Severity: finding.SevHigh, Method: "GET", URL: "http://box.htb/api/search?q='", Path: "/api/search", Param: "query:q", Payload: "'", Evidence: "SQLite error: unrecognized token", Why: "DB error"},
		{Rule: "default-credentials", Severity: finding.SevHigh, Method: "POST", URL: "http://box.htb/admin/login", Path: "/admin/login", Payload: "admin:admin", Evidence: "302 to /admin/dashboard", Why: "weak admin creds"},
		{Rule: "tech-fingerprint", Severity: finding.SevInfo, Method: "GET", URL: "http://box.htb", Path: "/", Evidence: "server=nginx; tech=PHP,jQuery", Why: "stack identified"},
		{Rule: "subfinder-subdomain", Severity: finding.SevInfo, Method: "DNS", URL: "dns://admin.box.htb", Path: "/", Source: "subfinder", Why: "subdomain"},
		{Rule: "subfinder-subdomain", Severity: finding.SevInfo, Method: "DNS", URL: "dns://cdn.box.htb", Path: "/", Source: "subfinder", Why: "subdomain"},
		{Rule: "httpx-live", Severity: finding.SevInfo, Method: "GET", URL: "https://admin.box.htb", Path: "/", Evidence: "title=Admin Panel; server=nginx; tech=PHP,Bootstrap", Source: "httpx", Why: "live HTTP"},
		{Rule: "dir-discovery", Severity: finding.SevMedium, Method: "GET", URL: "http://box.htb/admin", Path: "/admin", Evidence: "401 Unauthorized", Why: "auth-gated endpoint"},
	}
	PrintTerminal(os.Stdout, findings)
}
