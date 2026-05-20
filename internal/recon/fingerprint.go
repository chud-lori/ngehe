package recon

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/chud-lori/ngehe/internal/finding"
	"github.com/chud-lori/ngehe/internal/httpx"
)

// signature pairs a marker with the technology it identifies. Body markers
// use a regex; header markers use a substring match.
type signature struct {
	name        string
	headerName  string
	headerRegex *regexp.Regexp
	cookieName  string
	bodyRegex   *regexp.Regexp
}

var signatures = []signature{
	// Servers
	{name: "nginx", headerName: "Server", headerRegex: regexp.MustCompile(`(?i)nginx/?(\d[\d\.]*)?`)},
	{name: "Apache", headerName: "Server", headerRegex: regexp.MustCompile(`(?i)apache/?(\d[\d\.]*)?`)},
	{name: "IIS", headerName: "Server", headerRegex: regexp.MustCompile(`(?i)microsoft-iis/?(\d[\d\.]*)?`)},
	{name: "Caddy", headerName: "Server", headerRegex: regexp.MustCompile(`(?i)caddy`)},
	{name: "LiteSpeed", headerName: "Server", headerRegex: regexp.MustCompile(`(?i)litespeed`)},
	{name: "Cloudflare", headerName: "Server", headerRegex: regexp.MustCompile(`(?i)cloudflare`)},

	// Languages/frameworks via X-Powered-By
	{name: "PHP", headerName: "X-Powered-By", headerRegex: regexp.MustCompile(`(?i)php/?(\d[\d\.]*)?`)},
	{name: "ASP.NET", headerName: "X-Powered-By", headerRegex: regexp.MustCompile(`(?i)asp\.net`)},
	{name: "Express", headerName: "X-Powered-By", headerRegex: regexp.MustCompile(`(?i)express`)},
	{name: "Servlet", headerName: "X-Powered-By", headerRegex: regexp.MustCompile(`(?i)servlet/?(\d[\d\.]*)?`)},

	// Cookies
	{name: "PHP session", cookieName: "PHPSESSID"},
	{name: "Java servlet", cookieName: "JSESSIONID"},
	{name: "ASP.NET session", cookieName: "ASP.NET_SessionId"},
	{name: "Django", cookieName: "csrftoken"},
	{name: "Express session", cookieName: "connect.sid"},
	{name: "Laravel", cookieName: "laravel_session"},
	{name: "Rails", cookieName: "_rails_session"},

	// Body markers
	{name: "WordPress", bodyRegex: regexp.MustCompile(`(?i)wp-content|wp-includes|/wp-json/`)},
	{name: "Drupal", bodyRegex: regexp.MustCompile(`(?i)drupal\.settings|sites/default/files`)},
	{name: "Joomla", bodyRegex: regexp.MustCompile(`(?i)joomla|/components/com_`)},
	{name: "Magento", bodyRegex: regexp.MustCompile(`(?i)mage\.cookies|/skin/frontend/`)},
	{name: "Jenkins", bodyRegex: regexp.MustCompile(`(?i)<title>[^<]*jenkins`)},
	{name: "GitLab", bodyRegex: regexp.MustCompile(`(?i)gitlab`)},
	{name: "Grafana", bodyRegex: regexp.MustCompile(`(?i)grafana`)},
	{name: "Tomcat", bodyRegex: regexp.MustCompile(`(?i)apache tomcat`)},
	{name: "Spring Boot Actuator", bodyRegex: regexp.MustCompile(`(?i)"status":"UP"`)},
	{name: "Swagger UI", bodyRegex: regexp.MustCompile(`(?i)swagger-ui`)},
	{name: "GraphiQL", bodyRegex: regexp.MustCompile(`(?i)graphiql`)},
	{name: "phpMyAdmin", bodyRegex: regexp.MustCompile(`(?i)phpmyadmin`)},
}

// Fingerprint hits the target URL and emits one finding per identified tech.
func Fingerprint(client *httpClient, target string) []finding.Finding {
	resp := client.get(target)
	if resp.Status == 0 {
		return nil
	}
	var out []finding.Finding
	for _, sig := range signatures {
		evidence, matched := matchSignature(sig, resp)
		if !matched {
			continue
		}
		out = append(out, finding.Finding{
			Rule:     "tech-fingerprint",
			Severity: finding.SevInfo,
			Method:   "GET",
			URL:      target,
			Path:     "/",
			Evidence: evidence,
			Why:      fmt.Sprintf("identified %s via %s", sig.name, signatureSource(sig)),
		})
	}
	// Always emit raw Server / X-Powered-By when present, even unmatched.
	if s := resp.Headers.Get("Server"); s != "" {
		out = append(out, finding.Finding{
			Rule: "server-header", Severity: finding.SevInfo, Method: "GET", URL: target, Path: "/",
			Evidence: "Server: " + s,
			Why:      "server identified itself in HTTP response headers",
		})
	}
	if s := resp.Headers.Get("X-Powered-By"); s != "" {
		out = append(out, finding.Finding{
			Rule: "x-powered-by", Severity: finding.SevInfo, Method: "GET", URL: target, Path: "/",
			Evidence: "X-Powered-By: " + s,
			Why:      "server exposed framework/runtime version in X-Powered-By header",
		})
	}
	return out
}

func matchSignature(sig signature, resp httpx.Response) (string, bool) {
	if sig.headerName != "" && sig.headerRegex != nil {
		val := resp.Headers.Get(sig.headerName)
		if m := sig.headerRegex.FindString(val); m != "" {
			return sig.headerName + ": " + m, true
		}
	}
	if sig.cookieName != "" {
		for _, c := range resp.Headers.Values("Set-Cookie") {
			if strings.HasPrefix(c, sig.cookieName+"=") {
				return "Set-Cookie: " + sig.cookieName, true
			}
		}
	}
	if sig.bodyRegex != nil {
		if m := sig.bodyRegex.Find(resp.Body); m != nil {
			return "body: " + string(m), true
		}
	}
	return "", false
}

func signatureSource(sig signature) string {
	switch {
	case sig.headerName != "":
		return sig.headerName + " header"
	case sig.cookieName != "":
		return sig.cookieName + " cookie"
	case sig.bodyRegex != nil:
		return "response body"
	}
	return ""
}
