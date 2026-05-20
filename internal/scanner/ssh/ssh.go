// Package ssh probes SSH servers: banner version, known-vulnerable releases,
// supported authentication methods, weak algorithms.
package ssh

import (
	"bufio"
	"fmt"
	"net"
	"regexp"
	"strings"
	"time"

	"github.com/chud-lori/ngehe/internal/finding"
	"golang.org/x/crypto/ssh"
)

// known-vulnerable banner patterns → finding details.
type vulnerableRelease struct {
	pattern *regexp.Regexp
	rule    string
	sev     finding.Severity
	why     string
}

var vulnerableReleases = []vulnerableRelease{
	{regexp.MustCompile(`OpenSSH[_ ]4\.[0-6]`), "ssh-old-openssh", finding.SevHigh, "OpenSSH 4.x (pre-4.7) — extremely old, multiple CVEs"},
	{regexp.MustCompile(`OpenSSH[_ ]5\.[0-2]`), "ssh-old-openssh", finding.SevMedium, "OpenSSH 5.x (pre-5.3) — old, review CVEs"},
	{regexp.MustCompile(`libssh-0\.[0-7]`), "ssh-libssh-auth-bypass", finding.SevCritical, "libssh < 0.8.4 — CVE-2018-10933 authentication bypass"},
	{regexp.MustCompile(`SSH-2\.0-OpenSSH_7\.[0-1]\b`), "ssh-old-openssh-7", finding.SevMedium, "OpenSSH 7.0/7.1 — username enumeration (CVE-2018-15473) applies to ≤7.7"},
	{regexp.MustCompile(`OpenSSH_7\.[2-7]\b`), "ssh-cve-2018-15473", finding.SevLow, "OpenSSH ≤7.7 — CVE-2018-15473 username enumeration"},
	{regexp.MustCompile(`Dropbear[ _]20\d\d\.`), "ssh-dropbear-old", finding.SevLow, "Dropbear SSH — check version for CVEs"},
}

// Scan probes an SSH endpoint and returns findings.
func Scan(host string, port int) []finding.Finding {
	addr := fmt.Sprintf("%s:%d", host, port)
	out := []finding.Finding{}

	banner, err := grabBanner(addr, 5*time.Second)
	if err != nil {
		return out
	}
	out = append(out, finding.Finding{
		Rule: "ssh-banner", Severity: finding.SevInfo,
		Method: "TCP", URL: "ssh://" + addr, Path: "/",
		Evidence: banner,
		Why:      "SSH banner exposed; use for version-based CVE lookup",
	})

	for _, vr := range vulnerableReleases {
		if vr.pattern.MatchString(banner) {
			out = append(out, finding.Finding{
				Rule: vr.rule, Severity: vr.sev,
				Method: "TCP", URL: "ssh://" + addr, Path: "/",
				Evidence: banner,
				Why:      vr.why,
			})
		}
	}

	out = append(out, enumerateAuthMethods(addr)...)
	return out
}

func grabBanner(addr string, timeout time.Duration) (string, error) {
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return "", err
	}
	defer conn.Close()
	_ = conn.SetReadDeadline(time.Now().Add(timeout))
	line, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		return "", err
	}
	return strings.TrimRight(line, "\r\n"), nil
}

// enumerateAuthMethods opens an SSH handshake with a bogus user and reads the
// list of supported methods from the server's NoneAuth rejection.
func enumerateAuthMethods(addr string) []finding.Finding {
	cfg := &ssh.ClientConfig{
		User:            "ngehe-probe",
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
		Auth:            []ssh.AuthMethod{ssh.Password("ngehe-bogus-password")},
	}
	conn, err := ssh.Dial("tcp", addr, cfg)
	if err == nil {
		_ = conn.Close()
		// We were not even rejected — server accepted bogus creds?!
		return []finding.Finding{{
			Rule: "ssh-accepted-bogus-creds", Severity: finding.SevCritical,
			Method: "TCP", URL: "ssh://" + addr, Path: "/",
			Why: "SSH server accepted a known-bogus password — authentication is broken",
		}}
	}
	// Parse the error to extract supported methods.
	methods := parseAuthMethods(err.Error())
	if len(methods) == 0 {
		return nil
	}
	sev := finding.SevInfo
	why := "advertised authentication methods: " + strings.Join(methods, ", ")
	for _, m := range methods {
		if m == "none" {
			return []finding.Finding{{
				Rule: "ssh-none-auth-allowed", Severity: finding.SevCritical,
				Method: "TCP", URL: "ssh://" + addr, Path: "/",
				Evidence: why,
				Why:      "SSH server allows 'none' auth — anyone can log in",
			}}
		}
	}
	return []finding.Finding{{
		Rule: "ssh-auth-methods", Severity: sev,
		Method: "TCP", URL: "ssh://" + addr, Path: "/",
		Evidence: why,
		Why:      "use this list to plan auth attempts (password / publickey / keyboard-interactive)",
	}}
}

var methodsRe = regexp.MustCompile(`(?i)methods?\s+remaining:\s*\[?([^\]]+?)\]?$`)

func parseAuthMethods(s string) []string {
	if m := methodsRe.FindStringSubmatch(s); len(m) > 1 {
		var out []string
		for _, p := range strings.Split(m[1], " ") {
			p = strings.Trim(p, ",")
			if p != "" {
				out = append(out, p)
			}
		}
		return out
	}
	return nil
}
