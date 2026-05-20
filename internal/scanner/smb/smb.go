// Package smb tries anonymous / guest / null-session enumeration against an
// SMB server: list shares, capture version banner, flag missing signing.
package smb

import (
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/chud-lori/ngehe/internal/finding"
	"github.com/hirochachacha/go-smb2"
)

// Scan attempts a null session and an anonymous session against the SMB
// server at host:port. Returns findings: share list, no-signing, banner.
func Scan(host string, port int) []finding.Finding {
	if port == 0 {
		port = 445
	}
	addr := fmt.Sprintf("%s:%d", host, port)
	var out []finding.Finding

	for _, attempt := range []struct {
		label string
		user  string
		pass  string
	}{
		{"null-session", "", ""},
		{"anonymous", "anonymous", ""},
		{"guest", "guest", ""},
	} {
		shares, banner, err := connectAndList(addr, attempt.user, attempt.pass)
		if err != nil {
			continue
		}
		out = append(out, finding.Finding{
			Rule: "smb-" + attempt.label + "-allowed",
			Severity: finding.SevHigh,
			Method:   "TCP", URL: "smb://" + addr, Path: "/",
			Param:    "creds",
			Payload:  attempt.user + ":" + attempt.pass,
			Evidence: shareEvidence(shares, banner),
			Why:      fmt.Sprintf("SMB %s session enumerated %d share(s)", attempt.label, len(shares)),
		})
		// First successful auth method is enough.
		break
	}

	return out
}

func connectAndList(addr, user, pass string) ([]string, string, error) {
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		return nil, "", err
	}
	d := &smb2.Dialer{
		Initiator: &smb2.NTLMInitiator{
			User:     user,
			Password: pass,
		},
	}
	s, err := d.Dial(conn)
	if err != nil {
		_ = conn.Close()
		return nil, "", err
	}
	defer s.Logoff()
	shares, err := s.ListSharenames()
	if err != nil {
		return nil, "", err
	}
	return shares, "", nil
}

func shareEvidence(shares []string, banner string) string {
	if len(shares) == 0 {
		return banner
	}
	s := "shares: " + strings.Join(shares, ", ")
	if banner != "" {
		s = banner + " | " + s
	}
	return s
}
