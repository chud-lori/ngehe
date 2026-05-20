// Package wordlist embeds the wordlists ngehe uses for recon and active
// detectors. The bundled lists come from danielmiessler/SecLists (MIT) —
// the de-facto standard wordlist collection used by ffuf, gobuster,
// dirsearch, feroxbuster, and most other web pentest tools.
//
// See NOTICE.md for attribution.
package wordlist

import (
	_ "embed"
	"encoding/csv"
	"strings"
)

//go:embed seclists_common_paths.txt
var rawCommonPaths string

//go:embed seclists_quickhits.txt
var rawQuickHits string

//go:embed seclists_default_passwords.csv
var rawDefaultPasswordsCSV string

//go:embed seclists_snmp_community.txt
var rawSNMP string

//go:embed seclists_subdomains.txt
var rawSubdomains string

// CommonPaths returns SecLists' Discovery/Web-Content/common.txt — the
// classic ~4750-entry directory bruteforce wordlist used by gobuster/ffuf.
func CommonPaths() []string {
	return splitLines(rawCommonPaths)
}

// SensitiveFiles returns SecLists' Discovery/Web-Content/quickhits.txt —
// targeted probes for .git, .env, backup files, server-status, etc.
func SensitiveFiles() []string {
	return splitLines(rawQuickHits)
}

// DefaultCreds returns a curated subset of universally useful web-pentest
// credentials. Pulled from common practice + SecLists. Use AllDefaultCreds
// for the full vendor-default database (~2800 entries).
func DefaultCreds() [][2]string {
	return curatedWebCreds
}

// SNMPCommunities returns SecLists' common SNMP community strings.
func SNMPCommunities() []string {
	return splitLines(rawSNMP)
}

// Subdomains returns SecLists' top-1m DNS subdomain list (~5k entries).
// Used by both subdomain enumeration and vhost bruteforce.
func Subdomains() []string {
	return splitLines(rawSubdomains)
}

// AllDefaultCreds returns the full SecLists default-passwords database
// parsed from CSV. Useful when probing identified vendor login pages
// (e.g. Tomcat manager, JBoss console, network appliances). Skips entries
// where either username or password is "<BLANK>" (ngehe treats these as
// "try empty"; many web servers reject empty creds at the form layer, so
// the curated list is a better default).
func AllDefaultCreds() [][2]string {
	r := csv.NewReader(strings.NewReader(rawDefaultPasswordsCSV))
	r.FieldsPerRecord = -1
	rows, err := r.ReadAll()
	if err != nil {
		return nil
	}
	var out [][2]string
	for i, row := range rows {
		if i == 0 || len(row) < 3 {
			continue
		}
		u, p := row[1], row[2]
		if u == "<BLANK>" {
			u = ""
		}
		if p == "<BLANK>" {
			p = ""
		}
		if u == "" && p == "" {
			continue
		}
		out = append(out, [2]string{u, p})
	}
	return out
}

// curatedWebCreds — the credentials that actually matter for web pentest
// in practice. These crop up on admin panels, CI servers, dev tools, and
// hastily-deployed test instances. Order roughly by hit rate.
var curatedWebCreds = [][2]string{
	{"admin", "admin"},
	{"admin", "password"},
	{"admin", "admin123"},
	{"admin", "changeme"},
	{"admin", "123456"},
	{"admin", "secret"},
	{"admin", "welcome"},
	{"admin", "admin@123"},
	{"administrator", "administrator"},
	{"administrator", "password"},
	{"root", "root"},
	{"root", "toor"},
	{"root", "password"},
	{"root", "admin"},
	{"user", "user"},
	{"user", "password"},
	{"test", "test"},
	{"test", "test123"},
	{"guest", "guest"},
	{"demo", "demo"},
	{"tomcat", "tomcat"},
	{"tomcat", "s3cret"},
	{"manager", "manager"},
	{"jenkins", "jenkins"},
	{"postgres", "postgres"},
	{"mysql", "mysql"},
	{"oracle", "oracle"},
	{"sa", ""},
	{"sa", "sa"},
	{"sa", "password"},
	{"weblogic", "weblogic"},
	{"ftp", "ftp"},
	{"anonymous", ""},
}

func splitLines(s string) []string {
	var out []string
	for _, ln := range strings.Split(s, "\n") {
		ln = strings.TrimSpace(ln)
		if ln == "" || strings.HasPrefix(ln, "#") {
			continue
		}
		out = append(out, ln)
	}
	return out
}
