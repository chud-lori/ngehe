// Package ldap probes LDAP: anonymous bind + Root DSE query (extracts domain
// naming context), then with anonymous read enumerates users / computers /
// kerberos pre-auth-disabled accounts where the server allows it.
package ldap

import (
	"fmt"
	"strings"

	"github.com/chud-lori/ngehe/internal/finding"
	"github.com/go-ldap/ldap/v3"
)

// Scan probes the LDAP service at host:port for anonymous-readable info.
// `port`: usually 389. Pass empty `user` for anonymous bind.
func Scan(host string, port int, user, pass string) []finding.Finding {
	if port == 0 {
		port = 389
	}
	url := fmt.Sprintf("ldap://%s:%d", host, port)
	l, err := ldap.DialURL(url)
	if err != nil {
		return nil
	}
	defer l.Close()

	var out []finding.Finding

	if user == "" {
		if err := l.UnauthenticatedBind(""); err != nil {
			return out
		}
		out = append(out, finding.Finding{
			Rule: "ldap-anonymous-bind", Severity: finding.SevMedium,
			Method: "TCP", URL: url, Path: "/",
			Why: "LDAP server accepted anonymous bind",
		})
	} else {
		if err := l.Bind(user, pass); err != nil {
			return out
		}
	}

	// Root DSE — server's introspection record.
	dse, err := l.Search(ldap.NewSearchRequest(
		"", ldap.ScopeBaseObject, ldap.NeverDerefAliases, 0, 0, false,
		"(objectClass=*)",
		[]string{"defaultNamingContext", "namingContexts", "dnsHostName", "supportedLDAPVersion", "domainFunctionality"},
		nil,
	))
	if err == nil && len(dse.Entries) > 0 {
		entry := dse.Entries[0]
		evidence := entryEvidence(entry, []string{"defaultNamingContext", "dnsHostName", "domainFunctionality"})
		if evidence != "" {
			out = append(out, finding.Finding{
				Rule: "ldap-root-dse", Severity: finding.SevInfo,
				Method: "TCP", URL: url, Path: "/",
				Evidence: evidence,
				Why:      "LDAP Root DSE leaks domain controller info",
			})
		}
	}

	// If we have a naming context, list users + look for AS-REP roastable accounts.
	baseDN := defaultNamingContext(dse)
	if baseDN != "" {
		out = append(out, enumerateUsers(l, url, baseDN)...)
		out = append(out, asrepRoastable(l, url, baseDN)...)
	}
	return out
}

func defaultNamingContext(res *ldap.SearchResult) string {
	if res == nil || len(res.Entries) == 0 {
		return ""
	}
	if v := res.Entries[0].GetAttributeValue("defaultNamingContext"); v != "" {
		return v
	}
	for _, v := range res.Entries[0].GetAttributeValues("namingContexts") {
		if strings.HasPrefix(v, "DC=") {
			return v
		}
	}
	return ""
}

func enumerateUsers(l *ldap.Conn, url, baseDN string) []finding.Finding {
	req := ldap.NewSearchRequest(
		baseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		"(&(objectCategory=person)(objectClass=user))",
		[]string{"sAMAccountName", "userPrincipalName"},
		nil,
	)
	res, err := l.Search(req)
	if err != nil || len(res.Entries) == 0 {
		return nil
	}
	var users []string
	for _, e := range res.Entries {
		if n := e.GetAttributeValue("sAMAccountName"); n != "" {
			users = append(users, n)
		}
	}
	if len(users) == 0 {
		return nil
	}
	preview := strings.Join(users, ", ")
	if len(preview) > 400 {
		preview = preview[:400] + "…"
	}
	return []finding.Finding{{
		Rule: "ldap-user-enum", Severity: finding.SevMedium,
		Method: "TCP", URL: url, Path: "/",
		Evidence: preview,
		Why:      fmt.Sprintf("enumerated %d domain users via LDAP — feed into kerbrute / AS-REP roast / spray", len(users)),
	}}
}

// asrepRoastable: filter for accounts whose UAC bit DONT_REQUIRE_PREAUTH is set.
// 0x400000 = ADS_UF_DONT_REQUIRE_PREAUTH.
func asrepRoastable(l *ldap.Conn, url, baseDN string) []finding.Finding {
	req := ldap.NewSearchRequest(
		baseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		"(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))",
		[]string{"sAMAccountName"},
		nil,
	)
	res, err := l.Search(req)
	if err != nil || len(res.Entries) == 0 {
		return nil
	}
	var users []string
	for _, e := range res.Entries {
		if n := e.GetAttributeValue("sAMAccountName"); n != "" {
			users = append(users, n)
		}
	}
	if len(users) == 0 {
		return nil
	}
	return []finding.Finding{{
		Rule: "ldap-asrep-roastable", Severity: finding.SevHigh,
		Method: "TCP", URL: url, Path: "/",
		Evidence: strings.Join(users, ", "),
		Why:      fmt.Sprintf("%d account(s) have DONT_REQUIRE_PREAUTH set — AS-REP roastable", len(users)),
	}}
}

func entryEvidence(e *ldap.Entry, attrs []string) string {
	var parts []string
	for _, a := range attrs {
		if v := e.GetAttributeValue(a); v != "" {
			parts = append(parts, a+"="+v)
		}
	}
	return strings.Join(parts, " ")
}
