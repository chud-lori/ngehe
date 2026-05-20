// Package dns enumerates DNS info: attempts AXFR zone transfer and runs a
// small subdomain bruteforce against the configured wordlist.
package dns

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/chud-lori/ngehe/internal/finding"
	"github.com/chud-lori/ngehe/internal/wordlist"
	mdns "github.com/miekg/dns"
)

// Scan probes the given nameserver host:port for the given domain.
// `nameserver` is "1.2.3.4:53" or just the IP (port 53 implied).
// `domain` is "target.htb" — the zone to enumerate.
func Scan(nameserver, domain string, top int) []finding.Finding {
	ns := normalizeNS(nameserver)
	domain = strings.TrimRight(domain, ".") + "."
	var out []finding.Finding
	out = append(out, axfr(ns, domain)...)
	out = append(out, bruteforce(ns, domain, top)...)
	return out
}

func normalizeNS(ns string) string {
	if strings.Contains(ns, ":") {
		return ns
	}
	return ns + ":53"
}

func axfr(ns, domain string) []finding.Finding {
	tr := new(mdns.Transfer)
	m := new(mdns.Msg)
	m.SetAxfr(domain)
	ch, err := tr.In(m, ns)
	if err != nil {
		return nil
	}
	var records []string
	for env := range ch {
		if env.Error != nil {
			break
		}
		for _, rr := range env.RR {
			records = append(records, rr.String())
		}
	}
	if len(records) == 0 {
		return nil
	}
	preview := strings.Join(records, "\n")
	if len(preview) > 400 {
		preview = preview[:400] + "…"
	}
	return []finding.Finding{{
		Rule: "dns-axfr-allowed", Severity: finding.SevHigh,
		Method: "TCP", URL: "dns://" + ns + "/" + domain, Path: "/",
		Evidence: preview,
		Why:      fmt.Sprintf("zone transfer (AXFR) succeeded — %d records leaked", len(records)),
	}}
}

func bruteforce(ns, domain string, top int) []finding.Finding {
	subs := wordlist.Subdomains()
	if top > 0 && top < len(subs) {
		subs = subs[:top]
	}
	client := &mdns.Client{Net: "udp", Timeout: 3 * time.Second}

	var mu sync.Mutex
	var out []finding.Finding
	var wg sync.WaitGroup
	sem := make(chan struct{}, 50)
	for _, sub := range subs {
		wg.Add(1)
		sem <- struct{}{}
		go func(s string) {
			defer wg.Done()
			defer func() { <-sem }()
			fqdn := s + "." + domain
			m := new(mdns.Msg)
			m.SetQuestion(fqdn, mdns.TypeA)
			r, _, err := client.Exchange(m, ns)
			if err != nil || r == nil || len(r.Answer) == 0 {
				return
			}
			var addrs []string
			for _, a := range r.Answer {
				if rec, ok := a.(*mdns.A); ok {
					addrs = append(addrs, rec.A.String())
				}
			}
			if len(addrs) == 0 {
				return
			}
			mu.Lock()
			out = append(out, finding.Finding{
				Rule: "dns-subdomain", Severity: finding.SevLow,
				Method: "DNS", URL: "dns://" + fqdn, Path: "/",
				Evidence: strings.Join(addrs, ", "),
				Why:      "subdomain resolved — potential additional attack surface",
			})
			mu.Unlock()
		}(sub)
	}
	wg.Wait()
	return out
}
