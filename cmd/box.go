package cmd

import (
	"fmt"
	"net/url"
	"os"
	"strings"

	"github.com/chud-lori/ngehe/internal/config"
	"github.com/chud-lori/ngehe/internal/detector/cmdi"
	"github.com/chud-lori/ngehe/internal/detector/lfi"
	"github.com/chud-lori/ngehe/internal/detector/sqli"
	"github.com/chud-lori/ngehe/internal/detector/ssrf"
	"github.com/chud-lori/ngehe/internal/detector/ssti"
	"github.com/chud-lori/ngehe/internal/detector/xss"
	"github.com/chud-lori/ngehe/internal/finding"
	"github.com/chud-lori/ngehe/internal/portscan"
	"github.com/chud-lori/ngehe/internal/recon"
	"github.com/chud-lori/ngehe/internal/report"
	"github.com/chud-lori/ngehe/internal/scanner/dbcreds"
	"github.com/chud-lori/ngehe/internal/scanner/dns"
	"github.com/chud-lori/ngehe/internal/scanner/ftp"
	"github.com/chud-lori/ngehe/internal/scanner/ldap"
	"github.com/chud-lori/ngehe/internal/scanner/smb"
	"github.com/chud-lori/ngehe/internal/scanner/snmp"
	"github.com/chud-lori/ngehe/internal/scanner/ssh"
	"github.com/chud-lori/ngehe/internal/session"
	"github.com/chud-lori/ngehe/internal/synth"
	"github.com/spf13/cobra"
)

var (
	boxTarget   string
	boxProfile  string
	boxDomain   string
	boxOut      string
	boxMD       string
	boxNoWeb    bool
	boxTopWords int
)

var boxCmd = &cobra.Command{
	Use:   "box",
	Short: "Full-spectrum HTB-box scan: nmap → per-service scanners → web recon",
	Long: `Scan an entire box from one command. ngehe shells out to nmap (must be
installed) to discover open ports, then dispatches per-service scanners and
finally runs the web recon flow against any HTTP-ish ports found.

Detectors per service:
  ssh    banner + cve hints + auth methods + 'none' bypass
  ftp    anonymous login + listing + writable dirs
  smb    null/anonymous/guest session + share listing
  ldap   anonymous bind + root DSE + user enum + AS-REP roastable accounts
  snmp   common community strings (public, private, manager, ...)
  dns    AXFR zone transfer + subdomain bruteforce
  http   tech fingerprint + sensitive files + dir bruteforce
  mysql/postgres/mssql/redis  default credentials check`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if boxTarget == "" {
			return fmt.Errorf("--target is required (e.g. 10.10.11.5)")
		}
		fmt.Fprintf(os.Stderr, "ngehe box → %s (profile=%s)\n", boxTarget, boxProfile)

		scan, err := portscan.Run(boxTarget, portscan.Profile(boxProfile), nil)
		if err != nil {
			return err
		}
		findings := append([]finding.Finding{}, scan.Findings...)
		fmt.Fprintf(os.Stderr, "port-scan: %d open services\n", len(scan.Services))

		for _, svc := range scan.Services {
			label := fmt.Sprintf("%s/%d %s", svc.Proto, svc.Port, svc.Service)
			before := len(findings)
			switch svc.Service {
			case "ssh":
				findings = append(findings, ssh.Scan(svc.Host, svc.Port)...)
			case "ftp":
				findings = append(findings, ftp.Scan(svc.Host, svc.Port)...)
			case "snmp":
				findings = append(findings, snmp.Scan(svc.Host, svc.Port)...)
			case "domain", "dns":
				if boxDomain != "" {
					findings = append(findings, dns.Scan(svc.Host, boxDomain, boxTopWords)...)
				}
			case "microsoft-ds", "netbios-ssn":
				findings = append(findings, smb.Scan(svc.Host, svc.Port)...)
			case "ldap":
				findings = append(findings, ldap.Scan(svc.Host, svc.Port, "", "")...)
			case "mysql", "mariadb", "postgresql", "postgres", "ms-sql-s", "mssql", "redis":
				findings = append(findings, dbcreds.Scan(svc.Host, svc.Port, svc.Service)...)
			case "http", "https", "http-alt", "http-proxy":
				if !boxNoWeb {
					target := webURL(svc.Service, svc.Host, svc.Port)
					reconOpts := recon.Options{Target: target, Concurrency: 20, TimeoutMS: 5000, Top: boxTopWords}
					reconF := recon.Run(reconOpts)
					findings = append(findings, reconF...)

					// Hand off to active detectors against discovered paths.
					var paths []string
					for _, f := range reconF {
						if f.Rule == "dir-discovery" || f.Rule == "sensitive-path" {
							paths = append(paths, f.Path)
						}
					}
					synthReqs := synth.Requests(target, paths)
					emptyCfg := &config.Config{
						Replay: config.Replay{Concurrency: 4, TimeoutMS: 5000, MaxBodyBytes: 256 * 1024},
					}
					anon := []session.Session{session.Anon()}
					webF := []finding.Finding{}
					webF = append(webF, sqli.Run(synthReqs, anon, emptyCfg)...)
					webF = append(webF, cmdi.Run(synthReqs, anon, emptyCfg)...)
					webF = append(webF, ssti.Run(synthReqs, anon, emptyCfg)...)
					webF = append(webF, lfi.Run(synthReqs, anon, emptyCfg)...)
					webF = append(webF, ssrf.Run(synthReqs, anon, emptyCfg)...)
					webF = append(webF, xss.Run(synthReqs, anon, emptyCfg)...)
					findings = append(findings, webF...)
				}
			}
			fmt.Fprintf(os.Stderr, "%-30s → %d findings\n", label, len(findings)-before)
		}

		fmt.Fprintf(os.Stderr, "total: %d findings\n", len(findings))
		if err := report.WriteJSONL(boxOut, findings); err != nil {
			return err
		}
		if boxMD != "" {
			if err := report.WriteMarkdown(boxMD, findings); err != nil {
				return err
			}
		}
		return nil
	},
}

func webURL(service, host string, port int) string {
	scheme := "http"
	if service == "https" || port == 443 || port == 8443 {
		scheme = "https"
	}
	if (scheme == "http" && port == 80) || (scheme == "https" && port == 443) {
		return scheme + "://" + host
	}
	u := url.URL{Scheme: scheme, Host: fmt.Sprintf("%s:%d", host, port)}
	return strings.TrimRight(u.String(), "/")
}

func init() {
	boxCmd.Flags().StringVarP(&boxTarget, "target", "t", "", "target IP or hostname (required)")
	boxCmd.Flags().StringVar(&boxProfile, "profile", "quick", "nmap profile: quick (top 100 ports), full (-p-), service (-sV -sC -p-)")
	boxCmd.Flags().StringVar(&boxDomain, "domain", "", "domain name for DNS enumeration (e.g. target.htb)")
	boxCmd.Flags().StringVarP(&boxOut, "out", "o", "box.jsonl", "JSONL findings output")
	boxCmd.Flags().StringVar(&boxMD, "markdown", "", "optional markdown report path")
	boxCmd.Flags().BoolVar(&boxNoWeb, "no-web", false, "skip web recon on HTTP ports")
	boxCmd.Flags().IntVar(&boxTopWords, "top", 200, "wordlist depth for web recon / DNS / vhost (0 = full)")
	rootCmd.AddCommand(boxCmd)
}
