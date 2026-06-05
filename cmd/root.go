package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "ngehe",
	Short: "Web + AD pentest CLI for authorized assessments, HTB boxes, and CTFs.",
	Long: `ngehe covers the OWASP Top 10 plus non-HTTP services common on HTB boxes:
SSH, FTP, SMB, LDAP/AD, SNMP, DNS, databases, Kerberos (AS-REP roast +
Kerberoast), BloodHound collection, NTLM spray.

Core workflows:
  box      Shell out to nmap and dispatch per-service scanners
  surface  Enumerate subdomains and live HTTP hosts
  recon    URL-only web discovery (tech fingerprint, sensitive files, dirbust)
  scan     Active scan from HAR / OpenAPI / URL input
  chain    Walk findings interactively and run next-step commands
  view     Filter JSONL findings without jq

Authorized testing only. Use against systems you own or have permission
to assess.`,
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
