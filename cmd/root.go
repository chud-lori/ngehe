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

Three top-level commands:
  box     Shell out to nmap and dispatch per-service scanners
  recon   URL-only web discovery (tech fingerprint, sensitive files, dirbust)
  scan    Active scan from HAR / OpenAPI (BOLA, JWT, SQLi, RCE, SSTI, ...)

Authorized testing only. Use against systems you own or have permission
to assess.`,
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
