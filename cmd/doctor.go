package cmd

import (
	"fmt"
	"os/exec"
	"runtime"

	"github.com/chud-lori/ngehe/internal/scanner/amass"
	"github.com/chud-lori/ngehe/internal/scanner/httpx"
	"github.com/chud-lori/ngehe/internal/scanner/nuclei"
	"github.com/chud-lori/ngehe/internal/scanner/subfinder"
	"github.com/spf13/cobra"
)

type dep struct {
	cmd      string
	required bool
	purpose  string
	// smoke runs an extra runtime/data check beyond LookPath (e.g. nuclei
	// templates installed, binary executes -version). Returns (ok, hint).
	// nil = skip the smoke test (just check PATH).
	smoke func() (bool, string)
}

var deps = []dep{
	{cmd: "nmap", required: true, purpose: "required by ngehe box (port discovery + service detection)"},
	{cmd: "nuclei", purpose: "extra — template-based scanner (CVEs, default-config, exposures). Enables --nuclei on scan/box. Install: ./install.sh --with-extras", smoke: nuclei.SmokeTest},
	{cmd: "amass", purpose: "extra — OWASP passive subdomain enumeration. Used by ngehe surface. Install: ./install.sh --with-extras", smoke: amass.SmokeTest},
	{cmd: "subfinder", purpose: "extra — fast passive subdomain enumeration. Used by ngehe surface. Install: ./install.sh --with-extras", smoke: subfinder.SmokeTest},
	{cmd: "httpx", purpose: "extra — live-host probe + tech fingerprint. Used by ngehe surface. Install: ./install.sh --with-extras", smoke: httpx.SmokeTest},
	{cmd: "hashcat", purpose: "recommended — crack JWT / krb5asrep (-m 18200) / krb5tgs (-m 13100) hashes from ngehe"},
	{cmd: "sqlmap", purpose: "recommended — deeper SQLi exploitation after ngehe flags sqli-error-based / sqli-time-based"},
	{cmd: "bloodhound-python", purpose: "recommended — BloodHound collector. Ingest its JSON into BloodHound CE for AD attack-path analysis"},
	{cmd: "impacket-GetNPUsers", purpose: "recommended — heavier AS-REP roasting if ngehe's Go implementation misses"},
	{cmd: "impacket-GetUserSPNs", purpose: "recommended — heavier Kerberoasting"},
	{cmd: "evil-winrm", purpose: "recommended — Windows shell over WinRM after credential/hash theft"},
	{cmd: "netexec", purpose: "recommended — modern crackmapexec, AD swiss army knife (SMB/LDAP/MSSQL/WinRM)"},
}

var doctorCmd = &cobra.Command{
	Use:   "doctor",
	Short: "Check installed dependencies and suggest install commands",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("ngehe dependency check (%s)\n\n", runtime.GOOS)
		var missingRequired []string
		var brokenExtras []string

		for _, d := range deps {
			path, err := exec.LookPath(d.cmd)
			mark := "✓"
			loc := path
			detail := ""

			if err != nil {
				mark = "✗"
				loc = "(not found)"
				if d.required {
					missingRequired = append(missingRequired, d.cmd)
				}
			} else if d.smoke != nil {
				// Binary present — run the deeper sanity check.
				ok, hint := d.smoke()
				if !ok {
					mark = "⚠"
					detail = hint
					brokenExtras = append(brokenExtras, d.cmd)
				}
			}

			tag := "  [optional]"
			if d.required {
				tag = "  [required]"
			}
			fmt.Printf("  %s %-22s %s%s\n", mark, d.cmd, loc, tag)
			fmt.Printf("       %s\n", d.purpose)
			if detail != "" {
				fmt.Printf("       ⚠ %s\n", detail)
			}
		}
		fmt.Println()

		if len(missingRequired) > 0 {
			fmt.Println("MISSING REQUIRED DEPENDENCIES:")
			for _, c := range missingRequired {
				fmt.Println(" -", c, suggestInstall(c))
			}
			return
		}
		if len(brokenExtras) > 0 {
			fmt.Printf("Some optional extras need attention (%d): %v\n", len(brokenExtras), brokenExtras)
			fmt.Println("ngehe will skip them at runtime with a hint. Required deps are fine.")
			return
		}
		fmt.Println("All required dependencies present.")
		fmt.Println("Try: ngehe box --target <ip>")
	},
}

func suggestInstall(cmd string) string {
	switch runtime.GOOS {
	case "darwin":
		return "→ brew install " + cmd
	case "linux":
		return "→ sudo apt install " + cmd + "   (or your distro's pkg manager)"
	}
	return "→ install " + cmd + " from your package manager"
}

func init() {
	rootCmd.AddCommand(doctorCmd)
}
