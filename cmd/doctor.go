package cmd

import (
	"fmt"
	"os/exec"
	"runtime"

	"github.com/spf13/cobra"
)

type dep struct {
	cmd      string
	required bool
	purpose  string
}

var deps = []dep{
	{"nmap", true, "required by ngehe box (port discovery + service detection)"},
	{"nuclei", false, "extra — template-based scanner (CVEs, default-config, exposures). Enables --nuclei on scan/box. Install: ./install.sh --with-extras"},
	{"amass", false, "extra — OWASP passive subdomain enumeration. Used by ngehe surface. Install: ./install.sh --with-extras"},
	{"subfinder", false, "extra — fast passive subdomain enumeration. Used by ngehe surface. Install: ./install.sh --with-extras"},
	{"httpx", false, "extra — live-host probe + tech fingerprint. Used by ngehe surface. Install: ./install.sh --with-extras"},
	{"hashcat", false, "recommended — crack JWT / krb5asrep (-m 18200) / krb5tgs (-m 13100) hashes from ngehe"},
	{"sqlmap", false, "recommended — deeper SQLi exploitation after ngehe flags sqli-error-based / sqli-time-based"},
	{"bloodhound", false, "recommended — ingest ngehe's BloodHound JSON output for AD attack-path analysis"},
	{"impacket-GetNPUsers", false, "recommended — heavier AS-REP roasting if ngehe's Go implementation misses"},
	{"impacket-GetUserSPNs", false, "recommended — heavier Kerberoasting"},
}

var doctorCmd = &cobra.Command{
	Use:   "doctor",
	Short: "Check installed dependencies and suggest install commands",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("ngehe dependency check (%s)\n\n", runtime.GOOS)
		var missingRequired []string
		for _, d := range deps {
			path, err := exec.LookPath(d.cmd)
			mark := "✓"
			loc := path
			if err != nil {
				mark = "✗"
				loc = "(not found)"
				if d.required {
					missingRequired = append(missingRequired, d.cmd)
				}
			}
			tag := ""
			if d.required {
				tag = "  [required]"
			} else {
				tag = "  [optional]"
			}
			fmt.Printf("  %s %-22s %s%s\n", mark, d.cmd, loc, tag)
			fmt.Printf("       %s\n", d.purpose)
		}
		fmt.Println()
		if len(missingRequired) > 0 {
			fmt.Println("MISSING REQUIRED DEPENDENCIES:")
			for _, c := range missingRequired {
				fmt.Println(" -", c, suggestInstall(c))
			}
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
