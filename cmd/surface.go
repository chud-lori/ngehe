package cmd

import (
	"fmt"
	"os"
	"sort"
	"time"

	"github.com/chud-lori/ngehe/internal/finding"
	"github.com/chud-lori/ngehe/internal/report"
	"github.com/chud-lori/ngehe/internal/scanner/amass"
	"github.com/chud-lori/ngehe/internal/scanner/httpx"
	"github.com/chud-lori/ngehe/internal/scanner/nuclei"
	"github.com/chud-lori/ngehe/internal/scanner/subfinder"
	"github.com/spf13/cobra"
)

var (
	surfaceDomain   string
	surfaceOut      string
	surfaceMD       string
	surfaceTimeout  int
	surfaceConc     int
	surfaceNuclei   bool
	surfaceNoAmass  bool
	surfaceNoSubfin bool
	surfaceNoHTTPX  bool
)

var surfaceCmd = &cobra.Command{
	Use:   "surface",
	Short: "Subdomain enumeration + live-host probing (amass + subfinder + httpx, optional nuclei)",
	Long: `Map a domain's attack surface using external tools that complement ngehe's
native modules:

  amass enum -passive       — comprehensive passive subdomain enumeration (slow)
  subfinder -silent         — fast passive subdomain enumeration
  httpx -json -tech-detect  — probe each hostname for live HTTP + fingerprint stack
  nuclei -jsonl  (optional) — CVE / misconfig templates against the live hosts

Each tool is opt-out via a flag, and any missing binary is skipped without
failing the run. Hand off the live URLs printed at the end to ngehe recon /
ngehe scan / ngehe box.

Requires: at least one of amass, subfinder, httpx on PATH.
Install with: ./install.sh --with-extras`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if surfaceDomain == "" {
			return fmt.Errorf("--domain is required (e.g. example.com or target.htb)")
		}
		timeout := time.Duration(surfaceTimeout) * time.Second

		fmt.Fprintf(os.Stderr, "ngehe surface → %s\n", surfaceDomain)

		var findings []finding.Finding
		hostSet := map[string]bool{}

		add := func(hosts []string) {
			for _, h := range hosts {
				hostSet[h] = true
			}
		}

		if !surfaceNoAmass {
			if amass.Available() {
				hosts, fs, err := amass.Enumerate(amass.Options{Domain: surfaceDomain, Timeout: timeout})
				if err != nil {
					fmt.Fprintf(os.Stderr, "amass: %v\n", err)
				}
				findings = append(findings, fs...)
				add(hosts)
				fmt.Fprintf(os.Stderr, "amass:     %d hosts\n", len(hosts))
			} else {
				fmt.Fprintln(os.Stderr, "amass:     (not installed — skipping; install via ./install.sh --with-extras)")
			}
		}

		if !surfaceNoSubfin {
			if subfinder.Available() {
				hosts, fs, err := subfinder.Enumerate(subfinder.Options{Domain: surfaceDomain, Timeout: timeout})
				if err != nil {
					fmt.Fprintf(os.Stderr, "subfinder: %v\n", err)
				}
				findings = append(findings, fs...)
				add(hosts)
				fmt.Fprintf(os.Stderr, "subfinder: %d hosts\n", len(hosts))
			} else {
				fmt.Fprintln(os.Stderr, "subfinder: (not installed — skipping)")
			}
		}

		hosts := make([]string, 0, len(hostSet))
		for h := range hostSet {
			hosts = append(hosts, h)
		}
		sort.Strings(hosts)
		fmt.Fprintf(os.Stderr, "deduped:   %d unique hostnames\n", len(hosts))

		var liveURLs []string
		if !surfaceNoHTTPX && len(hosts) > 0 {
			if httpx.Available() {
				urls, fs, err := httpx.Probe(httpx.Options{Hosts: hosts, Timeout: timeout, Concurrency: surfaceConc})
				if err != nil {
					fmt.Fprintf(os.Stderr, "httpx: %v\n", err)
				}
				findings = append(findings, fs...)
				liveURLs = urls
				fmt.Fprintf(os.Stderr, "httpx:     %d live HTTP services\n", len(urls))
			} else {
				fmt.Fprintln(os.Stderr, "httpx:     (not installed — skipping)")
			}
		}

		if surfaceNuclei && len(liveURLs) > 0 {
			if nuclei.Available() {
				fmt.Fprintf(os.Stderr, "nuclei:    scanning %d live hosts (this can take a while)…\n", len(liveURLs))
				fs, err := nuclei.Scan(nuclei.Options{
					Targets:    liveURLs,
					Severity:   "low,medium,high,critical",
					Concurrent: 25,
					Timeout:    20 * time.Minute,
				})
				if err != nil {
					fmt.Fprintf(os.Stderr, "nuclei: %v\n", err)
				}
				findings = append(findings, fs...)
				fmt.Fprintf(os.Stderr, "nuclei:    %d findings\n", len(fs))
			} else {
				fmt.Fprintln(os.Stderr, "nuclei:    (not installed — skipping)")
			}
		}

		fmt.Fprintf(os.Stderr, "total: %d findings\n", len(findings))
		if err := report.WriteJSONL(surfaceOut, findings); err != nil {
			return err
		}
		if surfaceMD != "" {
			if err := report.WriteMarkdown(surfaceMD, findings); err != nil {
				return err
			}
		}

		if len(liveURLs) > 0 {
			fmt.Fprintln(os.Stderr, "\nLive HTTP hosts — chain into ngehe recon / scan / box:")
			for _, u := range liveURLs {
				fmt.Fprintln(os.Stdout, u)
			}
		}
		return nil
	},
}

func init() {
	surfaceCmd.Flags().StringVarP(&surfaceDomain, "domain", "d", "", "domain to enumerate (e.g. example.com) — required")
	surfaceCmd.Flags().StringVarP(&surfaceOut, "out", "o", "surface.jsonl", "JSONL findings output")
	surfaceCmd.Flags().StringVar(&surfaceMD, "markdown", "", "optional markdown report path")
	surfaceCmd.Flags().IntVar(&surfaceTimeout, "timeout", 300, "per-tool timeout in seconds (default 300)")
	surfaceCmd.Flags().IntVarP(&surfaceConc, "concurrency", "c", 50, "httpx probe concurrency")
	surfaceCmd.Flags().BoolVar(&surfaceNuclei, "nuclei", false, "also run nuclei against live hosts (slow; opt-in)")
	surfaceCmd.Flags().BoolVar(&surfaceNoAmass, "no-amass", false, "skip amass (use only subfinder for subdomain enum)")
	surfaceCmd.Flags().BoolVar(&surfaceNoSubfin, "no-subfinder", false, "skip subfinder")
	surfaceCmd.Flags().BoolVar(&surfaceNoHTTPX, "no-httpx", false, "skip httpx live-host probe (just emit subdomains)")
	rootCmd.AddCommand(surfaceCmd)
}
