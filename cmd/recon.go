package cmd

import (
	"fmt"
	"os"

	"github.com/chud-lori/ngehe/internal/recon"
	"github.com/chud-lori/ngehe/internal/report"
	"github.com/spf13/cobra"
)

var (
	reconTarget      string
	reconOut         string
	reconMD          string
	reconConcurrency int
	reconTimeoutMS   int
	reconTop         int
	reconSkipDirbust bool
)

var reconCmd = &cobra.Command{
	Use:   "recon",
	Short: "Discovery against a URL target: tech fingerprint, sensitive files, dir bruteforce",
	Long: `Run reconnaissance against a single URL. No HAR or OpenAPI required.

This is the first command to run against a fresh HTB box. It fingerprints
the technology stack, probes for sensitive files (.git, .env, etc.) using
the SecLists quickhits wordlist plus content fingerprinting, and walks the
SecLists common.txt wordlist to discover hidden endpoints.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if reconTarget == "" {
			return fmt.Errorf("--target is required (e.g. http://10.10.11.5)")
		}
		opts := recon.Options{
			Target:      reconTarget,
			Concurrency: reconConcurrency,
			TimeoutMS:   reconTimeoutMS,
			Top:         reconTop,
			SkipDirbust: reconSkipDirbust,
			Verbose:     true,
		}
		fmt.Fprintf(os.Stderr, "ngehe recon → %s (concurrency=%d, timeout=%dms, top=%d)\n",
			opts.Target, opts.Concurrency, opts.TimeoutMS, opts.Top)
		findings := recon.Run(opts)
		fmt.Fprintf(os.Stderr, "recon: %d findings\n", len(findings))
		if reconOut != "" {
			if err := report.WriteJSONL(reconOut, findings); err != nil {
				return err
			}
		}
		if reconMD != "" {
			if err := report.WriteMarkdown(reconMD, findings); err != nil {
				return err
			}
		}
		if reconOut == "" && reconMD == "" {
			report.PrintTerminal(os.Stdout, findings)
		}
		return nil
	},
}

func init() {
	reconCmd.Flags().StringVarP(&reconTarget, "target", "t", "", "target URL (e.g. http://10.10.11.5)")
	reconCmd.Flags().StringVarP(&reconOut, "out", "o", "", "write JSONL findings to this path (default: print to terminal)")
	reconCmd.Flags().StringVar(&reconMD, "markdown", "", "write markdown report to this path (default: print to terminal)")
	reconCmd.Flags().IntVar(&reconConcurrency, "concurrency", 20, "concurrent probes")
	reconCmd.Flags().IntVar(&reconTimeoutMS, "timeout-ms", 5000, "per-request timeout")
	reconCmd.Flags().IntVar(&reconTop, "top", 500, "test the first N entries from each wordlist (0 = all)")
	reconCmd.Flags().BoolVar(&reconSkipDirbust, "skip-dirbust", false, "skip directory bruteforce")
	rootCmd.AddCommand(reconCmd)
}
