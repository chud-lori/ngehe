package cmd

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"

	"github.com/chud-lori/ngehe/internal/finding"
	"github.com/chud-lori/ngehe/internal/report"
	"github.com/spf13/cobra"
)

var (
	viewSeverity string
	viewRule     string
	viewSource   string
	viewParam    string
	viewURLs     bool
	viewOut      string
	viewMD       string
	viewJSONL    string
)

var viewCmd = &cobra.Command{
	Use:   "view <findings.jsonl>",
	Short: "Read a findings JSONL, filter, and display — replaces jq for common queries",
	Long: `view loads a JSONL produced by ngehe surface / scan / box / recon and renders
it back to terminal (or file), with optional filters. Built so users don't have
to memorize jq syntax for the four or five queries everyone actually runs:

  ngehe view findings.jsonl
  ngehe view findings.jsonl --severity critical,high
  ngehe view findings.jsonl --rule ssti
  ngehe view findings.jsonl --source nuclei
  ngehe view findings.jsonl --param query
  ngehe view findings.jsonl --urls            # one URL per line, machine-pipeable
  ngehe view findings.jsonl --markdown report.md
  ngehe view findings.jsonl --out filtered.jsonl

Filters are AND-combined: --severity critical,high --source nuclei shows only
critical/high findings that came from nuclei.

--rule and --param are case-insensitive substring matches. To use regex, anchor
with ^ or $ or use Go regex syntax — they're compiled as RE2.`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		return runView(args[0])
	},
}

func runView(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open findings: %w", err)
	}
	defer f.Close()

	var all []finding.Finding
	dec := json.NewDecoder(f)
	for {
		var fnd finding.Finding
		if err := dec.Decode(&fnd); err != nil {
			if err == io.EOF {
				break
			}
			return fmt.Errorf("parse jsonl: %w", err)
		}
		all = append(all, fnd)
	}

	filtered, err := applyFilters(all)
	if err != nil {
		return err
	}

	// Output modes — first match wins.
	switch {
	case viewURLs:
		// Machine-pipeable: one URL per line, no formatting. Good for
		// piping into other tools (curl, ngehe scan, …).
		seen := map[string]bool{}
		for _, fnd := range filtered {
			if fnd.URL == "" || seen[fnd.URL] {
				continue
			}
			seen[fnd.URL] = true
			fmt.Println(fnd.URL)
		}
		return nil
	case viewJSONL != "":
		return report.WriteJSONL(viewJSONL, filtered)
	case viewMD != "":
		return report.WriteMarkdown(viewMD, filtered)
	case viewOut != "":
		// Alias: --out also writes JSONL.
		return report.WriteJSONL(viewOut, filtered)
	default:
		// Default: pretty-print to terminal (same formatter as live scans).
		report.PrintTerminal(os.Stdout, filtered)
		return nil
	}
}

// applyFilters reduces the input slice by all configured flags.
// Flags are AND-combined; missing values are wildcards.
func applyFilters(all []finding.Finding) ([]finding.Finding, error) {
	var sevSet map[finding.Severity]bool
	if viewSeverity != "" {
		sevSet = map[finding.Severity]bool{}
		for _, s := range strings.Split(viewSeverity, ",") {
			s = strings.TrimSpace(strings.ToLower(s))
			switch s {
			case "critical", "crit", "c":
				sevSet[finding.SevCritical] = true
			case "high", "h":
				sevSet[finding.SevHigh] = true
			case "medium", "med", "m":
				sevSet[finding.SevMedium] = true
			case "low", "l":
				sevSet[finding.SevLow] = true
			case "info", "i":
				sevSet[finding.SevInfo] = true
			default:
				return nil, fmt.Errorf("unknown severity %q (use: critical, high, medium, low, info)", s)
			}
		}
	}

	var ruleRe *regexp.Regexp
	if viewRule != "" {
		re, err := regexp.Compile("(?i)" + viewRule)
		if err != nil {
			return nil, fmt.Errorf("invalid --rule regex %q: %w", viewRule, err)
		}
		ruleRe = re
	}

	var paramRe *regexp.Regexp
	if viewParam != "" {
		re, err := regexp.Compile("(?i)" + viewParam)
		if err != nil {
			return nil, fmt.Errorf("invalid --param regex %q: %w", viewParam, err)
		}
		paramRe = re
	}

	// --source "" matches "native ngehe" findings (no Source set). To filter
	// to native, use --source native or --source ngehe. To filter to any
	// upstream, use --source upstream or --source external.
	sourceMatch := func(f finding.Finding) bool {
		if viewSource == "" {
			return true
		}
		want := strings.ToLower(viewSource)
		got := strings.ToLower(f.Source)
		switch want {
		case "native", "ngehe", "":
			return got == ""
		case "upstream", "external", "any":
			return got != ""
		default:
			return got == want
		}
	}

	out := make([]finding.Finding, 0, len(all))
	for _, f := range all {
		if sevSet != nil && !sevSet[f.Severity] {
			continue
		}
		if ruleRe != nil && !ruleRe.MatchString(f.Rule) {
			continue
		}
		if paramRe != nil && !paramRe.MatchString(f.Param) {
			continue
		}
		if !sourceMatch(f) {
			continue
		}
		out = append(out, f)
	}
	return out, nil
}

func init() {
	viewCmd.Flags().StringVarP(&viewSeverity, "severity", "s", "", "filter by severity (comma-separated: critical,high,medium,low,info)")
	viewCmd.Flags().StringVarP(&viewRule, "rule", "r", "", "filter by rule name (case-insensitive substring or RE2 regex)")
	viewCmd.Flags().StringVar(&viewSource, "source", "", "filter by source: native/ngehe, nuclei, amass, subfinder, httpx, upstream/external")
	viewCmd.Flags().StringVar(&viewParam, "param", "", "filter by param name (substring match)")
	viewCmd.Flags().BoolVar(&viewURLs, "urls", false, "print just the URLs, one per line (machine-pipeable; replaces jq -r '.url')")
	viewCmd.Flags().StringVarP(&viewOut, "out", "o", "", "write filtered JSONL to this path")
	viewCmd.Flags().StringVar(&viewMD, "markdown", "", "write filtered markdown report to this path")
	viewCmd.Flags().StringVar(&viewJSONL, "jsonl", "", "(alias for --out) write filtered JSONL")
	rootCmd.AddCommand(viewCmd)
}
