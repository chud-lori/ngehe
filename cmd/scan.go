package cmd

import (
	"fmt"
	"os"
	"time"

	"github.com/chud-lori/ngehe/internal/config"
	"github.com/chud-lori/ngehe/internal/detector/cmdi"
	"github.com/chud-lori/ngehe/internal/detector/creds"
	"github.com/chud-lori/ngehe/internal/detector/lfi"
	"github.com/chud-lori/ngehe/internal/detector/sqli"
	"github.com/chud-lori/ngehe/internal/detector/ssrf"
	"github.com/chud-lori/ngehe/internal/detector/ssti"
	"github.com/chud-lori/ngehe/internal/detector/xss"
	"github.com/chud-lori/ngehe/internal/differ"
	"github.com/chud-lori/ngehe/internal/finding"
	"github.com/chud-lori/ngehe/internal/har"
	"github.com/chud-lori/ngehe/internal/idmutate"
	"github.com/chud-lori/ngehe/internal/jwtabuse"
	"github.com/chud-lori/ngehe/internal/massassign"
	"github.com/chud-lori/ngehe/internal/openapi"
	"github.com/chud-lori/ngehe/internal/recon"
	"github.com/chud-lori/ngehe/internal/replay"
	"github.com/chud-lori/ngehe/internal/report"
	"github.com/chud-lori/ngehe/internal/scanner/nuclei"
	"github.com/chud-lori/ngehe/internal/session"
	"github.com/chud-lori/ngehe/internal/synth"
	"github.com/spf13/cobra"
)

var (
	scanHAR     string
	scanOpenAPI string
	scanTarget  string
	scanCrawl   bool
	scanBase    string
	scanConfig  string
	scanOut     string
	scanMD      string
	scanNuclei  bool
)

var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Replay a HAR capture across configured sessions and report BOLA findings",
	RunE: func(cmd *cobra.Command, args []string) error {
		if scanHAR == "" && scanOpenAPI == "" && scanTarget == "" {
			return fmt.Errorf("provide --har, --openapi, or --target")
		}
		cfg, err := config.Load(scanConfig)
		if err != nil {
			return fmt.Errorf("load config: %w", err)
		}

		var findings []finding.Finding
		var requests []har.Request
		if scanHAR != "" {
			rs, err := har.Load(scanHAR, cfg.Scope)
			if err != nil {
				return fmt.Errorf("load har: %w", err)
			}
			requests = append(requests, rs...)
		}
		if scanOpenAPI != "" {
			rs, err := openapi.Load(scanOpenAPI, cfg.Scope, scanBase)
			if err != nil {
				return fmt.Errorf("load openapi: %w", err)
			}
			rs = filterScope(rs, cfg.Scope)
			requests = append(requests, rs...)
		}
		if scanTarget != "" {
			paths := []string{"/"}
			if scanCrawl {
				reconFindings := recon.Run(recon.Options{
					Target: scanTarget, Concurrency: 20, TimeoutMS: 5000,
					Top: 200, SkipDirbust: false, Verbose: true,
				})
				findings = append(findings, reconFindings...)
				for _, f := range reconFindings {
					if (f.Rule == "dir-discovery" || f.Rule == "sensitive-path" || f.Rule == "sensitive-file") &&
						f.OffenderStatus < 400 && (f.BaselineStatus >= 200 && f.BaselineStatus < 400) {
						paths = append(paths, f.Path)
					}
				}
				fmt.Fprintf(os.Stderr, "crawled %d paths\n", len(paths))
			}
			synthReqs := synth.Requests(scanTarget, paths)
			requests = append(requests, synthReqs...)
		}
		fmt.Fprintf(os.Stderr, "loaded %d in-scope requests\n", len(requests))

		sessions, err := session.ResolveLogins(cfg.Sessions, cfg.Replay.TimeoutMS)
		if err != nil {
			return fmt.Errorf("resolve sessions: %w", err)
		}
		fmt.Fprintf(os.Stderr, "loaded %d sessions\n", len(sessions))

		runDetector := func(name string, enabled bool, fn func() []finding.Finding) {
			if !enabled {
				return
			}
			fs := fn()
			findings = append(findings, fs...)
			fmt.Fprintf(os.Stderr, "%s: %d findings\n", name, len(fs))
		}

		if cfg.Detectors.BOLA {
			results, err := replay.Run(requests, sessions, cfg)
			if err != nil {
				return fmt.Errorf("replay: %w", err)
			}
			bola := differ.Analyze(results)
			findings = append(findings, bola...)
			fmt.Fprintf(os.Stderr, "bola: %d findings\n", len(bola))
		}
		runDetector("id-mutation", cfg.Detectors.IDMutation, func() []finding.Finding {
			return idmutate.Run(requests, sessions, cfg)
		})
		runDetector("mass-assign", cfg.Detectors.MassAssign, func() []finding.Finding {
			return massassign.Run(requests, sessions, cfg)
		})
		runDetector("jwt-abuse", cfg.Detectors.JWTAbuse, func() []finding.Finding {
			return jwtabuse.Run(sessions, cfg)
		})
		runDetector("sqli", cfg.Detectors.SQLi, func() []finding.Finding {
			return sqli.Run(requests, sessions, cfg)
		})
		runDetector("cmdi", cfg.Detectors.CmdInjection, func() []finding.Finding {
			return cmdi.Run(requests, sessions, cfg)
		})
		runDetector("ssti", cfg.Detectors.SSTI, func() []finding.Finding {
			return ssti.Run(requests, sessions, cfg)
		})
		runDetector("lfi", cfg.Detectors.LFI, func() []finding.Finding {
			return lfi.Run(requests, sessions, cfg)
		})
		runDetector("ssrf", cfg.Detectors.SSRF, func() []finding.Finding {
			return ssrf.Run(requests, sessions, cfg)
		})
		runDetector("xss", cfg.Detectors.XSS, func() []finding.Finding {
			return xss.Run(requests, sessions, cfg)
		})
		runDetector("default-creds", cfg.Detectors.DefaultCreds, func() []finding.Finding {
			return creds.Run(cfg)
		})

		if scanNuclei {
			if nuclei.Available() {
				targets := uniqueHostURLs(requests, scanTarget)
				if len(targets) > 0 {
					fmt.Fprintf(os.Stderr, "nuclei: scanning %d targets…\n", len(targets))
					nf, err := nuclei.Scan(nuclei.Options{
						Targets:    targets,
						Severity:   "low,medium,high,critical",
						Concurrent: 25,
						Timeout:    20 * time.Minute,
					})
					if err != nil {
						fmt.Fprintf(os.Stderr, "nuclei: %v\n", err)
					}
					findings = append(findings, nf...)
					fmt.Fprintf(os.Stderr, "nuclei: %d findings\n", len(nf))
				}
			} else {
				fmt.Fprintln(os.Stderr, "nuclei: --nuclei requested but binary not on PATH (install via ./install.sh --with-extras)")
			}
		}

		fmt.Fprintf(os.Stderr, "total: %d findings\n", len(findings))

		if err := report.WriteJSONL(scanOut, findings); err != nil {
			return fmt.Errorf("write jsonl: %w", err)
		}
		if scanMD != "" {
			if err := report.WriteMarkdown(scanMD, findings); err != nil {
				return fmt.Errorf("write markdown: %w", err)
			}
		}
		return nil
	},
}

// uniqueHostURLs collects one URL per host (scheme + host[:port]) from the
// captured requests, plus the explicit --target if supplied. Used to feed
// nuclei: scanning every request URL is excessive, scanning once per origin
// is the right granularity for template-based scanners.
func uniqueHostURLs(reqs []har.Request, target string) []string {
	seen := map[string]string{}
	addURL := func(raw string) {
		if raw == "" {
			return
		}
		i := indexOf(raw, "://")
		if i < 0 {
			return
		}
		rest := raw[i+3:]
		host := rest
		if j := indexOfAny(rest, "/?#"); j >= 0 {
			host = rest[:j]
		}
		origin := raw[:i+3] + host
		if _, ok := seen[origin]; !ok {
			seen[origin] = origin
		}
	}
	addURL(target)
	for _, r := range reqs {
		addURL(r.URL)
	}
	out := make([]string, 0, len(seen))
	for _, v := range seen {
		out = append(out, v)
	}
	return out
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}

func indexOfAny(s, chars string) int {
	for i := 0; i < len(s); i++ {
		for j := 0; j < len(chars); j++ {
			if s[i] == chars[j] {
				return i
			}
		}
	}
	return -1
}

func filterScope(reqs []har.Request, scope config.Scope) []har.Request {
	hostSet := map[string]bool{}
	for _, h := range scope.Hosts {
		hostSet[h] = true
	}
	var out []har.Request
	for _, r := range reqs {
		if len(hostSet) > 0 && !hostSet[r.Host] {
			continue
		}
		excluded := false
		for _, p := range scope.ExcludePaths {
			if len(p) > 0 && len(r.Path) >= len(p) && r.Path[:len(p)] == p {
				excluded = true
				break
			}
		}
		if excluded {
			continue
		}
		out = append(out, r)
	}
	return out
}

func init() {
	scanCmd.Flags().StringVarP(&scanHAR, "har", "H", "", "path to HAR file")
	scanCmd.Flags().StringVar(&scanOpenAPI, "openapi", "", "path to OpenAPI 3 spec")
	scanCmd.Flags().StringVarP(&scanTarget, "target", "t", "", "target URL — synthesizes requests for common params and runs every active detector")
	scanCmd.Flags().BoolVar(&scanCrawl, "crawl", true, "with --target, run dir-bruteforce first to widen the path list")
	scanCmd.Flags().StringVar(&scanBase, "base", "", "base URL override for OpenAPI (e.g. http://127.0.0.1:8787)")
	scanCmd.Flags().StringVarP(&scanConfig, "config", "c", "ngehe.yaml", "path to ngehe config")
	scanCmd.Flags().StringVarP(&scanOut, "out", "o", "findings.jsonl", "JSONL findings output path")
	scanCmd.Flags().StringVar(&scanMD, "markdown", "", "optional markdown report path")
	scanCmd.Flags().BoolVar(&scanNuclei, "nuclei", false, "after native detectors, run nuclei (-jsonl) against in-scope hosts; requires nuclei on PATH")
	rootCmd.AddCommand(scanCmd)
}
