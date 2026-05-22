package report

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	"github.com/chud-lori/ngehe/internal/finding"
)

func WriteJSONL(path string, findings []finding.Finding) error {
	findings = finding.Enrich(findings)
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	for _, fnd := range findings {
		if err := enc.Encode(fnd); err != nil {
			return err
		}
	}
	return nil
}

func WriteMarkdown(path string, findings []finding.Finding) error {
	findings = finding.Enrich(findings)
	sorted := append([]finding.Finding(nil), findings...)
	sort.SliceStable(sorted, func(i, j int) bool {
		return finding.SevRank(sorted[i].Severity) < finding.SevRank(sorted[j].Severity)
	})

	var b strings.Builder
	b.WriteString("# ngehe findings\n\n")
	if len(sorted) == 0 {
		b.WriteString("_No findings._\n")
		return os.WriteFile(path, []byte(b.String()), 0o644)
	}
	counts := map[finding.Severity]int{}
	for _, f := range sorted {
		counts[f.Severity]++
	}
	b.WriteString(fmt.Sprintf("**Total:** %d — critical: %d, high: %d, medium: %d, low: %d, info: %d\n\n",
		len(sorted),
		counts[finding.SevCritical], counts[finding.SevHigh], counts[finding.SevMedium], counts[finding.SevLow], counts[finding.SevInfo]))

	writeAttackChain(&b, sorted)

	for _, f := range sorted {
		b.WriteString(fmt.Sprintf("## [%s] %s %s\n\n", strings.ToUpper(string(f.Severity)), f.Method, f.Path))
		b.WriteString(fmt.Sprintf("- **rule:** `%s`\n", f.Rule))
		b.WriteString(fmt.Sprintf("- **url:** `%s`\n", f.URL))
		if f.Param != "" {
			b.WriteString(fmt.Sprintf("- **param:** `%s`\n", f.Param))
		}
		if f.Payload != "" {
			b.WriteString(fmt.Sprintf("- **payload:** `%s`\n", f.Payload))
		}
		if f.BaselineStatus != 0 {
			b.WriteString(fmt.Sprintf("- **baseline status:** %d\n", f.BaselineStatus))
		}
		if f.OffenderName != "" {
			b.WriteString(fmt.Sprintf("- **offender:** `%s` got %d\n", f.OffenderName, f.OffenderStatus))
		}
		if f.Evidence != "" {
			b.WriteString(fmt.Sprintf("- **evidence:** `%s`\n", truncate(f.Evidence, 200)))
		}
		b.WriteString(fmt.Sprintf("- **why:** %s\n", f.Why))
		if f.Next != "" {
			b.WriteString("- **next:**\n\n```\n" + f.Next + "\n```\n")
		}
		b.WriteString("\n")
	}
	return os.WriteFile(path, []byte(b.String()), 0o644)
}

// writeAttackChain emits a top-of-report summary that orders critical / high
// findings and concatenates the actionable next-steps. Designed to be the
// first thing you read after running a scan.
func writeAttackChain(b *strings.Builder, findings []finding.Finding) {
	var chain []finding.Finding
	for _, f := range findings {
		if (f.Severity == finding.SevCritical || f.Severity == finding.SevHigh) && f.Next != "" {
			chain = append(chain, f)
		}
	}
	if len(chain) == 0 {
		return
	}
	b.WriteString("## Suggested attack chain\n\n")
	b.WriteString("Highest-impact findings, in execution order. Each `next:` block tells you the concrete command or payload to move toward shell / root.\n\n")
	for i, f := range chain {
		title := fmt.Sprintf("%d. **[%s] `%s`** — %s",
			i+1, strings.ToUpper(string(f.Severity)), f.Rule, fmt.Sprintf("%s %s", f.Method, f.Path))
		b.WriteString(title + "\n")
		if f.Param != "" {
			b.WriteString(fmt.Sprintf("   - param: `%s`  payload: `%s`\n", f.Param, truncate(f.Payload, 60)))
		}
		if f.Evidence != "" {
			b.WriteString(fmt.Sprintf("   - evidence: `%s`\n", truncate(f.Evidence, 120)))
		}
		b.WriteString("\n   ```\n")
		for _, ln := range strings.Split(f.Next, "\n") {
			b.WriteString("   " + ln + "\n")
		}
		b.WriteString("   ```\n\n")
	}
	b.WriteString("---\n\n")
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

// PrintTerminal renders findings for direct terminal viewing. Layout:
//   - Summary counts line
//   - Suggested attack chain (critical/high with next-step playbook)
//   - All findings, one row each, grouped by severity
//
// ANSI colors when w is a TTY; plain text when piped to a file.
func PrintTerminal(w io.Writer, findings []finding.Finding) {
	findings = finding.Enrich(findings)
	if len(findings) == 0 {
		fmt.Fprintln(w, "No findings.")
		return
	}

	sorted := append([]finding.Finding(nil), findings...)
	sort.SliceStable(sorted, func(i, j int) bool {
		return finding.SevRank(sorted[i].Severity) < finding.SevRank(sorted[j].Severity)
	})

	color := isTTY(w)
	counts := map[finding.Severity]int{}
	for _, f := range sorted {
		counts[f.Severity]++
	}

	fmt.Fprintf(w, "\n%s %d findings — %s %d  %s %d  %s %d  %s %d  %s %d\n\n",
		bold("Total:", color), len(sorted),
		colorize("critical", finding.SevCritical, color), counts[finding.SevCritical],
		colorize("high", finding.SevHigh, color), counts[finding.SevHigh],
		colorize("medium", finding.SevMedium, color), counts[finding.SevMedium],
		colorize("low", finding.SevLow, color), counts[finding.SevLow],
		dim("info", color), counts[finding.SevInfo],
	)

	// Attack chain
	var chain []finding.Finding
	for _, f := range sorted {
		if (f.Severity == finding.SevCritical || f.Severity == finding.SevHigh) && f.Next != "" {
			chain = append(chain, f)
		}
	}
	if len(chain) > 0 {
		fmt.Fprintln(w, bold("Suggested attack chain:", color))
		fmt.Fprintln(w)
		for i, f := range chain {
			fmt.Fprintf(w, "  %d. %s %s — %s %s\n", i+1,
				sevBadge(f.Severity, color), bold(f.Rule, color), f.Method, f.Path)
			if f.Param != "" {
				fmt.Fprintf(w, "     %s %s  %s %s\n",
					dim("param:", color), f.Param,
					dim("payload:", color), truncate(f.Payload, 80))
			}
			if f.Evidence != "" {
				fmt.Fprintf(w, "     %s %s\n", dim("evidence:", color), truncate(f.Evidence, 140))
			}
			fmt.Fprintf(w, "     %s\n", dim("next:", color))
			for _, ln := range strings.Split(strings.TrimRight(f.Next, "\n"), "\n") {
				fmt.Fprintf(w, "       %s\n", ln)
			}
			fmt.Fprintln(w)
		}
	}

	fmt.Fprintln(w, bold("All findings:", color))
	fmt.Fprintln(w)
	for _, f := range sorted {
		target := f.URL
		if target == "" {
			target = f.Path
		}
		src := ""
		if f.Source != "" {
			src = " " + dim("("+f.Source+")", color)
		}
		fmt.Fprintf(w, "  %s %-26s %s%s\n", sevBadge(f.Severity, color), f.Rule, target, src)
		if f.Evidence != "" && f.Severity != finding.SevInfo {
			fmt.Fprintf(w, "    %s %s\n", dim("└─", color), truncate(f.Evidence, 140))
		}
	}
	fmt.Fprintln(w)
}

func sevBadge(s finding.Severity, color bool) string {
	label := strings.ToUpper(string(s))
	if len(label) > 8 {
		label = label[:8]
	}
	padded := fmt.Sprintf("[%s]", label+strings.Repeat(" ", 8-len(label)))
	if !color {
		return padded
	}
	var c string
	switch s {
	case finding.SevCritical:
		c = "\033[1;31m"
	case finding.SevHigh:
		c = "\033[1;33m"
	case finding.SevMedium:
		c = "\033[1;36m"
	case finding.SevLow:
		c = "\033[34m"
	default:
		c = "\033[2;37m"
	}
	return c + padded + "\033[0m"
}

func colorize(s string, sev finding.Severity, color bool) string {
	if !color {
		return s
	}
	switch sev {
	case finding.SevCritical:
		return "\033[1;31m" + s + "\033[0m"
	case finding.SevHigh:
		return "\033[1;33m" + s + "\033[0m"
	case finding.SevMedium:
		return "\033[1;36m" + s + "\033[0m"
	case finding.SevLow:
		return "\033[34m" + s + "\033[0m"
	default:
		return "\033[2;37m" + s + "\033[0m"
	}
}

func bold(s string, color bool) string {
	if !color {
		return s
	}
	return "\033[1m" + s + "\033[0m"
}

func dim(s string, color bool) string {
	if !color {
		return s
	}
	return "\033[2m" + s + "\033[0m"
}

func isTTY(w io.Writer) bool {
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	fi, err := f.Stat()
	if err != nil {
		return false
	}
	return (fi.Mode() & os.ModeCharDevice) != 0
}
