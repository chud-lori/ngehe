package report

import (
	"encoding/json"
	"fmt"
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
