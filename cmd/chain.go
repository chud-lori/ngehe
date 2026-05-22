package cmd

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"sort"
	"strings"

	"github.com/chud-lori/ngehe/internal/finding"
	"github.com/spf13/cobra"
)

var (
	chainAllSeverities bool
)

var chainCmd = &cobra.Command{
	Use:   "chain <findings.jsonl>",
	Short: "Walk through findings interactively and run next-step commands",
	Long: `chain reads a JSONL findings file (from 'ngehe surface/scan/box --out X.jsonl'),
filters to critical+high (or all severities with --all), and walks each finding
interactively. For every actionable finding it displays:

  - rule, severity, target URL
  - evidence + why
  - the per-rule playbook (the 'next' field)

…then prompts you for a command to run. Whatever you type is shelled out via
bash with stdin/stdout/stderr attached to your terminal — so reverse-shell
listeners, evil-winrm sessions, interactive sqlmap runs etc. all work normally.

This is the "guided exploit" mode. ngehe stays in the analyzer role and does
not wrap individual tools; it just lays the playbook in front of you and lets
you execute against your container's PATH.

Best run inside the ngehe Docker image where every handoff tool is pre-installed:
  ./scripts/ngehe chain findings.jsonl

Outside the container, you'll need to have hashcat / impacket / evil-winrm /
etc. installed locally for the suggested commands to work.`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		return runChain(args[0])
	},
}

func runChain(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open findings: %w", err)
	}
	defer f.Close()

	// Parse JSONL — one finding per line.
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
	if len(all) == 0 {
		fmt.Println("Findings file is empty.")
		return nil
	}

	// Filter to actionable: by default critical+high with a Next field.
	// --all relaxes to every finding that has a Next.
	var actionable []finding.Finding
	for _, fnd := range all {
		if fnd.Next == "" {
			continue
		}
		if chainAllSeverities {
			actionable = append(actionable, fnd)
			continue
		}
		if fnd.Severity == finding.SevCritical || fnd.Severity == finding.SevHigh {
			actionable = append(actionable, fnd)
		}
	}
	if len(actionable) == 0 {
		fmt.Println("No actionable findings (critical/high with a 'next' playbook).")
		fmt.Println("Run with --all to walk every finding that carries a next-step.")
		return nil
	}

	// Sort by severity then rule for stable, useful traversal order.
	sort.SliceStable(actionable, func(i, j int) bool {
		ri, rj := finding.SevRank(actionable[i].Severity), finding.SevRank(actionable[j].Severity)
		if ri != rj {
			return ri < rj
		}
		return actionable[i].Rule < actionable[j].Rule
	})

	fmt.Printf("\nLoaded %d total findings (%d actionable). Press q at any prompt to quit.\n\n",
		len(all), len(actionable))

	reader := bufio.NewReader(os.Stdin)

	for i, fnd := range actionable {
		fmt.Printf("\033[1m=== Finding %d/%d ===\033[0m\n", i+1, len(actionable))
		fmt.Printf("  rule:     %s\n", colorRule(fnd.Severity, fnd.Rule))
		fmt.Printf("  severity: %s\n", strings.ToUpper(string(fnd.Severity)))
		fmt.Printf("  target:   %s %s\n", fnd.Method, fnd.URL)
		if fnd.Param != "" {
			fmt.Printf("  param:    %s\n", fnd.Param)
		}
		if fnd.Payload != "" {
			fmt.Printf("  payload:  %s\n", truncForDisplay(fnd.Payload, 100))
		}
		if fnd.Evidence != "" {
			fmt.Printf("  evidence: %s\n", truncForDisplay(fnd.Evidence, 200))
		}
		if fnd.Why != "" {
			fmt.Printf("  why:      %s\n", truncForDisplay(fnd.Why, 200))
		}
		fmt.Println()
		fmt.Println("\033[1mPlaybook (ngehe per-rule guidance):\033[0m")
		for _, line := range strings.Split(strings.TrimRight(fnd.Next, "\n"), "\n") {
			fmt.Printf("  %s\n", line)
		}
		fmt.Println()

		// Pre-fill: if Next is a clean single-line command starting with a
		// known tool, suggest it directly. Otherwise prompt empty.
		suggestion := extractCommand(fnd.Next)

	prompt:
		if suggestion != "" {
			fmt.Printf("Run [\033[1;32m%s\033[0m] ? (y/n/e=edit/s=skip/q=quit) ", suggestion)
		} else {
			fmt.Print("Type a command to run (Enter to skip / q to quit / e to edit a multi-line block):\n> ")
		}
		input, err := reader.ReadString('\n')
		if err != nil {
			return err
		}
		input = strings.TrimSpace(input)

		switch input {
		case "q", "quit":
			fmt.Println("Stopping.")
			return nil
		case "s", "skip", "n", "no":
			fmt.Println("Skipped.")
			fmt.Println()
			continue
		case "":
			if suggestion != "" {
				// Empty + suggestion present = skip (mirror "y/N" default-No semantics).
				fmt.Println("Skipped.")
				fmt.Println()
				continue
			}
			fmt.Println("Skipped.")
			fmt.Println()
			continue
		case "y", "yes":
			if suggestion == "" {
				fmt.Println("(no suggested command — type one to run)")
				goto prompt
			}
			runShellCommand(suggestion)
			fmt.Println()
		case "e", "edit":
			fmt.Print("Edit command:\n> ")
			edited, _ := reader.ReadString('\n')
			edited = strings.TrimSpace(edited)
			if edited != "" {
				runShellCommand(edited)
				fmt.Println()
			}
		default:
			// User typed a literal command — run it.
			runShellCommand(input)
			fmt.Println()
		}
	}

	fmt.Println("\nAll findings walked.")
	return nil
}

// runShellCommand shells out via 'bash -c' so pipes / redirects / && work,
// and attaches stdio so interactive tools (evil-winrm, sqlmap prompts,
// netcat listeners) behave normally.
func runShellCommand(cmd string) {
	fmt.Printf("\033[2m→ %s\033[0m\n", cmd)
	c := exec.Command("bash", "-c", cmd)
	c.Stdin = os.Stdin
	c.Stdout = os.Stdout
	c.Stderr = os.Stderr
	if err := c.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "\033[33m(command exited with: %v)\033[0m\n", err)
	}
}

// extractCommand tries to recognize a clean single-line shell command in
// the Next field. Returns "" if Next is multi-line or doesn't look like
// a direct command. Conservative — better to prompt than to guess wrong.
//
// Heuristic: if Next has exactly one non-empty line AND that line starts
// with a known handoff-tool name (hashcat, sqlmap, nuclei, evil-winrm,
// netexec, etc.), treat the line as a runnable command.
func extractCommand(next string) string {
	knownTools := []string{
		"hashcat", "sqlmap", "nuclei", "evil-winrm", "netexec",
		"crackmapexec", "impacket-", "GetNPUsers.py", "GetUserSPNs.py",
		"secretsdump.py", "ticketer.py", "psexec.py", "wmiexec.py",
		"smbclient", "smbmap", "ldapsearch", "enum4linux", "enum4linux-ng",
		"bloodhound-python", "kerbrute", "ffuf", "gobuster", "dalfox",
		"john", "ncat", "nc", "curl", "wget",
		"git-dumper", "git clone",
	}
	var nonEmpty []string
	for _, ln := range strings.Split(next, "\n") {
		if s := strings.TrimSpace(ln); s != "" {
			nonEmpty = append(nonEmpty, s)
		}
	}
	if len(nonEmpty) != 1 {
		return ""
	}
	line := nonEmpty[0]
	for _, tool := range knownTools {
		if strings.HasPrefix(line, tool) {
			return line
		}
	}
	return ""
}

func colorRule(sev finding.Severity, rule string) string {
	switch sev {
	case finding.SevCritical:
		return "\033[1;31m" + rule + "\033[0m"
	case finding.SevHigh:
		return "\033[1;33m" + rule + "\033[0m"
	case finding.SevMedium:
		return "\033[1;36m" + rule + "\033[0m"
	default:
		return rule
	}
}

func truncForDisplay(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

func init() {
	chainCmd.Flags().BoolVar(&chainAllSeverities, "all", false, "walk every finding with a next-step (not just critical+high)")
	rootCmd.AddCommand(chainCmd)
}
