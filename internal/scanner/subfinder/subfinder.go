// Package subfinder shells out to projectdiscovery/subfinder for fast passive
// subdomain enumeration. Pairs with amass: subfinder is fast and goes wide
// across passive sources; amass is more thorough.
package subfinder

import (
	"bufio"
	"context"
	"os/exec"
	"strings"
	"time"

	"github.com/chud-lori/ngehe/internal/finding"
)

type Options struct {
	Domain  string
	Timeout time.Duration
}

func Available() bool {
	_, err := exec.LookPath("subfinder")
	return err == nil
}

// Enumerate runs `subfinder -d <domain> -silent`. Returns the discovered
// hostnames plus a finding per host. Missing tool → empty slices, no error.
func Enumerate(opts Options) (hosts []string, findings []finding.Finding, err error) {
	if !Available() || opts.Domain == "" {
		return nil, nil, nil
	}
	timeout := opts.Timeout
	if timeout == 0 {
		timeout = 3 * time.Minute
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, "subfinder", "-d", opts.Domain, "-silent", "-nc")
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, nil, err
	}

	seen := map[string]bool{}
	scanner := bufio.NewScanner(stdout)
	for scanner.Scan() {
		name := strings.TrimSpace(strings.ToLower(scanner.Text()))
		if name == "" || seen[name] {
			continue
		}
		seen[name] = true
		hosts = append(hosts, name)
		findings = append(findings, finding.Finding{
			Rule:     "subfinder-subdomain",
			Severity: finding.SevInfo,
			Method:   "DNS",
			URL:      "dns://" + name,
			Path:     "/",
			Why:      "subfinder passive discovery surfaced subdomain " + name,
			Source:   "subfinder",
		})
	}
	_ = cmd.Wait()
	return hosts, findings, nil
}
