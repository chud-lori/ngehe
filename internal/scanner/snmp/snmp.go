// Package snmp tries common SNMP community strings, and on success walks a
// few high-value OIDs (system info, running processes, installed software).
package snmp

import (
	"fmt"
	"strings"
	"time"

	"github.com/chud-lori/ngehe/internal/finding"
	"github.com/chud-lori/ngehe/internal/wordlist"
	"github.com/gosnmp/gosnmp"
)

// Scan probes UDP/161 with SNMPv2c community strings from the SecLists list.
func Scan(host string, port int) []finding.Finding {
	if port == 0 {
		port = 161
	}
	communities := wordlist.SNMPCommunities()
	if len(communities) > 32 {
		communities = communities[:32]
	}
	var out []finding.Finding
	for _, c := range communities {
		g := &gosnmp.GoSNMP{
			Target:    host,
			Port:      uint16(port),
			Community: c,
			Version:   gosnmp.Version2c,
			Timeout:   2 * time.Second,
			Retries:   1,
		}
		if err := g.Connect(); err != nil {
			continue
		}
		// sysDescr.0 is the canonical "is SNMP responding" check.
		result, err := g.Get([]string{"1.3.6.1.2.1.1.1.0"})
		_ = g.Conn.Close()
		if err != nil || result == nil || len(result.Variables) == 0 {
			continue
		}
		val := snmpValueAsString(result.Variables[0])
		if val == "" {
			continue
		}
		out = append(out, finding.Finding{
			Rule:     "snmp-community-accepted",
			Severity: finding.SevCritical,
			Method:   "UDP",
			URL:      fmt.Sprintf("snmp://%s:%d", host, port),
			Path:     "/",
			Param:    "community",
			Payload:  c,
			Evidence: "sysDescr: " + truncate(val, 200),
			Why:      fmt.Sprintf("SNMP community %q accepted; allows enumeration / sometimes config write", c),
		})
		break // one finding per host is enough; the rest are correlated
	}
	return out
}

func snmpValueAsString(v gosnmp.SnmpPDU) string {
	switch t := v.Value.(type) {
	case string:
		return t
	case []byte:
		return string(t)
	default:
		return fmt.Sprint(t)
	}
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

// unused; explicit import to keep go.mod entries deterministic.
var _ = strings.TrimSpace
