// Package oracle provides detection helpers used by every active detector.
package oracle

import (
	"bytes"
	"regexp"
)

// StringOracle returns the matched marker if any of `markers` appears in body,
// or "" if none do.
func StringOracle(body []byte, markers ...string) string {
	for _, m := range markers {
		if m != "" && bytes.Contains(body, []byte(m)) {
			return m
		}
	}
	return ""
}

// RegexOracle returns the first match of any regex in `patterns`.
func RegexOracle(body []byte, patterns ...*regexp.Regexp) string {
	for _, p := range patterns {
		if p == nil {
			continue
		}
		if m := p.Find(body); m != nil {
			return string(m)
		}
	}
	return ""
}

// TimingOracle reports whether observed timing exceeded baseline + threshold.
// Both are milliseconds. A 4x multiplier is the default heuristic.
func TimingOracle(baselineMS, observedMS, expectedDelayMS int64) bool {
	if expectedDelayMS <= 0 {
		expectedDelayMS = 5000
	}
	floor := baselineMS + (expectedDelayMS * 80 / 100) // accept 80% of expected delay
	return observedMS >= floor
}

// StatusDiff returns true when the offender status indicates a meaningful
// change from baseline: e.g. 200 vs 500, 403 vs 200, or any 5xx introduced.
func StatusDiff(baseline, offender int) bool {
	if baseline == offender {
		return false
	}
	// new server error introduced by payload is interesting
	if offender >= 500 {
		return true
	}
	// auth boundary changed
	if (baseline == 401 || baseline == 403) && offender >= 200 && offender < 300 {
		return true
	}
	if baseline >= 200 && baseline < 300 && (offender == 401 || offender == 403) {
		return true
	}
	return false
}
