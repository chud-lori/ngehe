package differ

import (
	"encoding/json"
	"fmt"

	"github.com/chud-lori/ngehe/internal/finding"
	"github.com/chud-lori/ngehe/internal/replay"
	"github.com/chud-lori/ngehe/internal/session"
)

type (
	Finding  = finding.Finding
	Severity = finding.Severity
)

const (
	SevHigh   = finding.SevHigh
	SevMedium = finding.SevMedium
	SevLow    = finding.SevLow
	SevInfo   = finding.SevInfo
)

// Analyze applies BOLA/IDOR heuristics to each replay result.
func Analyze(results []replay.Result) []Finding {
	var findings []Finding
	for _, r := range results {
		origin, ok := r.Responses[replay.OriginKey]
		if !ok {
			continue
		}
		// Only meaningful if the original successfully accessed the resource.
		if origin.Status < 200 || origin.Status >= 300 {
			continue
		}
		for name, resp := range r.Responses {
			if name == replay.OriginKey {
				continue
			}
			f, ok := evaluate(r.Req.Method, r.Req.URL, r.Req.Path, origin, resp, name)
			if ok {
				findings = append(findings, f)
			}
		}
	}
	return findings
}

func evaluate(method, url, path string, origin, swap replay.Response, name string) (Finding, bool) {
	// Anonymous access to an authenticated resource: any 2xx is suspicious.
	if name == session.AnonName {
		if swap.Status >= 200 && swap.Status < 300 {
			sim := bodySimilarity(origin.Body, swap.Body)
			return Finding{
				Rule:           "broken-auth-anon-access",
				Severity:       SevHigh,
				Method:         method,
				URL:            url,
				Path:           path,
				BaselineStatus: origin.Status,
				OffenderName:   name,
				OffenderStatus: swap.Status,
				BodySimilar:    sim,
				Why: fmt.Sprintf(
					"unauthenticated request returned %d on an endpoint the baseline user accessed authenticated; body similarity %.2f",
					swap.Status, sim,
				),
			}, true
		}
		return Finding{}, false
	}

	// BOLA: another authenticated user got 2xx for what should be the
	// baseline's resource. Strong signal when bodies are similar.
	if swap.Status >= 200 && swap.Status < 300 {
		sim := bodySimilarity(origin.Body, swap.Body)
		sev := SevMedium
		if sim >= 0.6 {
			sev = SevHigh
		} else if sim < 0.2 && method == "GET" {
			// Different body — could be the other user's own data being
			// returned for an ID that wasn't theirs (rare) or legitimate
			// shared content (common). Keep as medium-low signal.
			sev = SevLow
		}
		return Finding{
			Rule:           "bola-cross-user-access",
			Severity:       sev,
			Method:         method,
			URL:            url,
			Path:           path,
			BaselineStatus: origin.Status,
			OffenderName:   name,
			OffenderStatus: swap.Status,
			BodySimilar:    sim,
			Why: fmt.Sprintf(
				"session %q got %d on baseline's request; body similarity %.2f",
				name, swap.Status, sim,
			),
		}, true
	}

	return Finding{}, false
}

// bodySimilarity returns a 0..1 score of how similar two response bodies are.
// For JSON it uses Jaccard over (key, leaf-value-shape) pairs; otherwise it
// falls back to a length-ratio heuristic.
func bodySimilarity(a, b []byte) float64 {
	if len(a) == 0 || len(b) == 0 {
		return 0
	}
	ja, errA := unmarshalAny(a)
	jb, errB := unmarshalAny(b)
	if errA == nil && errB == nil {
		setA := jsonShape(ja, "")
		setB := jsonShape(jb, "")
		return jaccard(setA, setB)
	}
	// Byte length ratio fallback.
	min, max := len(a), len(b)
	if min > max {
		min, max = max, min
	}
	return float64(min) / float64(max)
}

func unmarshalAny(b []byte) (interface{}, error) {
	var v interface{}
	err := json.Unmarshal(b, &v)
	return v, err
}

// jsonShape flattens a JSON value to a set of "path=value" tokens. Including
// scalar values matters: two responses with the *same structure but different
// content* (e.g. /api/me for alice vs bob) should score low, while two
// responses returning the same resource (BOLA) should score high. String
// values are truncated to avoid huge token sets.
func jsonShape(v interface{}, prefix string) map[string]bool {
	out := map[string]bool{}
	const maxStr = 64
	switch t := v.(type) {
	case map[string]interface{}:
		for k, val := range t {
			child := prefix + "." + k
			for tok := range jsonShape(val, child) {
				out[tok] = true
			}
		}
	case []interface{}:
		// Sample up to first 5 elements so a list of similar records still
		// produces a meaningful overlap signature without exploding.
		n := len(t)
		if n > 5 {
			n = 5
		}
		if n == 0 {
			out[prefix+"=[]"] = true
		}
		for i := 0; i < n; i++ {
			for tok := range jsonShape(t[i], prefix+"[]") {
				out[tok] = true
			}
		}
	case string:
		v := t
		if len(v) > maxStr {
			v = v[:maxStr]
		}
		out[prefix+"=s:"+v] = true
	case float64:
		out[fmt.Sprintf("%s=n:%v", prefix, t)] = true
	case bool:
		out[fmt.Sprintf("%s=b:%v", prefix, t)] = true
	case nil:
		out[prefix+"=null"] = true
	}
	return out
}

func jaccard(a, b map[string]bool) float64 {
	if len(a) == 0 && len(b) == 0 {
		return 0
	}
	inter := 0
	for k := range a {
		if b[k] {
			inter++
		}
	}
	union := len(a) + len(b) - inter
	if union == 0 {
		return 0
	}
	return float64(inter) / float64(union)
}
