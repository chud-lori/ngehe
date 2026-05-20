// Package idmutate detects IDOR by permuting resource IDs in path segments
// and JSON body fields, then comparing responses against the baseline.
package idmutate

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/chud-lori/ngehe/internal/config"
	"github.com/chud-lori/ngehe/internal/differ"
	"github.com/chud-lori/ngehe/internal/har"
	"github.com/chud-lori/ngehe/internal/session"
)

var uuidRe = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
var idFieldRe = regexp.MustCompile(`(?i)^(id|.*_id|.*Id|user_?id|owner_?id)$`)

func Run(reqs []har.Request, sessions []session.Session, cfg *config.Config) []differ.Finding {
	pool := buildIDPool(reqs)
	client := &http.Client{
		Timeout:   time.Duration(cfg.Replay.TimeoutMS) * time.Millisecond,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	var findings []differ.Finding
	for _, r := range reqs {
		baseline := session.IdentifyBaseline(r.Headers["Authorization"], sessions)
		var ses session.Session
		found := false
		for _, s := range sessions {
			if s.Name == baseline {
				ses = s
				found = true
				break
			}
		}
		if !found && len(sessions) > 0 {
			ses = sessions[0]
		}
		mutants := mutate(r, pool)
		if len(mutants) == 0 {
			continue
		}
		origStatus := r.OrigStatus
		origBody := r.OrigBody
		if origStatus == 0 {
			// HAR may lack a captured response (OpenAPI source) — fetch baseline.
			origStatus, origBody = fire(client, r, ses, cfg.Replay.MaxBodyBytes)
		}
		if origStatus < 200 || origStatus >= 300 {
			continue
		}
		for _, m := range mutants {
			status, body := fire(client, m.req, ses, cfg.Replay.MaxBodyBytes)
			if status < 200 || status >= 300 {
				continue
			}
			sim := bodySimilarity(origBody, body)
			if sim < 0.2 && bytesAlmostEqual(body, origBody) {
				// guard against trivially-empty bodies; keep at low similarity.
			}
			sev := differ.SevMedium
			if sim >= 0.6 {
				sev = differ.SevHigh
			} else if sim < 0.2 {
				sev = differ.SevLow
			}
			findings = append(findings, differ.Finding{
				Rule:           "idor-mutated-id",
				Severity:       sev,
				Method:         m.req.Method,
				URL:            m.req.URL,
				Path:           m.req.Path,
				BaselineStatus: origStatus,
				OffenderName:   "mutated:" + m.label,
				OffenderStatus: status,
				BodySimilar:    sim,
				Why: fmt.Sprintf("replacing %s yielded %d (vs baseline %d); body similarity %.2f",
					m.label, status, origStatus, sim),
			})
		}
	}
	return findings
}

type mutant struct {
	req   har.Request
	label string
}

func mutate(r har.Request, pool []string) []mutant {
	var out []mutant
	parts := strings.Split(r.Path, "/")
	for i, seg := range parts {
		if !looksLikeID(seg) {
			continue
		}
		for _, alt := range candidatesFor(seg, pool) {
			np := append([]string{}, parts...)
			np[i] = alt
			newPath := strings.Join(np, "/")
			newURL := replacePath(r.URL, r.Path, newPath)
			clone := cloneRequest(r)
			clone.URL = newURL
			clone.Path = newPath
			out = append(out, mutant{req: clone, label: fmt.Sprintf("path[%d]=%s→%s", i, seg, alt)})
		}
	}
	if len(r.Body) > 0 && strings.Contains(r.ContentType, "json") {
		var v interface{}
		if json.Unmarshal(r.Body, &v) == nil {
			for _, mut := range mutateJSONIDs(v, pool, "") {
				b, _ := json.Marshal(mut.value)
				clone := cloneRequest(r)
				clone.Body = b
				out = append(out, mutant{req: clone, label: "body." + mut.path + "→" + mut.alt})
			}
		}
	}
	return out
}

type jsonMutation struct {
	value interface{}
	path  string
	alt   string
}

func mutateJSONIDs(root interface{}, pool []string, prefix string) []jsonMutation {
	var muts []jsonMutation
	m, ok := root.(map[string]interface{})
	if !ok {
		return nil
	}
	for k, v := range m {
		if !idFieldRe.MatchString(k) {
			continue
		}
		s, ok := v.(string)
		if !ok {
			if f, ok := v.(float64); ok {
				s = strconv.FormatFloat(f, 'f', -1, 64)
			} else {
				continue
			}
		}
		for _, alt := range candidatesFor(s, pool) {
			clone := deepCopyMap(m)
			clone[k] = alt
			muts = append(muts, jsonMutation{value: clone, path: prefix + k, alt: alt})
		}
	}
	return muts
}

func looksLikeID(s string) bool {
	if s == "" {
		return false
	}
	if _, err := strconv.Atoi(s); err == nil {
		return true
	}
	return uuidRe.MatchString(s)
}

func candidatesFor(s string, pool []string) []string {
	out := []string{}
	if n, err := strconv.Atoi(s); err == nil {
		out = append(out, strconv.Itoa(n+1), strconv.Itoa(n-1))
		if n > 0 {
			out = append(out, "0")
		}
	}
	for _, p := range pool {
		if p == s {
			continue
		}
		out = append(out, p)
		if len(out) >= 6 {
			break
		}
	}
	return out
}

func buildIDPool(reqs []har.Request) []string {
	seen := map[string]bool{}
	for _, r := range reqs {
		for _, seg := range strings.Split(r.Path, "/") {
			if looksLikeID(seg) {
				seen[seg] = true
			}
		}
	}
	var out []string
	for s := range seen {
		out = append(out, s)
	}
	return out
}

func cloneRequest(r har.Request) har.Request {
	c := r
	c.Headers = map[string]string{}
	for k, v := range r.Headers {
		c.Headers[k] = v
	}
	c.Body = append([]byte(nil), r.Body...)
	return c
}

func deepCopyMap(m map[string]interface{}) map[string]interface{} {
	b, _ := json.Marshal(m)
	var out map[string]interface{}
	_ = json.Unmarshal(b, &out)
	return out
}

func replacePath(url, oldPath, newPath string) string {
	idx := strings.Index(url, oldPath)
	if idx < 0 {
		return url
	}
	return url[:idx] + newPath + url[idx+len(oldPath):]
}

func fire(client *http.Client, r har.Request, s session.Session, maxBody int) (int, []byte) {
	var body io.Reader
	if len(r.Body) > 0 {
		body = bytes.NewReader(r.Body)
	}
	req, err := http.NewRequest(r.Method, r.URL, body)
	if err != nil {
		return 0, nil
	}
	for k, v := range r.Headers {
		req.Header.Set(k, v)
	}
	if r.ContentType != "" && req.Header.Get("Content-Type") == "" {
		req.Header.Set("Content-Type", r.ContentType)
	}
	s.Apply(req)
	resp, err := client.Do(req)
	if err != nil {
		return 0, nil
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, int64(maxBody)))
	return resp.StatusCode, b
}

func bytesAlmostEqual(a, b []byte) bool {
	return len(a) > 0 && len(b) > 0 && bytes.Equal(a, b)
}

// bodySimilarity duplicates differ.bodySimilarity intentionally to keep the
// package decoupled; both are tiny.
func bodySimilarity(a, b []byte) float64 {
	if len(a) == 0 || len(b) == 0 {
		return 0
	}
	var va, vb interface{}
	if json.Unmarshal(a, &va) == nil && json.Unmarshal(b, &vb) == nil {
		sa := shape(va, "")
		sb := shape(vb, "")
		return jaccard(sa, sb)
	}
	mn, mx := len(a), len(b)
	if mn > mx {
		mn, mx = mx, mn
	}
	return float64(mn) / float64(mx)
}

func shape(v interface{}, prefix string) map[string]bool {
	out := map[string]bool{}
	switch t := v.(type) {
	case map[string]interface{}:
		for k, val := range t {
			for tok := range shape(val, prefix+"."+k) {
				out[tok] = true
			}
		}
	case []interface{}:
		n := len(t)
		if n > 5 {
			n = 5
		}
		for i := 0; i < n; i++ {
			for tok := range shape(t[i], prefix+"[]") {
				out[tok] = true
			}
		}
	case string:
		v := t
		if len(v) > 64 {
			v = v[:64]
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
