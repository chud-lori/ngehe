// Package massassign detects OWASP API6:2023 mass assignment.
//
// For each POST/PUT/PATCH with a JSON object body, ngehe injects a small
// dictionary of "trust-elevating" fields (isAdmin, role, owner, ...) and
// fires the request. The bug fires when the server *reflects* one of those
// fields in its 2xx response — meaning it accepted the unsanctioned input.
package massassign

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/chud-lori/ngehe/internal/config"
	"github.com/chud-lori/ngehe/internal/differ"
	"github.com/chud-lori/ngehe/internal/har"
	"github.com/chud-lori/ngehe/internal/session"
)

var injections = map[string]interface{}{
	"isAdmin":     true,
	"is_admin":    true,
	"admin":       true,
	"role":        "admin",
	"roles":       []string{"admin"},
	"verified":    true,
	"is_verified": true,
	"owner":       "ngehe-injected",
	"is_owner":    true,
	"userId":      "ngehe-injected",
	"permissions": []string{"*"},
}

func Run(reqs []har.Request, sessions []session.Session, cfg *config.Config) []differ.Finding {
	client := &http.Client{
		Timeout:   time.Duration(cfg.Replay.TimeoutMS) * time.Millisecond,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	var findings []differ.Finding
	for _, r := range reqs {
		if !writesJSON(r) {
			continue
		}
		var body map[string]interface{}
		if err := json.Unmarshal(r.Body, &body); err != nil {
			continue
		}
		ses := chooseSession(r, sessions)
		for key, value := range injections {
			if _, exists := body[key]; exists {
				continue
			}
			mutated := cloneMap(body)
			mutated[key] = value
			newBody, _ := json.Marshal(mutated)
			clone := cloneRequest(r)
			clone.Body = newBody
			status, respBody := fire(client, clone, ses, cfg.Replay.MaxBodyBytes)
			if status < 200 || status >= 300 {
				continue
			}
			if reflected(respBody, key, value) {
				findings = append(findings, differ.Finding{
					Rule:           "mass-assign-reflected",
					Severity:       differ.SevHigh,
					Method:         r.Method,
					URL:            r.URL,
					Path:           r.Path,
					BaselineStatus: r.OrigStatus,
					OffenderName:   "injected:" + key,
					OffenderStatus: status,
					BodySimilar:    0,
					Why: fmt.Sprintf("server accepted unsanctioned field %q and reflected it in the response", key),
				})
			} else {
				findings = append(findings, differ.Finding{
					Rule:           "mass-assign-accepted",
					Severity:       differ.SevLow,
					Method:         r.Method,
					URL:            r.URL,
					Path:           r.Path,
					BaselineStatus: r.OrigStatus,
					OffenderName:   "injected:" + key,
					OffenderStatus: status,
					BodySimilar:    0,
					Why: fmt.Sprintf("server returned %d when extra field %q was injected (not reflected; may be silently bound)", status, key),
				})
			}
		}
	}
	return findings
}

func writesJSON(r har.Request) bool {
	switch strings.ToUpper(r.Method) {
	case "POST", "PUT", "PATCH":
	default:
		return false
	}
	if len(r.Body) == 0 {
		return false
	}
	return strings.Contains(strings.ToLower(r.ContentType), "json") ||
		(len(r.Body) > 0 && r.Body[0] == '{')
}

func chooseSession(r har.Request, sessions []session.Session) session.Session {
	baseline := session.IdentifyBaseline(r.Headers["Authorization"], sessions)
	for _, s := range sessions {
		if s.Name == baseline {
			return s
		}
	}
	if len(sessions) > 0 {
		return sessions[0]
	}
	return session.Anon()
}

func reflected(respBody []byte, key string, value interface{}) bool {
	if len(respBody) == 0 {
		return false
	}
	var resp interface{}
	if err := json.Unmarshal(respBody, &resp); err != nil {
		return false
	}
	return walkFind(resp, key, value)
}

func walkFind(v interface{}, key string, want interface{}) bool {
	switch t := v.(type) {
	case map[string]interface{}:
		if got, ok := t[key]; ok && deepEqualLoose(got, want) {
			return true
		}
		for _, vv := range t {
			if walkFind(vv, key, want) {
				return true
			}
		}
	case []interface{}:
		for _, vv := range t {
			if walkFind(vv, key, want) {
				return true
			}
		}
	}
	return false
}

func deepEqualLoose(a, b interface{}) bool {
	switch av := a.(type) {
	case string:
		if bv, ok := b.(string); ok {
			return av == bv
		}
	case bool:
		if bv, ok := b.(bool); ok {
			return av == bv
		}
	case []interface{}:
		bs, ok := b.([]string)
		if !ok {
			return false
		}
		if len(av) != len(bs) {
			return false
		}
		for i := range av {
			if s, ok := av[i].(string); !ok || s != bs[i] {
				return false
			}
		}
		return true
	}
	// fall back to JSON equality for awkward types
	ja, _ := json.Marshal(a)
	jb, _ := json.Marshal(b)
	return bytes.Equal(ja, jb)
}

func cloneMap(m map[string]interface{}) map[string]interface{} {
	b, _ := json.Marshal(m)
	var out map[string]interface{}
	_ = json.Unmarshal(b, &out)
	return out
}

func cloneRequest(r har.Request) har.Request {
	c := r
	c.Headers = map[string]string{}
	for k, v := range r.Headers {
		c.Headers[k] = v
	}
	return c
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
