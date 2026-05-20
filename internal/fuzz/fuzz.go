// Package fuzz injects payloads into the mutable parts of a captured request:
// query parameters, JSON body string fields, and (optionally) headers.
package fuzz

import (
	"encoding/json"
	"net/url"
	"strings"

	"github.com/chud-lori/ngehe/internal/har"
)

// Injection describes one payload-substituted variant of a request.
type Injection struct {
	Request har.Request
	Param   string // "query:q", "body:user.name", "header:X-Forwarded-For"
	Payload string
}

// QueryParams returns one injection per query parameter, substituting payload.
func QueryParams(r har.Request, payload string) []Injection {
	u, err := url.Parse(r.URL)
	if err != nil {
		return nil
	}
	q := u.Query()
	var out []Injection
	for k := range q {
		nq := cloneValues(q)
		nq.Set(k, payload)
		u2 := *u
		u2.RawQuery = nq.Encode()
		clone := r
		clone.URL = u2.String()
		clone.Query = valuesToMap(nq)
		out = append(out, Injection{Request: clone, Param: "query:" + k, Payload: payload})
	}
	return out
}

// JSONStrings returns one injection per string-valued field in a JSON body.
// Nested fields use dotted paths.
func JSONStrings(r har.Request, payload string) []Injection {
	if len(r.Body) == 0 || !strings.Contains(strings.ToLower(r.ContentType), "json") {
		return nil
	}
	var root interface{}
	if err := json.Unmarshal(r.Body, &root); err != nil {
		return nil
	}
	paths := stringFieldPaths(root, "")
	var out []Injection
	for _, p := range paths {
		mutated := setAtPath(deepCopy(root), p, payload)
		b, _ := json.Marshal(mutated)
		clone := r
		clone.Body = b
		clone.Headers = copyHeaders(r.Headers)
		out = append(out, Injection{Request: clone, Param: "body:" + p, Payload: payload})
	}
	return out
}

// AppendQuery appends `?<name>=<payload>` (or & if a query exists). Useful for
// detectors testing parameters that may not appear in the capture.
func AppendQuery(r har.Request, name, payload string) Injection {
	u, _ := url.Parse(r.URL)
	q := u.Query()
	q.Set(name, payload)
	u.RawQuery = q.Encode()
	clone := r
	clone.URL = u.String()
	clone.Query = valuesToMap(q)
	return Injection{Request: clone, Param: "query:" + name, Payload: payload}
}

func cloneValues(v url.Values) url.Values {
	out := url.Values{}
	for k, vs := range v {
		out[k] = append([]string{}, vs...)
	}
	return out
}

func valuesToMap(v url.Values) map[string]string {
	out := map[string]string{}
	for k, vs := range v {
		if len(vs) > 0 {
			out[k] = vs[0]
		}
	}
	return out
}

func copyHeaders(h map[string]string) map[string]string {
	out := map[string]string{}
	for k, v := range h {
		out[k] = v
	}
	return out
}

func stringFieldPaths(v interface{}, prefix string) []string {
	var out []string
	switch t := v.(type) {
	case map[string]interface{}:
		for k, val := range t {
			child := k
			if prefix != "" {
				child = prefix + "." + k
			}
			out = append(out, stringFieldPaths(val, child)...)
		}
	case []interface{}:
		for i, val := range t {
			child := prefix + "[0]"
			_ = i
			out = append(out, stringFieldPaths(val, child)...)
			break // first element only to keep things tractable
		}
	case string:
		out = append(out, prefix)
	}
	return out
}

func setAtPath(root interface{}, path, value string) interface{} {
	parts := strings.Split(path, ".")
	set(root, parts, value)
	return root
}

func set(v interface{}, parts []string, value string) {
	if len(parts) == 0 {
		return
	}
	key := parts[0]
	if idx := strings.Index(key, "["); idx > 0 {
		// not handling array writes in MVP
		return
	}
	m, ok := v.(map[string]interface{})
	if !ok {
		return
	}
	if len(parts) == 1 {
		m[key] = value
		return
	}
	set(m[key], parts[1:], value)
}

func deepCopy(v interface{}) interface{} {
	b, _ := json.Marshal(v)
	var out interface{}
	_ = json.Unmarshal(b, &out)
	return out
}
