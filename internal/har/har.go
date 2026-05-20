package har

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"strings"

	"github.com/chud-lori/ngehe/internal/config"
)

// Request is ngehe's normalized view of one captured HTTP request.
type Request struct {
	Method      string
	URL         string
	Host        string
	Path        string
	Headers     map[string]string
	Query       map[string]string
	Body        []byte
	ContentType string
	OrigStatus  int
	OrigBody    []byte
}

type harFile struct {
	Log struct {
		Entries []harEntry `json:"entries"`
	} `json:"log"`
}

type harEntry struct {
	Request struct {
		Method      string         `json:"method"`
		URL         string         `json:"url"`
		Headers     []harNameValue `json:"headers"`
		QueryString []harNameValue `json:"queryString"`
		PostData    *struct {
			MimeType string `json:"mimeType"`
			Text     string `json:"text"`
		} `json:"postData"`
	} `json:"request"`
	Response struct {
		Status  int `json:"status"`
		Content struct {
			Text string `json:"text"`
		} `json:"content"`
	} `json:"response"`
}

type harNameValue struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// Load parses a HAR file and filters down to in-scope requests.
func Load(path string, scope config.Scope) ([]Request, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var hf harFile
	if err := json.Unmarshal(data, &hf); err != nil {
		return nil, fmt.Errorf("parse har: %w", err)
	}

	methodSet := stringSet(scope.Methods)
	hostSet := stringSet(scope.Hosts)
	seen := make(map[string]bool)

	var out []Request
	for _, e := range hf.Log.Entries {
		u, err := url.Parse(e.Request.URL)
		if err != nil {
			continue
		}
		if !hostMatches(u.Host, hostSet) {
			continue
		}
		if len(methodSet) > 0 && !methodSet[strings.ToUpper(e.Request.Method)] {
			continue
		}
		if !pathIncluded(u.Path, scope.IncludePaths, scope.ExcludePaths) {
			continue
		}
		// Asset noise filter.
		if isAssetPath(u.Path) {
			continue
		}

		req := Request{
			Method:     strings.ToUpper(e.Request.Method),
			URL:        e.Request.URL,
			Host:       u.Host,
			Path:       u.Path,
			Headers:    map[string]string{},
			Query:      map[string]string{},
			OrigStatus: e.Response.Status,
			OrigBody:   []byte(e.Response.Content.Text),
		}
		for _, h := range e.Request.Headers {
			// HAR puts pseudo-headers like :method too — skip.
			if strings.HasPrefix(h.Name, ":") {
				continue
			}
			req.Headers[h.Name] = h.Value
		}
		for _, q := range e.Request.QueryString {
			req.Query[q.Name] = q.Value
		}
		if e.Request.PostData != nil {
			req.Body = []byte(e.Request.PostData.Text)
			req.ContentType = e.Request.PostData.MimeType
		}

		// Dedupe identical method+path+query signatures so we don't
		// re-test the same endpoint 50 times for an SPA poll loop.
		sig := req.Method + " " + req.Path + " " + canonicalQuery(req.Query)
		if seen[sig] {
			continue
		}
		seen[sig] = true
		out = append(out, req)
	}
	return out, nil
}

func stringSet(xs []string) map[string]bool {
	s := make(map[string]bool, len(xs))
	for _, x := range xs {
		s[strings.ToUpper(x)] = true
	}
	return s
}

func hostMatches(host string, allowed map[string]bool) bool {
	if len(allowed) == 0 {
		return true
	}
	h := strings.ToUpper(host)
	if allowed[h] {
		return true
	}
	// strip port
	if i := strings.IndexByte(h, ':'); i > 0 {
		if allowed[h[:i]] {
			return true
		}
	}
	return false
}

func pathIncluded(path string, include, exclude []string) bool {
	for _, p := range exclude {
		if strings.HasPrefix(path, p) {
			return false
		}
	}
	if len(include) == 0 {
		return true
	}
	for _, p := range include {
		if strings.HasPrefix(path, p) {
			return true
		}
	}
	return false
}

var assetExts = []string{".js", ".css", ".png", ".jpg", ".jpeg", ".svg", ".woff", ".woff2", ".ico", ".map", ".gif", ".webp"}

func isAssetPath(p string) bool {
	low := strings.ToLower(p)
	for _, ext := range assetExts {
		if strings.HasSuffix(low, ext) {
			return true
		}
	}
	return false
}

func canonicalQuery(q map[string]string) string {
	if len(q) == 0 {
		return ""
	}
	keys := make([]string, 0, len(q))
	for k := range q {
		keys = append(keys, k)
	}
	// stable order without importing sort just for this — small slice
	for i := 1; i < len(keys); i++ {
		for j := i; j > 0 && keys[j] < keys[j-1]; j-- {
			keys[j], keys[j-1] = keys[j-1], keys[j]
		}
	}
	var b strings.Builder
	for _, k := range keys {
		b.WriteString(k)
		b.WriteByte('=')
		b.WriteString(q[k])
		b.WriteByte('&')
	}
	return b.String()
}
