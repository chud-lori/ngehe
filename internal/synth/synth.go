// Package synth turns a target URL + discovered paths into the synthetic
// har.Request entries the active detectors expect. Used when the user
// passes --target instead of a HAR / OpenAPI spec.
//
// Each path becomes multiple requests, one per common parameter name and
// one POST with a generic JSON body. This is best-effort — without a real
// HAR, we don't know which params actually exist, so we guess at the most
// commonly-named ones.
package synth

import (
	"encoding/json"
	"net/url"
	"strings"

	"github.com/chud-lori/ngehe/internal/har"
)

// commonParams: the parameter names that get tested for each path. Tuned
// to maximize HTB / CTF hits — every name here has been the injection
// point on real CTF / OWASP-Top-10 challenges.
var commonParams = []string{
	"id", "user_id", "userid", "uid", "user", "username",
	"q", "query", "search", "term", "keyword",
	"file", "filename", "path", "filepath", "page", "include",
	"url", "uri", "next", "redirect", "redir", "return", "callback",
	"name", "title", "content", "message", "data", "msg", "text",
	"category", "type", "kind", "format", "lang", "locale",
	"host", "target", "addr", "ip", "domain", "site",
	"cmd", "command", "exec", "action",
	"debug", "test", "admin", "preview",
}

// jsonBodyShape: a single generic JSON POST shape. Active detectors will
// inject payloads into each string field, so we want a few realistic-looking
// values that an app might bind.
func jsonBodyShape() []byte {
	body, _ := json.Marshal(map[string]string{
		"id":       "1",
		"name":     "ngehe",
		"email":    "ngehe@example.com",
		"username": "ngehe",
		"password": "ngehe",
		"content":  "test",
		"message":  "hello",
		"url":      "http://example.com",
	})
	return body
}

// Requests synthesizes a slice of har.Request entries for the given target +
// paths. Paths can be just the host root ("/") or a list discovered via
// ngehe recon's dir-bruteforce.
func Requests(target string, paths []string) []har.Request {
	target = strings.TrimRight(target, "/")
	u, err := url.Parse(target)
	if err != nil {
		return nil
	}
	// Common API surface that dirbust often misses (because they're app-
	// specific and not in SecLists' wordlist). Worth testing on every
	// URL-only scan as a fallback before active detectors run.
	defaultAPIPrefixes := []string{
		"/", "/api", "/api/v1", "/api/v2", "/api/v3",
		"/api/users", "/api/user", "/api/items", "/api/products", "/api/search",
		"/api/login", "/api/auth", "/api/admin", "/api/files", "/api/upload",
		"/api/notes", "/api/posts", "/api/comments", "/api/me", "/api/profile",
		"/api/ping", "/api/greet", "/api/echo", "/api/file", "/api/fetch",
		"/v1", "/v2", "/rest", "/graphql",
	}
	if len(paths) == 0 {
		paths = defaultAPIPrefixes
	} else {
		merged := make(map[string]bool, len(paths)+len(defaultAPIPrefixes))
		for _, p := range paths {
			merged[p] = true
		}
		for _, p := range defaultAPIPrefixes {
			merged[p] = true
		}
		paths = paths[:0]
		for p := range merged {
			paths = append(paths, p)
		}
	}
	seen := map[string]bool{}
	var out []har.Request
	for _, p := range paths {
		p = "/" + strings.TrimLeft(p, "/")
		if seen[p] {
			continue
		}
		seen[p] = true

		for _, param := range commonParams {
			q := url.Values{}
			q.Set(param, "1")
			fullURL := target + p + "?" + q.Encode()
			out = append(out, har.Request{
				Method:  "GET",
				URL:     fullURL,
				Host:    u.Host,
				Path:    p,
				Headers: map[string]string{"User-Agent": "ngehe-synth/0.3"},
				Query:   map[string]string{param: "1"},
			})
		}

		out = append(out, har.Request{
			Method:      "POST",
			URL:         target + p,
			Host:        u.Host,
			Path:        p,
			Headers:     map[string]string{"User-Agent": "ngehe-synth/0.3", "Content-Type": "application/json"},
			Body:        jsonBodyShape(),
			ContentType: "application/json",
		})
	}
	return out
}

// FromRecon takes a list of recon findings (rule=dir-discovery) and
// returns the paths they hit. Convenience: ngehe recon → ngehe synth → detectors.
func FromRecon(reconJSONLPath string) []string {
	// Caller can construct this themselves; expose helper if needed later.
	_ = reconJSONLPath
	return nil
}
