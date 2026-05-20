package httpx

import (
	"net/http"

	"github.com/chud-lori/ngehe/internal/har"
)

// Bearer is what each detector needs to inject auth without dragging in
// the session package (which would create import cycles for some detectors).
type Bearer struct {
	Token   string
	Headers map[string]string
}

// FireRequest sends a captured har.Request with the given bearer/headers
// applied. It strips the request's original Authorization header before
// re-injecting, mirroring how session.Apply works.
func FireRequest(client *http.Client, r har.Request, b Bearer, maxBody int) Response {
	headers := map[string]string{}
	for k, v := range r.Headers {
		if k == "Authorization" || k == "Cookie" {
			continue
		}
		headers[k] = v
	}
	if b.Token != "" {
		headers["Authorization"] = "Bearer " + b.Token
	}
	for k, v := range b.Headers {
		headers[k] = v
	}
	if r.ContentType != "" && headers["Content-Type"] == "" {
		headers["Content-Type"] = r.ContentType
	}
	return Do(client, r.Method, r.URL, headers, r.Body, maxBody)
}
