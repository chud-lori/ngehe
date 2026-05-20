package session

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/chud-lori/ngehe/internal/config"
)

const AnonName = "anon"

// Session holds the credentials ngehe will inject when replaying a request.
type Session struct {
	Name    string
	Bearer  string
	Cookies map[string]string
	Headers map[string]string
}

// Apply rewrites a request to authenticate as this session.
// It first strips the headers/cookies that typically carry the *original*
// session's identity, then injects this session's credentials.
func (s Session) Apply(r *http.Request) {
	stripAuth(r)
	if s.Name == AnonName {
		return
	}
	if s.Bearer != "" {
		r.Header.Set("Authorization", "Bearer "+s.Bearer)
	}
	for k, v := range s.Headers {
		r.Header.Set(k, v)
	}
	for k, v := range s.Cookies {
		r.AddCookie(&http.Cookie{Name: k, Value: v})
	}
}

func stripAuth(r *http.Request) {
	r.Header.Del("Authorization")
	r.Header.Del("Cookie")
	r.Header.Del("X-Auth-Token")
	r.Header.Del("X-Api-Key")
	// Tenant/scoping headers that commonly travel with auth in multi-tenant
	// APIs — strip well-known names so callers don't accidentally keep the
	// baseline user's tenant context. Custom names are re-added via Headers.
	for k := range r.Header {
		low := strings.ToLower(k)
		if strings.HasPrefix(low, "x-tenant") || strings.HasPrefix(low, "x-org") {
			r.Header.Del(k)
		}
	}
}

func FromConfig(in []config.Session) []Session {
	out := make([]Session, 0, len(in))
	for _, s := range in {
		out = append(out, Session{
			Name:    s.Name,
			Bearer:  s.Bearer,
			Cookies: s.Cookies,
			Headers: s.Headers,
		})
	}
	return out
}

func Anon() Session {
	return Session{Name: AnonName}
}

// IdentifyBaseline returns the name of the session whose credentials match
// the request's existing Authorization header. First tries exact bearer
// match; falls back to matching the JWT `sub` claim against session.Name
// (robust when the HAR was captured with a now-refreshed token).
func IdentifyBaseline(authHeader string, sessions []Session) string {
	if authHeader == "" {
		return ""
	}
	for _, s := range sessions {
		if s.Bearer != "" && authHeader == "Bearer "+s.Bearer {
			return s.Name
		}
	}
	if sub := jwtSub(strings.TrimPrefix(authHeader, "Bearer ")); sub != "" {
		for _, s := range sessions {
			if s.Name == sub {
				return s.Name
			}
		}
	}
	return ""
}

func jwtSub(tok string) string {
	parts := strings.Split(tok, ".")
	if len(parts) < 2 {
		return ""
	}
	b, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return ""
	}
	var c struct {
		Sub string `json:"sub"`
	}
	if err := json.Unmarshal(b, &c); err != nil {
		return ""
	}
	return c.Sub
}
