package session

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/chud-lori/ngehe/internal/config"
)

func ResolveLogins(in []config.Session, timeoutMS int) ([]Session, error) {
	client := &http.Client{
		Timeout:   time.Duration(timeoutMS) * time.Millisecond,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}},
	}
	out := make([]Session, 0, len(in))
	for _, s := range in {
		sess := Session{Name: s.Name, Bearer: s.Bearer, Cookies: s.Cookies, Headers: s.Headers}
		if s.Login != nil && s.Bearer == "" {
			tok, err := performLogin(client, s.Login)
			if err != nil {
				return nil, fmt.Errorf("login %q: %w", s.Name, err)
			}
			sess.Bearer = tok
		}
		out = append(out, sess)
	}
	return out, nil
}

func performLogin(client *http.Client, l *config.Login) (string, error) {
	method := strings.ToUpper(l.Method)
	if method == "" {
		method = "POST"
	}
	var body io.Reader
	if l.Body != "" {
		body = strings.NewReader(l.Body)
	}
	req, err := http.NewRequest(method, l.URL, body)
	if err != nil {
		return "", err
	}
	if l.ContentType != "" {
		req.Header.Set("Content-Type", l.ContentType)
	}
	for k, v := range l.Headers {
		req.Header.Set(k, v)
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		buf, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return "", fmt.Errorf("login returned %d: %s", resp.StatusCode, string(buf))
	}
	buf, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil {
		return "", err
	}
	tok, err := extractToken(buf, l.TokenJSONPath)
	if err != nil {
		return "", err
	}
	if tok == "" {
		return "", fmt.Errorf("token at %q was empty", l.TokenJSONPath)
	}
	return tok, nil
}

func extractToken(body []byte, path string) (string, error) {
	if path == "" {
		path = "token"
	}
	var v interface{}
	if err := json.Unmarshal(body, &v); err != nil {
		return "", fmt.Errorf("login response not JSON: %w", err)
	}
	for _, key := range strings.Split(path, ".") {
		m, ok := v.(map[string]interface{})
		if !ok {
			return "", fmt.Errorf("path %q: %q is not an object", path, key)
		}
		v = m[key]
	}
	if s, ok := v.(string); ok {
		return s, nil
	}
	return "", fmt.Errorf("token at %q is not a string", path)
}
