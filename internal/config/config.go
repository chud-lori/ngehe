package config

import (
	_ "embed"
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

//go:embed sample.yaml
var Sample string

type Config struct {
	Scope     Scope     `yaml:"scope"`
	Sessions  []Session `yaml:"sessions"`
	Replay    Replay    `yaml:"replay"`
	Detectors Detectors `yaml:"detectors"`
}

type Scope struct {
	Hosts        []string `yaml:"hosts"`
	IncludePaths []string `yaml:"include_paths"`
	ExcludePaths []string `yaml:"exclude_paths"`
	Methods      []string `yaml:"methods"`
}

type Session struct {
	Name    string            `yaml:"name"`
	Bearer  string            `yaml:"bearer"`
	Cookies map[string]string `yaml:"cookies"`
	Headers map[string]string `yaml:"headers"`
	Login   *Login            `yaml:"login,omitempty"`
}

type Login struct {
	Method        string            `yaml:"method"`
	URL           string            `yaml:"url"`
	Body          string            `yaml:"body"`
	ContentType   string            `yaml:"content_type"`
	Headers       map[string]string `yaml:"headers"`
	TokenJSONPath string            `yaml:"token_jsonpath"` // dot path: e.g. "token" or "data.access_token"
}

type Replay struct {
	Concurrency  int  `yaml:"concurrency"`
	IncludeAnon  bool `yaml:"include_anon"`
	TimeoutMS    int  `yaml:"timeout_ms"`
	MaxBodyBytes int  `yaml:"max_body_bytes"`
}

type Detectors struct {
	BOLA             bool     `yaml:"bola"`
	JWTAbuse         bool     `yaml:"jwt_abuse"`
	MassAssign       bool     `yaml:"mass_assign"`
	IDMutation       bool     `yaml:"id_mutation"`
	SQLi             bool     `yaml:"sqli"`
	CmdInjection     bool     `yaml:"cmd_injection"`
	SSTI             bool     `yaml:"ssti"`
	LFI              bool     `yaml:"lfi"`
	SSRF             bool     `yaml:"ssrf"`
	XSS              bool     `yaml:"xss"`
	DefaultCreds     bool     `yaml:"default_creds"`
	JWTProbeURL      string   `yaml:"jwt_probe_url"`
	DefaultCredsURLs []string `yaml:"default_creds_urls"`
}

func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var c Config
	if err := yaml.Unmarshal(data, &c); err != nil {
		return nil, fmt.Errorf("yaml: %w", err)
	}
	if c.Replay.Concurrency == 0 {
		c.Replay.Concurrency = 4
	}
	if c.Replay.TimeoutMS == 0 {
		c.Replay.TimeoutMS = 10000
	}
	if c.Replay.MaxBodyBytes == 0 {
		c.Replay.MaxBodyBytes = 256 * 1024
	}
	// If no detector was explicitly enabled, light up the safe authn/authz ones.
	// Injection-class detectors stay off-by-default — they fire many requests
	// with payloads that can be noisy in shared environments.
	anyOn := c.Detectors.BOLA || c.Detectors.JWTAbuse || c.Detectors.MassAssign ||
		c.Detectors.IDMutation || c.Detectors.SQLi || c.Detectors.CmdInjection ||
		c.Detectors.SSTI || c.Detectors.LFI || c.Detectors.SSRF || c.Detectors.XSS ||
		c.Detectors.DefaultCreds
	if !anyOn {
		c.Detectors.BOLA = true
		c.Detectors.IDMutation = true
		c.Detectors.MassAssign = true
		c.Detectors.JWTAbuse = true
	}
	return &c, nil
}
