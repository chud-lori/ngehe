package recon

import "testing"

func TestCheckNginxRift(t *testing.T) {
	cases := []struct {
		server  string
		wantHit bool
	}{
		// Vulnerable range.
		{"nginx/0.6.27", true},
		{"nginx/1.18.0", true},
		{"nginx/1.30.0", true},
		// Edges just outside the range.
		{"nginx/0.6.26", false},
		{"nginx/1.30.1", false},
		{"nginx/2.0.0", false},
		// Non-nginx banners.
		{"Apache/2.4.41", false},
		{"", false},
		// nginx without a version (can't decide → skip).
		{"nginx", false},
	}
	for _, c := range cases {
		_, ok := checkNginxRift("http://x", c.server)
		if ok != c.wantHit {
			t.Errorf("checkNginxRift(%q) = %v, want %v", c.server, ok, c.wantHit)
		}
	}
}

func TestCheckCPanelAuthBypass(t *testing.T) {
	cases := []struct {
		name     string
		server   string
		cookies  []string
		body     string
		wantHit  bool
		wantRule string
	}{
		{
			name:     "vulnerable cpsrvd banner",
			server:   "cpsrvd 11.110.0.96",
			wantHit:  true,
			wantRule: "cve-2026-41940-cpanel-whm-auth-bypass",
		},
		{
			name:     "patched cpsrvd banner",
			server:   "cpsrvd 11.110.0.97",
			wantHit:  true,
			wantRule: "cpanel-whm-management-plane",
		},
		{
			name:     "older affected branch",
			server:   "cpsrvd 11.86.0.40",
			wantHit:  true,
			wantRule: "cve-2026-41940-cpanel-whm-auth-bypass",
		},
		{
			name:     "unknown version whm login",
			body:     "<html><title>WHM Login</title></html>",
			wantHit:  true,
			wantRule: "cpanel-whm-management-plane",
		},
		{
			name:    "non cpanel",
			server:  "nginx/1.26.0",
			body:    "<html><title>Example</title></html>",
			wantHit: false,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f, ok := checkCPanelAuthBypass("https://x:2087", c.server, c.cookies, c.body)
			if ok != c.wantHit {
				t.Fatalf("checkCPanelAuthBypass() hit = %v, want %v", ok, c.wantHit)
			}
			if ok && f.Rule != c.wantRule {
				t.Fatalf("rule = %q, want %q", f.Rule, c.wantRule)
			}
		})
	}
}

func TestIsCPanelVulnerableVersion(t *testing.T) {
	cases := []struct {
		ver  string
		want bool
	}{
		{"11.110.0.96", true},
		{"11.110.0.97", false},
		{"11.118.0.62", true},
		{"11.118.0.63", false},
		{"11.130.0.18", true},
		{"11.130.0.19", false},
		{"11.136.0.4", true},
		{"11.136.0.5", false},
		{"11.40.0.0", false},
		{"11.30.0.0", false},
	}
	for _, c := range cases {
		if got := isCPanelVulnerableVersion(c.ver); got != c.want {
			t.Errorf("isCPanelVulnerableVersion(%q) = %v, want %v", c.ver, got, c.want)
		}
	}
}
