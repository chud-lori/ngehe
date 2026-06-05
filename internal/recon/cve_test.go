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
