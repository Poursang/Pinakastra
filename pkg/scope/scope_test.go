package scope

import "testing"

// The target is the engagement boundary by default: the apex and its
// subdomains are in scope, and a host merely discovered while enumerating
// the target is NOT authorized unless it falls inside that boundary.
func TestTargetBoundaryIsDefaultScope(t *testing.T) {
	m := New("example.com", nil, nil)

	in := []string{"example.com", "api.example.com", "a.b.example.com", "EXAMPLE.COM", "api.example.com:8443"}
	for _, h := range in {
		if !m.InScope(h) {
			t.Errorf("expected %q in scope", h)
		}
	}

	// Discovered during recon, but outside the target: must be refused.
	out := []string{"example.com.evil.com", "notexample.com", "example.org", "cdn.cloudfront.net"}
	for _, h := range out {
		if m.InScope(h) {
			t.Errorf("expected %q out of scope", h)
		}
	}
}

// Deny always wins, even over an explicit allow. A carve-out (e.g. a shared
// production host inside an otherwise in-scope domain) must never be touched.
func TestDenyWinsOverAllow(t *testing.T) {
	m := New("example.com", []string{"*.example.com"}, []string{"prod.example.com"})

	if m.InScope("prod.example.com") {
		t.Error("deny must override allow for prod.example.com")
	}
	if !m.InScope("staging.example.com") {
		t.Error("staging.example.com should remain in scope")
	}
}

// "*." matches subdomains only, not the apex — the distinction a tester
// relies on when the apex is explicitly excluded.
func TestWildcardIsSubdomainsOnly(t *testing.T) {
	m := New("other.test", []string{"*.example.com"}, nil)

	if !m.InScope("api.example.com") {
		t.Error("*.example.com should match a subdomain")
	}
	if m.InScope("example.com") {
		t.Error("*.example.com should not match the apex")
	}
}

// An empty matcher (no target, no patterns) is fail-closed: nothing is in
// scope. A misconfigured scope must refuse everything, never allow everything.
func TestEmptyMatcherFailsClosed(t *testing.T) {
	m := New("", nil, nil)
	if m.InScope("example.com") {
		t.Error("empty scope must refuse all hosts")
	}
}
