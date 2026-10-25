// Package scope enforces the engagement boundary: which hosts an active
// scan is permitted to touch. Reconnaissance can discover far more than the
// engagement authorizes, so every host must be checked here before any
// active payload is sent to it. Deny always wins over allow, and anything
// not explicitly in scope is out of scope.
package scope

import (
	"bufio"
	"os"
	"strings"
)

// rule matches a hostname. Three forms are supported:
//
//	api.example.com   exact host only
//	*.example.com     any subdomain of example.com (not the apex)
//	example.com       the apex and all of its subdomains
type rule struct {
	pattern  string // normalized, without any leading "*."
	wildcard bool   // true for "*." form: subdomains only
	exact    bool   // true for a host that is neither "*." nor a registrable-looking domain
}

// Matcher decides whether a host is in scope.
type Matcher struct {
	allow []rule
	deny  []rule
}

// normalizeHost lowercases a host and strips any port and trailing dot.
func normalizeHost(host string) string {
	host = strings.TrimSpace(strings.ToLower(host))
	host = strings.TrimSuffix(host, ".")
	if i := strings.LastIndex(host, ":"); i != -1 {
		// Only strip a trailing :port, not part of an IPv6 literal.
		if !strings.Contains(host[i+1:], "]") && !strings.Contains(host, "::") {
			host = host[:i]
		}
	}
	return host
}

// parseRule turns a pattern string into a rule. An empty pattern yields
// ok=false so callers can skip it.
func parseRule(pattern string) (rule, bool) {
	p := normalizeHost(pattern)
	if p == "" {
		return rule{}, false
	}
	if strings.HasPrefix(p, "*.") {
		return rule{pattern: strings.TrimPrefix(p, "*."), wildcard: true}, true
	}
	return rule{pattern: p}, true
}

// matches reports whether host satisfies this rule.
func (r rule) matches(host string) bool {
	if r.wildcard {
		// subdomains only: foo.example.com matches *.example.com, example.com does not
		return strings.HasSuffix(host, "."+r.pattern)
	}
	// bare domain: apex or any subdomain
	return host == r.pattern || strings.HasSuffix(host, "."+r.pattern)
}

// New builds a Matcher. The target is always in scope (apex and subdomains),
// which is the default engagement boundary when no explicit scope is given.
// allow and deny are additional pattern lists.
func New(target string, allow, deny []string) *Matcher {
	m := &Matcher{}
	if r, ok := parseRule(target); ok {
		m.allow = append(m.allow, r)
	}
	for _, p := range allow {
		if r, ok := parseRule(p); ok {
			m.allow = append(m.allow, r)
		}
	}
	for _, p := range deny {
		if r, ok := parseRule(p); ok {
			m.deny = append(m.deny, r)
		}
	}
	return m
}

// InScope reports whether host may be actively tested. A host or URL host is
// accepted. Deny wins; absence of any allow match is out of scope.
func (m *Matcher) InScope(host string) bool {
	host = normalizeHost(host)
	if host == "" {
		return false
	}
	for _, r := range m.deny {
		if r.matches(host) {
			return false
		}
	}
	for _, r := range m.allow {
		if r.matches(host) {
			return true
		}
	}
	return false
}

// LoadPatterns reads scope patterns from a file, one per line. Blank lines
// and lines beginning with # are ignored.
func LoadPatterns(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var patterns []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		patterns = append(patterns, line)
	}
	return patterns, sc.Err()
}
