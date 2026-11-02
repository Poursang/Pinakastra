package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/who0xac/pinakastra/pkg/exploit"
)

// The shipped canary server must satisfy the contract the shipped HTTPCanary
// client expects: a token reads as not-contacted until its /c/<token> URL is
// requested, then reads as contacted. This exercises both sides together, so
// they cannot drift apart.
func TestCanarySatisfiesHTTPCanaryClient(t *testing.T) {
	srv := httptest.NewServer(newCanary().handler())
	defer srv.Close()

	client := exploit.NewHTTPCanary(srv.URL, nil)
	payloadURL, token := client.Payload()

	if hit, err := client.Interacted(context.Background(), token); err != nil || hit {
		t.Fatalf("token should not be contacted yet (hit=%v err=%v)", hit, err)
	}

	// Simulate the target fetching the injected canary URL.
	resp, err := http.Get(payloadURL)
	if err != nil {
		t.Fatalf("fetching payload URL: %v", err)
	}
	resp.Body.Close()

	if hit, err := client.Interacted(context.Background(), token); err != nil || !hit {
		t.Fatalf("token should read as contacted after the fetch (hit=%v err=%v)", hit, err)
	}
}

// An unknown token reads as not contacted.
func TestCanaryUnknownTokenIsNotHit(t *testing.T) {
	srv := httptest.NewServer(newCanary().handler())
	defer srv.Close()

	client := exploit.NewHTTPCanary(srv.URL, nil)
	if hit, err := client.Interacted(context.Background(), "never-registered"); err != nil || hit {
		t.Fatalf("unknown token must not be a hit (hit=%v err=%v)", hit, err)
	}
}
