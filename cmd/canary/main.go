// Command canary is a minimal out-of-band interaction logger for blind SSRF
// detection. Run it on a host the target can reach, then point the scanner at
// it with --oob-url. It records a contact on GET /c/<token> and reports whether
// a token has been contacted on GET /hits/<token> ("1" or "0") — the contract
// pinakastra's HTTPCanary expects.
//
// It stores nothing but opaque per-probe tokens in memory and serves no other
// routes. Use only as part of testing you are authorized to run.
package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync"
)

// canary records which tokens have been contacted.
type canary struct {
	mu   sync.Mutex
	seen map[string]bool
}

func newCanary() *canary {
	return &canary{seen: make(map[string]bool)}
}

// handler returns the HTTP routes: /c/<token> records a hit, /hits/<token>
// reports one. Both require a non-empty token.
func (c *canary) handler() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("/c/", func(w http.ResponseWriter, r *http.Request) {
		token := strings.TrimPrefix(r.URL.Path, "/c/")
		if token == "" {
			http.NotFound(w, r)
			return
		}
		c.mu.Lock()
		c.seen[token] = true
		c.mu.Unlock()
		w.WriteHeader(http.StatusOK)
	})

	mux.HandleFunc("/hits/", func(w http.ResponseWriter, r *http.Request) {
		token := strings.TrimPrefix(r.URL.Path, "/hits/")
		if token == "" {
			http.NotFound(w, r)
			return
		}
		c.mu.Lock()
		hit := c.seen[token]
		c.mu.Unlock()
		if hit {
			fmt.Fprint(w, "1")
		} else {
			fmt.Fprint(w, "0")
		}
	})

	return mux
}

func main() {
	addr := flag.String("addr", ":8099", "address to listen on")
	flag.Parse()

	log.Printf("canary listening on %s (routes: /c/<token>, /hits/<token>)", *addr)
	if err := http.ListenAndServe(*addr, newCanary().handler()); err != nil {
		log.Fatal(err)
	}
}
