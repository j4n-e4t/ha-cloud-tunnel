// HA Cloud Tunnel Server
//
// This server enables secure remote access to Home Assistant by:
// 1. Accepting TLS tunnel connections from authenticated clients
// 2. Proxying public HTTP requests through the tunnel to the client
//
// Architecture:
// - State: Persists token, certificates, and connection state to /data/state.json
// - Tunnel: TLS listener on :7777 that authenticates clients via token
// - HTTP: Public server on :80 that proxies requests through the tunnel
//
// The server generates a self-signed certificate and authentication token on first run.
// Clients must verify the certificate fingerprint to prevent MITM attacks.

package main

import (
	"log"
	"time"
)

// Configuration constants
const (
	DataDir     = "/data"           // Directory for persistent state
	StateFile   = "/data/state.json" // Path to state file
	TunnelPort  = ":7777"           // Port for TLS tunnel connections
	PublicPort  = ":80"             // Port for public HTTP server
	TokenLength = 16                // Token length in bytes (32 hex chars + "sk-" prefix)
	ReadTimeout = 10 * time.Second  // Timeout for reading client token
)

// main initializes the server and starts both the tunnel listener and HTTP server.
// The tunnel listener runs in a goroutine while the HTTP server runs in the main goroutine.
func main() {
	s, err := NewServer()
	if err != nil {
		log.Fatalf("Failed to initialize server: %v", err)
	}

	go StartTunnelListener(s)

	StartHTTPServer(s)
}
