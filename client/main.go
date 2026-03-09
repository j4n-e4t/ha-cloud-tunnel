// HA Cloud Tunnel Client
//
// This client establishes a secure tunnel to a remote server, allowing
// external access to a local Home Assistant instance.
//
// Architecture:
// - Client: Manages the tunnel session and reconnection logic
// - Tunnel: Establishes TLS connection with certificate fingerprint verification
// - Proxy: Forwards incoming streams to Home Assistant
//
// The client authenticates using a pre-shared token and verifies the server's
// certificate fingerprint to prevent MITM attacks.

package main

import (
	"log"
	"os"
	"strings"
	"time"
)

// Configuration constants
const (
	DefaultTargetAddr = "homeassistant:8123" // Default local Home Assistant address
	ReconnectDelay    = 5 * time.Second      // Delay between reconnection attempts
	ConnectTimeout    = 30 * time.Second     // Timeout for establishing connection
	AckTimeout        = 10 * time.Second     // Timeout for authentication response
	ProxyTimeout      = 10 * time.Second     // Timeout for connecting to target
)

// main loads configuration from environment variables and starts the tunnel client.
// Required environment variables:
// - SERVER_ADDR: Server address (host:port)
// - TOKEN: Authentication token (sk-{32-hex-chars})
// - FINGERPRINT: Server certificate fingerprint (SHA256:xxxx)
// Optional:
// - TARGET_ADDR: Local target address (default: homeassistant:8123)
// Client key is derived from token + fingerprint (not stored).
func main() {
	serverAddr := os.Getenv("SERVER_ADDR")
	if serverAddr == "" {
		log.Fatal("SERVER_ADDR environment variable is required")
	}

	token := os.Getenv("TOKEN")
	if token == "" {
		log.Fatal("TOKEN environment variable is required")
	}
	if len(token) != 35 || token[:3] != "sk-" {
		log.Fatal("TOKEN must be in format sk-{32-hex-chars}")
	}

	fingerprint := os.Getenv("FINGERPRINT")
	if fingerprint == "" {
		log.Fatal("FINGERPRINT environment variable is required")
	}
	// Normalize fingerprint to uppercase with SHA256: prefix
	fingerprint = strings.ToUpper(strings.TrimPrefix(fingerprint, "SHA256:"))
	fingerprint = "SHA256:" + fingerprint

	targetAddr := os.Getenv("TARGET_ADDR")
	if targetAddr == "" {
		targetAddr = DefaultTargetAddr
	}

	c := NewClient(serverAddr, token, fingerprint, targetAddr)

	log.Printf("Server: %s", serverAddr)
	log.Printf("Target: %s", targetAddr)
	log.Printf("Fingerprint: %s", fingerprint)

	c.Run()
}
