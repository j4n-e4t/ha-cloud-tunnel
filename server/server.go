package main

import (
	"crypto/tls"
	"log"
	"os"
	"sync"

	"github.com/hashicorp/yamux"
)

// Server holds the runtime state and configuration for the tunnel server.
// It manages the TLS configuration, active tunnel session, and persistent state.
type Server struct {
	Fingerprint string         // SHA256 fingerprint of the server certificate
	ServerAddr  string         // Public address for clients (from Railway TCP proxy)
	TLSConfig   *tls.Config    // TLS configuration with server certificate
	Session     *yamux.Session // Active multiplexed tunnel session (nil if disconnected)
	SessionMu   sync.RWMutex   // Protects Session field
	State       *State         // Persistent state (token, certs, client state)
}

// NewServer initializes the server by loading or creating persistent state,
// configuring TLS, and determining the public server address from environment.
func NewServer() (*Server, error) {
	s := &Server{}

	// Ensure data directory exists for state persistence
	if err := os.MkdirAll(DataDir, 0777); err != nil {
		log.Printf("Warning: could not create data directory: %v", err)
	}

	// Initialize state (loads existing or creates new token + certs)
	s.State = GetState()

	// Build TLS config from stored certificate
	tlsConfig, fingerprint, err := s.State.GetTLSConfig()
	if err != nil {
		return nil, err
	}
	s.TLSConfig = tlsConfig
	s.Fingerprint = fingerprint
	log.Printf("Certificate fingerprint: %s", fingerprint)

	// Get public server address from Railway environment variables
	tcpDomain := os.Getenv("RAILWAY_TCP_PROXY_DOMAIN")
	tcpPort := os.Getenv("RAILWAY_TCP_PROXY_PORT")
	if tcpDomain != "" && tcpPort != "" {
		s.ServerAddr = tcpDomain + ":" + tcpPort
		log.Printf("Server address (Railway TCP Proxy): %s", s.ServerAddr)
	}

	return s, nil
}

// GetSession returns the current tunnel session, or nil if no client is connected.
// Thread-safe for concurrent access.
func (s *Server) GetSession() *yamux.Session {
	s.SessionMu.RLock()
	defer s.SessionMu.RUnlock()
	return s.Session
}

// SetSession establishes a new tunnel session, closing any existing session first.
// Updates the client state to CONNECTED.
func (s *Server) SetSession(session *yamux.Session) {
	s.SessionMu.Lock()
	if s.Session != nil {
		s.Session.Close()
	}
	s.Session = session
	s.SessionMu.Unlock()

	s.State.SetClientState(StateConnected)
}

// ClearSession removes the given session if it matches the current one.
// This prevents a new connection from being cleared by an old session's cleanup.
// Updates the client state to DISCONNECTED.
func (s *Server) ClearSession(session *yamux.Session) {
	s.SessionMu.Lock()
	if s.Session == session {
		s.Session = nil
	}
	s.SessionMu.Unlock()

	s.State.SetClientState(StateDisconnected)
}

// Token returns the authentication token that clients must present.
func (s *Server) Token() string {
	return s.State.GetToken()
}
