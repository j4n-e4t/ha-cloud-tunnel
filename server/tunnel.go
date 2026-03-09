package main

import (
	"crypto/subtle"
	"crypto/tls"
	"io"
	"log"
	"net"
	"time"

	"github.com/hashicorp/yamux"
)

// sanitizeRemoteAddr removes potentially dangerous characters from remote addresses
// to prevent log injection attacks
func sanitizeRemoteAddr(addr string) string {
	// Remove newlines, carriage returns, and other control characters
	safe := make([]byte, 0, len(addr))
	for i := 0; i < len(addr); i++ {
		c := addr[i]
		if c >= 32 && c < 127 {
			safe = append(safe, c)
		}
	}
	return string(safe)
}

// tunnelConnSem limits concurrent tunnel connection handling
var tunnelConnSem = make(chan struct{}, MaxTunnelConns)

// StartTunnelListener starts the TLS listener that accepts tunnel connections from clients.
// Each connection is handled in a separate goroutine. This function blocks forever.
func StartTunnelListener(s *Server) {
	listener, err := tls.Listen("tcp", TunnelPort, s.TLSConfig)
	if err != nil {
		log.Fatalf("Failed to start tunnel listener: %v", err)
	}
	log.Printf("TLS tunnel listener started on %s (max %d concurrent)", TunnelPort, MaxTunnelConns)

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("Tunnel accept error: %v", err)
			continue
		}

		// Try to acquire semaphore, reject if at capacity
		select {
		case tunnelConnSem <- struct{}{}:
			go func() {
				defer func() { <-tunnelConnSem }()
				handleTunnelConnection(s, conn)
			}()
		default:
			log.Printf("Connection limit reached, rejecting %s", sanitizeRemoteAddr(conn.RemoteAddr().String()))
			conn.Write([]byte("SERVER_BUSY"))
			conn.Close()
		}
	}
}

// handleTunnelConnection processes a new tunnel connection:
// 1. Rejects if a session is already active
// 2. Reads and validates the authentication token and client key
// 3. Sends acknowledgment on success
// 4. Establishes a yamux multiplexed session
// 5. Monitors the session until it closes
func handleTunnelConnection(s *Server, conn net.Conn) {
	remoteAddr := sanitizeRemoteAddr(conn.RemoteAddr().String())
	log.Printf("New tunnel connection from %s", remoteAddr)

	// Reject if we already have an active session
	if s.GetSession() != nil {
		log.Printf("Rejecting connection from %s: session already active", remoteAddr)
		conn.Write([]byte("SESSION_ACTIVE"))
		conn.Close()
		return
	}

	conn.SetReadDeadline(time.Now().Add(ReadTimeout))

	// Read authentication token (35 bytes: "sk-" + 32 hex chars)
	tokenBuf := make([]byte, 35)
	if _, err := io.ReadFull(conn, tokenBuf); err != nil {
		log.Printf("Failed to read token: %v", err)
		conn.Close()
		return
	}

	conn.SetReadDeadline(time.Time{}) // Clear deadline

	// Validate token using constant-time comparison to prevent timing attacks
	expectedToken := []byte(s.Token())
	if subtle.ConstantTimeCompare(tokenBuf, expectedToken) != 1 {
		log.Printf("Invalid token from %s", remoteAddr)
		conn.Write([]byte("INVALID_TOKEN"))
		conn.Close()
		return
	}

	log.Printf("Authentication successful from %s", remoteAddr)

	// Send success acknowledgment
	if _, err := conn.Write([]byte("OK")); err != nil {
		log.Printf("Failed to send ack: %v", err)
		conn.Close()
		return
	}

	// Create yamux session for multiplexing streams over this connection
	cfg := yamux.DefaultConfig()
	cfg.EnableKeepAlive = true
	cfg.KeepAliveInterval = 30 * time.Second

	session, err := yamux.Client(conn, cfg)
	if err != nil {
		log.Printf("Failed to create yamux session: %v", err)
		conn.Close()
		return
	}

	// Register session with server (closes any existing session)
	s.SetSession(session)

	log.Printf("Tunnel established with %s", conn.RemoteAddr())

	// Block until session closes
	<-session.CloseChan()
	log.Printf("Tunnel session closed")

	// Cleanup session from server
	s.ClearSession(session)
}
