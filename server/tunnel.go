package main

import (
	"crypto/tls"
	"io"
	"log"
	"net"
	"time"

	"github.com/hashicorp/yamux"
)

// StartTunnelListener starts the TLS listener that accepts tunnel connections from clients.
// Each connection is handled in a separate goroutine. This function blocks forever.
func StartTunnelListener(s *Server) {
	listener, err := tls.Listen("tcp", TunnelPort, s.TLSConfig)
	if err != nil {
		log.Fatalf("Failed to start tunnel listener: %v", err)
	}
	log.Printf("TLS tunnel listener started on %s", TunnelPort)

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("Tunnel accept error: %v", err)
			continue
		}
		go handleTunnelConnection(s, conn)
	}
}

// handleTunnelConnection processes a new tunnel connection:
// 1. Reads and validates the authentication token and client key
// 2. Sends acknowledgment on success
// 3. Establishes a yamux multiplexed session
// 4. Monitors the session until it closes
func handleTunnelConnection(s *Server, conn net.Conn) {
	log.Printf("New tunnel connection from %s", conn.RemoteAddr())

	conn.SetReadDeadline(time.Now().Add(ReadTimeout))

	// Read authentication token (35 bytes: "sk-" + 32 hex chars)
	tokenBuf := make([]byte, 35)
	if _, err := io.ReadFull(conn, tokenBuf); err != nil {
		log.Printf("Failed to read token: %v", err)
		conn.Close()
		return
	}

	// Read client key (35 bytes: "ck-" + 32 hex chars)
	clientKeyBuf := make([]byte, 35)
	if _, err := io.ReadFull(conn, clientKeyBuf); err != nil {
		log.Printf("Failed to read client key: %v", err)
		conn.Close()
		return
	}

	conn.SetReadDeadline(time.Time{}) // Clear deadline

	// Validate token
	if string(tokenBuf) != s.Token() {
		log.Printf("Invalid token from %s", conn.RemoteAddr())
		conn.Write([]byte("INVALID_TOKEN"))
		conn.Close()
		return
	}

	// Verify or bind client key
	clientKey := string(clientKeyBuf)
	if !s.State.VerifyOrBindClientKey(clientKey) {
		log.Printf("Invalid client key from %s", conn.RemoteAddr())
		conn.Write([]byte("INVALID_CLIENT"))
		conn.Close()
		return
	}

	log.Printf("Authentication successful from %s", conn.RemoteAddr())

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
