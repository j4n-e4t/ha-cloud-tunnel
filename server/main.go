package main

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/hashicorp/yamux"
)

const (
	tokenFile    = "/data/token.txt"
	tunnelPort   = ":7777"
	publicPort   = ":80"
	infoPort     = ":8080"
	tokenLength  = 16 // 16 bytes = 32 hex chars
	readTimeout  = 10 * time.Second
)

type Server struct {
	token           string
	session         *yamux.Session
	sessionMu       sync.RWMutex
	connectedOnce   bool
	connectedOnceMu sync.RWMutex
}

func main() {
	s := &Server{}

	// Load or generate token
	token, err := s.loadOrGenerateToken()
	if err != nil {
		log.Fatalf("Failed to initialize token: %v", err)
	}
	s.token = token
	log.Printf("=== SETUP TOKEN: %s ===", token)

	// Start listeners
	go s.startTunnelListener()
	go s.startPublicListener()

	// Start info HTTP server
	s.startInfoServer()
}

func (s *Server) loadOrGenerateToken() (string, error) {
	// Try to load existing token
	data, err := os.ReadFile(tokenFile)
	if err == nil && len(data) >= 32 {
		token := string(data[:32])
		log.Println("Loaded existing token from file")
		return token, nil
	}

	// Generate new token
	bytes := make([]byte, tokenLength)
	if _, err := rand.Read(bytes); err != nil {
		return "", fmt.Errorf("failed to generate random token: %w", err)
	}
	token := hex.EncodeToString(bytes)

	// Ensure directory exists
	if err := os.MkdirAll(filepath.Dir(tokenFile), 0755); err != nil {
		log.Printf("Warning: could not create data directory: %v", err)
	}

	// Save token
	if err := os.WriteFile(tokenFile, []byte(token), 0600); err != nil {
		log.Printf("Warning: could not save token to file: %v", err)
	} else {
		log.Println("Generated and saved new token")
	}

	return token, nil
}

func (s *Server) startTunnelListener() {
	listener, err := net.Listen("tcp", tunnelPort)
	if err != nil {
		log.Fatalf("Failed to start tunnel listener: %v", err)
	}
	log.Printf("Tunnel listener started on %s", tunnelPort)

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("Tunnel accept error: %v", err)
			continue
		}
		go s.handleTunnelConnection(conn)
	}
}

func (s *Server) handleTunnelConnection(conn net.Conn) {
	log.Printf("New tunnel connection from %s", conn.RemoteAddr())

	// Read token (32 bytes)
	conn.SetReadDeadline(time.Now().Add(readTimeout))
	tokenBuf := make([]byte, 32)
	n, err := io.ReadFull(conn, tokenBuf)
	if err != nil {
		log.Printf("Failed to read token: %v", err)
		conn.Close()
		return
	}
	conn.SetReadDeadline(time.Time{})

	receivedToken := string(tokenBuf[:n])
	if receivedToken != s.token {
		log.Printf("Invalid token from %s", conn.RemoteAddr())
		conn.Write([]byte("INVALID_TOKEN"))
		conn.Close()
		return
	}

	log.Printf("Token validated from %s", conn.RemoteAddr())

	// Send acknowledgment
	_, err = conn.Write([]byte("OK"))
	if err != nil {
		log.Printf("Failed to send ack: %v", err)
		conn.Close()
		return
	}

	// Create yamux session (server mode - we accept streams from client)
	config := yamux.DefaultConfig()
	config.EnableKeepAlive = true
	config.KeepAliveInterval = 30 * time.Second

	session, err := yamux.Client(conn, config)
	if err != nil {
		log.Printf("Failed to create yamux session: %v", err)
		conn.Close()
		return
	}

	// Mark as connected once
	s.connectedOnceMu.Lock()
	s.connectedOnce = true
	s.connectedOnceMu.Unlock()

	// Close existing session if any
	s.sessionMu.Lock()
	if s.session != nil {
		s.session.Close()
	}
	s.session = session
	s.sessionMu.Unlock()

	log.Printf("Tunnel established with %s", conn.RemoteAddr())

	// Monitor session
	<-session.CloseChan()
	log.Printf("Tunnel session closed")

	s.sessionMu.Lock()
	if s.session == session {
		s.session = nil
	}
	s.sessionMu.Unlock()
}

func (s *Server) startPublicListener() {
	listener, err := net.Listen("tcp", publicPort)
	if err != nil {
		log.Fatalf("Failed to start public listener: %v", err)
	}
	log.Printf("Public listener started on %s", publicPort)

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("Public accept error: %v", err)
			continue
		}
		go s.proxyConnection(conn)
	}
}

func (s *Server) proxyConnection(publicConn net.Conn) {
	defer publicConn.Close()

	s.sessionMu.RLock()
	session := s.session
	s.sessionMu.RUnlock()

	if session == nil {
		log.Printf("No tunnel available for %s", publicConn.RemoteAddr())
		// Send a simple error response for HTTP clients
		publicConn.Write([]byte("HTTP/1.1 503 Service Unavailable\r\nContent-Type: text/plain\r\n\r\nTunnel not connected\n"))
		return
	}

	// Open a stream to the client
	stream, err := session.Open()
	if err != nil {
		log.Printf("Failed to open stream: %v", err)
		publicConn.Write([]byte("HTTP/1.1 502 Bad Gateway\r\nContent-Type: text/plain\r\n\r\nFailed to connect to tunnel\n"))
		return
	}
	defer stream.Close()

	log.Printf("Proxying connection from %s", publicConn.RemoteAddr())

	// Bidirectional copy
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		io.Copy(stream, publicConn)
		stream.Close()
	}()

	go func() {
		defer wg.Done()
		io.Copy(publicConn, stream)
		publicConn.Close()
	}()

	wg.Wait()
	log.Printf("Connection closed for %s", publicConn.RemoteAddr())
}

func (s *Server) startInfoServer() {
	http.HandleFunc("/", s.handleInfo)
	http.HandleFunc("/health", s.handleHealth)

	log.Printf("Info server started on %s", infoPort)
	if err := http.ListenAndServe(infoPort, nil); err != nil {
		log.Fatalf("Info server failed: %v", err)
	}
}

func (s *Server) handleInfo(w http.ResponseWriter, r *http.Request) {
	s.connectedOnceMu.RLock()
	connectedOnce := s.connectedOnce
	s.connectedOnceMu.RUnlock()

	s.sessionMu.RLock()
	tunnelActive := s.session != nil
	s.sessionMu.RUnlock()

	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	if !connectedOnce {
		// Token page - shown until first connection
		html := fmt.Sprintf(`<!DOCTYPE html>
<html>
<head>
<title>HA Cloud Tunnel</title>
<meta http-equiv="refresh" content="5">
<style>body{font-family:monospace;max-width:600px;margin:40px auto;padding:20px}pre{background:#f5f5f5;padding:20px;overflow-x:auto}</style>
</head>
<body>
<h1>HA Cloud Tunnel</h1>
<p>Setup token:</p>
<pre>%s</pre>
<p>Copy this token to your client configuration.<br>This page will update when connected.</p>
<hr>
<p>Status: waiting for client...</p>
</body>
</html>`, s.token)
		w.Write([]byte(html))
		return
	}

	// Status page - shown after first connection
	status := "disconnected"
	if tunnelActive {
		status = "connected"
	}

	html := fmt.Sprintf(`<!DOCTYPE html>
<html>
<head>
<title>HA Cloud Tunnel</title>
<meta http-equiv="refresh" content="5">
<style>body{font-family:monospace;max-width:600px;margin:40px auto;padding:20px}</style>
</head>
<body>
<h1>HA Cloud Tunnel</h1>
<p>Status: %s</p>
</body>
</html>`, status)
	w.Write([]byte(html))
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	s.sessionMu.RLock()
	tunnelActive := s.session != nil
	s.sessionMu.RUnlock()

	if tunnelActive {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	} else {
		w.WriteHeader(http.StatusServiceUnavailable)
		w.Write([]byte("NO_TUNNEL"))
	}
}
