package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/hashicorp/yamux"
)

const (
	dataDir     = "/data"
	tokenFile   = "/data/token.txt"
	certFile    = "/data/server.crt"
	keyFile     = "/data/server.key"
	tunnelPort  = ":7777"
	publicPort  = ":80"
	tokenLength = 16 // 16 bytes = 32 hex chars
	readTimeout = 10 * time.Second
)

type Server struct {
	token           string
	fingerprint     string
	tlsConfig       *tls.Config
	session         *yamux.Session
	sessionMu       sync.RWMutex
	connectedOnce   bool
	connectedOnceMu sync.RWMutex
}

func main() {
	s := &Server{}

	// Ensure data directory exists
	if err := os.MkdirAll(dataDir, 0755); err != nil {
		log.Printf("Warning: could not create data directory: %v", err)
	}

	// Load or generate token
	token, err := s.loadOrGenerateToken()
	if err != nil {
		log.Fatalf("Failed to initialize token: %v", err)
	}
	s.token = token

	// Load or generate TLS certificate
	tlsConfig, fingerprint, err := s.loadOrGenerateCert()
	if err != nil {
		log.Fatalf("Failed to initialize TLS: %v", err)
	}
	s.tlsConfig = tlsConfig
	s.fingerprint = fingerprint
	log.Printf("Certificate fingerprint: %s", fingerprint)

	// Start listeners
	go s.startTunnelListener()

	// Start HTTP server on public port
	s.startPublicServer()
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

	// Save token
	if err := os.WriteFile(tokenFile, []byte(token), 0600); err != nil {
		log.Printf("Warning: could not save token to file: %v", err)
	} else {
		log.Println("Generated and saved new token")
	}

	return token, nil
}

func (s *Server) loadOrGenerateCert() (*tls.Config, string, error) {
	// Try to load existing cert
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err == nil {
		log.Println("Loaded existing certificate from file")
		fingerprint := computeCertFingerprint(cert.Certificate[0])
		tlsConfig := &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS12,
		}
		return tlsConfig, fingerprint, nil
	}

	// Generate new self-signed certificate
	log.Println("Generating new self-signed certificate...")

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, "", fmt.Errorf("failed to generate private key: %w", err)
	}

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, "", fmt.Errorf("failed to generate serial number: %w", err)
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"HA Cloud Tunnel"},
			CommonName:   "HA Cloud Tunnel Server",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0), // Valid for 10 years
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"localhost"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return nil, "", fmt.Errorf("failed to create certificate: %w", err)
	}

	// Save certificate
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	if err := os.WriteFile(certFile, certPEM, 0644); err != nil {
		log.Printf("Warning: could not save certificate: %v", err)
	}

	// Save private key
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)})
	if err := os.WriteFile(keyFile, keyPEM, 0600); err != nil {
		log.Printf("Warning: could not save private key: %v", err)
	}

	log.Println("Generated and saved new certificate")

	fingerprint := computeCertFingerprint(certDER)
	cert = tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  privateKey,
	}
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}

	return tlsConfig, fingerprint, nil
}

func computeCertFingerprint(certDER []byte) string {
	hash := sha256.Sum256(certDER)
	return "SHA256:" + hex.EncodeToString(hash[:])
}

func (s *Server) startTunnelListener() {
	listener, err := tls.Listen("tcp", tunnelPort, s.tlsConfig)
	if err != nil {
		log.Fatalf("Failed to start tunnel listener: %v", err)
	}
	log.Printf("TLS tunnel listener started on %s", tunnelPort)

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
	if _, err := conn.Write([]byte("OK")); err != nil {
		log.Printf("Failed to send ack: %v", err)
		conn.Close()
		return
	}

	// Create yamux session
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

func (s *Server) startPublicServer() {
	mux := http.NewServeMux()
	mux.HandleFunc("/health", s.handleHealth)
	mux.HandleFunc("/", s.handlePublic)

	server := &http.Server{
		Addr:    publicPort,
		Handler: mux,
	}

	log.Printf("Public server started on %s", publicPort)
	if err := server.ListenAndServe(); err != nil {
		log.Fatalf("Public server failed: %v", err)
	}
}

func (s *Server) handlePublic(w http.ResponseWriter, r *http.Request) {
	s.sessionMu.RLock()
	session := s.session
	s.sessionMu.RUnlock()

	// If no tunnel, show info page
	if session == nil {
		s.serveInfoPage(w, r)
		return
	}

	// Tunnel is connected - hijack and proxy
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "Hijacking not supported", http.StatusInternalServerError)
		return
	}

	clientConn, buf, err := hijacker.Hijack()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer clientConn.Close()

	// Open a stream to the tunnel client
	stream, err := session.Open()
	if err != nil {
		log.Printf("Failed to open stream: %v", err)
		clientConn.Write([]byte("HTTP/1.1 502 Bad Gateway\r\nContent-Type: text/plain\r\n\r\nFailed to connect to tunnel\n"))
		return
	}
	defer stream.Close()

	log.Printf("Proxying connection from %s", r.RemoteAddr)

	// Write the original request to the stream
	if err := r.Write(stream); err != nil {
		log.Printf("Failed to write request: %v", err)
		return
	}

	// Also write any buffered data
	if buf.Reader.Buffered() > 0 {
		buffered := make([]byte, buf.Reader.Buffered())
		buf.Read(buffered)
		stream.Write(buffered)
	}

	// Bidirectional copy
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		io.Copy(stream, clientConn)
		stream.Close()
	}()

	go func() {
		defer wg.Done()
		io.Copy(clientConn, stream)
		clientConn.Close()
	}()

	wg.Wait()
	log.Printf("Connection closed for %s", r.RemoteAddr)
}

func (s *Server) serveInfoPage(w http.ResponseWriter, r *http.Request) {
	s.connectedOnceMu.RLock()
	connectedOnce := s.connectedOnce
	s.connectedOnceMu.RUnlock()

	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	if !connectedOnce {
		// Setup page - shown until first connection
		html := fmt.Sprintf(`<!DOCTYPE html>
<html>
<head>
<title>HA Cloud Tunnel</title>
<meta http-equiv="refresh" content="5">
<style>
body{font-family:system-ui,sans-serif;max-width:700px;margin:40px auto;padding:20px;text-align:center}
.credential{background:#f5f5f5;padding:15px;margin:10px 0;border-radius:8px;font-family:monospace;font-size:0.95rem;word-break:break-all}
label{font-weight:bold;display:block;margin-top:20px}
</style>
</head>
<body>
<h1>HA Cloud Tunnel</h1>
<p>Copy these credentials to your client configuration:</p>

<label>Token</label>
<div class="credential">%s</div>

<label>Fingerprint</label>
<div class="credential">%s</div>

<hr>
<p>Status: waiting for client...</p>
</body>
</html>`, s.token, s.fingerprint)
		w.Write([]byte(html))
		return
	}

	// Disconnected page
	html := `<!DOCTYPE html>
<html>
<head>
<title>HA Cloud Tunnel</title>
<meta http-equiv="refresh" content="5">
<style>body{font-family:system-ui,sans-serif;max-width:600px;margin:40px auto;padding:20px;text-align:center}</style>
</head>
<body>
<h1>HA Cloud Tunnel</h1>
<p>Status: disconnected</p>
<p>Waiting for client to reconnect...</p>
</body>
</html>`
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
